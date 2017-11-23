#ifdef _WIN32
#include <windows.h>
#include <imagehlp.h>
#define PACKAGE 1
#define PACKAGE_VERSION 1
#include <bfd.h>
#include <viga_backtrace.h>
#include <viga_log.h>

extern char *vbacktrace_demangle(const char *name);

struct fnis_para {
    char *function;
    asymbol** symbol_table;
    bfd_vma pointer;
};

static void find_function_name_in_section(bfd* tabfd, asection* tsec, void *arg)
{
    fnis_para *para = (struct fnis_para*)arg;
    if(para->function) { // We have got the name.
        return;
    }
    if(!(bfd_get_section_flags(tabfd, tsec) & SEC_ALLOC)) {
        return; // Allocate space for this section.
    }
    bfd_vma vma = bfd_get_section_vma(tabfd, tsec);
    if(para->pointer < vma || para->pointer > vma + bfd_get_section_size(tsec)){
        return;        
    }
    const char* function = NULL;
    const char* file = NULL;
    uint32_t line = 0;
    // Get corresponding file and function name, and line number.
    if(bfd_find_nearest_line(tabfd, tsec, para->symbol_table, para->pointer - vma, &file, &function, &line) && function) {
        para->function = vbacktrace_demangle(function);
    }
}
static int32_t vbacktrace_fetch_context(vbacktrace_line **linep, int32_t limit, LPCONTEXT context)
{
    STACKFRAME frame = { 0 };

    int32_t count = 0;
    char procname[1024];
    char **matching = NULL;
    bfd* abfd = NULL;
    asymbol **symbol_table = NULL;
#if defined(_WIN64)
    const DWORD machine = IMAGE_FILE_MACHINE_AMD64;
#else
    const DWORD machine = IMAGE_FILE_MACHINE_I386;
#endif    
    const HANDLE process = GetCurrentProcess();
    const HANDLE thread = GetCurrentThread();
    uint32_t symbol_size = 0;


    *linep = NULL;
    if(!SymInitialize(GetCurrentProcess(), 0, TRUE)) {
        log_err("failed to initialize symbol context.\n");
        goto err_initialize;
    }

    // Prepare variables.
#if defined(_WIN64)
    frame.AddrPC.Offset = context->Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context->Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context->Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
#else
    frame.AddrPC.Offset = context->Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context->Esp;
    frame.AddrStack.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context->Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
#endif

    GetModuleFileName(NULL, procname, sizeof(procname));
    bfd_init();
    abfd = bfd_openr(procname, NULL);
    if(!abfd) {
        log_err("failed to parse the executable format:%s.\n", procname);
        goto err_bfd;
    }

    if(!(bfd_check_format(abfd, bfd_object) && // Whether the executable format is supported.
                bfd_check_format_matches(abfd, bfd_object, &matching) && // Whether the executable format is supported.
                (bfd_get_file_flags(abfd) & HAS_SYMS))) // Whether BFD has symbols
    {
        log_err("failed to parse the executable format:%s.\n", procname);
        goto err_match;
    }
    if(matching) {
        free(matching);
    }

    if(bfd_read_minisymbols(abfd, 0, (void **)&symbol_table, &symbol_size) == 0 &&
            bfd_read_minisymbols(abfd, 1, (void **)&symbol_table, &symbol_size) < 0) {
        log_err("failed to obtain the symbol table from the executable.\n");
        goto err_table;
    }

    char symbol_buffer[sizeof(IMAGEHLP_SYMBOL) + 512];
    char module_name_raw[1024];

    while(StackWalk(machine, process, thread, &frame, context, 0, SymFunctionTableAccess, SymGetModuleBase, 0))
    {       
        if(--limit == 0) {
            break; 
        }

        IMAGEHLP_SYMBOL *symbol = (IMAGEHLP_SYMBOL*)symbol_buffer;
        symbol->SizeOfStruct = sizeof(symbol_buffer);
        symbol->MaxNameLength = sizeof(symbol_buffer) - sizeof(*symbol) - 1;

        const uintptr_t module_base = SymGetModuleBase(process, frame.AddrPC.Offset);
        char *module_name = NULL;
        if(module_base && GetModuleFileNameA((HINSTANCE)module_base, module_name_raw, sizeof(module_name_raw))) {
            module_name = strdup(module_name_raw);
        } else {
            module_name = strdup("[unknown module]");
        }

        // get function name
        fnis_para para;
        para.symbol_table = symbol_table;
        para.pointer = frame.AddrPC.Offset;        
        para.function = NULL;
        bfd_map_over_sections(abfd, &find_function_name_in_section, &para); // Call the corresponding functions.

        if(!para.function) {
#ifdef _WIN64
            DWORD64 dummy = 0;
#else
            DWORD dummy = 0;
#endif
            const bool got_symbol = SymGetSymFromAddr(process, frame.AddrPC.Offset, &dummy, symbol);
            if(got_symbol) {
                para.function = strdup(symbol->Name);
            } else {
                para.function = strdup("[unknown function]");
            }
        }
        struct vbacktrace_line *l = (struct vbacktrace_line *)malloc(sizeof(*l));
        l->offset = frame.AddrPC.Offset;
        l->function = para.function;
        l->module = module_name;
        l->next = NULL;
        *linep = l;
        linep = &l->next;
        count++;
    }

    SymCleanup(GetCurrentProcess());
err_table:
    if(symbol_table) {
        free(symbol_table);
    }
    if(matching) {
        free(matching);
    }
err_match:
    bfd_close(abfd);
    free(matching);
err_bfd:
err_initialize:
    return count;
}
int32_t vbacktrace_fetch(vbacktrace_line **linep, int32_t limit)
{
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);
    return vbacktrace_fetch_context(linep, limit, &context);
}

static LONG WINAPI sigsegv(LPEXCEPTION_POINTERS info)
{
    struct vbacktrace_line *l;
    int32_t count = vbacktrace_fetch_context(&l, 128, info->ContextRecord);
    struct vbacktrace_line *p = l;
    while(p) {
        log_err("[%3d] %16p: %s in %s\n", count--, (void *)p->offset, p->function, p->module);
        p = p->next;
    }
    vbacktrace_free(l);
    return EXCEPTION_CONTINUE_SEARCH;
}
void vbacktrace_install_default()
{
    SetUnhandledExceptionFilter(sigsegv);
}
#endif
