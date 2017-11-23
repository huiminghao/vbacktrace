#ifndef _WIN32
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <execinfo.h>
#include <viga_backtrace.h>

#define log_err printf
#define log_dbg printf

extern char *vbacktrace_demangle(const char *name);
int32_t vbacktrace_fetch(struct vbacktrace_line **linep, int32_t limit)
{
    int32_t size = limit ? limit : 256;
    void *buffer[size];
    int ncalls = backtrace(buffer, sizeof(void *) * size);
    char **callstrings = backtrace_symbols(buffer, ncalls);
    
    *linep = NULL;
    if(callstrings == NULL) {
        log_err("failed to obtain the symbol table from the executable.\n");
        return 0;
    }

    for(int i = 0; i < ncalls; ++i) {
        char *posleftparenthesis = strrchr(callstrings[i], '(');
        char *posplus = strrchr(callstrings[i], '+');
        char *posleftbracket = strrchr(callstrings[i], '[');
        //char *posrightbracket = strrchr(callstrings[i], ']');

        uintptr_t offset = strtoull(posleftbracket + 1, NULL, 0);
        char *module_name = strdup(callstrings[i]);
        module_name[posleftparenthesis - callstrings[i]] = 0;
        char *function = strdup(posleftparenthesis + 1);
        if(posplus) {
            function[posplus - posleftparenthesis - 1] = 0;
        } else {
            function[0] = 0;
        }
        struct vbacktrace_line *l = (struct vbacktrace_line *)malloc(sizeof(*l));
        l->offset = offset;
        l->module = module_name;
        l->function = vbacktrace_demangle(function);
        l->next = NULL;
        *linep = l;
        linep = &l->next;
        free(function);
     }
     free(callstrings);

     return ncalls;
}
static void sigsegv(int signo)
{
    struct vbacktrace_line *l;
    int32_t count = vbacktrace_fetch(&l, 128);
    struct vbacktrace_line *p = l;
    while(p) {
        log_err("[%3d] %16p: %s in %s\n", count--, (void *)p->offset, p->function, p->module);
        p = p->next;
    }
    vbacktrace_free(l);
    signal(SIGSEGV, SIG_DFL);
}
void vbacktrace_install_default()
{
    signal(SIGSEGV, sigsegv);
}
#endif
