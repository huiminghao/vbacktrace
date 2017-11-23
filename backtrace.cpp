#include <viga_backtrace.h>
#include <cxxabi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

char *vbacktrace_demangle(const char *name)
{
    int32_t status;
    char *pdname = abi::__cxa_demangle(name, NULL, 0, &status);     
    if(status == 0) {
        return pdname;
    } else { 
        return strdup(name);
    }
}

void vbacktrace_free(struct vbacktrace_line *linep)
{
    struct vbacktrace_line *n;
    while(linep) {
        n = linep->next;
        free(linep->module);
        free(linep->function);
        free(linep);
        linep = n;
    }
}
