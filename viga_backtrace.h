#ifndef    _BACKTRACE_H_
#define    _BACKTRACE_H_

#ifdef __cplusplus
extern "C" {
#else
    //}
#endif
#include <stdint.h>

struct vbacktrace_line {
   uintptr_t offset;
   char *function;
   char *module;
   struct vbacktrace_line *next;
};

EXPORT int32_t vbacktrace_fetch(struct vbacktrace_line **linep, int32_t limit);
EXPORT void vbacktrace_free(struct vbacktrace_line *linep);
EXPORT void vbacktrace_install_default();

#ifdef __cplusplus
}
#endif
#endif
