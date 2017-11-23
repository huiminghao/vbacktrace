# vbacktrace
backtrace for mingw, suitable for Linux/win, x86/x64

# compile

for linux, use gcc.  
this module will use the backtrace api from execinfo.h.  
use -rdynamic in link option.

for win32/win64
use mingw32/mingw64 from msys2.  
you can use pacman to install the binutils, and get the libbfd.  
msys2 dont have libbfd in bintuils for mingw32, you have to compile it from source by hand.

use -limagehlp when linking.


# default handler

this module provides a default handler for SIGSEGV(SetUnhandledExceptionHander for win), which works in win32/win64/linux. this handler dont support ARM, bcz the handler is called in the interrupt stack, not the point at which the signal is emitted.
