// shim.c — deliberately empty.
//
// `CBPFShim` is header-only: every symbol is a `static inline` function that the Swift
// compiler evaluates at the call site. SwiftPM still requires a C target to have at
// least one source file, so this is it. Including the header keeps the compiler
// checking that it parses on its own rather than only when Swift imports it.
#include "include/CBPFShim.h"
