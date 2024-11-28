#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <iostream>
#include <string>

namespace varviewer {
/*
handle error
*/
#define SIMPLE_HANDLE_ERR(res) \
  do {                         \
    if (res != DW_DLV_OK) {    \
      return res;              \
    }                          \
  } while (0);

#define HANDLE_ERR(res, err)         \
  do {                               \
    if (res == DW_DLV_ERROR) {       \
      char *msg = dwarf_errmsg(err); \
      printf("%s\n", msg);           \
    }                                \
    if (res != DW_DLV_OK) {          \
      return res;                    \
    }                                \
  } while (0);

#define likely(x) __builtin_expect(!!(x), 1)

#define unlikely(x) __builtin_expect(!!(x), 0)

/*
assert
*/
#define VARVIEWER_ASSERT(condition, message)               \
  do {                                                     \
    if (!(condition)) {                                    \
      std::cerr << "Assertion failed: " << message << "\n" \
                << "File: " << __FILE__ << "\n"            \
                << "Line: " << __LINE__ << std::endl;      \
      std::abort();                                        \
    }                                                      \
  } while (0)

// translated as unsigned, convert to signed if need
Dwarf_Unsigned get_const_u(Dwarf_Half form, Dwarf_Attribute attr, Dwarf_Error *err);

int get_name(Dwarf_Debug dbg, Dwarf_Die die, char **name);

void printindent(int indent);

std::string addindent(int indent);

template <typename T>
std::string toHex(T v);

int log2(int x);

}  // namespace varviewer
