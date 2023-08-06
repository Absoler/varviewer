#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <string>
#define simple_handle_err(res) do{ \
    if(res!=DW_DLV_OK){ \
        return res; \
    } \
}while(0);

// translated as unsigned, convert to signed if need
Dwarf_Unsigned get_const_u(Dwarf_Half form, Dwarf_Attribute attr, Dwarf_Error *err);

int get_name(Dwarf_Debug dbg, Dwarf_Die die, char **name);

void printindent(int indent);
std::string addindent(int indent);

template<typename T> std::string toHex(T v);