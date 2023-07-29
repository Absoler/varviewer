#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <string>
#include <vector>


// <piece_start, piece_size>
typedef std::pair<Dwarf_Addr, int> piece_type;

class Type{
    public:
    std::string typeName;
    std::vector<piece_type> pieces;
    std::vector<std::string> piece_names;
    void clear();

    static int extract_struct_type(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Type *type);

};