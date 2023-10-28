#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <string>
#include <vector>
#include <memory>
#include <map>

// <piece_start, piece_size>
typedef std::pair<Dwarf_Addr, int> piece_type;

class Type;

extern std::map<Dwarf_Off, Type*> type_map;

/* now we don't care about float type */
enum BasicType{
    INVALID_TYPE = -1,
    GENERIC = 0,
    CHAR = 1,
    UNSIGNED_CHAR = 2,
    SHORT = 3,
    UNSIGNED_SHORT = 4,
    INT = 5,
    UNSIGNED_INT = 6,
};

class Type{
    public:
    Type();
    static int parse_type_die(Dwarf_Debug dbg, Dwarf_Die var_die, Type **type_p);
    static void finish();
    void clear();
    std::string to_string();

    private:
    BasicType basicType;
    int size;
    bool has_sign;
    bool valid;
    // std::string typeName;
    // std::vector<piece_type> pieces;
    // std::vector<std::string> piece_names;

    // static int extract_struct_type(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Type *type);

};