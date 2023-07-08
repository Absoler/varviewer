#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>


class Range{
    public:

    static Range createEmpty();
    static Range createFromDie(Dwarf_Die die);
    void clear();
    void setFromDie(Dwarf_Die);
    Dwarf_Addr startpc, endpc;
};

int parse_simple_ranges(Dwarf_Die die, Dwarf_Addr *startpc, Dwarf_Addr *endpc);