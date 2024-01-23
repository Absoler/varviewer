#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>


class Range{
    public:
    static Range createEmpty();
    static Range createFromDie(Dwarf_Die die);
    Range():startpc(0), endpc(0) {}
    Range(const Range &range);
    void clear();
    void setFromDie(Dwarf_Die);
    void setFromRange(const Range &range);
    Dwarf_Addr startpc, endpc;
};

int parse_simple_ranges(Dwarf_Die die, Dwarf_Addr *startpc, Dwarf_Addr *endpc);