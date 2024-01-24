#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include "Address.h"
#include "Expression.h"
#include "ranges.h"
#include <stack>

enum ArgType {
    ArgVarType,
    ArgBlockType
};
struct ArgVar {
    Range range;
    Dwarf_Half loc_form;
};

struct ArgBlock {
    Range range;
    bool print;
};
class ArgLocation {
    public:
    ArgLocation (const Range &range, Dwarf_Half loc_form);
    ArgLocation (const Range &range, bool print);
    union {
        ArgVar argvar;
        ArgBlock argblk;
    };
    int argType;
};

class Evaluator{
    static const int mx_stack = 1000;
    std::stack<Expression> stk;
    
    public:
    Dwarf_Debug dbg;

    int init_stack();

    int exec_operation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3);

    AddressExp parse_dwarf_block(Dwarf_Ptr exp_bytes, Dwarf_Unsigned exp_length, const Range &range = dummyrange, bool print = false);

    Address read_location(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, Range range);
    Address parse_loclist(Dwarf_Loc_Head_c loclist_head, Dwarf_Unsigned locentry_count, const ArgLocation &arg);
    Dwarf_Die getTypeDie();

};

extern Evaluator tempEvaluator;