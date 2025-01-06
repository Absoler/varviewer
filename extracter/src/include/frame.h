#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <vector>

#include "address.h"
#include "evaluator.h"
#include "expression.h"
#include "util.h"
namespace varviewer {

extern Address framebase;

extern std::vector<Expression> cfa_values;

extern std::vector<Dwarf_Addr> cfa_pcs;

void testFDE(Dwarf_Debug dbg, bool print = false);

int updateFrameBase(Dwarf_Die die, const Range &range);

}  // namespace varviewer
