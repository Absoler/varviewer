#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <vector>
#include "Address.h"
#include "Evaluator.h"
#include "Expression.h"

extern std::vector<AddressExp> cfa_values;
extern std::vector<Dwarf_Addr> cfa_pcs;

int testFDE(Dwarf_Debug dbg, bool print=false);

