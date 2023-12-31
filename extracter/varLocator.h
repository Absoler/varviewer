#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include "Address.h"
#include "Evaluator.h"
#include "jsonUtil.h"
#include "frame.h"
#include "ranges.h"
#include "util.h"
#include "statistics.h"
#include "type.h"


extern Statistics statistics;

int test_evaluator(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Range range, char *name);
int test_declPos(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, 
            char **decl_file_name, Dwarf_Unsigned *decl_row, Dwarf_Unsigned *decl_col, int indent);
int processLocation(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, int indent);
void walkDieTree(Dwarf_Die cu_die, Dwarf_Debug dbg, Dwarf_Die fa_die, Range range, bool is_info, int indent);