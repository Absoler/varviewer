#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <memory>

#include "Address.h"
#include "Evaluator.h"
#include "StructType.h"
#include "frame.h"
#include "jsonUtil.h"
#include "ranges.h"
#include "statistics.h"
#include "type.h"
#include "util.h"
namespace varviewer {

extern Statistics statistics;

int TestEvaluator(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Range range, char *name,
                  const std::shared_ptr<Type> &type_info);

int TestDeclPos(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, char **decl_file_name, Dwarf_Unsigned *decl_row,
                Dwarf_Unsigned *decl_col, int indent);

int ProcessLocation(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, int indent);

void WalkDieTree(Dwarf_Die cu_die, Dwarf_Debug dbg, Dwarf_Die fa_die, Range range, bool is_info, int indent);
}  // namespace varviewer
