#include "include/frame.h"

#include <libdwarf-0/libdwarf.h>

#include <iostream>
#include <vector>

#include "include/address.h"
#include "include/evaluator.h"
#include "include/expression.h"
#include "include/util.h"

namespace varviewer {
Address framebase;
// cfa_values and cfa_pcs record how to calculate cfa in a range of pc
std::vector<Expression> cfa_values;
std::vector<Dwarf_Addr> cfa_pcs;

int updateFrameBase(Dwarf_Die die, const Range &range) {
  // std::cout<<"\nin update frame base\n";
  int res;
  Dwarf_Error err;
  Dwarf_Bool has_framebase;
  // Dwarf_Attribute framebase_attr describes the frame base
  res = dwarf_hasattr(die, DW_AT_frame_base, &has_framebase, &err);
  SIMPLE_HANDLE_ERR(res);
  if (!has_framebase) {
    return 1;
  }
  Dwarf_Attribute framebase_attr;
  Dwarf_Half framebase_form;
  res = dwarf_attr(die, DW_AT_frame_base, &framebase_attr, &err);
  SIMPLE_HANDLE_ERR(res);
  res = dwarf_whatform(framebase_attr, &framebase_form, &err);
  SIMPLE_HANDLE_ERR(res);

  framebase = tempEvaluator.ReadLocation(framebase_attr, framebase_form, range);
  dwarf_dealloc_attribute(framebase_attr);
  std::cout << "\033[1;32m<frame base information>\033[0m\n";
  framebase.Output();
  std::cout << "\033[1;32m</frame base information>\033[0m\n";
  return (framebase.valid_ ? 0 : 1);
}

// record the information of the function call, update cfa_pcs and cfa_values
void testFDE(Dwarf_Debug dbg, bool print) {
  // pointer to all cie data
  Dwarf_Cie *cie_data;
  Dwarf_Signed cie_count = 0;
  Dwarf_Fde *fde_data = 0;
  Dwarf_Signed fde_count = 0;
  Dwarf_Error err;
  int res = 0;
  Evaluator evaluator;
  evaluator.dbg_ = dbg;

  res = dwarf_get_fde_list(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &err);
  if (fde_count == 0) {
    // similar to the above function, the difference is whether the source program has exception handling
    res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &err);
  }
  cfa_values.reserve(fde_count * 2);
  cfa_pcs.reserve(fde_count * 2);

  for (Dwarf_Signed i = 0; i < fde_count; ++i) {
    // function start address
    Dwarf_Addr low_pc;
    // function code length
    Dwarf_Unsigned func_length, fde_bytes_length;
    Dwarf_Small *fde_btyes;
    Dwarf_Off cie_offset, fde_offset;
    Dwarf_Signed cie_index;

    res = dwarf_get_fde_range(fde_data[i], &low_pc, &func_length, &fde_btyes, &fde_bytes_length, &cie_offset,
                              &cie_index, &fde_offset, &err);
    // ref used to compute cfa
    Dwarf_Unsigned reg = 0;
    Dwarf_Unsigned offset_relevant = 0;
    Dwarf_Small value_type = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Block block;
    // the pc of that code
    Dwarf_Addr row_pc = 0;
    Dwarf_Bool has_more_rows = 0;
    Dwarf_Addr subsequent_pc = 0;
    // deal instructions in the in the func [lowpc,lowpc + func_length]
    for (Dwarf_Unsigned j = low_pc; j < (low_pc + func_length); ++j) {
      // get the cfa value at the specific pc
      res = dwarf_get_fde_info_for_cfa_reg3_b(fde_data[i], j, &value_type, &offset_relevant, &reg, &offset, &block,
                                              &row_pc, &has_more_rows, &subsequent_pc, &err);

      if (has_more_rows) {
        if (subsequent_pc > j) j = subsequent_pc - 1;
      } else {
        j = low_pc + func_length - 1;
      }
      if (res == DW_DLV_NO_ENTRY) {
        continue;
      }
      switch (value_type) {
        /*
            DW_EXPR_OFFSET and DW_EXPR_EXPRESSION describe the address of the previous value,
            however, what we need is the address (frame base) instead of its value, so, we can
            omit the other two,

            !when need consideration of `DW_OP_entry_value`, we need take care of the other two
        */
        case DW_EXPR_OFFSET: {
          Expression off;
          off.offset_ = offset;
          off.reg_scale_[reg] += 1;
          off.sign_ = true;
          off.isCFA_ = true;
          off.Output();
          // row_pc and the corresponding cfa value expression object one to one correspond
          cfa_pcs.push_back(row_pc);
          cfa_values.push_back(off);

          if (print) printf("fde offset %llx    reg: %s offset: 0x%llx\n", row_pc, reg_names[reg], offset);
          break;
        }
        case DW_EXPR_VAL_OFFSET: {
          fprintf(stderr, "shouldn't meet val_offset cfa\n");
          Expression val_offset;
          val_offset.offset_ = offset;
          val_offset.reg_scale_[reg] += 1;
          val_offset.sign_ = true;

          cfa_values.push_back(val_offset);
          cfa_pcs.push_back(row_pc);

          if (print) printf("fde offset value %llx    reg: %s offset: 0x%llx\n", row_pc, reg_names[reg], offset);
          break;
        }
        case DW_EXPR_EXPRESSION: {
          Expression expression;
          AddressExp block_addrExp = evaluator.ParseDwarfBlock(block.bl_data, block.bl_len);
          expression.SetFromExp(block_addrExp);

          cfa_values.push_back(expression);
          cfa_pcs.push_back(row_pc);

          if (print) printf("fde exp %llx %s\n", row_pc, expression.ToString().c_str());
          break;
        }
        case DW_EXPR_VAL_EXPRESSION: {
          fprintf(stderr, "shouldn't meet val_expression cfa\n");
          Expression val_expression;
          AddressExp block_addrExp = evaluator.ParseDwarfBlock(block.bl_data, block.bl_len);
          val_expression.SetFromExp(block_addrExp);

          cfa_values.push_back(val_expression);
          cfa_pcs.push_back(row_pc);

          if (print) printf("fde exp val %llx %s\n", row_pc, val_expression.ToString().c_str());
          break;
        }
        default: {
          std::cout << "in default\n";
        }
      }
    }
  }
  VARVIEWER_ASSERT(cfa_pcs.size() == cfa_values.size(), "error, the pc and cfa value do not one to one correspond");
  // std::cout << "after record, the cfa values :\n";
  // for (const auto &ex : cfa_values) {
  //   ex.output();
  // }
  // std::cout << "the pc values:\n";
  // for (const auto &pc : cfa_pcs) {
  //   std::cout << pc << "\n";
  // }
}
}  // namespace varviewer
