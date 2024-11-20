#include "include/frame.h"

#include <libdwarf-0/libdwarf.h>

#include <iostream>
#include <vector>

#include "include/Address.h"
#include "include/Evaluator.h"
#include "include/Expression.h"
#include "include/util.h"

namespace varviewer {
Address framebase;
// cfa_values和cfa_pcs共同记录一段pc范围内的cfa如何计算
std::vector<Expression> cfa_values;
std::vector<Dwarf_Addr> cfa_pcs;

int updateFrameBase(Dwarf_Die die, const Range &range) {
  // std::cout<<"\nin update frame base\n";
  int res;
  Dwarf_Error err;
  Dwarf_Bool has_framebase;
  // DW_AT_frmae_base 描述当前函数栈帧的基地址
  res = dwarf_hasattr(die, DW_AT_frame_base, &has_framebase, &err);
  simple_handle_err(res);
  if (!has_framebase) {
    return 1;
  }
  std::cout << "****update frame base****\n";
  Dwarf_Attribute framebase_attr;
  Dwarf_Half framebase_form;
  // 获取 frame_base
  res = dwarf_attr(die, DW_AT_frame_base, &framebase_attr, &err);
  simple_handle_err(res);
  // 获取 form
  res = dwarf_whatform(framebase_attr, &framebase_form, &err);
  simple_handle_err(res);

  framebase = tempEvaluator.ReadLocation(framebase_attr, framebase_form, range);
  dwarf_dealloc_attribute(framebase_attr);
  std::cout << "\033[1;32m<frame base information>\033[0m\n";
  framebase.Output();
  std::cout << "\033[1;32m</frame base information>\033[0m\n";
  return (framebase.valid_ ? 0 : 1);
}

// 记录函数调用信息，更新cfa_pcs 和 cfa_values
void testFDE(Dwarf_Debug dbg, bool print) {
  // pointer to all cie data
  Dwarf_Cie *cie_data;
  Dwarf_Signed cie_count = 0;
  // 指向FDE数组的指针
  Dwarf_Fde *fde_data = 0;
  Dwarf_Signed fde_count = 0;
  Dwarf_Error err;
  int res = 0;
  Evaluator evaluator;
  evaluator.dbg_ = dbg;

  res = dwarf_get_fde_list(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &err);
  if (fde_count == 0) {
    // 与上面函数差不多，差别在于源程序是否有异常处理
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
    // value_type 说明如何计算cfa
    Dwarf_Small value_type = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Block block;
    // the pc of that code
    Dwarf_Addr row_pc = 0;
    Dwarf_Bool has_more_rows = 0;
    Dwarf_Addr subsequent_pc = 0;
    std::cout << "low pc :" << low_pc << "\n";
    std::cout << " func length:" << func_length << "\n";
    // deal instructions in the in the func [lowpc,lowpc + func_length]
    for (Dwarf_Unsigned j = low_pc; j < (low_pc + func_length); ++j) {
      std::cout << "j :" << j << "\n";
      // 获取特定pc处的cfa value是多少
      res = dwarf_get_fde_info_for_cfa_reg3_b(fde_data[i], j, &value_type, &offset_relevant, &reg, &offset, &block,
                                              &row_pc, &has_more_rows, &subsequent_pc, &err);

      if (has_more_rows) {
        // 汇编中下一条指令的地址
        if (subsequent_pc > j) j = subsequent_pc - 1;
      } else {  // 没有了，停止
        j = low_pc + func_length - 1;
      }
      if (res == DW_DLV_NO_ENTRY) {
        continue;
      }
      std::cout << "value_type:" << static_cast<int>(value_type) << "\n";
      switch (value_type) {
        /*
            DW_EXPR_OFFSET and DW_EXPR_EXPRESSION describe the address of the previous value,
            however, what we need is the address (frame base) instead of its value, so, we can
            omit the other two,

            !when need consideration of `DW_OP_entry_value`, we need take care of the other two
        */
        case DW_EXPR_OFFSET: {
          std::cout << "in 1\n";
          std::cout << "row pc:" << row_pc << "\n";
          Expression off;
          off.offset_ = offset;
          off.reg_scale_[reg] += 1;
          off.sign_ = true;
          off.isCFA_ = true;
          off.Output();
          // row_pc与对应的cfa value expression对象一一对应
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
          std::cout << "in 2\n";
          Expression expression;
          AddressExp block_addrExp = evaluator.ParseDwarfBlock(block.bl_data, block.bl_len);
          expression.SetFromExp(block_addrExp);

          cfa_values.push_back(expression);
          cfa_pcs.push_back(row_pc);

          if (print) printf("fde exp %llx %s\n", row_pc, expression.ToString().c_str());
          break;
        }
        case DW_EXPR_VAL_EXPRESSION: {
          std::cout << "in 3\n";
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
