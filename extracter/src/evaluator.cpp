#include "include/evaluator.h"

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <ios>
#include <iostream>
#include <map>
#include <memory>
#include <stack>

#include "include/address.h"
#include "include/expression.h"
#include "include/frame.h"
#include "include/logger.h"
#include "include/util.h"
#include "include/var_locator.h"

// defined in main.cpp
extern bool finishTestFde;

namespace varviewer {
Evaluator tempEvaluator;

#define no_handle(x) \
  case x:            \
    ret = x;         \
    break;

ArgLocation::ArgLocation(const Range &range, Dwarf_Half loc_form)
    : argvar(range, loc_form), argType(ArgType::ArgVarType) {}

ArgLocation::ArgLocation(const Range &range, bool print) : argblk(range, print), argType(ArgType::ArgBlockType) {}

int Evaluator::InitStack() {
  while (!stk_.empty()) {
    stk_.pop();
  }
  VARVIEWER_ASSERT(stk_.empty(), "stack clear failed");
  return 0;
}

int Evaluator::ExecOperation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3) {
  /*
      retval indicates the operation an error happened in
  */
  int ret = 0;
  switch (op) {
    case DW_OP_addr:
      stk_.push(Expression(op1));
      break;
    // DW_OP_deref means get the top value of the dwarf stack,and treat it as an address 
    case DW_OP_deref: {
      auto addr = std::make_shared<Expression>();
      addr->SetFromExp(stk_.top());
      Expression deref;
      deref.mem_ = addr;
      stk_.push(deref);
      break;
    }
    case DW_OP_deref_size:
    case DW_OP_deref_type: {
      auto addr = std::make_shared<Expression>();
      addr->SetFromExp(stk_.top());
      stk_.pop();
      Expression deref;
      deref.mem_ = addr;
      deref.mem_size_ = op1 * 8;
      stk_.push(deref);
      break;
      /*
          do not care about type now, `DW_OP_deref_type` has the second
          operand as type die offset
      */
    }

    case DW_OP_const1u:
    case DW_OP_const2u:
    case DW_OP_const4u:
    case DW_OP_const8u:
    case DW_OP_constu:
      stk_.push(Expression(op1));
      break;
    case DW_OP_const1s:
    case DW_OP_const2s:
    case DW_OP_const4s:
    case DW_OP_const8s:
    case DW_OP_consts:
      stk_.push(Expression((Dwarf_Signed)op1));
      break;
    case DW_OP_dup:
      stk_.push(stk_.top());
      break;
    case DW_OP_drop:
      stk_.pop();
      break;
    case DW_OP_over: {
      Expression exp1 = stk_.top();
      stk_.pop();
      Expression exp2 = stk_.top();
      stk_.push(exp1);
      stk_.push(exp2);
      break;
    }
    case DW_OP_pick: {
      std::stack<Expression> tmpstk_;
      for (Dwarf_Small i = 0; i < op1 - 1; ++i) {
        tmpstk_.push(stk_.top());
        stk_.pop();
      }
      Expression pick = stk_.top();
      while (!tmpstk_.empty()) {
        stk_.push(tmpstk_.top());
        tmpstk_.pop();
      }
      stk_.push(std::move(pick));
      break;
    }
    case DW_OP_swap: {
      Expression first = stk_.top();
      stk_.pop();
      Expression second = stk_.top();
      stk_.pop();
      stk_.push(first);
      stk_.push(second);
      break;
    }
    case DW_OP_rot: {
      Expression first = stk_.top();
      stk_.pop();
      Expression second = stk_.top();
      stk_.pop();
      Expression third = stk_.top();
      stk_.pop();
      stk_.push(first);
      stk_.push(third);
      stk_.push(second);
      break;
    }

    case DW_OP_and:
    case DW_OP_div:
    case DW_OP_minus:
    case DW_OP_mod:
    case DW_OP_mul:
    case DW_OP_or:
    case DW_OP_plus:
    case DW_OP_plus_uconst:
    case DW_OP_shl:
    case DW_OP_shr:
    case DW_OP_shra:
    case DW_OP_xor:
    case DW_OP_eq:
    case DW_OP_ge:
    case DW_OP_gt:
    case DW_OP_le:
    case DW_OP_lt:
    case DW_OP_ne: {
      Expression exp1 = stk_.top();
      stk_.pop();
      Expression exp2;
      if (op == DW_OP_plus_uconst) {
        exp2.offset_ = op1;
      } else {
        exp2 = stk_.top();
        stk_.pop();
      }
      Expression res = Expression::BinOp(exp1, exp2, op);
      if (!res.valid_) {
        ret = op;
      } else {
        stk_.push(res);
      }
      break;
    }

    case DW_OP_abs:
    case DW_OP_neg:
    case DW_OP_not: {
      Expression exp = stk_.top();
      stk_.pop();
      Expression res = Expression::UnaryOp(exp, op);
      if (!res.valid_) {
        ret = op;
      } else {
        stk_.push(res);
      }
      break;
    }

      no_handle(DW_OP_bra) no_handle(DW_OP_skip)

          case DW_OP_lit0 : case DW_OP_lit1 : case DW_OP_lit2 : case DW_OP_lit3 : case DW_OP_lit4 : case DW_OP_lit5
          : case DW_OP_lit6 : case DW_OP_lit7 : case DW_OP_lit8 : case DW_OP_lit9 : case DW_OP_lit10 : case DW_OP_lit11
          : case DW_OP_lit12 : case DW_OP_lit13 : case DW_OP_lit14 : case DW_OP_lit15 : case DW_OP_lit16
          : case DW_OP_lit17 : case DW_OP_lit18 : case DW_OP_lit19 : case DW_OP_lit20 : case DW_OP_lit21
          : case DW_OP_lit22 : case DW_OP_lit23 : case DW_OP_lit24 : case DW_OP_lit25 : case DW_OP_lit26
          : case DW_OP_lit27 : case DW_OP_lit28 : case DW_OP_lit29 : case DW_OP_lit30 : case DW_OP_lit31
          : stk_.push(Expression((Dwarf_Unsigned)op - DW_OP_lit0));
      break;

    case DW_OP_breg0:
    case DW_OP_breg1:
    case DW_OP_breg2:
    case DW_OP_breg3:
    case DW_OP_breg4:
    case DW_OP_breg5:
    case DW_OP_breg6:
    case DW_OP_breg7:
    case DW_OP_breg8:
    case DW_OP_breg9:
    case DW_OP_breg10:
    case DW_OP_breg11:
    case DW_OP_breg12:
    case DW_OP_breg13:
    case DW_OP_breg14:
    case DW_OP_breg15:
    case DW_OP_breg16:
    case DW_OP_breg17:
    case DW_OP_breg18:
    case DW_OP_breg19:
    case DW_OP_breg20:
    case DW_OP_breg21:
    case DW_OP_breg22:
    case DW_OP_breg23:
    case DW_OP_breg24:
    case DW_OP_breg25:
    case DW_OP_breg26:
    case DW_OP_breg27:
    case DW_OP_breg28:
    case DW_OP_breg29:
    case DW_OP_breg30:
    case DW_OP_breg31: {
      Expression reg_off;
      reg_off.reg_scale_[op - DW_OP_breg0] = 1;
      reg_off.offset_ = op1;
      stk_.push(reg_off);
      break;
    }

      no_handle(DW_OP_fbreg)

          case DW_OP_bregx : {
        Expression reg_off;
        reg_off.reg_scale_[op1] = 1;
        reg_off.offset_ = op2;
        stk_.push(reg_off);
        break;
      }

      // don't understand, not use in vmlinux and redis-server
      no_handle(DW_OP_xderef) no_handle(DW_OP_xderef_size) no_handle(DW_OP_xderef_type)

          no_handle(DW_OP_nop)

          // has version 3 or 4 label, thought unsupported now wrongly..
          no_handle(DW_OP_push_object_address) no_handle(DW_OP_call2) no_handle(DW_OP_call4) no_handle(DW_OP_call_ref)
              no_handle(DW_OP_form_tls_address) no_handle(DW_OP_call_frame_cfa) no_handle(DW_OP_implicit_pointer)

          // retrieve from .debug_addr
          no_handle(DW_OP_addrx) no_handle(DW_OP_constx)

              no_handle(DW_OP_const_type)

                  case DW_OP_regval_type : {
        // no handle op2 type
        Expression reg_off;
        reg_off.reg_scale_[op1] = 1;
        stk_.push(reg_off);
        break;
      }

    case DW_OP_convert:
      /*
          1. get an DW_AT_base_type die (with dwarf_offdie_b())
          2. cast stk_.top() to it, need parse a type die
      */
      break;

    case DW_OP_reinterpret:
      /*
          reinterpret the bits
      */
      break;
    default:
      fprintf(stderr, "unknown op %u", op);
      ret = op;
  }
  // no use, just for warning
  if (op3) {
    LOG_DEBUG("op3 is not 0");
  }
  return ret;
}

AddressExp Evaluator::ParseDwarfBlock(Dwarf_Ptr exp_bytes, Dwarf_Unsigned exp_length, const Range &range, bool print) {
  int ret;
  Dwarf_Error err;

  AddressExp addrExp;
  Address addr;
  Dwarf_Half addrsize_size;
  Dwarf_Half offset_size;

  ret = dwarf_get_address_size(dbg_, &addrsize_size, &err);
  ret = dwarf_get_offset_size(dbg_, &offset_size, &err);

  Dwarf_Loc_Head_c loclist_head;
  Dwarf_Unsigned locentry_count;

  ret = dwarf_loclist_from_expr_c(dbg_, exp_bytes, exp_length, addrsize_size, offset_size, 5, &loclist_head,
                                  &locentry_count, &err);
  if (ret != DW_DLV_OK) {
    addrExp.valid_ = false;
    return addrExp;
  }

  // extract from loclist
  // there's only one expression in DW_OP_entry_value's block
  ArgLocation arg(range, print);
  addr = ParseLoclist(loclist_head, locentry_count, arg,false);
  return addr.addrs_[0];
}

// when from updatebase is true, we do not record it in statistics
Address Evaluator::ReadLocation(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, Range range,bool from_update_base) {
  /*
      only parse DW_FORM_sec_offset and DW_FORM_exprloc now
  */
  int ret = -1;
  Address res;
  Dwarf_Error err;
  // deallocate in parseLoclist
  Dwarf_Loc_Head_c loclist_head{nullptr};
  Dwarf_Unsigned locentry_count;

  if (loc_form != DW_FORM_sec_offset && loc_form != DW_FORM_exprloc && loc_form != DW_FORM_block &&
      loc_form != DW_FORM_data1 && loc_form != DW_FORM_data2 && loc_form != DW_FORM_data4 &&
      loc_form != DW_FORM_data8) {
    res.valid_ = false;
    std::cout << "loc form unvalid\n";
  } else {
    /* get location expression information */
    ret = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_count, &err);
  }

  if (ret != DW_DLV_OK) {
    res.valid_ = false;
    return res;
  }
  LOG_DEBUG("location description count:%llu", locentry_count);
  ArgLocation arg(range, loc_form);
  res = ParseLoclist(loclist_head, locentry_count, arg, from_update_base);
  return res;
}

/*
 *  parse location list or location expression
 *  location expression is a single location description, which describes an object whose lifetime is fixed or
 *  whose lifetime is consistent with the block subprogram that owns it
 *  a single location description may be one or more
 *  location list describes an object whose position changes during its lifetime
 *  return an address object, which may contain multiple addr_exp objects (depending on the number of location
 *  descriptions)
 */
Address Evaluator::ParseLoclist(Dwarf_Loc_Head_c loclist_head, Dwarf_Unsigned locentry_count, const ArgLocation &arg,bool from_update_base) {
  int ret;
  Dwarf_Error err;
  Address res{};

  for (Dwarf_Unsigned i = 0; i < locentry_count; i++) {
    Dwarf_Small lkind = 0, lle_value = 0;
    Dwarf_Unsigned raw_lopc = 0, raw_hipc = 0;
    Dwarf_Bool debug_addr_unavailable = false;
    Dwarf_Addr cooked_lopc = 0;
    Dwarf_Addr cooked_hipc = 0;
    Dwarf_Unsigned locexpr_op_count = 0;
    Dwarf_Locdesc_c locentry = 0;
    Dwarf_Unsigned expression_offset = 0;
    Dwarf_Unsigned locdesc_offset = 0;

    // get location description information
    ret = dwarf_get_locdesc_entry_d(loclist_head, i, &lle_value, &raw_lopc, &raw_hipc, &debug_addr_unavailable,
                                    &cooked_lopc, &cooked_hipc, &locexpr_op_count, &locentry, &lkind,
                                    &expression_offset, &locdesc_offset, &err);

    if (ret != DW_DLV_OK) {
      res.valid_ = false;
      return res;
    }

    // operand count == 0;
    if (locexpr_op_count == 0) {
      continue;
    }

    // every location operation generate an addrExp
    AddressExp addrExp{};

    if (arg.argType == ArgType::ArgVarType) {
      LOG_DEBUG("argType is ArgVarType");
      // block parsing don't need code range
      Dwarf_Half loc_form = arg.argvar.loc_form_;
      Range range = arg.argvar.range_;
      if (!debug_addr_unavailable) {
        addrExp.startpc_ = cooked_lopc;
        addrExp.endpc_ = cooked_hipc;
      } else {
        addrExp.startpc_ = raw_lopc;
        addrExp.endpc_ = raw_hipc;
      }
      // `exprloc` is single location description, getting range from lexical block owning it
      // `DW_FORM_exprloc` can only be `exprloc` class
      if (loc_form == DW_FORM_exprloc) {
        addrExp.startpc_ = range.startpc;
        addrExp.endpc_ = range.endpc;
      }
    } else if (arg.argType == ArgType::ArgBlockType) {
      Range range = arg.argblk.range_;
      addrExp.startpc_ = range.startpc;
      addrExp.endpc_ = range.endpc;
    }

    // clear stack
    InitStack();
    VARVIEWER_ASSERT(stk_.empty(), "Error, stack is not empty");
    Dwarf_Small op = 0;
    Dwarf_Unsigned op1, op2, op3, offsetForBranch;
    Dwarf_Unsigned piece_base = 0;

    bool last_is_piece = false;  // last operation is DW_OP_piece

    std::map<Dwarf_Unsigned, Dwarf_Unsigned> offset_to_index;

    for (Dwarf_Unsigned j = 0; j < locexpr_op_count; j++) {
      // get the operand value of location operation
      // for example, (DW_OP_fbreg -80) -> op = DW_OP_fbreg, op1 = -80
      ret = dwarf_get_location_op_value_c(locentry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
      if (ret != DW_DLV_OK) {
      }
      if (arg.argType == ArgType::ArgBlockType && arg.argblk.print_) {
        const char *op_name;
        dwarf_get_OP_name(op, &op_name);
        printf("%s %llx %llx %llx\n", op_name, op1, op2, op3);
      }

      offset_to_index[offsetForBranch] = j;
      // only when finish testfde, do we record the statistics
      if(finishTestFde && !from_update_base){
        statistics.addOp(op);
      }
      LOG_DEBUG("op : %d", static_cast<int>(op));
      if ((op >= DW_OP_reg0 && op <= DW_OP_reg31) || op == DW_OP_regx) {
        // save in reg
        addrExp.dwarfType_ = DwarfType::REGISTER;
        addrExp.valid_ = true;
        // reg num
        addrExp.reg_ = (op == DW_OP_regx ? op1 : op - DW_OP_reg0);
      } else if (op == DW_OP_implicit_value || op == DW_OP_stack_value) {
        addrExp.dwarfType_ = DwarfType::VALUE;
        // implicit value
        if (op == DW_OP_implicit_value) {
          if (op1 > 8) {
            // how to deal with LEB128 coding with size > 8?
          }
          addrExp.offset_ = op2;
          // the object is not in memory, but its value is on the top of the DWARF expression stack
        } else if (op == DW_OP_stack_value) {
          if (stk_.empty()) {
            addrExp.valid_ = false;
            fprintf(stderr, "stack empty meeting DW_OP_stack_value");
          } else
            addrExp.SetFromExp(stk_.top());
        }
      } else if (op == DW_OP_piece) {
        // deal with piece case
        if (!last_is_piece) {
          addrExp.piece_ = std::pair<Dwarf_Unsigned, int>(piece_base, op1);
          if (addrExp.dwarfType_ == DwarfType::MEMORY) {
            if (stk_.empty()) {
              addrExp.SetFromExp(Expression::CreateEmpty());
            } else {
              addrExp.SetFromExp(stk_.top());
            }
          }
          if(finishTestFde){
          addrExp.detailedDwarfType_ = statistics.solveOneExpr();
          }
          res.addrs_.push_back(addrExp);
          addrExp.ResetData();
        }
        piece_base += op1;

      } else if (op == DW_OP_entry_value || op == DW_OP_GNU_entry_value) {
        assert(arg.argType != ArgType::ArgBlockType);
        tempEvaluator.dbg_ = dbg_;
        AddressExp entry_value = tempEvaluator.ParseDwarfBlock((Dwarf_Ptr)op2, op1);
        Expression exp;
        // there should be no `DW_OP_stack_value` or `DW_OP_implicit_value` in entry_value block
        assert(entry_value.dwarfType_ != DwarfType::VALUE);
        if (entry_value.dwarfType_ == DwarfType::REGISTER) {
          exp.reg_scale_[entry_value.reg_] += 1;
        } else {
          exp.SetFromExp(entry_value);
        }
        exp.valid_ = false;
        stk_.push(exp);

      } else if (op == DW_OP_bra || op == DW_OP_skip) { /* operate control flow */

      } else if (op == DW_OP_call_frame_cfa) {
        /*
            DW_OP_call_frame_cfa push cfa value to stack, get it from CFI indicate the base of the current function,
            occurs in DW_TAG_subprogram
            get current `cfa` value, we postpone it
            until the match time to decide which.
            now we just bring enough of them
        */
        Expression cfa = Expression::CreateCFA();

        stk_.push(cfa);
        /*
            record useful cfa values in addrExp
        */
        if (addrExp.startpc_ == 0 && addrExp.endpc_ == 0) {
          ret = op;
          addrExp.valid_ = false;
          fprintf(stderr, "getting CFA values without range\n");
          break;
        }
        // addrExp.needCFA = true;
        VARVIEWER_ASSERT(cfa_pcs.size() == cfa_values.size(),
                         "error, the pc and cfa value do not one to one correspond");

        // find the first element that is greater than start_pc
        int startid = std::upper_bound(cfa_pcs.begin(), cfa_pcs.end(), addrExp.startpc_) - cfa_pcs.begin() - 1;
        // find the first element that is greater than or equal to  end_pc
        int endid = std::lower_bound(cfa_pcs.begin(), cfa_pcs.end(), addrExp.endpc_) - cfa_pcs.begin() - 1;
        for (int i = startid; i <= endid; ++i) {
          addrExp.cfa_pcs_.push_back(cfa_pcs[i]);
          addrExp.cfa_values_.push_back(cfa_values[i]);
        }

      } else if (op == DW_OP_fbreg) {
        /*
           DW_OP_fbreg indicates this variable's address is calculated by cfa + offset
        */
        VARVIEWER_ASSERT(arg.argType != ArgType::ArgBlockType, "Error,Dw_OP_fbreg can not operate on block");
        tempEvaluator.dbg_ = dbg_;

        /*
         currently, when encountering the subprogram without low_pc and high_pc, we can't get the range of the
         subprogram,so the framebase can't be used, just break here
         (maybe fix it in the future,aka to get the range of the subprogram)
        */
        if (framebase.addrs_.size() == 0) {
          addrExp.valid_ = false;
          break;
        }
        /* frame base may be loc list, seldomly. if yes, we choose the one whose range cover `addrExp` */
        int list_id = 0;
        // VARVIEWER_ASSERT(framebase.addrs_.size() >= 1, "Error, has no frame base record");
        if (framebase.addrs_.size() > 1) {
          for (unsigned i = 0; i < framebase.addrs_.size(); i++) {
            if (framebase.addrs_[i].startpc_ <= addrExp.startpc_ && addrExp.endpc_ <= framebase.addrs_[i].endpc_) {
              list_id = i;
            }
          }
        }
        // TODO(tangc): here may have some logic error, fix it later
        addrExp.needCFA_ = true;
        addrExp.cfa_pcs_ = framebase.addrs_[list_id].cfa_pcs_;
        addrExp.cfa_values_ = framebase.addrs_[list_id].cfa_values_;

        /* push it with offset into stack */
        Expression fbreg;
        const AddressExp &fb = framebase.addrs_[list_id];
        // fbreg.setFromExp(fb);

        if (fb.dwarfType_ == DwarfType::REGISTER) {
          fbreg.reg_scale_[fb.reg_] += 1;
        }
        fbreg.offset_ += op1;
        stk_.push(fbreg);

      } else {
        // indirect addressing
        // operate the stack
        ret = ExecOperation(op, op1, op2, op3);
        if (ret != 0) {
          const char *op_name;
          dwarf_get_OP_name(op, &op_name);
          fprintf(stderr, "parse expression wrong at %s\n", op_name);
          addrExp.valid_ = false;
          break;
        }
        /* gloval var , set its start pc and end pc to 0 */
        if (op == DW_OP_addr) {
          addrExp.startpc_ = 0;
          addrExp.endpc_ = 0;
        }
      }

      last_is_piece = (op == DW_OP_piece);
    }

    if ((!last_is_piece) && addrExp.dwarfType_ == DwarfType::MEMORY && addrExp.valid_) {
      /* if the last op is not `reg addressing` or `imme addressing`
          or not ended by `DW_OP_piece`, gather the stack top value
          if meet error before, there's also no need to process
          addrExp
      */
      if (stk_.empty()) {
        addrExp.SetFromExp(Expression::CreateEmpty());
      } else {
        addrExp.SetFromExp(stk_.top());
      }
    }

    if (!last_is_piece) {
      if(finishTestFde && !from_update_base){
      addrExp.detailedDwarfType_ = statistics.solveOneExpr();
      }
      res.addrs_.push_back(addrExp);
    }
  }
  res.UpdateValid();
  std::cout << "\033[1;31m<Address information>\033[0m\n";
  res.Output();
  std::cout << "\033[1;31m</Address information>\033[0m\n";
  dwarf_dealloc_loc_head_c(loclist_head);
  return res;
}
}  // namespace varviewer