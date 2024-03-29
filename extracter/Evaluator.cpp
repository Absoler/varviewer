#include "Evaluator.h"
#include "Address.h"
#include "Expression.h"
#include "frame.h"
#include "varLocator.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <map>
#include <memory>
#include <stack>

Evaluator tempEvaluator;

#define no_handle(x) case x:\
    ret = x; \
    break;

ArgLocation::ArgLocation(const Range& range, Dwarf_Half loc_form) {
    argvar.range = range;
    argvar.loc_form = loc_form;
    argType = ArgVarType;
}

ArgLocation::ArgLocation(const Range &range, bool print) {
    argblk.range = range;
    argblk.print = print;
    argType = ArgBlockType;
}

int Evaluator::init_stack(){
    while(!stk.empty()){
        stk.pop();
    }
    return 0;
}

int Evaluator::exec_operation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3){
    /*
        retval indicates the operation an error happened in
    */
    int ret = 0;
    switch (op) {
    case DW_OP_addr:
        stk.push(std::move(Expression(op1)));
        break;
    
    case DW_OP_deref:
    {
        auto addr = std::make_shared<Expression>();
        addr->setFromExp(stk.top());
        stk.pop();
        Expression deref;
        deref.mem = addr;
        stk.push(deref);
        break;
    }
    case DW_OP_deref_size:
    case DW_OP_deref_type:
    {
        auto addr = std::make_shared<Expression>();
        addr->setFromExp(stk.top());
        stk.pop();
        Expression deref;
        deref.mem = addr;
        deref.mem_size = op1*8;
        stk.push(deref);
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
        stk.push(std::move(Expression(op1)));
        break;
    case DW_OP_const1s:
    case DW_OP_const2s:
    case DW_OP_const4s:
    case DW_OP_const8s:
    case DW_OP_consts:
        stk.push(std::move(Expression((Dwarf_Signed)op1)));
        break;
    case DW_OP_dup:
        stk.push(stk.top());
        break;
    case DW_OP_drop:
        stk.pop();
        break;
    case DW_OP_over:{
        Expression exp1 = stk.top();
        stk.pop();
        Expression exp2 = stk.top();
        stk.push(exp1);
        stk.push(exp2);
        break;
    }
    case DW_OP_pick:
    {
        std::stack<Expression> tmpStk;
        for(Dwarf_Small i = 0; i<op1-1; ++i){
            tmpStk.push(stk.top());
            stk.pop();
        }
        Expression pick = stk.top();
        while(!tmpStk.empty()){
            stk.push(tmpStk.top());
            tmpStk.pop();
        }
        stk.push(std::move(pick));
        break;
    }
    case DW_OP_swap:
        {
            Expression first = stk.top();
            stk.pop();
            Expression second = stk.top();
            stk.pop();
            stk.push(first);
            stk.push(second);
            break;
        }
    case DW_OP_rot:
        {
            Expression first = stk.top();
            stk.pop();
            Expression second = stk.top();
            stk.pop();
            Expression third = stk.top();
            stk.pop();
            stk.push(first);
            stk.push(third);
            stk.push(second);
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
    case DW_OP_ne:
    {
        Expression exp1 = stk.top();
        stk.pop();
        Expression exp2;
        if(op==DW_OP_plus_uconst){
            exp2.offset = op1;
        }else{
            exp2 = stk.top();
            stk.pop();
        }
        Expression res = Expression::bin_op(exp1, exp2, op);
        if(!res.valid){
            ret = op;
        }else{
            stk.push(res);
        }
        break;
    }

    case DW_OP_abs:
    case DW_OP_neg:
    case DW_OP_not:
    {
        Expression exp = stk.top();
        stk.pop();
        Expression res = Expression::unary_op(exp, op);
        if(!res.valid){
            ret = op;
        }else{
            stk.push(res);
        }
        break;
    }

    no_handle(DW_OP_bra)
    no_handle(DW_OP_skip)

    case DW_OP_lit0:
    case DW_OP_lit1:
    case DW_OP_lit2:
    case DW_OP_lit3:
    case DW_OP_lit4:
    case DW_OP_lit5:
    case DW_OP_lit6:
    case DW_OP_lit7:
    case DW_OP_lit8:
    case DW_OP_lit9:
    case DW_OP_lit10:
    case DW_OP_lit11:
    case DW_OP_lit12:
    case DW_OP_lit13:
    case DW_OP_lit14:
    case DW_OP_lit15:
    case DW_OP_lit16:
    case DW_OP_lit17:
    case DW_OP_lit18:
    case DW_OP_lit19:
    case DW_OP_lit20:
    case DW_OP_lit21:
    case DW_OP_lit22:
    case DW_OP_lit23:
    case DW_OP_lit24:
    case DW_OP_lit25:
    case DW_OP_lit26:
    case DW_OP_lit27:
    case DW_OP_lit28:
    case DW_OP_lit29:
    case DW_OP_lit30:
    case DW_OP_lit31:
        stk.push(std::move(Expression((Dwarf_Unsigned)op-DW_OP_lit0)));
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
    case DW_OP_breg31:
    {
        Expression reg_off;
        reg_off.reg_scale[op-DW_OP_breg0] = 1;
        reg_off.offset = op1;
        stk.push(reg_off);
        break;
    }

    no_handle(DW_OP_fbreg)

    case DW_OP_bregx:
    {
        Expression reg_off;
        reg_off.reg_scale[op1] = 1;
        reg_off.offset = op2;
        stk.push(reg_off);
        break;
    }


    // don't understand, not use in vmlinux and redis-server
    no_handle(DW_OP_xderef)
    no_handle(DW_OP_xderef_size)
    no_handle(DW_OP_xderef_type)

    no_handle(DW_OP_nop)

    // has version 3 or 4 label, thought unsupported now wrongly..
    no_handle(DW_OP_push_object_address)
    no_handle(DW_OP_call2)
    no_handle(DW_OP_call4)
    no_handle(DW_OP_call_ref)
    no_handle(DW_OP_form_tls_address)
    no_handle(DW_OP_call_frame_cfa)
    no_handle(DW_OP_implicit_pointer)


    // retrieve from .debug_addr
    no_handle(DW_OP_addrx)
    no_handle(DW_OP_constx)

    
    no_handle(DW_OP_const_type)
    
    case DW_OP_regval_type:
    {
        // no handle op2 type
        Expression reg_off;
        reg_off.reg_scale[op1] = 1;
        stk.push(reg_off);
        break;
    }
    

    case DW_OP_convert:
        /*
            1. get an DW_AT_base_type die (with dwarf_offdie_b()) 
            2. cast stk.top() to it, need parse a type die
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
        
    return ret;
}

AddressExp Evaluator::parse_dwarf_block(Dwarf_Ptr exp_bytes, Dwarf_Unsigned exp_length, const Range &range, bool print){
    int ret;
    Dwarf_Error err;
    
    AddressExp addrExp;
    Address addr;
    Dwarf_Half addrsize_size;
    Dwarf_Half offset_size;

    ret = dwarf_get_address_size(dbg, &addrsize_size, &err);
    ret = dwarf_get_offset_size(dbg, &offset_size, &err);

    Dwarf_Loc_Head_c loclist_head;
    Dwarf_Unsigned locentry_count;

    ret = dwarf_loclist_from_expr_c(dbg, exp_bytes, exp_length, addrsize_size, offset_size, 5, &loclist_head, &locentry_count, &err);
    if (ret != DW_DLV_OK){
        addrExp.valid = false;
        return addrExp;
    }

    // extract from loclist
    // there's only one expression in DW_OP_entry_value's block
    ArgLocation arg(range, print);
    addr = parse_loclist(loclist_head, locentry_count, arg);
    return addr.addrs[0];
}

Address Evaluator::read_location(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, Range range){
    /*
        only parse DW_FORM_sec_offset and DW_FORM_exprloc now
    */
    int ret;
    Address res;
    Dwarf_Error err;
    Dwarf_Loc_Head_c loclist_head;
    Dwarf_Unsigned locentry_count;
    
    if(loc_form!=DW_FORM_sec_offset&&
        loc_form!=DW_FORM_exprloc&&
        loc_form!=DW_FORM_block&&
        loc_form!=DW_FORM_data1&&loc_form!=DW_FORM_data2&&loc_form!=DW_FORM_data4&&loc_form!=DW_FORM_data8)
        res.valid = false;
    else
        ret = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_count, &err);
    
    if(ret!=DW_DLV_OK){
        res.valid = false;
        return res;
    }

    ArgLocation arg(range, loc_form);
    res = parse_loclist(loclist_head, locentry_count, arg);
    return res;
}

Address
Evaluator::parse_loclist(Dwarf_Loc_Head_c loclist_head, Dwarf_Unsigned locentry_count, const ArgLocation &arg) {
    
    int ret;
    Dwarf_Error err;
    Address res;
    

    for(Dwarf_Unsigned i = 0; i<locentry_count; i++){
        Dwarf_Small lkind=0, lle_value=0;
        Dwarf_Unsigned raw_lopc=0, raw_hipc=0;
        Dwarf_Bool debug_addr_unavailable = false;
        Dwarf_Addr cooked_lopc = 0;
        Dwarf_Addr cooked_hipc = 0;
        Dwarf_Unsigned locexpr_op_count = 0;
        Dwarf_Locdesc_c locentry = 0;
        Dwarf_Unsigned expression_offset = 0;
        Dwarf_Unsigned locdesc_offset = 0;

        ret = dwarf_get_locdesc_entry_d(loclist_head, i,
        &lle_value,
        &raw_lopc, &raw_hipc,
        &debug_addr_unavailable,
        &cooked_lopc,&cooked_hipc,
        &locexpr_op_count,
        &locentry,
        &lkind,
        &expression_offset,
        &locdesc_offset,
        &err);

        if(ret!=DW_DLV_OK){
            res.valid = false;
            return res;
        }

        
        if(locexpr_op_count == 0){
            continue;
        }
        
        AddressExp addrExp;

        if (arg.argType == ArgVarType) {
            // block parsing don't need code range
            Dwarf_Half loc_form = arg.argvar.loc_form;
            Range range = arg.argvar.range;

            if(!debug_addr_unavailable){
                addrExp.startpc = cooked_lopc;
                addrExp.endpc = cooked_hipc;
            }else{
                addrExp.startpc = raw_lopc;
                addrExp.endpc = raw_hipc;
            }

            // `exprloc` is single location description, getting range from lexical block owning it
            // `DW_FORM_exprloc` can only be `exprloc` class
            if(loc_form == DW_FORM_exprloc){
                addrExp.startpc = range.startpc;
                addrExp.endpc = range.endpc;
            }
        } else if (arg.argType == ArgBlockType) {
            Range range = arg.argblk.range;
            addrExp.startpc = range.startpc;
            addrExp.endpc = range.endpc;
        }

        init_stack();

        Dwarf_Small op = 0;
        Dwarf_Unsigned op1, op2, op3, offsetForBranch;
        Dwarf_Unsigned piece_base = 0;

        bool last_is_piece = false;     // last operation is DW_OP_piece
        
        std::map<Dwarf_Unsigned, Dwarf_Unsigned> offset_to_index;
        
        for(Dwarf_Unsigned j = 0; j<locexpr_op_count; j++){

            ret = dwarf_get_location_op_value_c(locentry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
            if(ret != DW_DLV_OK){
                
            }
            if (arg.argType == ArgBlockType && arg.argblk.print) {
                const char *op_name;
                dwarf_get_OP_name(op, &op_name);
                printf("%s %llx %llx %llx\n", op_name, op1, op2, op3);
            }

            offset_to_index[offsetForBranch] = j;
            statistics.addOp(op);

            if((op>=DW_OP_reg0&&op<=DW_OP_reg31) || op==DW_OP_regx){
                // reg addressing

                addrExp.dwarfType = REGISTER;
                addrExp.reg = (op==DW_OP_regx? op1 : op-DW_OP_reg0);

            }
            else if(op==DW_OP_implicit_value || op==DW_OP_stack_value){
                // immediate addressing
                addrExp.dwarfType = VALUE;

                if(op==DW_OP_implicit_value){
                    if(op1>8){
                        // how to deal with LEB128 coding with size > 8?
                    }
                    addrExp.offset = op2;
                    
                }else if(op==DW_OP_stack_value){
                    if(stk.empty()){
                        addrExp.valid = false;
                        fprintf(stderr, "stack empty meeting DW_OP_stack_value");
                    }else
                        addrExp.setFromExp(stk.top());

                }
                
            }else if(op==DW_OP_piece){

                // deal with piece case
                if(!last_is_piece){
                    addrExp.piece = std::pair<Dwarf_Unsigned, int>(piece_base, op1);
                    if(addrExp.dwarfType == MEMORY){
                        if(stk.empty()){
                            addrExp.setFromExp(Expression::createEmpty());
                        }else{
                            addrExp.setFromExp(stk.top());
                        }
                    }
                    addrExp.detailedDwarfType = statistics.solveOneExpr();
                    res.addrs.push_back(addrExp);
                    addrExp.resetData();
                }
                piece_base += op1;
                
            }else if (op==DW_OP_entry_value || op==DW_OP_GNU_entry_value) {
                assert(arg.argType != ArgBlockType);
                tempEvaluator.dbg = dbg;
                AddressExp entry_value = tempEvaluator.parse_dwarf_block((Dwarf_Ptr)op2, op1);
                Expression exp;
                // there should be no `DW_OP_stack_value` or `DW_OP_implicit_value` in entry_value block
                assert(entry_value.dwarfType != VALUE);
                if(entry_value.dwarfType == REGISTER){
                    exp.reg_scale[entry_value.reg] += 1;
                }else{
                    exp.setFromExp(entry_value);
                }
                exp.valid = false;
                stk.push(exp);
            
            }else if (op==DW_OP_bra || op==DW_OP_skip) {
                /* operate control flow
                */

            }

            else if (op==DW_OP_call_frame_cfa){
                /*  get current `cfa` value, we postpone it 
                    until the match time to decide which. 
                    now we just bring enough of them
                */
                Expression cfa = Expression::createCFA();
                
                stk.push(cfa);
                /*
                    record useful cfa values in addrExp
                */
                if(addrExp.startpc==0&&addrExp.endpc==0){
                    ret = op;
                    addrExp.valid = false;
                    fprintf(stderr, "getting CFA values without range\n");
                    break;
                }
                addrExp.needCFA = true;
                int startid = std::upper_bound(cfa_pcs.begin(), cfa_pcs.end(), addrExp.startpc) - cfa_pcs.begin() -1;
                int endid = std::lower_bound(cfa_pcs.begin(), cfa_pcs.end(), addrExp.endpc) - cfa_pcs.begin() - 1;
                for(int i=startid; i<=endid; ++i){
                    addrExp.cfa_pcs.push_back(cfa_pcs[i]);
                    addrExp.cfa_values.push_back(cfa_values[i]);
                }
            }

            else if (op == DW_OP_fbreg) {
                /*
                    an offset + current frame base (usually a register or cfa value)
                */
                assert(arg.argType != ArgBlockType);
                tempEvaluator.dbg = dbg;

                /* frame base may be loc list, seldomly. if yes, we choose the one whose range cover `addrExp` */
                int list_id = 0;
                if (framebase.addrs.size() > 1) {
                    for (unsigned i = 0; i < framebase.addrs.size(); i++ ) {
                        if (framebase.addrs[i].startpc <= addrExp.startpc && addrExp.endpc <= framebase.addrs[i].endpc) {
                            list_id = i;
                        }
                    }
                    assert(0);
                }

                /* push it with offset into stack */
                Expression fbreg;
                const AddressExp &fb = framebase.addrs[list_id];
                fbreg.setFromExp(fb);
                if (fb.dwarfType == REGISTER) {
                    fbreg.reg_scale[fb.reg] += 1;
                }
                fbreg.offset += op1;
                stk.push(fbreg);

            }
            
            else{

                // indirect addressing
                // operate the stack
                ret = exec_operation(op, op1, op2, op3);
                if(ret!=0){
                    const char *op_name;
                    dwarf_get_OP_name(op, &op_name);
                    fprintf(stderr, "parse expression wrong at %s\n", op_name);
                    addrExp.valid = false;
                    break;
                }

            }

            last_is_piece = (op==DW_OP_piece);            
        }

        if((!last_is_piece) && addrExp.dwarfType == MEMORY && addrExp.valid){
            /* if the last op is not `reg addressing` or `imme addressing`
                or not ended by `DW_OP_piece`, gather the stack top value
                
                if meet error before, there's also no need to process
                addrExp
            */
            if(stk.empty()){
                addrExp.setFromExp(Expression::createEmpty());
            }else{
                addrExp.setFromExp(stk.top());
            }
        }

        if(!last_is_piece){
            addrExp.detailedDwarfType = statistics.solveOneExpr();
            res.addrs.push_back(addrExp);
        }


    }
    res.update_valid();
    dwarf_dealloc_loc_head_c(loclist_head);
    return res;
}