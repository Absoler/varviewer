#include "frame.h"
#include "Address.h"
#include "Expression.h"
#include "Evaluator.h"
#include <libdwarf-0/libdwarf.h>
#include <memory>
#include <vector>

std::vector<AddressExp> cfa_values;
std::vector<Dwarf_Addr> cfa_pcs;

int testFDE(Dwarf_Debug dbg, bool print){
    Dwarf_Cie *cie_data;
    Dwarf_Signed cie_count = 0;
    Dwarf_Fde *fde_data = 0;
    Dwarf_Signed fde_count = 0;
    Dwarf_Error err;
    int res = 0;
    Evaluator evaluator;
    evaluator.dbg = dbg;
 
    res = dwarf_get_fde_list(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &err);
    if(fde_count==0){
        res = dwarf_get_fde_list_eh(dbg, &cie_data, &cie_count, &fde_data, &fde_count, &err);
    }

    cfa_values.reserve(fde_count*2);
    cfa_values.reserve(fde_count*2);

    for(Dwarf_Signed i = 0; i<fde_count; ++i){
        Dwarf_Addr low_pc;
        Dwarf_Unsigned func_length, fde_bytes_length;
        Dwarf_Small *fde_btyes;
        Dwarf_Off cie_offset, fde_offset;
        Dwarf_Signed cie_index;
        
        res = dwarf_get_fde_range(fde_data[i], &low_pc, &func_length, &fde_btyes, &fde_bytes_length, &cie_offset, &cie_index, &fde_offset, &err);

        Dwarf_Unsigned reg = 0;
        Dwarf_Unsigned offset_relevant = 0;
        Dwarf_Small  value_type = 0;
        Dwarf_Unsigned offset = 0;
        Dwarf_Block block;
        Dwarf_Addr   row_pc = 0;
        Dwarf_Bool   has_more_rows = 0;
        Dwarf_Addr   subsequent_pc = 0;

        for(Dwarf_Unsigned j = low_pc; j < (low_pc + func_length); ++j){
            res = dwarf_get_fde_info_for_cfa_reg3_b(fde_data[i], j, 
            &value_type, &offset_relevant, &reg, &offset, &block, &row_pc, &has_more_rows, &subsequent_pc, 
            &err);


            if(has_more_rows){
                if(subsequent_pc>j) j = subsequent_pc - 1;
            }else{
                j = low_pc + func_length - 1;
            }
            if(res==DW_DLV_NO_ENTRY){
                continue;
            }
            switch (value_type) {
                case DW_EXPR_OFFSET:{
                    AddressExp off;
                    off.offset = offset;
                    off.reg_scale[reg] += 1;
                    off.sign = true;

                    cfa_values.push_back(off);
                    cfa_pcs.push_back(row_pc);
                    
                    if(print) printf("fde offset %llx    reg: %s offset: 0x%llx\n", row_pc, reg_names[reg], offset);
                    break;
                }
                case DW_EXPR_VAL_OFFSET:{
                    AddressExp val_offset;
                    val_offset.offset = offset;
                    val_offset.reg_scale[reg] += 1;
                    val_offset.type = VALUE;
                    val_offset.sign = true;

                    cfa_values.push_back(val_offset);
                    cfa_pcs.push_back(row_pc);

                    if(print) printf("fde offset value %llx    reg: %s offset: 0x%llx\n", row_pc, reg_names[reg], offset);
                    break;
                }
                case DW_EXPR_EXPRESSION:{
                    AddressExp expression = evaluator.parse_dwarf_block(block.bl_data, block.bl_len);

                    cfa_values.push_back(expression);
                    cfa_pcs.push_back(row_pc);

                    if(print) printf("fde exp %llx %s\n", row_pc, expression.toString().c_str());
                    break;
                }
                case DW_EXPR_VAL_EXPRESSION:{
                    AddressExp val_expression = evaluator.parse_dwarf_block(block.bl_data, block.bl_len);
                    val_expression.type = VALUE;

                    cfa_values.push_back(val_expression);
                    cfa_pcs.push_back(row_pc);

                    if(print) printf("fde exp val %llx %s\n", row_pc, val_expression.toString().c_str());
                    break;
                }
                default:{
                }
            }

        }
    }


}
