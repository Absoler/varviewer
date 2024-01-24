#include <cstddef>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <libdwarf-0/libdwarf.h>
#include <stack>
#include <string>
#include <unistd.h>
#include <vector>
#include <queue>

#include "util.h"
#include "varLocator.h"



using namespace std;

// global options
string jsonFileStr;
ofstream jsonOut;
string frameFileStr;
int useJson = 1;
bool printRawLoc = false;
bool onlyComplex = false;
bool printFDE = false;
bool noTraverse = false;

// important variables
bool isFirstJson = true;

// statistic variables
int varNoLocation = 0;
Statistics statistics;


int test_evaluator(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Range range, char *name){
    int res;
    Dwarf_Error err;
    Dwarf_Attribute location_attr;
    res = dwarf_attr(var_die, DW_AT_location, &location_attr, &err);
    simple_handle_err(res)
    Dwarf_Half loc_form;
    res = dwarf_whatform(location_attr, &loc_form, &err);
    simple_handle_err(res)

    Evaluator evaluator;
    evaluator.dbg = dbg;
    Address addr = evaluator.read_location(location_attr, loc_form, range);
    if(addr.valid == false){
        return 1;
    }

    if(name)
        addr.name = string(name);
    
    char *file_name = NULL;
    Dwarf_Unsigned decl_row = -1, decl_col = -1;
    res = test_declPos(dbg, cu_die, var_die, &file_name, &decl_row, &decl_col, 0);
    if(file_name) addr.decl_file = string(file_name);
    addr.decl_row = decl_row;
    addr.decl_col = decl_col;

    Dwarf_Half tag;
    dwarf_tag(var_die, &tag, &err);

    if(useJson){
        json addrJson = createJsonforAddress(addr);
        string jsonStr = addrJson.dump(4);
        addrJson.clear();
        if (likely(!isFirstJson)) {
            jsonOut << ",\n";
        }else{
            isFirstJson = false;
        }
        jsonOut << jsonStr;
        jsonOut.flush();
        
    }else{
        addr.output();
    }

    dwarf_dealloc_attribute(location_attr);
    return 0;
}

int test_declPos(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, 
            char **decl_file_name, Dwarf_Unsigned *decl_row, Dwarf_Unsigned *decl_col, int indent)
{
    Dwarf_Error err;
    int res = 0;

    Dwarf_Bool has_decl_file;
    res = dwarf_hasattr(var_die, DW_AT_decl_file, &has_decl_file, &err);
    simple_handle_err(res)
    if(!has_decl_file){
        Dwarf_Bool has_origin;
        res = dwarf_hasattr(var_die, DW_AT_abstract_origin, &has_origin, &err);
        simple_handle_err(res)
        if(!has_origin){
            return 1;
        }

        Dwarf_Attribute off_attr;
        // Dwarf_Half off_form;
        res = dwarf_attr(var_die, DW_AT_abstract_origin, &off_attr, &err);
        simple_handle_err(res)

        // res = dwarf_whatform(off_attr, &off_form, &err);
        // simple_handle_err(res)

        Dwarf_Off offset;
        Dwarf_Bool is_info;
        res = dwarf_global_formref_b(off_attr, &offset, &is_info, &err);
        simple_handle_err(res)

        Dwarf_Die origin_die;
        res = dwarf_offdie_b(dbg, offset, is_info, &origin_die, &err);
        // dwarf_dealloc_die(var_die);
        var_die = origin_die;

        dwarf_dealloc_attribute(off_attr);
    }
    
    // get file name
    Dwarf_Attribute decl_file_attr;
    res = dwarf_attr(var_die, DW_AT_decl_file, &decl_file_attr, &err);
    simple_handle_err(res)

    Dwarf_Unsigned decl_file;
    res = dwarf_formudata(decl_file_attr, &decl_file, &err);
    simple_handle_err(res)

    char **filenames;
    Dwarf_Signed count;
    res = dwarf_srcfiles(cu_die, &filenames, &count, &err);
    simple_handle_err(res);

    (*decl_file_name) = filenames[decl_file-1];
    // printindent(indent);
    // printf("%lld %llu %s\n", count, decl_file, filenames[decl_file-1]);
    
    // get decl row and col
    Dwarf_Attribute decl_row_attr, decl_col_attr;
    Dwarf_Bool has_row = true;
    res = dwarf_hasattr(var_die, DW_AT_decl_line, &has_row, &err);
    if(has_row){
        res = dwarf_attr(var_die, DW_AT_decl_line, &decl_row_attr, &err);
        simple_handle_err(res)

        res = dwarf_formudata(decl_row_attr, decl_row, &err);
        simple_handle_err(res)
    }

    Dwarf_Bool has_col = true;
    res = dwarf_hasattr(var_die, DW_AT_decl_column, &has_col, &err);
    simple_handle_err(res)
    if(has_col){
        res = dwarf_attr(var_die, DW_AT_decl_column, &decl_col_attr, &err);
        simple_handle_err(res)

        res = dwarf_formudata(decl_col_attr, decl_col, &err);
        simple_handle_err(res)
    }
    dwarf_dealloc_attribute(decl_file_attr);
    dwarf_dealloc_attribute(decl_row_attr);
    dwarf_dealloc_attribute(decl_row_attr);

    return DW_DLV_OK;
}

int print_raw_location(Dwarf_Debug dbg, Dwarf_Attribute loc_attr, Dwarf_Half loc_form, int indent){
    int ret = 0;
    int res = 0;
    Dwarf_Error err;
    Dwarf_Loc_Head_c loclist_head;
    Dwarf_Unsigned locentry_len;
    if(loc_form!=DW_FORM_sec_offset&&
        loc_form!=DW_FORM_exprloc&&
        loc_form!=DW_FORM_block&&
        loc_form!=DW_FORM_data1&&loc_form!=DW_FORM_data2&&loc_form!=DW_FORM_data4&&loc_form!=DW_FORM_data8)
        res = 1;
    else
        res = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_len, &err);
    
    simple_handle_err(res)
    
    string outputString;
    bool isMultiLoc = true;
    int bored_cnt = 0;
    for(Dwarf_Unsigned i = 0; i<locentry_len; i++){
        Dwarf_Small lkind=0, lle_value=0;
        Dwarf_Unsigned rawval1=0, rawval2=0;
        Dwarf_Bool debug_addr_unavailable = false;
        Dwarf_Addr lopc = 0;
        Dwarf_Addr hipc = 0;
        Dwarf_Unsigned loclist_expr_op_count = 0;
        Dwarf_Locdesc_c locdesc_entry = 0;
        Dwarf_Unsigned expression_offset = 0;
        Dwarf_Unsigned locdesc_offset = 0;

        res = dwarf_get_locdesc_entry_d(loclist_head, i,
        &lle_value,
        &rawval1, &rawval2,
        &debug_addr_unavailable,
        &lopc,&hipc,
        &loclist_expr_op_count,
        &locdesc_entry,
        &lkind,
        &expression_offset,
        &locdesc_offset,
        &err);

        simple_handle_err(res)

        bool isSingleExpr = false;
        bool isEmptyExpr = false;
        bool isImplicit = false;
        bool isReg = false;
        bool hasCFA = false;

        Dwarf_Small op = 0;
        
        if(loclist_expr_op_count == 1){
            isSingleExpr = true;
        }
        if(lopc == hipc && loclist_expr_op_count>0){
            isEmptyExpr = true;
        }
        outputString += '\n' + addindent(indent) + "--- exp start " + toHex(lopc) + " " + toHex(hipc) + "\n";
        for(Dwarf_Unsigned j = 0; j<loclist_expr_op_count; j++){
            Dwarf_Unsigned op1, op2, op3, offsetForBranch;
                
            ret = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
            simple_handle_err(ret)

            // record operator
            statistics.addOp(op);

            const char *op_name;
            res = dwarf_get_OP_name(op, &op_name);
            
           
            if(op==DW_OP_entry_value||op==DW_OP_GNU_entry_value){
                tempEvaluator.dbg = dbg;
                tempEvaluator.parse_dwarf_block((Dwarf_Ptr)op2, op1, dummyrange, true);
            }
            if(op==DW_OP_fbreg){
                hasCFA = true;
                outputString += "DW_OP_fbreg_range " + toHex(lopc) + " " + toHex(hipc) + "\n";
            }

            if(j==1 && loclist_expr_op_count == 2 && op == DW_OP_stack_value){
                isSingleExpr = true;
            }
            if(op==DW_OP_stack_value){
                isImplicit = true;
            }else if(op>=DW_OP_reg0 && op<=DW_OP_reg31){
                isReg = true;
            }
            outputString += addindent(indent) + string(op_name) + " " + toHex(op1) + " " + toHex(op2) + " " + toHex(op3) + "\n";
            
        }
        outputString += addindent(indent) + "[" + to_string(loclist_expr_op_count) + (isReg?"r":(isImplicit?"i":"m")) + (hasCFA?"c":"") + "]\n";
        statistics.solveOneExpr();
        
        isMultiLoc = isMultiLoc && (!isSingleExpr);
        if(isSingleExpr || isEmptyExpr){
            bored_cnt++;
        }
    }
    if(!onlyComplex || isMultiLoc && bored_cnt < locentry_len){
        cout<<outputString<<endl;
    }
    
    dwarf_dealloc_loc_head_c(loclist_head);
    if(loc_form == DW_FORM_sec_offset){

    }else if(loc_form == DW_FORM_exprloc){

    }

    return ret;
}

// pre-order traverse
void walkDieTree(Dwarf_Die cu_die, Dwarf_Debug dbg, Dwarf_Die fa_die, Range range, bool is_info, int indent){
    Dwarf_Error err;
    Range fa_range(range);
    do{
        const char *tag_name;
        Dwarf_Half tag;
        Dwarf_Die child_die;
        bool modifyRange = false;
        int res = 0;
        res = dwarf_tag(fa_die, &tag, &err);
        if(res==DW_DLV_OK){
            res = dwarf_get_TAG_name(tag, &tag_name);
            if (res == DW_DLV_OK){
                printindent(indent);
                printf("%s", tag_name);

            }

            if(tag==DW_TAG_lexical_block || tag==DW_TAG_subprogram){
                range.setFromDie(fa_die);
                modifyRange = true;
            }
            updateFrameBase(fa_die, range);

            if (tag==DW_TAG_variable||tag==DW_TAG_formal_parameter){
                Dwarf_Bool hasLoc = false;
                char *var_name = nullptr;
                res = get_name(dbg, fa_die, &var_name);
                
                if(res == DW_DLV_OK){
                    printf(" name: %s", var_name);
                }

                Type *type_p;
                res = Type::parse_type_die(dbg, fa_die, &type_p);
                if (res == DW_DLV_OK) {
                    printf(" %s", type_p->to_string().c_str());
                }

                res = dwarf_hasattr(fa_die, DW_AT_location, &hasLoc, &err);
                
                
                if(res == DW_DLV_OK && hasLoc){

                    Dwarf_Attribute location_attr;
                    dwarf_attr(fa_die, DW_AT_location, &location_attr, &err);
                    Dwarf_Half form;
                    dwarf_whatform(location_attr, &form, &err);
                    const char *form_name;
                    res = dwarf_get_FORM_name(form, &form_name);
                    if(res == DW_DLV_OK){
                        printf(" %s\n", form_name);
                        // fprintf(stderr, "%s\n", form_name);
                    }
                    
                    statistics.addVar(tag);
                    if(printRawLoc){
                        print_raw_location(dbg, location_attr, form, indent+1);
                    }else{
                        test_evaluator(dbg, cu_die, fa_die, range, var_name);
                    }

                    dwarf_dealloc_attribute(location_attr);
                }else{
                    // fprintf(stderr, "%s no location\n", var_name);
                    varNoLocation += 1;
                }
            }

            printf("\n");
        }

        if(dwarf_child(fa_die, &child_die, &err)==DW_DLV_OK){
            walkDieTree(cu_die, dbg, child_die, range, is_info, indent+1);
            dwarf_dealloc_die(child_die);
        }
        if (modifyRange) {
            range.setFromRange(fa_range);
        }
    }while(dwarf_siblingof_b(dbg, fa_die, is_info, &fa_die, &err) == DW_DLV_OK);
}

int main(int argc, char *argv[]) {
    const char *progname = argv[1];
    int fd = open(progname, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    for(int i=2; i<argc; ++i){
        if (strcmp(argv[i], "-o")==0 ||
            strcmp(argv[i], "--output") == 0) {
                jsonFileStr = string(argv[i+1]);
                jsonOut = ofstream(jsonFileStr);
                ++i;
        }else if (strcmp(argv[i], "-nj") == 0) {
            useJson = 0;
        }else if (strcmp(argv[i], "-r") == 0 ||
                strcmp(argv[i], "--raw") == 0){
            printRawLoc = true;
        }else if (strcmp(argv[i], "-nc") == 0){
            onlyComplex = true;
        }else if (strcmp(argv[i], "-fde") == 0){
            printFDE = true;
        }else if(strcmp(argv[i], "-fo") == 0){
            frameFileStr = string(argv[i+1]);
            ++i;
        }else if(strcmp(argv[i], "--no-traverse") == 0){
            noTraverse = true;
        }
    }

    /*
        main process
    */
    Dwarf_Debug dbg;
    Dwarf_Error err;
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
    Dwarf_Half version_stamp, address_size, length_size, extension_size, header_cu_type;
    Dwarf_Sig8 type_signature;
    if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY , NULL, NULL, &dbg, &err) != DW_DLV_OK) {
        fprintf(stderr, "dwarf_init failed: %s\n", dwarf_errmsg(err));
        return 1;
    }
    testFDE(dbg, printFDE);
    printf("--- parsing frame info done ---\n");

    if (useJson) {
        jsonOut << "[\n";
    }
    Dwarf_Die cu_die;
    bool is_info = true;
    int res = 0;
    while(!noTraverse){
        res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size, &length_size, &extension_size, 
            &type_signature, &typeoffset, &next_cu_header, &header_cu_type, &err);
        if (res==DW_DLV_ERROR){
            return 1;
        }
        if (res==DW_DLV_NO_ENTRY){
            break;
            if(is_info){
                is_info = false;
                continue;
            }
            // return 1;
        }
        
        printf("cu_header_length:%llu\nnext_cu_header:%llu\n", cu_header_length, next_cu_header);

        if (dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, &err) != DW_DLV_OK) {
            fprintf(stderr, "Error in dwarf_siblingof: %s\n", dwarf_errmsg(err));
            return 1;
        }

        walkDieTree(cu_die, dbg, cu_die, Range::createFromDie(cu_die), is_info, 0);

        Type::finish();
        dwarf_dealloc_die(cu_die);
    }
    dwarf_finish(dbg);
    close(fd);

    if (useJson) {
        jsonOut << "\n]";
    }
    jsonOut.close();

    // output statistics
    cout<<"---------------- statistics ----------------"<<endl;
    cout<<"variable die doesn't have location attribute: " << varNoLocation << endl;
    cout<<statistics.output()<<endl;
    return 0;
}
