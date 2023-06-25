#include <cstddef>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <stack>
#include <string>
#include <unistd.h>
#include <vector>
#include <queue>

#include "varLocator.h"



using namespace std;

// global options
string jsonFileStr;
string frameFileStr;
int useJson = 1;
bool printRawLoc = false;
bool onlyComplex = false;
bool printFDE = false;
bool noTraverse = false;

// important variables
json allJson = json::array();

inline void printindent(int indent){
    for(int _=0;_<indent;++_)
        printf("\t");
}

inline string addindent(int indent){
    string res = "";
    for(int _=0;_<indent;++_)
        res += '\t';
    return res;
}

template<typename T>
string toHex(T v){
    static const char* digits = "0123456789ABCDEF";
    int size = sizeof(T)<<1;
    string res(size, '0');
    for (size_t i=0, j=(size-1)*4 ; i<size; ++i,j-=4)
        res[i] = digits[(v>>j) & 0x0f];
    return res;
}

int get_name(Dwarf_Debug dbg, Dwarf_Die die, char **name){
    Dwarf_Error err;
    int res;
    Dwarf_Bool has_name = false, has_origin = false;
    res = dwarf_hasattr(die, DW_AT_name, &has_name, &err);
    res = dwarf_hasattr(die, DW_AT_abstract_origin, &has_origin, &err);
    simple_handle_err(res)
    if(has_name){
        Dwarf_Attribute name_attr;
        Dwarf_Half name_form;
        dwarf_attr(die, DW_AT_name, &name_attr, &err);
        if(res == DW_DLV_OK){
            dwarf_whatform(name_attr, &name_form, &err);
            if(name_form==DW_FORM_string||name_form==DW_FORM_line_strp||name_form==DW_FORM_strp){
                res = dwarf_formstring(name_attr, name, &err);
                return res;
            }
        }
    }else if(has_origin){
        Dwarf_Attribute off_attr;
        Dwarf_Half off_form;
        res = dwarf_attr(die, DW_AT_abstract_origin, &off_attr, &err);
        simple_handle_err(res)

        res = dwarf_whatform(off_attr, &off_form, &err);
        if(res!=DW_DLV_OK){
            dwarf_dealloc_attribute(off_attr);
            return 1;
        }

        Dwarf_Off offset;
        Dwarf_Bool is_info;
        res = dwarf_global_formref_b(off_attr, &offset, &is_info, &err);

        if(res!=DW_DLV_OK){
            dwarf_dealloc_attribute(off_attr);
            return 1;
        }

        Dwarf_Die origin_die;
        res = dwarf_offdie_b(dbg, offset, is_info, &origin_die, &err);

        Dwarf_Attribute name_attr;
        Dwarf_Half name_form;

        Dwarf_Bool has_name = true;
        res = dwarf_hasattr(origin_die, DW_AT_name, &has_name, &err);
        if(!has_name){
            return 1;
        }
        dwarf_attr(origin_die, DW_AT_name, &name_attr, &err);
        if(res == DW_DLV_OK){
            dwarf_whatform(name_attr, &name_form, &err);
            if(name_form==DW_FORM_string||name_form==DW_FORM_line_strp||name_form==DW_FORM_strp){
                res = dwarf_formstring(name_attr, name, &err);
                return res;
            }
        }
    }
    return 0;
}

int test_evaluator(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die){
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
    Address addr = evaluator.read_location(location_attr, loc_form);
    if(addr.valid == false){
        return 1;
    }

    char *name = NULL;
    res = get_name(dbg, var_die, &name);
    simple_handle_err(res)
    if(name)
        addr.name = string(name);
    
    char *file_name = NULL;
    Dwarf_Unsigned decl_row = -1, decl_col = -1;
    res = test_declPos(dbg, cu_die, var_die, &file_name, &decl_row, &decl_col, 0);
    if(file_name) addr.decl_file = string(file_name);
    addr.decl_row = decl_row;
    addr.decl_col = decl_col;

    if(useJson){
    // addr.output();
        json addrJson = createJsonforAddress(addr);
        allJson.push_back(move(addrJson));
        
        // auto addrStr = addrJson.dump(4);
        // if (oFileStr!="") {
        //     fstream out(oFileStr.c_str(), ios::app);
        //     out << addrStr <<endl;
        //     out.close();
        // }else{
        //     cout << addrStr << endl;
        // }
        
    }else{
        addr.output();
    }

    // dealloc memory
    // for(AddressExp addrExp: addr.addrs){
    //     stack<Expression*> ptrs;
    //     queue<Expression*> que;
    //     if(addrExp.mem){
    //         // que.push(addrExp.mem);
    //         // ptrs.push(addrExp.mem);
    //         delete addrExp.mem;
    //         addrExp.mem = NULL;
    //     }
    //     if(addrExp.hasChild && addrExp.sub1){
    //         // que.push(addrExp.sub1);
    //         // ptrs.push(addrExp.sub1);
    //         delete addrExp.sub1;
    //         addrExp.sub1 = NULL;
    //     }
    //     if(addrExp.hasChild && addrExp.sub2){
    //         // que.push(addrExp.sub2);
    //         // ptrs.push(addrExp.sub2);
    //         delete addrExp.sub2;
    //         addrExp.sub2 = NULL;
    //     }
    //     // while(!que.empty()){
    //     //     Expression *ptr = que.front();
    //     //     que.pop();
    //     //     if(ptr->mem){
    //     //         que.push(ptr->mem);
    //     //         ptrs.push(ptr->mem);
    //     //     }
    //     //     if(ptr->hasChild && ptr->sub1){
    //     //         que.push(ptr->sub1);
    //     //         ptrs.push(ptr->sub1);
    //     //     }
    //     //     if(ptr->hasChild && ptr->sub2){
    //     //         que.push(ptr->sub2);
    //     //         ptrs.push(ptr->sub2);
    //     //     }
    //     // }
    //     // while(!ptrs.empty()){
    //     //     Expression *tmp = ptrs.top();
    //     //     delete tmp;
    //     //     ptrs.pop();
    //     // }
    // }
    
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
        var_die = origin_die;
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
    // printf(" %s", (res==DW_DLV_OK?" get success! ":" fail "));
    if(res==DW_DLV_OK){
        string ops_for_complexOnly;
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

            bool isMultiExpr = true;
            bool isBoredExpr = false;
            if(res==DW_DLV_OK){
                // get entry successfully
                Dwarf_Small op = 0;
                int opres;
                if(!onlyComplex){
                    printf("\n");
                    printindent(indent);
                    printf("--- exp start %llx %llx\n", lopc, hipc);
                }
                if(loclist_expr_op_count==1){
                    isMultiExpr = false;
                }
                if(lopc == hipc && loclist_expr_op_count>0){
                    isBoredExpr = true;
                }
                ops_for_complexOnly += '\n' + addindent(indent) + "--- exp start " + toHex(lopc) + " " + toHex(hipc) + "\n";
                for(Dwarf_Unsigned j = 0; j<loclist_expr_op_count; j++){
                    Dwarf_Unsigned op1, op2, op3, offsetForBranch;
                    bool 
                    opres = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
                    if(opres == DW_DLV_OK){
                        const char *op_name;
                        res = dwarf_get_OP_name(op, &op_name);
                        // printf("\n");
                        if(!onlyComplex){
                            printindent(indent);
                            printf("%s ", op_name);
                            printf(" %llx %llx %llx %llx\n", op1, op2, op3, offsetForBranch);
                            if(op==DW_OP_entry_value||op==DW_OP_GNU_entry_value){
                                tempEvaluator.dbg = dbg;
                                tempEvaluator.parse_dwarf_block((Dwarf_Ptr)op2, op1, true);
                            }
                            if(op==DW_OP_fbreg){
                                printf("DW_OP_fbreg_range %llu %llu\n", lopc, hipc);
                            }
                        }
                        if(j==1 && loclist_expr_op_count == 2 && op == DW_OP_stack_value){
                            isBoredExpr = true;
                        }
                        ops_for_complexOnly += addindent(indent) + string(op_name) + " " + toHex(op1) + " " + toHex(op2) + " " + toHex(op3) + "\n";
                    }
                }
            }
            isMultiLoc = isMultiLoc && isMultiExpr;
            if(isBoredExpr){
                bored_cnt++;
            }
        }
        if(onlyComplex && isMultiLoc && bored_cnt < locentry_len){
            cout<<ops_for_complexOnly<<endl;
        }
    }
    dwarf_dealloc_loc_head_c(loclist_head);
    if(loc_form == DW_FORM_sec_offset){

    }else if(loc_form == DW_FORM_exprloc){

    }

    return ret;
}

void walkDieTree(Dwarf_Die cu_die, Dwarf_Debug dbg, Dwarf_Die fa_die, bool is_info, int indent){
    Dwarf_Error err;
    do{
        const char *tag_name;
        Dwarf_Half tag;
        Dwarf_Die child_die;
        int res = 0;
        res = dwarf_tag(fa_die, &tag, &err);
        if(res==DW_DLV_OK){
            res = dwarf_get_TAG_name(tag, &tag_name);
            if (res == DW_DLV_OK){
                printindent(indent);
                printf("%s", tag_name);

            }

            if (tag==DW_TAG_variable||tag==DW_TAG_formal_parameter){
                Dwarf_Bool hasLoc = false;
                char *var_name = nullptr;
                res = get_name(dbg, fa_die, &var_name);
                
                if(res == DW_DLV_OK){
                    printf(" name: %s", var_name);
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
                    
                    if(printRawLoc){
                        
                        print_raw_location(dbg, location_attr, form, indent+1);
                    }else{
                        test_evaluator(dbg, cu_die, fa_die);
                    }
                }
            }

            printf("\n");
        }

        if(dwarf_child(fa_die, &child_die, &err)==DW_DLV_OK){
            walkDieTree(cu_die, dbg, child_die, is_info, indent+1);
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

    Dwarf_Die cu_die;
    bool is_info = true;
    int res = 0;
    bool isFirstCu = true;
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

        walkDieTree(cu_die, dbg, cu_die, is_info, 0);

        if(isFirstCu){
            isFirstCu = false;
        }
    }
    dwarf_finish(dbg);
    close(fd);

    // output json result
    if(useJson){
        string jsonStr = allJson.dump(4);
        if (jsonFileStr!="") {
            fstream out(jsonFileStr.c_str(), ios::out);
            out << jsonStr << endl;
            out.close();
        }else{
            cout << jsonStr << endl;
        }
        
    }

    return 0;
}
