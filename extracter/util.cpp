#include "util.h"
#include <libdwarf-0/libdwarf.h>
#include <cstdio>

using namespace std;

Dwarf_Unsigned get_const_u(Dwarf_Half form, Dwarf_Attribute attr, Dwarf_Error *err){
    /*
     *  form must belong to `DW_FORM_CLASS_CONSTANT`
     */

    Dwarf_Unsigned offset;
    if(form==DW_FORM_data1 || form==DW_FORM_data2 || form==DW_FORM_data4 || form==DW_FORM_data8 || form==DW_FORM_data16){
        // endpc must > startpc, so data can't be negative
        dwarf_formudata(attr, &offset, err);
    }
    else if(form==DW_FORM_udata){
        dwarf_formudata(attr, &offset, err);

    }else if(form==DW_FORM_sdata){
        Dwarf_Signed offset_s = 0;
        dwarf_formsdata(attr, &offset_s, err);
        offset = (Dwarf_Unsigned)offset_s;

    }
    return offset;
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


void printindent(int indent){
    for(int _=0;_<indent;++_)
        printf("\t");
}

string addindent(int indent){
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
template string toHex(Dwarf_Unsigned v);