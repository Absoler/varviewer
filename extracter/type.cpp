
#include "type.h"
#include "util.h"
#include "varLocator.h"
#include <cstddef>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <memory>

using namespace std;

map<Dwarf_Off, Type*> type_map;

string basic_type_names[4][2] = {
    {"unsigned char", "char"},
    {"unsigned short", "short"},
    {"unsigned", "int"},
    {"unsigned long long", "long long"}
};

Type::Type() {
    valid = true;
    basicType = INVALID_TYPE;
}

int
Type::parse_type_die(Dwarf_Debug dbg, Dwarf_Die var_die, Type **type_p) {
    Dwarf_Attribute type_attr;
    Dwarf_Die type_die;
    Dwarf_Off type_global_offset;
    Dwarf_Bool is_info;
    Dwarf_Error err;
    Dwarf_Half tag;

    int res = 0;

    res = dwarf_attr(var_die, DW_AT_type, &type_attr, &err);
    handle_err(res, err)

    res = dwarf_global_formref_b(type_attr, &type_global_offset, &is_info, &err);
    simple_handle_err(res)

    if (type_map.find(type_global_offset) != type_map.end()) {
        *type_p = type_map[type_global_offset];
        return DW_DLV_OK;
    }

    res = dwarf_offdie_b(dbg, type_global_offset, is_info, &type_die, &err);
    simple_handle_err(res)

    
    dwarf_tag(type_die, &tag, &err);

    Type *type = new Type();
    *type_p = type;
    type_map[type_global_offset] = type;

    if (tag == DW_TAG_base_type) {
        Dwarf_Attribute encoding_attr;
        Dwarf_Half encoding_form;
        Dwarf_Unsigned encoding, size;
        res = dwarf_attr(type_die, DW_AT_encoding, &encoding_attr, &err);
        handle_err(res, err)
        res = dwarf_whatform(encoding_attr, &encoding_form, &err);
        handle_err(res, err)
        encoding = get_const_u(encoding_form, encoding_attr, &err);

        Dwarf_Bool has_byte = true;
        res = dwarf_hasattr(type_die, DW_AT_byte_size, &has_byte, &err);
        handle_err(res, err)
        if (has_byte) {
            res = dwarf_bytesize(type_die, &size, &err);
            handle_err(res, err)
        } else {
            res = dwarf_bitsize(type_die, &size, &err);
            handle_err(res, err)
            if (size % 8 != 0) {
                return DW_DLV_ERROR;
            }
            size /= 8;
        }

        dwarf_dealloc_attribute(encoding_attr);
        
        if (encoding == DW_ATE_signed || encoding == DW_ATE_signed_char) {
            type->has_sign = true;
        } else if (encoding == DW_ATE_unsigned_char || encoding == DW_ATE_unsigned) {
            type->has_sign = false;
        } else {
            type->valid = false;
        }
        type->size = size;
    } else {
        return DW_DLV_ERROR;
    }
    return 0;
}


void
Type::finish() {
    auto iter = type_map.begin();
    for (; iter != type_map.end(); iter++ ) {
        delete iter->second;
    }
    type_map.clear();
}

string
Type::to_string() {
    if (!valid) {
        return string("invalid type");
    } else {
        return basic_type_names[log2(size)][static_cast<int>(has_sign)];
    }
}

void
Type::clear(){
//     typeName.clear();
//     piece_names.clear();
//     pieces.clear();
}

// int
// Type::extract_struct_type(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Type *type){

//     Dwarf_Error err;
//     Dwarf_Bool has_type, is_info;
//     Dwarf_Off type_off;
//     int res;

//     res = dwarf_hasattr(var_die, DW_AT_type, &has_type, &err);
//     if(res!=DW_DLV_OK || !has_type){
//         return -1;
//     }

//     res = dwarf_dietype_offset(var_die, &type_off, &err);
//     simple_handle_err(res)

//     Dwarf_Die type_die, pointer_type_die, typedef_die;
//     Dwarf_Half tag;
    
//     res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//     dwarf_tag(type_die, &tag, &err);

//     if (tag==DW_TAG_pointer_type){
//         // take pointee type
//         pointer_type_die = type_die;
//         res = dwarf_dietype_offset(var_die, &type_off, &err);
//         simple_handle_err(res)
//         res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//         simple_handle_err(res)
//         dwarf_tag(type_die, &tag, &err);
//     }

//     if (tag==DW_TAG_typedef){
//         // try take real definition
//         typedef_die = typedef_die;
//         res = dwarf_dietype_offset(var_die, &type_off, &err);
//         simple_handle_err(res)
//         res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//         simple_handle_err(res)
//         dwarf_tag(type_die, &tag, &err);
//     }

//     if (tag != DW_TAG_structure_type){
//         return 1;
//     }

//     // parse structural die
//     Dwarf_Die member;
//     res = dwarf_child(type_die, &member, &err);
//     simple_handle_err(res)

//     type->clear();
//     do{
//         Dwarf_Attribute name_attr, loc_attr;
//         res = dwarf_attr(member, DW_AT_name, &name_attr, &err);
//         char *name = NULL;
//         res = get_name(dbg, type_die, &name);
        
//         type->piece_names.push_back(name ? string(name) : "");

//         res = dwarf_attr(member, DW_AT_data_member_location, &loc_attr, &err);
        
//         Dwarf_Half loc_form, version, offset_size;
//         dwarf_whatform(loc_attr, &loc_form, &err);
//         dwarf_get_version_of_die(type_die, &version, &offset_size);
//         Dwarf_Form_Class loc_form_class = dwarf_get_form_class(version, DW_AT_data_member_location, offset_size, loc_form);
//         if (loc_form_class == DW_FORM_CLASS_CONSTANT){
//             Dwarf_Unsigned piece_start = get_const_u(loc_form, loc_attr, &err);
            
//         }

//     }while(dwarf_siblingof_b(dbg, member, is_info, &member, &err) == DW_DLV_OK);
// }