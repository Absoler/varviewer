
#include "type.h"
#include "util.h"
#include "varLocator.h"
#include <cstddef>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

using namespace std;

void
Type::clear(){
    typeName.clear();
    piece_names.clear();
    pieces.clear();
}

int
Type::extract_struct_type(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Type *type){

    Dwarf_Error err;
    Dwarf_Bool has_type, is_info;
    Dwarf_Off type_off;
    int res;

    res = dwarf_hasattr(var_die, DW_AT_type, &has_type, &err);
    if(res!=DW_DLV_OK || !has_type){
        return -1;
    }

    res = dwarf_dietype_offset(var_die, &type_off, &err);
    simple_handle_err(res)

    Dwarf_Die type_die, pointer_type_die, typedef_die;
    Dwarf_Half tag;
    
    res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
    dwarf_tag(type_die, &tag, &err);

    if (tag==DW_TAG_pointer_type){
        // take pointee type
        pointer_type_die = type_die;
        res = dwarf_dietype_offset(var_die, &type_off, &err);
        simple_handle_err(res)
        res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
        simple_handle_err(res)
        dwarf_tag(type_die, &tag, &err);
    }

    if (tag==DW_TAG_typedef){
        // try take real definition
        typedef_die = typedef_die;
        res = dwarf_dietype_offset(var_die, &type_off, &err);
        simple_handle_err(res)
        res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
        simple_handle_err(res)
        dwarf_tag(type_die, &tag, &err);
    }

    if (tag != DW_TAG_structure_type){
        return 1;
    }

    // parse structural die
    Dwarf_Die member;
    res = dwarf_child(type_die, &member, &err);
    simple_handle_err(res)

    type->clear();
    do{
        Dwarf_Attribute name_attr, loc_attr;
        res = dwarf_attr(member, DW_AT_name, &name_attr, &err);
        char *name = NULL;
        res = get_name(dbg, type_die, &name);
        
        type->piece_names.push_back(name ? string(name) : "");

        res = dwarf_attr(member, DW_AT_data_member_location, &loc_attr, &err);
        
        Dwarf_Half loc_form, version, offset_size;
        dwarf_whatform(loc_attr, &loc_form, &err);
        dwarf_get_version_of_die(type_die, &version, &offset_size);
        Dwarf_Form_Class loc_form_class = dwarf_get_form_class(version, DW_AT_data_member_location, offset_size, loc_form);
        if (loc_form_class == DW_FORM_CLASS_CONSTANT){
            Dwarf_Unsigned piece_start = get_const_u(loc_form, loc_attr, &err);
            
        }

    }while(dwarf_siblingof_b(dbg, member, is_info, &member, &err) == DW_DLV_OK);








}