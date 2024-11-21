
#include "include/type.h"
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <cstddef>
#include <iostream>
#include <memory>
namespace varviewer {

Type::Type(std::string &&type_name, size_t size, const bool &user_defined, const bool &is_pointer, size_t pointer_level)
    : type_name_(std::move(type_name)),
      size_(size),
      user_defined_(user_defined),
      is_pointer_(is_pointer),
      pointer_level_(pointer_level) {}

Type::Type(const Type &type)
    : type_name_(type.type_name_),
      size_(type.size_),
      user_defined_(type.user_defined_),
      is_pointer_(type.is_pointer_),
      pointer_level_(type.pointer_level_) {}

auto Type::ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
    -> std::shared_ptr<Type> {
  Dwarf_Attribute type_attr;
  Dwarf_Die type_die;
  Dwarf_Off type_global_offset;
  Dwarf_Bool is_info;
  Dwarf_Error err;
  Dwarf_Half tag;
  int res = 0;

  /* get DW_AT_type attribute */
  res = dwarf_attr(var_die, DW_AT_type, &type_attr, &err);

  /*
  must check no entry first, because the err may be null pointer
  */
  if (res == DW_DLV_NO_ENTRY) {
    std::cout << "DW_AT_type attribute not found.\n";
    return nullptr;
  }
  if (res == DW_DLV_ERROR) {
    char *msg = dwarf_errmsg(err);
    std::cout << "Error: " << msg << "\n";
    return nullptr;
  }
  /* get the dw_at_type really point to's type die offset in global*/
  res = dwarf_global_formref_b(type_attr, &type_global_offset, &is_info, &err);

  if (res != DW_DLV_OK) {
    return nullptr;
  }

  /* using global offset to get the type die */
  res = dwarf_offdie_b(dbg, type_global_offset, is_info, &type_die, &err);

  if (res != DW_DLV_OK) {
    return nullptr;
  }
  /* get tag name */
  dwarf_tag(type_die, &tag, &err);

  if (tag == DW_TAG_pointer_type) {
    return ParseTypeDie(dbg, type_die, true, level + 1);
  } else if (tag == DW_TAG_const_type || tag == DW_TAG_array_type || tag == DW_TAG_typedef ||
             tag == DW_TAG_volatile_type || tag == DW_TAG_atomic_type || tag == DW_TAG_reference_type ||
             tag == DW_TAG_restrict_type || tag == DW_TAG_rvalue_reference_type) {
    /*
    const type does not need to level + 1
    and the recur is_pointer parameter should be same as the top caller
    because for const int *, its die's type will point to a
    pointer type die, then the pointer type die willl point
    to a const type die, so need to keep same as the top caller
    btw, for int const *, its dies's type will point to a const type die
    then const type die point to point type die.
    other tag similarly
    */
    return ParseTypeDie(dbg, type_die, is_pointer, level);
  }
  Dwarf_Unsigned byte_size;
  Dwarf_Bool has_byte_size = true;
  res = dwarf_hasattr(type_die, DW_AT_byte_size, &has_byte_size, &err);
  if (has_byte_size) {
    res = dwarf_bytesize(type_die, &byte_size, &err);
  } else {
    return nullptr;
  }
  Dwarf_Bool has_name;
  char *type_name;
  res = dwarf_hasattr(type_die, DW_AT_name, &has_name, &err);
  if (has_name) {
    res = dwarf_diename(type_die, &type_name, &err);
    if (res != DW_DLV_OK) {
      return nullptr;
    }
  } else {
    return nullptr;
  }
  if (tag == DW_TAG_base_type) {
    auto new_type = std::make_shared<Type>(std::string(type_name), byte_size, false, is_pointer, level);
    return new_type;
  } else {
    auto new_type = std::make_shared<Type>(std::string(type_name), byte_size, true, is_pointer, level);
    return new_type;
  }
}

}  // namespace varviewer
   // int Type::parse_type_die(Dwarf_Debug dbg, Dwarf_Die var_die, Type **type_p) {
   //   Dwarf_Attribute type_attr;
   //   Dwarf_Die type_die;
   //   Dwarf_Off type_global_offset;
   //   Dwarf_Bool is_info;
   //   Dwarf_Error err;
   //   Dwarf_Half tag;

//   int res = 0;

//   res = dwarf_attr(var_die, DW_AT_type, &type_attr, &err);
//   HANDLE_ERR(res, err);

//   res = dwarf_global_formref_b(type_attr, &type_global_offset, &is_info, &err);
//   SIMPLE_HANDLE_ERR(res);

//   if (type_map.find(type_global_offset) != type_map.end()) {
//     *type_p = type_map[type_global_offset];
//     return DW_DLV_OK;
//   }

//   res = dwarf_offdie_b(dbg, type_global_offset, is_info, &type_die, &err);
//   SIMPLE_HANDLE_ERR(res);

//   dwarf_tag(type_die, &tag, &err);

//   Type *type = new Type();
//   *type_p = type;
//   type_map[type_global_offset] = type;

//   if (tag == DW_TAG_base_type) {
//     Dwarf_Attribute encoding_attr;
//     Dwarf_Half encoding_form;
//     Dwarf_Unsigned encoding, size;
//     res = dwarf_attr(type_die, DW_AT_encoding, &encoding_attr, &err);
//     HANDLE_ERR(res, err);
//     res = dwarf_whatform(encoding_attr, &encoding_form, &err);
//     HANDLE_ERR(res, err);
//     encoding = get_const_u(encoding_form, encoding_attr, &err);

//     Dwarf_Bool has_byte = true;
//     res = dwarf_hasattr(type_die, DW_AT_byte_size, &has_byte, &err);
//     HANDLE_ERR(res, err);
//     if (has_byte) {
//       res = dwarf_bytesize(type_die, &size, &err);
//       HANDLE_ERR(res, err);
//     } else {
//       res = dwarf_bitsize(type_die, &size, &err);
//       HANDLE_ERR(res, err) if (size % 8 != 0) { return DW_DLV_ERROR; }
//       size /= 8;
//     }

//     dwarf_dealloc_attribute(encoding_attr);

//     if (encoding == DW_ATE_signed || encoding == DW_ATE_signed_char) {
//       type->has_sign = true;
//     } else if (encoding == DW_ATE_unsigned_char || encoding == DW_ATE_unsigned) {
//       type->has_sign = false;
//     } else {
//       type->valid = false;
//     }
//     type->size = size;
//   } else {
//     return DW_DLV_ERROR;
//   }
//   return 0;
// }

// void Type::finish() {
//   auto iter = type_map.begin();
//   for (; iter != type_map.end(); iter++) {
//     delete iter->second;
//   }
//   type_map.clear();
// }

// std::string Type::to_string() {
//   if (!valid) {
//     return std::string("invalid type");
//   } else {
//     if (size < 4 && size >= 0)
//       return basic_type_names[log2(size)][static_cast<int>(has_sign)];
//     else
//       return "";
//   }
// }

// void Type::clear() {
//     typeName.clear();
//     piece_names.clear();
//     pieces.clear();

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
//     SIMPLE_HANDLE_ERR(res)

//     Dwarf_Die type_die, pointer_type_die, typedef_die;
//     Dwarf_Half tag;

//     res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//     dwarf_tag(type_die, &tag, &err);

//     if (tag==DW_TAG_pointer_type){
//         // take pointee type
//         pointer_type_die = type_die;
//         res = dwarf_dietype_offset(var_die, &type_off, &err);
//         SIMPLE_HANDLE_ERR(res)
//         res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//         SIMPLE_HANDLE_ERR(res)
//         dwarf_tag(type_die, &tag, &err);
//     }

//     if (tag==DW_TAG_typedef){
//         // try take real definition
//         typedef_die = typedef_die;
//         res = dwarf_dietype_offset(var_die, &type_off, &err);
//         SIMPLE_HANDLE_ERR(res)
//         res = dwarf_offdie_b(dbg, type_off, is_info, &type_die, &err);
//         SIMPLE_HANDLE_ERR(res)
//         dwarf_tag(type_die, &tag, &err);
//     }

//     if (tag != DW_TAG_structure_type){
//         return 1;
//     }

//     // parse structural die
//     Dwarf_Die member;
//     res = dwarf_child(type_die, &member, &err);
//     SIMPLE_HANDLE_ERR(res)

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
//         Dwarf_Form_Class loc_form_class = dwarf_get_form_class(version, DW_AT_data_member_location,
//         offset_size, loc_form); if (loc_form_class == DW_FORM_CLASS_CONSTANT){
//             Dwarf_Unsigned piece_start = get_const_u(loc_form, loc_attr, &err);

//         }

//     }while(dwarf_siblingof_b(dbg, member, is_info, &member, &err) == DW_DLV_OK);
// }
