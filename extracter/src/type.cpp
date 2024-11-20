
#include "include/type.h"

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <cstddef>
#include <iostream>
#include <memory>
#include <unordered_map>

namespace varviewer {

/* static member must init out of class */
std::unordered_map<Dwarf_Off, std::shared_ptr<Type>> Type::offset_to_type_map_;

Type::Type(const std::string &type_name, size_t size, const bool &user_defined, const bool &is_pointer,
           size_t pointer_level)
    : type_name_(type_name),
      size_(size),
      user_defined_(user_defined),
      is_pointer_(is_pointer),
      pointer_level_(pointer_level) {}

auto Type::PareTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
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

  if (res == DW_DLV_ERROR) {
    char *msg = dwarf_errmsg(err);
    printf("%s\n", msg);
    return nullptr;
  }

  /* get the dw_at_type really point to's type die offset in global*/
  res = dwarf_global_formref_b(type_attr, &type_global_offset, &is_info, &err);

  if (res != DW_DLV_OK) {
    return nullptr;
  }

  /* already recorded */
  if (offset_to_type_map_.count(type_global_offset) != 0U) {
    return offset_to_type_map_[type_global_offset];
  }

  /* using global offset to get the type die */
  res = dwarf_offdie_b(dbg, type_global_offset, is_info, &type_die, &err);

  if (res != DW_DLV_OK) {
    return nullptr;
  }
  /* get tag name */
  dwarf_tag(type_die, &tag, &err);

  // TODO(tangc):add const type check
  if (tag == DW_TAG_pointer_type) {
    return PareTypeDie(dbg, type_die, true, level + 1);
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
  std::cout << "make type object now ,level : " << level << "\n";
  if (tag == DW_TAG_base_type) {
    auto new_type = std::make_shared<Type>(std::string(type_name), byte_size, false, is_pointer, level);
    // offset_to_type_map_[type_global_offset] = new_type;
    return new_type;
  } else {
    auto new_type = std::make_shared<Type>(std::string(type_name), byte_size, true, is_pointer, level);
    // offset_to_type_map_[type_global_offset] = new_type;
    return new_type;
  }
}
auto Type::GetTypeName() const -> std::string { return type_name_; }

auto Type::GetTypeSize() const -> size_t { return size_; }

auto Type::IsUserDefined() const -> bool { return user_defined_; }

auto Type::IsPointer() const -> bool { return is_pointer_; }

auto Type::GetPointerLevel() const -> size_t { return pointer_level_; }

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
//   handle_err(res, err);

//   res = dwarf_global_formref_b(type_attr, &type_global_offset, &is_info, &err);
//   simple_handle_err(res);

//   if (type_map.find(type_global_offset) != type_map.end()) {
//     *type_p = type_map[type_global_offset];
//     return DW_DLV_OK;
//   }

//   res = dwarf_offdie_b(dbg, type_global_offset, is_info, &type_die, &err);
//   simple_handle_err(res);

//   dwarf_tag(type_die, &tag, &err);

//   Type *type = new Type();
//   *type_p = type;
//   type_map[type_global_offset] = type;

//   if (tag == DW_TAG_base_type) {
//     Dwarf_Attribute encoding_attr;
//     Dwarf_Half encoding_form;
//     Dwarf_Unsigned encoding, size;
//     res = dwarf_attr(type_die, DW_AT_encoding, &encoding_attr, &err);
//     handle_err(res, err);
//     res = dwarf_whatform(encoding_attr, &encoding_form, &err);
//     handle_err(res, err);
//     encoding = get_const_u(encoding_form, encoding_attr, &err);

//     Dwarf_Bool has_byte = true;
//     res = dwarf_hasattr(type_die, DW_AT_byte_size, &has_byte, &err);
//     handle_err(res, err);
//     if (has_byte) {
//       res = dwarf_bytesize(type_die, &size, &err);
//       handle_err(res, err);
//     } else {
//       res = dwarf_bitsize(type_die, &size, &err);
//       handle_err(res, err) if (size % 8 != 0) { return DW_DLV_ERROR; }
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
//         Dwarf_Form_Class loc_form_class = dwarf_get_form_class(version, DW_AT_data_member_location,
//         offset_size, loc_form); if (loc_form_class == DW_FORM_CLASS_CONSTANT){
//             Dwarf_Unsigned piece_start = get_const_u(loc_form, loc_attr, &err);

//         }

//     }while(dwarf_siblingof_b(dbg, member, is_info, &member, &err) == DW_DLV_OK);
// }
