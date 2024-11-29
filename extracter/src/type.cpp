
#include "include/type.h"
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <cstddef>
#include <iostream>
#include <iterator>
#include <list>
#include <memory>
#include <unordered_map>
#include "include/util.h"
namespace varviewer {

StructType::StructType(std::string &&struct_name, size_t struct_size)
    : struct_name_(std::move(struct_name)), struct_size_(struct_size) {}

/* static member must init out of class */
std::list<std::shared_ptr<StructType>> Type::struct_infos_;

std::unordered_map<std::string, std::list<std::shared_ptr<StructType>>::iterator> Type::struct_name_to_iter_;

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

/* public interface */
auto Type::ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die) -> std::shared_ptr<Type> {
  return ParseTypeDieInternal(dbg, var_die, false, 0);
}

/**
 * @brief
         parse type info of the var die,get the dw_at_type attribute and parse it until base type and user defined
         struct type
 * @param dbg
         the dwarf debug info
 * @param var_die
         the variable die interested (has DW_AT_type attribute)
 * @param is_pointer
         whether the type is a pointer
 * @param level
         the pointer level
 * @return
         std::shared_ptr<Type> the type info
 *       ,nullptr if failed
 */
auto Type::ParseTypeDieInternal(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
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
  some die may not have DW_AT_type attribute(happen in recur ,
  now i do not know why, but it is true)
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
    return ParseTypeDieInternal(dbg, type_die, true, level + 1);
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
    return ParseTypeDieInternal(dbg, type_die, is_pointer, level);
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
    /* user defined struct */
    auto new_type = std::make_shared<Type>(std::string(type_name), byte_size, true, is_pointer, level);
    /* it : (struct name, std::list<std::shared_ptr<StructType>>::iterator) */
    auto it = struct_name_to_iter_.find(std::string(type_name));
    if (it != struct_name_to_iter_.end()) {
      auto &struct_ptr = *(it->second);
      new_type->member_name_ = struct_ptr->GetMemberNames();
      new_type->member_type_ = struct_ptr->GetMemberTypes();
      new_type->member_offset_ = struct_ptr->GetMemberOffsets();
    }
    return new_type;
  }
}

/**
 * @brief
         parse struct type info of the struct die which is a dw_tag_struct_type, traverse all the member which is
          a dw_tag_member, and save the struct info to the static member struct_infos_
 * @param dbg
         the dwarf debug info
 * @param struct_die
         the struct die interested
 * @return
         std::shared_ptr<StructType> the struct type info
 *       ,nullptr if failed
 */
void Type::ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die) {
  Dwarf_Error err;
  Dwarf_Unsigned byte_size;
  Dwarf_Bool has_byte_size = true;
  Dwarf_Die child_die;
  Dwarf_Attribute offset_attr;
  auto struct_info = std::make_shared<StructType>();
  char *name;
  int res;
  res = get_name(dbg, struct_die, &name);
  if (res == DW_DLV_OK) {
    printf("struct name: %s;", name);
    struct_info->SetStructName(std::string(name));
  }

  res = dwarf_hasattr(struct_die, DW_AT_byte_size, &has_byte_size, &err);
  if (!has_byte_size) {
    return;
  }
  res = dwarf_bytesize(struct_die, &byte_size, &err);
  if (res != DW_DLV_OK) {
    return;
  }
  struct_info->SetStructSize(byte_size);

  if (dwarf_child(struct_die, &child_die, &err) != DW_DLV_OK) {
    /* has no member */
    return;
  }
  /* traverse all the DW_TAG_member */
  do { /* get DW_AT_data_member_location attr */
    res = dwarf_attr(child_die, DW_AT_data_member_location, &offset_attr, &err);
    if (res != DW_DLV_OK) {
      return;
    }
    /* get member name */
    char *member_name;
    res = get_name(dbg, child_die, &member_name);

    /* get the member offser in struct */
    Dwarf_Unsigned offset_in_struct;
    res = dwarf_formudata(offset_attr, &offset_in_struct, &err);
    printf("struct member name : %s;", member_name);
    printf("struct member offset : %llu;", offset_in_struct);

    /* get the meber type info */
    auto type_info = Type::ParseTypeDie(dbg, child_die);

    /* save */
    struct_info->SetMemberOffset(std::string(member_name), offset_in_struct);
    struct_info->SetMemberType(std::string(member_name), type_info);
    struct_info->InsertName(std::string(member_name));

    /* get next sibling */
  } while (dwarf_siblingof_b(dbg, child_die, true, &child_die, &err) == DW_DLV_OK);

  /* save struct and iter */
  struct_infos_.push_back(struct_info);
  struct_name_to_iter_[struct_info->GetStructName()] = std::prev(struct_infos_.end());
  std::cout << " struct " << struct_info->GetStructName() << " saved\n";
  dwarf_dealloc_attribute(offset_attr);
}
}  // namespace varviewer