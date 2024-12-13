
#include "include/type.h"
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include "include/util.h"
namespace varviewer {

/* static member must init out of class */
std::unordered_map<std::string, std::shared_ptr<Type>> Type::struct_infos_ =
    []() -> std::unordered_map<std::string, std::shared_ptr<Type>> {
  std::unordered_map<std::string, std::shared_ptr<Type>> ret;
  ret.reserve(1000);
  return ret;
}();

Type::Type(const std::string &type_name, const Dwarf_Unsigned &size, const bool &user_defined, const bool &is_pointer,
           const size_t &pointer_level)
    : type_name_(type_name),
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
  }
  Dwarf_Bool has_name;
  char *type_name;
  std::string type_name_str;
  res = dwarf_hasattr(type_die, DW_AT_name, &has_name, &err);
  if (has_name) {
    res = dwarf_diename(type_die, &type_name, &err);
    type_name_str = std::string(type_name);
  } else {
    type_name_str = "anonymous";
  }
  if (tag == DW_TAG_base_type) {
    auto new_type = std::make_shared<Type>(type_name_str, byte_size, false, is_pointer, level);
    return new_type;
  } else {
    /* user defined struct */
    auto new_type = std::make_shared<Type>(type_name_str, byte_size, true, is_pointer, level);

    /*
    if the struct has not been record, tells that the struct member type die is defined
    behind the current struct
    for example,
    struct A;
    struct B{struct A * sa_;};
    struct A{int a_;};
    in this situation, the A die in dwarf will behind B, so when parse B's member
    sa_, there has not a record, so here we need to parse the A struct first
    */
    if (struct_infos_.count(type_name_str) == 0U) {
      ParseStructType(dbg, type_die);
    }
    auto it = struct_infos_.find(type_name_str);
    if (it != struct_infos_.end()) {
      auto &struct_ptr = it->second;
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
  auto struct_type_info = std::make_shared<Type>();
  char *name = nullptr;
  int res;
  res = get_name(dbg, struct_die, &name);
  /* some struct may not have name */
  if (res == DW_DLV_OK) {
    if (struct_infos_.count(std::string(name)) != 0U) {
      std::cout << "Struct " << name << " has been recorded\n";
      return;
    }
    printf("struct name: %s;", name);
    struct_type_info->type_name_ = std::string(name);
  } else {
    struct_type_info->type_name_ = "anonymous";
  }
  /*
  placeholder first, avoid endless recur when the
  struct has member which type is itself
  */
  if (struct_type_info->type_name_ != "anonymous") {
    struct_infos_[struct_type_info->type_name_] = struct_type_info;
  }

  res = dwarf_hasattr(struct_die, DW_AT_byte_size, &has_byte_size, &err);
  if (!has_byte_size) {
    return;
  }
  res = dwarf_bytesize(struct_die, &byte_size, &err);
  if (res != DW_DLV_OK) {
    return;
  }
  struct_type_info->size_ = byte_size;
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
    std::string member_name_str;
    if (res != DW_DLV_OK) {
      member_name_str = "anonymous_member";
    }
    member_name_str = std::string(member_name);
    /* get the member offser in struct */
    Dwarf_Unsigned offset_in_struct;
    res = dwarf_formudata(offset_attr, &offset_in_struct, &err);
    printf("struct member name : %s;", member_name);
    printf("struct member offset : %llu;", offset_in_struct);

    /* get the meber type info */
    auto member_type_info = Type::ParseTypeDie(dbg, child_die);
    /* save */
    struct_type_info->SetMemberOffset(member_name_str, offset_in_struct);
    struct_type_info->SetMemberType(member_name_str, member_type_info);
    struct_type_info->InsertName(member_name_str);

    /* get next sibling */
  } while (dwarf_siblingof_b(dbg, child_die, true, &child_die, &err) == DW_DLV_OK);

  /* save struct info, if anoymous, do not save */
  if (struct_type_info->type_name_ != "anonymous") {
    struct_infos_[struct_type_info->GetTypeName()] = struct_type_info;
    std::cout << " struct " << struct_type_info->GetTypeName() << " saved\n";
  }
  dwarf_dealloc_attribute(offset_attr);
}
}  // namespace varviewer