#include "include/StructType.h"
#include <libdwarf-0/libdwarf.h>
#include <memory>
#include "include/type.h"
#include "include/util.h"

namespace varviewer {
StructType::StructType(std::string &&struct_name, size_t struct_size)
    : struct_name_(std::move(struct_name)), struct_size_(struct_size) {}

auto StructType::ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die) -> std::shared_ptr<StructType> {
  Dwarf_Error err;
  Dwarf_Unsigned byte_size;
  Dwarf_Bool has_byte_size = true;
  Dwarf_Die child_die;
  Dwarf_Attribute offset_attr;
  std::shared_ptr<StructType> ret_struct = std::make_shared<StructType>();
  char *name;
  int res;
  res = get_name(dbg, struct_die, &name);
  if (res == DW_DLV_OK) {
    printf("struct name: %s;", name);
    ret_struct->struct_name_ = std::string(name);
  }

  res = dwarf_hasattr(struct_die, DW_AT_byte_size, &has_byte_size, &err);
  if (!has_byte_size) {
    return nullptr;
  }
  res = dwarf_bytesize(struct_die, &byte_size, &err);
  if (res != DW_DLV_OK) {
    return nullptr;
  }
  ret_struct->struct_size_ = byte_size;

  if (dwarf_child(struct_die, &child_die, &err) != DW_DLV_OK) {
    /* has no member */
    return ret_struct;
  }
  /* traverse all the DW_TAG_member */
  do { /* get DW_AT_data_member_location attr */
    res = dwarf_attr(child_die, DW_AT_data_member_location, &offset_attr, &err);
    if (res != DW_DLV_OK) {
      return nullptr;
    }
    /* get member name */
    char *member_name;
    res = get_name(dbg, child_die, &member_name);

    /* get the member offser in struct */
    Dwarf_Unsigned offset_in_struct;
    res = dwarf_formudata(offset_attr, &offset_in_struct, &err);
    printf("struct member name : %s;", member_name);
    printf("struct member offset : %llu;", offset_in_struct);

    /* get type info */
    auto type_info = Type::ParseTypeDie(dbg, child_die, false, 0);
    if (type_info != nullptr) {
      printf("struct member type : %s;", type_info->GetTypeName().c_str());
    }
    /* save */
    ret_struct->members_[member_name] = type_info;
    ret_struct->member_offset_[member_name] = offset_in_struct;
    /* get next sibling */
  } while (dwarf_siblingof_b(dbg, child_die, true, &child_die, &err) == DW_DLV_OK);

  dwarf_dealloc_attribute(offset_attr);
  return ret_struct;
}

}  // namespace varviewer
