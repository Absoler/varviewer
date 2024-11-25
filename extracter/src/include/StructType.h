#pragma once

#include <libdwarf-0/libdwarf.h>
#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include "type.h"
namespace varviewer {
class StructType {
 public:
  StructType() = default;

  StructType(std::string &&struct_name, size_t struct_size);

  auto static ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die) -> std::shared_ptr<StructType>;

  auto inline GetStructName() const -> std::string { return struct_name_; }

  auto inlineGetStructSize() const -> size_t { return struct_size_; }

  auto inline GetMemberType(const std::string &member_name) -> std::shared_ptr<Type> {
    if (members_.find(member_name) != members_.end()) {
      return members_[member_name];
    }
    return nullptr;
  }

  auto inline GetMemberOffset(const std::string &member_name, Dwarf_Signed *offset) -> bool {
    if (member_offset_.find(member_name) != member_offset_.end()) {
      *offset = member_offset_[member_name];
      return true;
    }
    return false;
  }

 private:
  /* struct name */
  std::string struct_name_;

  /* whole size */
  size_t struct_size_;

  /* members name to type */
  std::unordered_map<std::string, std::shared_ptr<Type>> members_;

  /* members name to offset in struct */
  std::unordered_map<std::string, Dwarf_Unsigned> member_offset_;
};
}  // namespace varviewer
