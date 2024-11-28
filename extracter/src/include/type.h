#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <cassert>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "util.h"
namespace varviewer {

// <piece_start, piece_size>
using piece_type = std::pair<Dwarf_Addr, int>;

class Type;

class StructType {
 public:
  StructType() = default;

  StructType(std::string &&struct_name, size_t struct_size);

  inline auto GetStructName() const -> std::string { return struct_name_; }

  inline void SetStructName(std::string &&name) { struct_name_ = std::move(name); }

  inline auto GetStructSize() const -> size_t { return struct_size_; }

  inline void SetStructSize(size_t size) { struct_size_ = size; }

  auto inline GetMemberOffset(const std::string &member_name) -> Dwarf_Unsigned {
    VARVIEWER_ASSERT(member_names_.find(member_name) != member_names_.end(), "member not exists");
    return member_offset_[member_name];
  }

  inline void SetMemberOffset(const std::string &member_name, Dwarf_Unsigned offset) {
    VARVIEWER_ASSERT(member_offset_.find(member_name) == member_offset_.end(), "member already exists");
    member_offset_[member_name] = offset;
  }

  inline auto GetMemberType(const std::string &member_name) -> std::shared_ptr<Type> {
    VARVIEWER_ASSERT(member_offset_.find(member_name) != member_offset_.end(), "member not exists");
    return member_type_[member_name];
  }

  inline auto SetMemberType(const std::string &member_name, std::shared_ptr<Type> type) -> void {
    VARVIEWER_ASSERT(member_type_.find(member_name) == member_type_.end(), "member already exists");
    member_type_[member_name] = type;
  }

  inline void InsertName(const std::string &name) {
    VARVIEWER_ASSERT(member_names_.find(name) == member_names_.end(), "member already exists");
    member_names_.insert(name);
  }

  inline auto GetMemberNames() const -> const std::unordered_set<std::string> & { return member_names_; }

 private:
  /* struct name */
  std::string struct_name_;

  /* whole size */
  size_t struct_size_;

  /* all the member names */
  std::unordered_set<std::string> member_names_;

  /* members name to offset in struct */
  std::unordered_map<std::string, Dwarf_Unsigned> member_offset_;

  /* members name to type */
  std::unordered_map<std::string, std::shared_ptr<Type>> member_type_;
};

class Type {
 public:
  Type() = default;

  Type(std::string &&type_name, size_t size, const bool &user_defined, const bool &is_pointer, size_t level);

  Type(const Type &type);

  auto static ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die) -> std::shared_ptr<Type>;

  static void ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die);

  inline auto GetTypeName() const -> std::string { return type_name_; }

  inline auto GetTypeSize() const -> size_t { return size_; }

  inline auto IsUserDefined() const -> bool { return user_defined_; }

  inline auto IsPointer() const -> bool { return is_pointer_; }

  inline auto GetPointerLevel() const -> size_t { return pointer_level_; }

  inline auto GetMemberNames() const -> const std::unordered_set<std::string> & { return member_name_; }

  inline auto GetMemberTypes() -> std::unordered_map<std::string, std::shared_ptr<Type>> & { return member_type_; }

  inline auto GetMemberOffsets() -> std::unordered_map<std::string, Dwarf_Unsigned> & { return member_offset_; }

  inline void InsertName(const std::string &name) {
    VARVIEWER_ASSERT(member_name_.find(name) == member_name_.end(), "member already exists");
    member_name_.insert(name);
  }

  inline void SetMemberOffset(const std::string &name, Dwarf_Unsigned offset) {
    VARVIEWER_ASSERT(member_offset_.find(name) == member_offset_.end(), "member already exists");
    member_offset_[name] = offset;
  }

  inline void SetMemberType(const std::string &name, std::shared_ptr<Type> type) {
    VARVIEWER_ASSERT(member_type_.find(name) == member_type_.end(), "member already exists");
    member_type_[name] = type;
  }

  ~Type() = default;

 private:
  /* record struct info */
  static std::vector<std::shared_ptr<StructType>> struct_infos_;

  /* real parse logic */
  auto static ParseTypeDieInternal(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
      -> std::shared_ptr<Type>;

  /*type name*/
  std::string type_name_;

  /* size */
  Dwarf_Unsigned size_;

  /* whether user-defined*/
  bool user_defined_;

  /*if user-defined struct, record the members name */
  std::unordered_set<std::string> member_name_;

  /*if user-defined struct, record the members type */
  std::unordered_map<std::string, std::shared_ptr<Type>> member_type_;

  /* if user-defined struct, record the members offset */
  std::unordered_map<std::string, Dwarf_Unsigned> member_offset_;

  /* whether pointer */
  bool is_pointer_{false};

  /*pointer level*/
  size_t pointer_level_{0};
};
}  // namespace varviewer
