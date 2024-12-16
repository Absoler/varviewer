#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <list>
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

class Type {
 public:
  Type() = default;

  Type(const std::string &type_name, const Dwarf_Unsigned &size, const bool &user_defined, const bool &is_pointer,
       const size_t &level);

  Type(const Type &type);

  auto static ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die) -> std::shared_ptr<Type>;

  static void ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die);

  inline auto GetTypeName() const -> std::string { return type_name_; }

  inline auto GetTypeSize() const -> Dwarf_Unsigned { return size_; }

  inline auto IsUserDefined() const -> bool { return user_defined_; }

  inline auto IsPointer() const -> bool { return is_pointer_; }

  inline auto GetPointerLevel() const -> size_t { return pointer_level_; }

  inline auto GetMemberOffsets() const -> const std::list<Dwarf_Unsigned> & { return member_offsets_; }

  inline auto GetMemberTypes() const -> const std::unordered_map<Dwarf_Unsigned, std::shared_ptr<Type>> & {
    return member_types_;
  }

  inline auto GetMemberNames() const -> const std::unordered_map<Dwarf_Unsigned, std::string> & {
    return member_names_;
  }

  inline void InsertOffset(const Dwarf_Unsigned &offset) {
    VARVIEWER_ASSERT(
        std::find_if(member_offsets_.begin(), member_offsets_.end(),
                     [&offset](const Dwarf_Unsigned &off) -> bool { return off == offset; }) == member_offsets_.end(),
        "offset already exists");
    member_offsets_.push_back(offset);
  }

  inline void SetMemberName(const Dwarf_Unsigned &offset, const std::string &name) {
    VARVIEWER_ASSERT(member_names_.find(offset) == member_names_.end(), "offset already exists");
    member_names_[offset] = name;
  }

  inline void SetMemberType(const Dwarf_Unsigned &offset, std::shared_ptr<Type> &type) {
    VARVIEWER_ASSERT(member_types_.find(offset) == member_types_.end(), "offset already exists");
    member_types_[offset] = type;
  }

  ~Type() = default;

 private:
  /* record struct info */
  static std::unordered_map<std::string, std::shared_ptr<Type>> struct_infos_;

  /* real parse logic */
  auto static ParseTypeDieInternal(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
      -> std::shared_ptr<Type>;

  /* type name */
  std::string type_name_;

  /* size */
  Dwarf_Unsigned size_;

  /* whether user-defined */
  bool user_defined_;

  /*if user-defined struct, record the members offsets */
  std::list<Dwarf_Unsigned> member_offsets_;

  /*if user-defined struct, record the members names */
  std::unordered_map<Dwarf_Unsigned, std::string> member_names_;

  /*if user-defined struct, record the members type */
  std::unordered_map<Dwarf_Unsigned, std::shared_ptr<Type>> member_types_;

  /* whether pointer */
  bool is_pointer_{false};

  /* pointer level */
  size_t pointer_level_{0};
};
}  // namespace varviewer
