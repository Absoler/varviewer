#pragma once
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
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

enum class UserDefindType : uint8_t { STRUCT, UNION };

class Type {
 public:
  Type() = default;

  // constructor for base type
  Type(const std::string &type_name, const Dwarf_Unsigned &size, const bool &user_defined, const bool &is_pointer,
       const size_t &level);

  // constructor for user defined type
  Type(const std::string &type_name, const Dwarf_Unsigned &size, const bool &user_defined, const bool &is_pointer,
       const size_t &level, const UserDefindType &user_defined_type, const std::list<Dwarf_Unsigned> &member_offsets,
       const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &member_names,
       const std::unordered_map<Dwarf_Unsigned, std::vector<std::shared_ptr<Type>>> &member_types);

  Type(const Type &type);

  auto static ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die) -> std::shared_ptr<Type>;

  static void ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die);

  auto static ParseUnionType(Dwarf_Debug dbg, Dwarf_Die union_die) -> std::shared_ptr<Type>;

  auto GetTypeName() const -> const std::string &;

  void SetTypeName(const std::string &type_name);

  auto GetTypeSize() const -> const Dwarf_Unsigned &;

  void SetTypeSize(const Dwarf_Unsigned &size);

  auto IsUserDefined() const -> bool;

  void SetUserDefined(const bool &user_defined);

  auto IsPointer() const -> bool;

  void SetIsPointer(const bool &is_pointer);

  auto GetPointerLevel() const -> size_t;

  void SetPointerLevel(const size_t &pointer_level);

  auto GetUserDefinedType() const -> UserDefindType;

  void SetUserDefinedType(const UserDefindType &user_defined_type);

  auto GetMemberOffsets() const -> const std::list<Dwarf_Unsigned> &;

  void SetMemberOffsets(const std::list<Dwarf_Unsigned> &member_offsets);

  auto GetMemberTypes() const -> const std::unordered_map<Dwarf_Unsigned, std::vector<std::shared_ptr<Type>>> &;

  void SetMemberTypes(const std::unordered_map<Dwarf_Unsigned, std::vector<std::shared_ptr<Type>>> &member_types);

  auto GetMemberNames() const -> const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &;

  void SetMemberNames(const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &member_names);

  void InsertOffset(const Dwarf_Unsigned &offset);

  void InsertMemberName(const Dwarf_Unsigned &offset, const std::string &name);

  void InsertMemberType(const Dwarf_Unsigned &offset, std::shared_ptr<Type> &type);

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

  /* if user-defined, whether struct or union? */
  UserDefindType user_defined_type_;

  /*if user-defined struct, record the members offsets */
  std::list<Dwarf_Unsigned> member_offsets_;
  /*
  if user-defined struct, record the members names, value use set because there may be same offset member in struct,
  eg: union and bit field
  */
  std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> member_names_;

  /*if user-defined struct, record the members type */
  std::unordered_map<Dwarf_Unsigned, std::vector<std::shared_ptr<Type>>> member_types_;

  /* whether pointer */
  bool is_pointer_{false};

  /* pointer level */
  size_t pointer_level_{0};
};
}  // namespace varviewer
