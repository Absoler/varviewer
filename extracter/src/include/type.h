#ifndef VARVIEWER_TYPE_H_
#define VARVIEWER_TYPE_H_
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

enum class UserDefined : uint8_t { STRUCT, UNION };

class Type;

using TypeRef = std::shared_ptr<Type>;

class Type {
 public:
  Type() = default;

  Type(const std::string &type_name, const Dwarf_Unsigned &size, const bool &is_pointer, const size_t &pointer_level);

  Type(const Type &type);

  auto static ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die) -> TypeRef;

  auto static ParseStructType(Dwarf_Debug dbg, Dwarf_Die struct_die) -> TypeRef;

  auto static ParseUnionType(Dwarf_Debug dbg, Dwarf_Die union_die) -> TypeRef;

  void static DeallocDwarfResources(Dwarf_Debug dbg, Dwarf_Die type_die, Dwarf_Error err, Dwarf_Attribute attr);

  auto GetTypeName() const -> const std::string &;

  void SetTypeName(const std::string &type_name);

  auto GetTypeSize() const -> const Dwarf_Unsigned &;

  void SetTypeSize(const Dwarf_Unsigned &size);

  auto IsPointer() const -> bool;

  void SetIsPointer(const bool &is_pointer);

  auto GetPointerLevel() const -> size_t;

  void SetPointerLevel(const size_t &pointer_level);

  /* override in basetype and userdefinedtype */
  virtual auto IsUserDefined() const -> bool = 0;

  virtual ~Type() = default;

 private:
  /* real parse logic */
  auto static ParseTypeDieInternal(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level) -> TypeRef;

  /* record struct info */
  static std::unordered_map<std::string, TypeRef> struct_infos_;

  /* record union info */
  static std::unordered_map<std::string, TypeRef> union_infos;

  /* type name */
  std::string type_name_;

  /* size */
  Dwarf_Unsigned size_;

  /* whether pointer */
  bool is_pointer_{false};

  /* pointer level */
  size_t pointer_level_{0};
};

/* builtin type */
class BaseType : public Type {
 public:
  BaseType() = default;

  BaseType(const std::string &type_name, const Dwarf_Unsigned &size, const bool &is_pointer, const size_t &level);

  BaseType(const BaseType &base_type);

  virtual auto IsUserDefined() const -> bool override;

  void SetUserDefined(const bool &user_defined);

  ~BaseType() = default;

 private:
  bool user_defined_{false};
};

/* user defined type */
class UserDefinedType : public Type {
 public:
  UserDefinedType() = default;

  UserDefinedType(UserDefined user_defined_type);

  UserDefinedType(const std::string &type_name, const Dwarf_Unsigned &size, const bool &is_pointer, const size_t &level,
                  const UserDefined &user_defined_type, const std::list<Dwarf_Unsigned> &member_offsets,
                  const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &member_names,
                  const std::unordered_map<Dwarf_Unsigned, std::vector<TypeRef>> &member_types);

  UserDefinedType(const UserDefinedType &user_defined_type);

  virtual auto IsUserDefined() const -> bool override;

  auto GetUserDefinedType() const -> UserDefined;

  void SetUserDefinedType(const UserDefined &user_defined_type);

  auto GetMemberOffsets() const -> const std::list<Dwarf_Unsigned> &;

  void SetMemberOffsets(const std::list<Dwarf_Unsigned> &member_offsets);

  auto GetMemberTypes() const -> const std::unordered_map<Dwarf_Unsigned, std::vector<TypeRef>> &;

  void SetMemberTypes(const std::unordered_map<Dwarf_Unsigned, std::vector<TypeRef>> &member_types);

  auto GetMemberNames() const -> const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &;

  void SetMemberNames(const std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> &member_names);

  void InsertOffset(const Dwarf_Unsigned &offset);

  void InsertMemberName(const Dwarf_Unsigned &offset, const std::string &name);

  void InsertMemberType(const Dwarf_Unsigned &offset, TypeRef &type);

  ~UserDefinedType() = default;

 private:
  /* whether user-defined */
  bool user_defined_{true};

  /* if user-defined, whether struct or union? */
  UserDefined user_defined_type_;

  /*if user-defined struct, record the members offsets */
  std::list<Dwarf_Unsigned> member_offsets_;
  /*
  if user-defined struct, record the members names, value use set because there may be same offset member in struct,
  eg: union and bit field
  */
  std::unordered_map<Dwarf_Unsigned, std::vector<std::string>> member_names_;

  /*if user-defined struct, record the members type */
  std::unordered_map<Dwarf_Unsigned, std::vector<TypeRef>> member_types_;
};

}  // namespace varviewer

#endif  // VARVIEWER_TYPE_H_