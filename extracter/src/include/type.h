#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include "json.hpp"
namespace varviewer {
// <piece_start, piece_size>
using piece_type = std::pair<Dwarf_Addr, int>;

using json = nlohmann::json;
class Type {
 public:
  friend json createJsonForType(const Type &type);
  /* record offset to the type, aboid redundant parse */
  static std::unordered_map<Dwarf_Off, std::shared_ptr<Type>> offset_to_type_map_;

  Type() = default;

  Type(const std::string &type_name, size_t size, const bool &user_defined, const bool &is_pointer, size_t level);

  auto static PareTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
      -> std::shared_ptr<Type>;

  auto GetTypeName() const -> std::string;

  auto GetTypeSize() const -> size_t;

  auto IsUserDefined() const -> bool;

  auto IsPointer() const -> bool;

  auto GetPointerLevel() const -> size_t;

  ~Type() = default;

 private:
  /*type name*/
  std::string type_name_;
  /* size */
  size_t size_;
  /* whether user-defined*/
  bool user_defined_;
  /* whether pointer */
  bool is_pointer_{false};
  /*pointer level*/
  size_t pointer_level_{0};
};
// class Type {
//  public:
//   Type();
//   static int parse_type_die(Dwarf_Debug dbg, Dwarf_Die var_die, Type **type_p);

//   static void finish();

//   void clear();

//   std::string to_string();

//  private:
//   BasicType basicType;
//   int size;
//   bool has_sign;
//   bool valid;
//   // std::string typeName;
//   // std::vector<piece_type> pieces;
//   // std::vector<std::string> piece_names;

//   // static int extract_struct_type(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Type *type);
// };
}  // namespace varviewer
