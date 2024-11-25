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

  Type() = default;

  Type(std::string &&type_name, size_t size, const bool &user_defined, const bool &is_pointer, size_t level);

  Type(const Type &type);

  auto static ParseTypeDie(Dwarf_Debug dbg, Dwarf_Die var_die, const bool &is_pointer, size_t level)
      -> std::shared_ptr<Type>;

  inline auto GetTypeName() const -> std::string { return type_name_; }

  inline auto GetTypeSize() const -> size_t { return size_; }

  inline auto IsUserDefined() const -> bool { return user_defined_; }

  inline auto IsPointer() const -> bool { return is_pointer_; }

  inline auto GetPointerLevel() const -> size_t { return pointer_level_; }

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
}  // namespace varviewer
