#include "include/jsonUtil.h"

#include <libdwarf-0/libdwarf.h>

#include <memory>
#include <string>
#include <vector>

#include "include/Address.h"
#include "include/Expression.h"
#include "include/type.h"

namespace varviewer {
json createJsonforExpression(const Expression &exp) {
  /*
      {
          "offset" : <Dwarf_Unsigned>
          "regs" : {
              <int>(reg_ind) : <int>(scale),
          }
          "mem" : <Expression>
          "mem_size" : <Dwarf_Small>
          "valid" : <bool>
          "empty" : <bool>
          "sign" : <bool>

          "hasChild" : <bool>
          "sub1" : <Expression>
          "sub2" : <Expression>
          "op" : <Dwarf_Unsigned>

          "isCFA" : <Bool>
      }
  */
  nlohmann::json res;
  if (exp.sign_) {
    res["offset"] = static_cast<Dwarf_Signed>(exp.offset_);
  } else {
    res["offset"] = exp.offset_;
  }

  nlohmann::json reg_dict;
  for (int i = 0; i < REG_END; ++i) {
    if (exp.reg_scale_[i]) {
      reg_dict[std::to_string(i)] = exp.reg_scale_[i];
      // reg_dict[i] = exp.reg_scale[i];
    }
  }
  res["regs"] = reg_dict;
  res["valid"] = exp.valid_;
  res["empty"] = exp.empty_;
  if (exp.mem_) {
    res["mem"] = createJsonforExpression(*exp.mem_);
  }
  if (exp.mem_size_) {
    res["mem_size"] = exp.mem_size_;
  }
  res["sign"] = exp.sign_;

  res["hasChild"] = exp.hasChild_;
  if (exp.hasChild_) {
    res["op"] = exp.op_;
    if (exp.sub1_) {
      res["sub1"] = createJsonforExpression(*exp.sub1_);
    }
    if (exp.sub2_) {
      res["sub2"] = createJsonforExpression(*exp.sub2_);
    }
  }

  res["isCFA"] = exp.isCFA_;

  return res;
}

json createJsonforAddressExp(const AddressExp &addrexp) {
  /*
      {
          Expression part ...

          "type" : <int>
          "detailedDwarfType" : <bool>
          "startpc" : <Dwarf_Addr>
          "endpc" : <Dwarf_Addr>
          "reg" : <Dwarf_Half>
          "piece_start" : <Dwarf_Addr>,
          "piece_size" : <int>

          "needCFA" : <bool>
          "cfa_values" : [
              <Expression>
          ]
          "cfa_pcs" : [
              <Dwarf_Addr>
          ]
      }
  */
  nlohmann::json res = createJsonforExpression(addrexp);
  res["dwarfType"] = static_cast<int>(addrexp.dwarfType_);
  res["detailedDwarfType"] = addrexp.detailedDwarfType_;
  res["startpc"] = addrexp.startpc_;
  res["endpc"] = addrexp.endpc_;
  res["reg"] = addrexp.reg_;
  res["piece_start"] = addrexp.piece_.first;
  res["piece_size"] = addrexp.piece_.second;

  res["needCFA"] = addrexp.needCFA_;
  if (addrexp.needCFA_) {
    res["cfa_values"] = std::vector<nlohmann::json>();
    for (auto cfa_value : addrexp.cfa_values_) {
      res["cfa_values"].push_back(createJsonforExpression(cfa_value));
    }
    res["cfa_pcs"] = addrexp.cfa_pcs_;
  }
  return res;
}

json createJsonforAddress(const Address &addr) {
  /*
      {
          "addrExps" : [
              <AddressExp>
          ]
          "name" : <string>
          "decl_file" : <string>
          "decl_row"  : <Dwarf_Unsigned>
          "decl_col"  : <Dwarf_Unsigned>
          "piece_num" : <int>
          "valid" : <bool>
      }
  */
  nlohmann::json res;
  for (AddressExp addrExp : addr.addrs_) {
    res["addrExps"].push_back(createJsonforAddressExp(addrExp));
  }
  res["name"] = addr.name_;
  if (addr.type_info_ != nullptr) {
    res["type_info"] = createJsonForType(addr.type_info_);
  }
  res["decl_file"] = addr.decl_file_;
  res["decl_row"] = addr.decl_row_;
  res["decl_col"] = addr.decl_col_;
  res["valid"] = addr.valid_;

  return res;
}

/*
  {
      "typeName" : <string>
      "size" : <size_t>
      "userDefined" : <bool>
      "isPointer" : <bool>
      "pointerLevel" : <size_t>
      "members" : {
          <string>(offset) : {
              "name" : <string>
              "type" : <Type>
          }
      }
  }
*/
nlohmann::json createJsonForType(const std::shared_ptr<Type> &type) {
  nlohmann::json res;
  if (type == nullptr) {
    return res;
  }
  res["typeName"] = type->GetTypeName();
  res["size"] = type->GetTypeSize();
  res["userDefined"] = type->IsUserDefined();
  res["isPointer"] = type->IsPointer();
  res["pointerLevel"] = type->GetPointerLevel();

  // If the type is user-defined, include member information
  if (type->IsUserDefined()) {
    auto user_defined_type = std::dynamic_pointer_cast<UserDefinedType>(type);
    res["userDefinedType"] = user_defined_type->GetUserDefinedType() == UserDefined::STRUCT ? "Struct" : "Union";
    nlohmann::json members_json = nlohmann::json::object();

    // Get member information
    const auto &member_offsets = user_defined_type->GetMemberOffsets();
    const auto &member_names = user_defined_type->GetMemberNames();
    const auto &member_types = user_defined_type->GetMemberTypes();

    // Iterate over the member offsets and retrieve their details
    for (const auto &offset : member_offsets) {
      // Ensure the offset exists in both maps
      if (member_names.count(offset) == 0 || member_types.count(offset) == 0) {
        throw std::runtime_error("Invalid offset in struct member information");
      }

      const auto &names = member_names.at(offset);
      const auto &types = member_types.at(offset);

      // Ensure the number of names and types match
      if (names.size() != types.size()) {
        throw std::runtime_error("Mismatched member names and types at offset: " + std::to_string(offset));
      }

      // Iterate through the members at the current offset
      nlohmann::json members_at_offset = nlohmann::json::array();
      for (size_t i = 0; i < names.size(); ++i) {
        nlohmann::json member_info = nlohmann::json::object();
        member_info["memberName"] = names[i];
        member_info["type"] = createJsonForType(types[i]);  // Recursive call

        members_at_offset.push_back(member_info);
      }

      // Use the offset as the key in the members JSON object
      members_json[std::to_string(offset)] = members_at_offset;
    }

    // Add members to the result JSON
    res["members"] = members_json;
  }

  return res;
}

}  // namespace varviewer
