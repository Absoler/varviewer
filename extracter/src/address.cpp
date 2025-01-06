
#include "include/address.h"

#include <libdwarf-0/libdwarf.h>

#include <cstdio>
#include <string>

#include "include/expression.h"
using namespace std;

namespace varviewer {

AddressExp::AddressExp(DwarfType type) : dwarfType_(type) {}

void AddressExp::ResetData() {
  Expression::Reset();
  dwarfType_ = DwarfType::MEMORY;
  reg_ = REG_END;

  needCFA_ = false;
  cfa_pcs_.clear();
  cfa_values_.clear();
}

void AddressExp::Output() const {
  printf("start pc : %llx,end pc : %llx\n", startpc_, endpc_);
  printf("dwartType : %u\n", static_cast<int>(dwarfType_));
  if (dwarfType_ == DwarfType::MEMORY) {
    Expression::Output();
  } else if (dwarfType_ == DwarfType::REGISTER) {
    printf("%s\n", reg_names[reg_]);
  } else {
    Expression::Output();
  }
}

string AddressExp::ToString() {
  string res;
  if (dwarfType_ == DwarfType::MEMORY) {
    res = "*(" + Expression::ToString() + ")";
  } else if (dwarfType_ == DwarfType::REGISTER) {
    res = string(reg_names[reg_]);
  } else {
    res = Expression::ToString();
  }
  return res;
}

void Address::Output() {
  printf("address %s\n", name_.c_str());
  for (const AddressExp &addr : addrs_) {
    addr.Output();
  }
}

void Address::UpdateValid() {
  valid_ = true;
  for (auto it = addrs_.begin(); it != addrs_.end();) {
    if (it->valid_) {
      it++;
    } else {
      it = addrs_.erase(it);
    }
  }
  valid_ = (addrs_.size() != 0);
}
}  // namespace varviewer
