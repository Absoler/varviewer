#ifndef VARVIEWER_EVALUATOR_H_
#define VARVIEWER_EVALUATOR_H_
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

#include <stack>

#include "address.h"
#include "expression.h"
#include "ranges.h"

namespace varviewer {
  
enum class ArgType { ArgVarType, ArgBlockType };

// simple variable
struct ArgVar {
  ArgVar(const Range &range, Dwarf_Half loc_form) : range_(range), loc_form_(loc_form) {}
  Range range_;
  Dwarf_Half loc_form_;
};

struct ArgBlock {
  ArgBlock(const Range &range, const bool &print) : range_(range), print_(print) {}
  Range range_;
  bool print_;
};

class ArgLocation {
 public:
  /* construct argvar*/
  ArgLocation(const Range &range, Dwarf_Half loc_form);
  /* construct argblk */
  ArgLocation(const Range &range, bool print);
  union {
    ArgVar argvar;
    ArgBlock argblk;
  };
  ArgType argType;
};

class Evaluator {
  static constexpr int max_stack_ = 1000;
  /*stack used to simulate dwarf operation*/
  std::stack<Expression> stk_;

 public:
  Dwarf_Debug dbg_;

  int InitStack();

  int ExecOperation(Dwarf_Small op, Dwarf_Unsigned op1, Dwarf_Unsigned op2, Dwarf_Unsigned op3);

  AddressExp ParseDwarfBlock(Dwarf_Ptr exp_bytes, Dwarf_Unsigned exp_length, const Range &range = dummyrange,
                             bool print = false);

  Address ReadLocation(Dwarf_Attribute loc_attr, Dwarf_Half loc_form, Range range, bool from_update_base);

  Address ParseLoclist(Dwarf_Loc_Head_c loclist_head, Dwarf_Unsigned locentry_count, const ArgLocation &arg,bool from_update_base);

  Dwarf_Die GetTypeDie();
};

extern Evaluator tempEvaluator;
}  // namespace varviewer

#endif  // VARVIEWER_EVALUATOR_H_