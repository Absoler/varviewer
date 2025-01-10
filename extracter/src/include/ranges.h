#ifndef VARVIEWER_RANGES_H
#define VARVIEWER_RANGES_H
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>

namespace varviewer {
// keep the start_pc and end_pc of a DIE
class Range {
 public:
  static Range createEmpty();

  static Range createFromDie(Dwarf_Die die);

  Range() : startpc(0), endpc(0) {}

  Range(const Range &range);

  void clear();

  void setFromDie(Dwarf_Die);

  void setFromRange(const Range &range);

  Dwarf_Addr startpc, endpc;
};

extern const Range dummyrange;

int parse_simple_ranges(Dwarf_Die die, Dwarf_Addr *startpc, Dwarf_Addr *endpc);

}  // namespace varviewer

#endif  // VARVIEWER_RANGES_H_