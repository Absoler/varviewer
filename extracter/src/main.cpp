#include <fcntl.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <unistd.h>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <ostream>
#include <string>
#include "include/logger.h"
#include "include/var_locator.h"
// global options
std::string jsonFileStr;
std::ofstream jsonOut;
std::string frameFileStr;

int useJson = 1;
bool printRawLoc = false;
bool onlyComplex = false;
bool printFDE = false;
bool noTraverse = false;
bool OutMemberInMember = false;
bool matchField = false;

// important variables
bool isFirstJson = true;

// statistic variables
int varNoLocation = 0;

int main(int argc, char *argv[]) {
  if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    std::cout << "Usage: " << argv[0] << " <elf file> [options]\n"
              << "Options:\n"
              << "  -o, --output <file>    output json file\n"
              << "  -nj                    not use json format\n"
              << "  -r, --raw              print raw location expression\n"
              << "  -nc                    only print complex location expression\n"
              << "  -fde                   print frame description entry\n"
              << "  -fo <file>             output frame info to file\n"
              << "  --no-traverse          not traverse the DIE tree\n"
              << "  -omm                   output member in member\n"
              << "  -mf, --match-field     match field\n";
    return 0;
  }

  const char *progname = argv[1];
  int fd = open(progname, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  for (int i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
      jsonFileStr = std::string(argv[i + 1]);
      jsonOut = std::ofstream(jsonFileStr);
      ++i;
    } else if (strcmp(argv[i], "-nj") == 0) {
      useJson = 0;
    } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--raw") == 0) {
      printRawLoc = true;
    } else if (strcmp(argv[i], "-nc") == 0) {
      onlyComplex = true;
    } else if (strcmp(argv[i], "-fde") == 0) {
      printFDE = true;
    } else if (strcmp(argv[i], "-fo") == 0) {
      frameFileStr = std::string(argv[i + 1]);
      ++i;
    } else if (strcmp(argv[i], "--no-traverse") == 0) {
      noTraverse = true;
    } else if (strcmp(argv[i], "-omm") == 0) {
      OutMemberInMember = true;
    } else if (strcmp(argv[i], "--match-field") == 0 || strcmp(argv[i], "-mf") == 0) {
      matchField = true;
    } else {
      std::cerr << "unknown option: " << argv[i] << "\n";
      return 1;
    }
  }

  /*
      main process
  */
  // save dwarf content
  Dwarf_Debug dbg;
  Dwarf_Error err;
  Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header, typeoffset;
  Dwarf_Half version_stamp, address_size, length_size, extension_size, header_cu_type;
  Dwarf_Sig8 type_signature;
  if (dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err) != DW_DLV_OK) {
    fprintf(stderr, "dwarf_init failed: %s\n", dwarf_errmsg(err));
    return 1;
  }
  varviewer::testFDE(dbg, printFDE);
  printf("\033[1;34m--- parsing frame info done ---\033[0m\n");

  if (useJson) {
    jsonOut << "[\n";
  }
  // a cu_DIE describle a compilation unit
  Dwarf_Die cu_die;
  // reading through .debug_info
  bool is_info = true;
  int res = 0;
  while (!noTraverse) {
    // read the content of next compilationm unit
    // like python's yield
    res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length, &version_stamp, &abbrev_offset, &address_size,
                                 &length_size, &extension_size, &type_signature, &typeoffset, &next_cu_header,
                                 &header_cu_type, &err);
    if (res == DW_DLV_ERROR) {
      return 1;
    }
    // all cu have been read
    if (res == DW_DLV_NO_ENTRY) {
      break;
      if (is_info) {
        is_info = false;
        continue;
      }
      // return 1;
    }

    LOG_DEBUG("cu_header_length:%llu\nnext_cu_header:%llu\n", cu_header_length, next_cu_header);

    // get the first die or next die ,NULL to retrieve the CU DIE.
    if (dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, &err) != DW_DLV_OK) {
      fprintf(stderr, "Error in dwarf_siblingof: %s\n", dwarf_errmsg(err));
      return 1;
    }

    // Range::createFromDie create a Range(startpc,endpc) according to the die
    varviewer::WalkDieTree(cu_die, dbg, cu_die, varviewer::Range::createFromDie(cu_die), is_info, 0);

    dwarf_dealloc_die(cu_die);
  }
  dwarf_finish(dbg);
  close(fd);

  if (useJson) {
    jsonOut << "\n]";
  }
  jsonOut.close();

  // output statistics
  std::cout << "---------------- statistics ----------------"
            << "\n";
  std::cout << "variable die doesn't have location attribute: " << varNoLocation << "\n";
  std::cout << varviewer::statistics.output() << "\n";
  return 0;
}