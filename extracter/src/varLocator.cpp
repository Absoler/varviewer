#include "include/varLocator.h"
#include <fcntl.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <unistd.h>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include "include/Address.h"
#include "include/jsonUtil.h"
#include "include/type.h"
#include "include/util.h"

// global options
std::string jsonFileStr;
std::ofstream jsonOut;
std::string frameFileStr;
int useJson = 1;
bool printRawLoc = false;
bool onlyComplex = false;
bool printFDE = false;
bool noTraverse = false;

// important variables
bool isFirstJson = true;

// statistic variables
int varNoLocation = 0;

namespace varviewer {
/* a global sta */
Statistics statistics{};

/**
 * @brief
         get the location list or location expression of the variable, and outout to json
 * @param dbg
         the dwarf debug info
 * @param cu_die
          the compilation unit die
 * @param var_die
          the variable die
 * @param range
          the range of the block or sub_program that may contain the variable
 * @param name
          the name of the variable
 * @param type_info
          the type info of the variable
 * @return
          0 if success
 */
int TestEvaluator(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, Range range, char *name,
                  const std::shared_ptr<Type> &type_info) {
  std::cout << "in test evaluator\n";
  int res;
  Dwarf_Error err;

  /* a pointer point to the DW_AT_location */
  Dwarf_Attribute location_attr;
  res = dwarf_attr(var_die, DW_AT_location, &location_attr, &err);
  SIMPLE_HANDLE_ERR(res);
  Dwarf_Half loc_form;
  res = dwarf_whatform(location_attr, &loc_form, &err);
  SIMPLE_HANDLE_ERR(res);

  Evaluator evaluator;
  evaluator.dbg_ = dbg;
  /* range use to pass the start pc and end pc of the sub_program which contain the variable */

  Address addr = evaluator.ReadLocation(location_attr, loc_form, range);
  if (addr.valid_ == false) {
    return 1;
  }
  if (name) {
    addr.name_ = std::string(name);
  }
  char *file_name = NULL;
  Dwarf_Unsigned decl_row = -1, decl_col = -1;
  res = TestDeclPos(dbg, cu_die, var_die, &file_name, &decl_row, &decl_col, 0);
  if (file_name) addr.decl_file_ = std::string(file_name);
  addr.decl_row_ = decl_row;
  addr.decl_col_ = decl_col;
  addr.type_info_ = type_info;
  Dwarf_Half tag;
  dwarf_tag(var_die, &tag, &err);
  if (useJson) {
    json addrJson = createJsonforAddress(addr);
    std::string jsonStr = addrJson.dump(4);
    addrJson.clear();
    if (likely(!isFirstJson)) {
      jsonOut << ",\n";
    } else {
      isFirstJson = false;
    }
    jsonOut << jsonStr;
    jsonOut.flush();

    /* for every member of the struct, output the a addr json( if has ) */
    if (type_info && type_info->IsUserDefined()) {
      OutputJsonForMembers(addr, addr.type_info_);
    }
  } else {
    addr.Output();
  }
  dwarf_dealloc_attribute(location_attr);
  return 0;
}

/**
 * @brief
         given a addr which type info is user defined, create a member
         addr for its every members, and because of members can be also
         user defined, it that case, need to recursively handle
         eg: a->b->c ...
 * @param addr
          the struct's address object
 * @param type_info
          the struct's type info
 */
void OutputJsonForMembers(const Address &addr, const std::shared_ptr<Type> &type_info) {
  if (type_info == nullptr || !type_info->IsUserDefined()) {
    return;
  }

  // Get members' offsets, names, and types
  const auto &member_offsets = type_info->GetMemberOffsets();
  const auto &member_names = type_info->GetMemberNames();
  const auto &member_types = type_info->GetMemberTypes();

  // Iterate through member offsets
  for (const auto &offset : member_offsets) {
    if (member_names.count(offset) == 0 || member_types.count(offset) == 0) {
      throw std::runtime_error("Invalid offset in struct member information");
    }

    const std::string &member_name = member_names.at(offset);
    const auto &member_type_info = member_types.at(offset);

    // Copy the parent address and update member name
    Address member_addr = addr;

    // If not a pointer, use "." to concatenate the struct and member names
    if (!type_info->IsPointer()) {
      member_addr.name_ = addr.name_ + "." + member_name;
    } else {
      // Handle pointer dereferencing levels with parentheses
      std::string pointer_prefix = addr.name_;
      size_t pointer_level = type_info->GetPointerLevel();
      for (size_t i = 1; i < pointer_level; ++i) {
        pointer_prefix = "*(" + pointer_prefix + ")";
      }
      member_addr.name_ = pointer_prefix + "->" + member_name;
    }

    // Update address expressions by adding the offset
    for (auto &addr_exp : member_addr.addrs_) {
      addr_exp.offset_ += offset;
    }

    // Set the member type info
    member_addr.type_info_ = member_type_info;

    // Output the member's JSON representation
    json memberJson = createJsonforAddress(member_addr);
    std::string memberJsonStr = memberJson.dump(4);
    memberJson.clear();
    jsonOut << ",\n";
    jsonOut << memberJsonStr;
    jsonOut.flush();

    // Recur if the member is also a user-defined struct
    if (member_type_info && member_type_info->IsUserDefined()) {
      OutputJsonForMembers(member_addr, member_type_info);
    }
  }
}

int TestDeclPos(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die var_die, char **decl_file_name, Dwarf_Unsigned *decl_row,
                Dwarf_Unsigned *decl_col, int indent) {
  Dwarf_Error err;
  int res = 0;

  Dwarf_Bool has_decl_file;
  res = dwarf_hasattr(var_die, DW_AT_decl_file, &has_decl_file, &err);
  SIMPLE_HANDLE_ERR(res);
  if (!has_decl_file) {
    Dwarf_Bool has_origin;
    res = dwarf_hasattr(var_die, DW_AT_abstract_origin, &has_origin, &err);
    SIMPLE_HANDLE_ERR(res);
    if (!has_origin) {
      return 1;
    }

    Dwarf_Attribute off_attr;
    // Dwarf_Half off_form;
    res = dwarf_attr(var_die, DW_AT_abstract_origin, &off_attr, &err);
    SIMPLE_HANDLE_ERR(res);

    // res = dwarf_whatform(off_attr, &off_form, &err);
    // SIMPLE_HANDLE_ERR(res)

    Dwarf_Off offset;
    Dwarf_Bool is_info;
    res = dwarf_global_formref_b(off_attr, &offset, &is_info, &err);
    SIMPLE_HANDLE_ERR(res);

    Dwarf_Die origin_die;
    res = dwarf_offdie_b(dbg, offset, is_info, &origin_die, &err);
    // dwarf_dealloc_die(var_die);
    var_die = origin_die;

    dwarf_dealloc_attribute(off_attr);
  }

  // get file name
  Dwarf_Attribute decl_file_attr;
  res = dwarf_attr(var_die, DW_AT_decl_file, &decl_file_attr, &err);
  SIMPLE_HANDLE_ERR(res);

  Dwarf_Unsigned decl_file;
  res = dwarf_formudata(decl_file_attr, &decl_file, &err);
  SIMPLE_HANDLE_ERR(res);

  char **filenames;
  Dwarf_Signed count;
  res = dwarf_srcfiles(cu_die, &filenames, &count, &err);
  SIMPLE_HANDLE_ERR(res);

  (*decl_file_name) = filenames[decl_file - 1];
  // printindent(indent);
  // printf("%lld %llu %s\n", count, decl_file, filenames[decl_file-1]);

  // get decl row and col
  Dwarf_Attribute decl_row_attr, decl_col_attr;
  Dwarf_Bool has_row = true;
  res = dwarf_hasattr(var_die, DW_AT_decl_line, &has_row, &err);
  if (has_row) {
    res = dwarf_attr(var_die, DW_AT_decl_line, &decl_row_attr, &err);
    SIMPLE_HANDLE_ERR(res)

    res = dwarf_formudata(decl_row_attr, decl_row, &err);
    SIMPLE_HANDLE_ERR(res)
  }

  Dwarf_Bool has_col = true;
  res = dwarf_hasattr(var_die, DW_AT_decl_column, &has_col, &err);
  SIMPLE_HANDLE_ERR(res) if (has_col) {
    res = dwarf_attr(var_die, DW_AT_decl_column, &decl_col_attr, &err);
    SIMPLE_HANDLE_ERR(res)

    res = dwarf_formudata(decl_col_attr, decl_col, &err);
    SIMPLE_HANDLE_ERR(res)
  }
  dwarf_dealloc_attribute(decl_file_attr);
  dwarf_dealloc_attribute(decl_row_attr);
  dwarf_dealloc_attribute(decl_row_attr);

  return DW_DLV_OK;
}

int PrintRawLocation(Dwarf_Debug dbg, Dwarf_Attribute loc_attr, Dwarf_Half loc_form, int indent) {
  int ret = 0;
  int res = 0;
  Dwarf_Error err;
  Dwarf_Loc_Head_c loclist_head;
  Dwarf_Unsigned locentry_len;
  if (loc_form != DW_FORM_sec_offset && loc_form != DW_FORM_exprloc && loc_form != DW_FORM_block &&
      loc_form != DW_FORM_data1 && loc_form != DW_FORM_data2 && loc_form != DW_FORM_data4 && loc_form != DW_FORM_data8)
    res = 1;
  else
    res = dwarf_get_loclist_c(loc_attr, &loclist_head, &locentry_len, &err);

  SIMPLE_HANDLE_ERR(res);

  std::string outputString;
  bool isMultiLoc = true;
  int bored_cnt = 0;
  for (Dwarf_Unsigned i = 0; i < locentry_len; i++) {
    Dwarf_Small lkind = 0, lle_value = 0;
    Dwarf_Unsigned rawval1 = 0, rawval2 = 0;
    Dwarf_Bool debug_addr_unavailable = false;
    Dwarf_Addr lopc = 0;
    Dwarf_Addr hipc = 0;
    Dwarf_Unsigned loclist_expr_op_count = 0;
    Dwarf_Locdesc_c locdesc_entry = 0;
    Dwarf_Unsigned expression_offset = 0;
    Dwarf_Unsigned locdesc_offset = 0;

    res = dwarf_get_locdesc_entry_d(loclist_head, i, &lle_value, &rawval1, &rawval2, &debug_addr_unavailable, &lopc,
                                    &hipc, &loclist_expr_op_count, &locdesc_entry, &lkind, &expression_offset,
                                    &locdesc_offset, &err);

    SIMPLE_HANDLE_ERR(res);

    bool isSingleExpr = false;
    bool isEmptyExpr = false;
    bool isImplicit = false;
    bool isReg = false;
    bool hasCFA = false;

    Dwarf_Small op = 0;

    if (loclist_expr_op_count == 1) {
      isSingleExpr = true;
    }
    if (lopc == hipc && loclist_expr_op_count > 0) {
      isEmptyExpr = true;
    }
    outputString += '\n' + addindent(indent) + "--- exp start " + toHex(lopc) + " " + toHex(hipc) + "\n";
    for (Dwarf_Unsigned j = 0; j < loclist_expr_op_count; j++) {
      Dwarf_Unsigned op1, op2, op3, offsetForBranch;

      ret = dwarf_get_location_op_value_c(locdesc_entry, j, &op, &op1, &op2, &op3, &offsetForBranch, &err);
      SIMPLE_HANDLE_ERR(ret);

      // record operator
      statistics.addOp(op);

      const char *op_name;
      res = dwarf_get_OP_name(op, &op_name);

      if (op == DW_OP_entry_value || op == DW_OP_GNU_entry_value) {
        tempEvaluator.dbg_ = dbg;
        tempEvaluator.ParseDwarfBlock((Dwarf_Ptr)op2, op1, dummyrange, true);
      }
      if (op == DW_OP_fbreg) {
        hasCFA = true;
        outputString += "DW_OP_fbreg_range " + toHex(lopc) + " " + toHex(hipc) + "\n";
      }

      if (j == 1 && loclist_expr_op_count == 2 && op == DW_OP_stack_value) {
        isSingleExpr = true;
      }
      if (op == DW_OP_stack_value) {
        isImplicit = true;
      } else if (op >= DW_OP_reg0 && op <= DW_OP_reg31) {
        isReg = true;
      }
      outputString +=
          addindent(indent) + std::string(op_name) + " " + toHex(op1) + " " + toHex(op2) + " " + toHex(op3) + "\n";
    }
    outputString += addindent(indent) + "[" + std::to_string(loclist_expr_op_count) +
                    (isReg ? "r" : (isImplicit ? "i" : "m")) + (hasCFA ? "c" : "") + "]\n";
    statistics.solveOneExpr();

    isMultiLoc = isMultiLoc && (!isSingleExpr);
    if (isSingleExpr || isEmptyExpr) {
      bored_cnt++;
    }
  }
  if (!onlyComplex || isMultiLoc && bored_cnt < locentry_len) {
    std::cout << outputString << "\n";
  }

  dwarf_dealloc_loc_head_c(loclist_head);
  if (loc_form == DW_FORM_sec_offset) {
  } else if (loc_form == DW_FORM_exprloc) {
  }

  return ret;
}

/**
 * @brief
         pre-order traverse the DIE tree to get the variable information
 * @param cu_die
          the compilation unit die
 * @param dbg
          the dwarf debug info
 * @param fa_die
          the current accessing die
 * @param range
          the range of the block or sub_program that may contain the variable
 * @param is_info
          whether the die is in the .debug_info section
 * @param indent
          the indent of the output , used to format the output
 */
void WalkDieTree(Dwarf_Die cu_die, Dwarf_Debug dbg, Dwarf_Die fa_die, Range range, bool is_info, int indent) {
  Dwarf_Error err;
  Range fa_range(range);
  do {
    const char *tag_name;
    Dwarf_Half tag;
    Dwarf_Die child_die;
    bool modifyRange = false;
    int res = 0;
    /*
    Get TAG value of DIE. DW_TAG_* in debug info
    Every DIE has a tag
    */
    res = dwarf_tag(fa_die, &tag, &err);
    if (res == DW_DLV_OK) {
      res = dwarf_get_TAG_name(tag, &tag_name);
      if (res == DW_DLV_OK) {
        // print indent ge "/t"
        printindent(indent);
        printf("tag_name is : %s;", tag_name);
      }

      if (tag == DW_TAG_lexical_block || tag == DW_TAG_subprogram) {
        // set start_pc and end_pc
        range.setFromDie(fa_die);
        modifyRange = true;
      }

      /* if has DW_TAG_structure_type, parse it , will save in the Type's static member struct_infos_ */
      if (tag == DW_TAG_structure_type) {
        Type::ParseStructType(dbg, fa_die);
      }

      /* if has DW_TAG_frame_base, update the global frame base */
      updateFrameBase(fa_die, range);

      /* variable and formal parameter */
      if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter) {
        Dwarf_Bool hasLoc = false;
        char *var_name = nullptr;
        res = get_name(dbg, fa_die, &var_name);

        if (res == DW_DLV_OK) {
          printf(" name: %s;", var_name);
        }
        auto type_info = Type::ParseTypeDie(dbg, fa_die);
        if (type_info != nullptr) {
          printf("type: %s;", type_info->GetTypeName().c_str());
        }

        // DW_AT_LOCATION
        res = dwarf_hasattr(fa_die, DW_AT_location, &hasLoc, &err);

        if (res == DW_DLV_OK && hasLoc) {
          Dwarf_Attribute location_attr;
          dwarf_attr(fa_die, DW_AT_location, &location_attr, &err);
          Dwarf_Half form;
          dwarf_whatform(location_attr, &form, &err);
          const char *form_name;
          res = dwarf_get_FORM_name(form, &form_name);
          if (res == DW_DLV_OK) {
            printf(" loc form : %s\n", form_name);
            // fprintf(stderr, "%s\n", form_name);
          }

          statistics.addVar(tag);
          if (printRawLoc) {
            PrintRawLocation(dbg, location_attr, form, indent + 1);
          } else {
            TestEvaluator(dbg, cu_die, fa_die, range, var_name, type_info);
          }
          dwarf_dealloc_attribute(location_attr);
        } else {
          // fprintf(stderr, "%s no location\n", var_name);
          varNoLocation += 1;
        }
      }
      printf("\n");
    }
    // get child DIE
    if (dwarf_child(fa_die, &child_die, &err) == DW_DLV_OK) {
      std::cout << "has child\n";
      WalkDieTree(cu_die, dbg, child_die, range, is_info, indent + 1);
      dwarf_dealloc_die(child_die);
    }
    if (modifyRange) {
      range.setFromRange(fa_range);
    }
    // std::cout<<"has no child, go to next die"<<"\n" ;
    // get the next DIE
  } while (dwarf_siblingof_b(dbg, fa_die, is_info, &fa_die, &err) == DW_DLV_OK);
}

}  // namespace varviewer

int main(int argc, char *argv[]) {
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

    printf("cu_header_length:%llu\nnext_cu_header:%llu\n", cu_header_length, next_cu_header);

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
