#pragma once

#include "Expression.h"
#include "jsonUtil.h"
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <map>
#include <string>
#include <vector>

enum AddrType{
    MEMORY,
    REGISTER,
    VALUE
};

// <piece_start, piece_size>
typedef std::pair<Dwarf_Addr, int> piece_type;


class AddressExp : public Expression{
    public:
    AddressExp() = default;
    AddressExp(AddrType _type);
    
    /*
        in dwarf standard, pieces belong to the same location expression,
        however I take each piece into an addrExp seperately, because each
        piece may have different `type`.
    */
    piece_type piece;
    AddrType type = MEMORY; // if type == MEMORY or type == CONSTANT, use Expression of the father
    Dwarf_Half reg = REG_END; // valid if type == REGISTER
    Dwarf_Addr startpc, endpc;  // endpc not include in range

    bool needCFA = false;
    // only valid when `DW_OP_fbreg` used, record cfa values between [startpc, endpc)
    std::vector<AddressExp> cfa_values;
    std::vector<Dwarf_Addr> cfa_pcs;

    // no reset startpc and endpc now
    void resetData();   
    void output();
    std::string toString();
    friend json createJsonforAddressExp(const AddressExp &addrexp);
};

/*
    `Address` record address info of some lifetimes of a variable
*/
class Address{

    public:
    Address() = default;
    Address(AddrType _type);

    bool valid = false;
    std::string name;
    std::vector<AddressExp> addrs;
    std::string decl_file;
    Dwarf_Unsigned decl_row, decl_col;

    
    void output();
    void update_valid();
    friend json createJsonforAddress(const Address &addr);
};
