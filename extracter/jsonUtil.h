#pragma once

#include "Expression.h"
#include "Address.h"
class Address;
class AddressExp;


/*
    {
        "addrs" : [
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

json createJsonforAddress(const Address& addr);


/*
    {
        Expression part ...

        "type" : <int>
        "startpc" : <Dwarf_Addr>
        "endpc" : <Dwarf_Addr>
        "reg" : <Dwarf_Half>
        "piece_start" : <Dwarf_Addr>,
        "piece_size" : <int>
    }
*/
json createJsonforAddressExp(const AddressExp& addrexp);

/*
    {
        Expression part ...

        "type" : <int>
        "startpc" : <Dwarf_Addr>
        "endpc" : <Dwarf_Addr>
        "reg" : <Dwarf_Half>
        "piece_start" : <Dwarf_Addr>,
        "piece_size" : <int>
        
        "needCFA" : <bool>
        "cfa_values" : [
            <AddrExp>
        ]
        "cfa_pcs" : [
            <Dwarf_Addr>
        ]
    }
*/
json createJsonforExpression(const Expression& exp);