#include "jsonUtil.h"
#include "Address.h"
#include <libdwarf-0/libdwarf.h>
#include <map>
#include <string>
#include <vector>

json createJsonforExpression(const Expression &exp){
    /*
        {
            "offset" : <Dwarf_Unsigned>
            "regs" : {
                <int>(reg_ind) : <int>(scale),
            }
            "mem" : <Expression>
            "valid" : <bool>
            "empty" : <bool>

            "hasChild" : <bool>
            "sub1" : <Expression>
            "sub2" : <Expression>
        }
    */
    json res;
    res["offset"] = (exp.sign ? (Dwarf_Signed)exp.offset : exp.offset);
    

    json reg_dict;
    for(int i=0; i<REG_END; ++i){
        if(exp.reg_scale[i]){
            reg_dict[std::to_string(i)] = exp.reg_scale[i];
            // reg_dict[i] = exp.reg_scale[i];
        }
    }
    res["regs"] = reg_dict;
    res["valid"] = exp.valid;
    res["empty"] = exp.empty;
    if(exp.mem){
        res["mem"] = createJsonforExpression(*exp.mem);
    }
    res["sign"] = exp.sign;
    
    res["hasChild"] = exp.hasChild;
    if(exp.hasChild){
        res["op"] = exp.op;
        if(exp.sub1){
            res["sub1"] = createJsonforExpression(*exp.sub1);
        }
        if(exp.sub2){
            res["sub2"] = createJsonforExpression(*exp.sub2);
        }
    }

    return res;
}

json createJsonforAddressExp(const AddressExp &addrexp){
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
    json res = createJsonforExpression(addrexp);
    res["type"] = addrexp.type;
    res["startpc"] = addrexp.startpc;
    res["endpc"] = addrexp.endpc;
    res["reg"] = addrexp.reg;
    res["piece_start"] = addrexp.piece.first;
    res["piece_size"] = addrexp.piece.second;
    
    res["needCFA"] = addrexp.needCFA;
    if(addrexp.needCFA){
        res["cfa_values"] = std::vector<json>();
        for(auto cfa_value:addrexp.cfa_values){
            res["cfa_values"].push_back(createJsonforAddressExp(cfa_value));
        }
        res["cfa_pcs"] = addrexp.cfa_pcs;
    }

    return res;
}

json createJsonforAddress(const Address &addr){
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
    json res;
    for(AddressExp addrExp:addr.addrs){
        res["addrExps"].push_back(createJsonforAddressExp(addrExp));
    }
    res["name"] = addr.name;
    res["decl_file"] = addr.decl_file;
    res["decl_row"] = addr.decl_row;
    res["decl_col"] = addr.decl_col;
    res["valid"] = addr.valid;

    return res;
}