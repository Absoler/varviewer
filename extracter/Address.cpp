#include "Address.h"
#include "Expression.h"
#include <cstdio>
#include <libdwarf-0/libdwarf.h>
#include <string>
using namespace std;

AddressExp::AddressExp(DwarfType _type){
    dwarfType = _type;
}

void AddressExp::resetData(){
    Expression::reset();
    dwarfType = MEMORY;
    reg = REG_END;

    needCFA = false;
    cfa_pcs.clear();
    cfa_values.clear();
}


void AddressExp::output(){
    printf("%llx %llx\n", startpc, endpc);
    printf("%u\n", dwarfType);
    if(dwarfType==MEMORY){
        Expression::output();
    }else if(dwarfType==REGISTER){

        printf("%s\n", reg_names[reg]);
    }else{
        Expression::output();
    }
}

string AddressExp::toString(){
    string res;
    if(dwarfType==MEMORY){
        res = "*(" + Expression::toString() + ")";
    }else if(dwarfType == REGISTER){
        res = string(reg_names[reg]);
    }else{
        res = Expression::toString();
    }
    return res;
}

void Address::output(){
    printf("\n");
    printf("address %s\n", name.c_str());
    for(AddressExp addr: addrs){
        addr.output();
    }
}

void Address::update_valid(){
    valid = true;
    for (vector<AddressExp>::iterator it = addrs.begin(); it != addrs.end(); ) {
        if (it->valid) {
            it ++;
        } else {
            it = addrs.erase(it);
        }
    }
    valid = (addrs.size() != 0);
}