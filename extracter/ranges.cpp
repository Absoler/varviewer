#include "ranges.h"
#include "util.h"
#include <cstdio>
#include <libdwarf-0/libdwarf.h>

/*
    Any debugging information entry describing an entity that has a machine code
    address or range of machine code addresses, which includes compilation units,
    module initialization, subroutines, lexical blocks, try/catch blocks
*/
const Range dummyrange = Range::createEmpty();

int parse_simple_ranges(Dwarf_Die die, Dwarf_Addr *startpc, Dwarf_Addr *endpc){
    /*
        only process `DW_AT_low_pc` and `DW_AT_high_pc`
    */

    int res;
    Dwarf_Error err;
    Dwarf_Bool has_low, has_high;
    Dwarf_Attribute low_pc, high_pc;
    Dwarf_Half low_form, high_form;

    res = dwarf_hasattr(die, DW_AT_low_pc, &has_low, &err);
    if (res!=DW_DLV_OK || has_low == false){
        return 1;
    }
    res = dwarf_hasattr(die, DW_AT_high_pc, &has_high, &err);


    // low pc
    res = dwarf_attr(die, DW_AT_low_pc, &low_pc, &err);
    if (res!=DW_DLV_OK){
        return res;
    }
    res = dwarf_whatform(low_pc, &low_form, &err);
    if (low_form == DW_FORM_addr){
        // set `startpc`
        res = dwarf_formaddr(low_pc, startpc, &err);
    }
    else{
        const char *form_name;
        res = dwarf_get_FORM_name(low_form, &form_name);
        printf("low pc has %s", form_name);
    }


    // high pc
    if(!has_high){
        return 0;
    }
    res = dwarf_attr(die, DW_AT_high_pc, &high_pc, &err);
    if(res!=DW_DLV_OK){
        return res;
    }    
    res = dwarf_whatform(high_pc, &high_form, &err);
    /*
        if of class address, it's the endpc
        if of class constant , it's the offset
    */
    
    Dwarf_Half version, offset_size;
    dwarf_get_version_of_die(die, &version, &offset_size);

    Dwarf_Form_Class high_form_class = dwarf_get_form_class(version, DW_AT_high_pc, offset_size, high_form);
    if(high_form_class == DW_FORM_CLASS_CONSTANT){
        Dwarf_Unsigned offset = get_const_u(high_form, high_pc, &err);
        *endpc = *startpc + offset;
    }else if(high_form_class == DW_FORM_CLASS_ADDRESS){
        if(high_form==DW_FORM_addr){
            res = dwarf_formaddr(high_pc, endpc, &err);
        }
    }

    dwarf_dealloc_attribute(high_pc);
    dwarf_dealloc_attribute(low_pc);
    return res;
}

Range::Range(const Range &range){
    startpc = range.startpc;
    endpc = range.endpc;
}

Range
Range::createEmpty(){
    Range res;
    res.startpc = 0;
    res.endpc = 0;
    return res;
}

Range
Range::createFromDie(Dwarf_Die die){
    Range res = createEmpty();
    int ret = parse_simple_ranges(die, &res.startpc, &res.endpc);
    if(ret){
        res.clear();
    }
    return res;
}

void Range::clear(){
    startpc = 0;
    endpc = 0;
}

void Range::setFromDie(Dwarf_Die die){
    int ret = parse_simple_ranges(die, &startpc, &endpc);
    if(ret){
        startpc = 0;
        endpc = 0;
    }
}

void
Range::setFromRange(const Range &range) {
    startpc = range.startpc;
    endpc = range.endpc;
}