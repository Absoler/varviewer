#pragma once

#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <memory>
#include <string>

#include "json.hpp"
using json = nlohmann::json;

#define REG_END 128
extern const char *reg_names[REG_END] ;

/*
    Expression is a symbolic simulation of dynamic calculation of Dwarf expression
*/
class Expression{
    public:
    bool valid = true;  // error when generating this
    bool empty = false; // optimized away by compiler
    bool sign = false;  // indicate whether signed

    Expression();
    ~Expression() = default;
    Expression(Dwarf_Unsigned val_u);
    Expression(Dwarf_Signed val_s);
    static Expression createEmpty();
    static Expression createCFA();
    
    bool equal(const Expression& other);
    static bool valid_bin_op(const Expression& exp1, const Expression& exp2, Dwarf_Small op);
    static Expression bin_op(const Expression& exp1, const Expression& exp2, Dwarf_Small op);
    static bool valid_unary_op(const Expression& exp, Dwarf_Small op);
    static Expression unary_op(const Expression& exp, Dwarf_Small op);


    /*
        the value of `Expression` is val + reg0 * reg_scale[0] + reg1 * reg_scale[1] ... + *(mem) 
    */
    Dwarf_Signed reg_scale[REG_END];
    Dwarf_Unsigned offset;
    std::shared_ptr<Expression> mem;
    Dwarf_Small mem_offset = 0;
    
    /*
        if true, then this expression is the currenet cfa value
    */
    bool isCFA = false;


    /*
        operation can't express inside one expression will expand a single expression node to a binary tree
    */
    std::shared_ptr<Expression> sub1 = NULL, sub2 = NULL;
    Dwarf_Small op;
    bool hasChild = false;
    
    bool no_reg() const;
    friend json createJsonforExpression(const Expression &exp);
    
    void reset();   // clear data
    void output();
    void setExpFrom(const Expression &);    // deep copy from another expression
    std::string toString();
};