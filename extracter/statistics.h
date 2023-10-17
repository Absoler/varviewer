#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <vector>
#include <string>

enum VariableType {
    INVALID = -1,
    MEM_GLOABL = 0,
    MEM_CFA = 1,
    MEM_SINGLE = 2,
    MEM_MULTI = 3,

    REG_PARAM = 4,
    REG_OTHER = 5,

    IMPLICIT = 6
};

class Statistics{
    int varCnt;
    int exprCnt;

    int memoryCnt;
    int globalCnt;
    int cfaCnt;
    int memoryMultiCnt;
    int registerCnt;
    int paramRegCnt;
    int implicitCnt;
    int implicitMultiCnt;

    bool isParam;
    std::vector<Dwarf_Small> ops;

    public:
    Statistics();
    void addOp(Dwarf_Small op);
    VariableType solveOneExpr();
    void addVar(Dwarf_Half tag);
    void reset();

    std::string output();
};