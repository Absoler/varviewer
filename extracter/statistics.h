#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <vector>
#include <string>


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
    void solveOneExpr();
    void addVar(Dwarf_Half tag);
    void reset();

    std::string output();
};