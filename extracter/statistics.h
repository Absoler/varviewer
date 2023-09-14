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
    int implicitCnt;
    int implicitMultiCnt;


    std::vector<Dwarf_Small> ops;

    public:
    Statistics();
    void addOp(Dwarf_Small op);
    void solveOneExpr();
    void addVar();
    void reset();

    std::string output();
};