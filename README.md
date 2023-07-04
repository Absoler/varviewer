## dependency

### libdwarf
need install `libdwarf`, can download from https://github.com/davea42/libdwarf-code/releases

### angr
`pip install angr, z3-solver`

## usage

### extract debug info

1. go into extracter/ and `make extracter`
2. execute `./extracter <binary-to-extract> -o <json-file>`, there are also some debug option(s)
   1. `-r` for print raw dwarf expression, `-nc` for only print complex expressions, `-fde` for print CFA info, and `--no-traverse` for avoidance of fully traversing, and quickly print other info

### analysis

1. `rewrite.py` rewrite a piece from large binary into a seperate binary file. `./rewrite.py <large-binary> <startpc> <endpc>`
2. `variable.py` deal with debuginfo from json 
3. `dwarf_iced_map.py`, `dwarf_vex_map.py` mapping between different framework