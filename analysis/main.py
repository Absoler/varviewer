#!/usr/local/bin/python3

from rewrite import *
from variable import *
from libanalysis import *
import shutil
import time
import argparse
from filter import Filter



piece_limit = 1000000

def main():
    beginTime:int = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("binPath")
    parser.add_argument("jsonPath")
    parser.add_argument("-uC","--useCache", action='store_true', help="use piece file(s) in the /tmp/varviewer")
    parser.add_argument("-uO","--useOffset", action="store_true", help="support match with constant offset, need more time")
    parser.add_argument("-s", "--start", type=int, help="specify start piece number", default=0)
    parser.add_argument("-e", "--end", type=int, help="specify end piece number", default=piece_limit)
    parser.add_argument("-oG", "--onlyGen", action="store_true", help="only generate piece(s) without analysis")
    parser.add_argument("-sT", "--showTime", action="store_true", help="show time statistics")
    parser.add_argument("-o", "--output", help="specify the output json file", default="")
    parser.add_argument("-tP", "--tempPath", help="specify the tmp path", default="/tmp/varviewer")
    parser.add_argument("-dV", "--dumpVex", action="store_true", help="dump vex ir statements for debugging")
    parser.add_argument("-tG", "--testGlobal", action="store_true", help="")
    parser.add_argument("-fP", "--filterPrefix", help="only match variables defined in given path", default="")
    parser.add_argument("-fA", "--filterAddressPath", help="specify a file containing cared code range", default="")
    args = parser.parse_args()

    mgr = VarMgr()

    binPath = args.binPath
    jsonPath = args.jsonPath

    # build filter
    checkFilter = Filter(args.filterPrefix, args.filterAddressPath)
    
    # prepare disassembly
    with open (binPath, "rb") as binFile:
        elf = ELFFile(binFile)
        text = elf.get_section_by_name(".text")
        code_addr = text['sh_addr']
        code = text.data()
        if len(code) == 0:
            code = text.stream.read()
            print("text.data() failed", file=sys.stderr)

        decoder = Decoder(64, code, ip=code_addr)
        all_insts:list[Instruction] = []
        for ins in decoder:
            all_insts.append(ins)
    
    file_name:string = os.path.basename(binPath)

    # prepare dwarf info
    mgr.load(jsonPath)

    # prepare pieces
    tempPath = args.tempPath
    useCache = args.useCache
    ''' 
    if set `useCache`, means we have run this already
    '''
    if not useCache:
        if not os.path.exists(tempPath):
            # shutil.rmtree(tempPath)
            os.mkdir(tempPath)

    print(f"preparations time: {time.time() - beginTime}s")
    
    
    # start analysis
    # all result will be stored in all_reses
    all_reses:list[Result] = []
    showTime:bool = args.showTime
    
    ''' 
    number of processed addrExps
    '''
    count, matchCount = 0, 0
    print("mgr local ind", mgr.local_ind)
    length = len(mgr.vars)
    for piece_num in range(mgr.local_ind, length):
        print (f"piece num {piece_num},total length {length}")
        startTime = time.time()
        if piece_num > piece_limit + mgr.local_ind:
            break
        if piece_num < args.start:
            continue
        if piece_num >= args.end:
            break

        piece_name = tempPath + '/piece_' + file_name + str(piece_num)
        addrExp = mgr.vars[piece_num]

        ''' 
        filter imme out
        '''
        if  addrExp.empty:
            continue

        ''' 
        filter uncare addrExp out
        '''
        if not checkFilter.valid(addrExp):
            print("not valid")
            continue
        
        # according to the startpc and endpc, we can find the corresponding piece, and build to assembly code
        startpc, endpc = addrExp.startpc, addrExp.endpc
        if not useCache or not os.path.exists(piece_name):     
            l, r = find_l_ind(all_insts, startpc), find_l_ind(all_insts, endpc)
            if l==r:
                continue
            piece_asm, piece_addrs = construct(all_insts[l:r], startpc, endpc)
            with open(piece_name + ".S", "w") as piece_file:
                # save asm code
                piece_file.write(piece_asm)
            with open(piece_name + ".addr", "w") as piece_addr_file:
                # save addrs
                piece_addr_file.write(' '.join(map(str, piece_addrs)))
            ret = os.system(f"as {piece_name}.S -o {piece_name}.o && ld {piece_name}.o -Ttext 0 -o {piece_name}")
            if ret != 0:
                continue
        
        count += 1
        print(f"piece num {piece_num}")

        if args.onlyGen:
            continue
        
        ''' 
        piece generated, start analysis
        '''
        piece_file = open(piece_name, "rb")
        with open (piece_name + ".addr", "r") as piece_addr_file:
            # read addrs and store in piece_addrs list
            piece_addrs:list[int] = list(map(int, piece_addr_file.read().split(' ')))

        
        if showTime:
            print(f"-- open piece {time.time()-startTime}")
            startTime = time.time()

        # solver.add(*dwarf_hint.conds)

        if showTime:
            print(f"-- summary dwarf {time.time()-startTime}")
            startTime = time.time()
        
        # angr analysis and cfg
        proj = angr.Project(piece_file, load_options={'auto_load_libs' : False})
        cfg:angr.analyses.cfg.cfg_fast.CFGFast = proj.analyses.CFGFast()
        analysis = Analysis(proj, cfg)
        analysis.analyzeCFG()
        print("\033[31mcfg analysis done\033[0m")
        
        if args.dumpVex:
            analysis.dumpVex(piece_name + ".vex")

        if showTime:
            print(f"-- analysis {time.time()-startTime}")
            startTime = time.time()

        ''' try match
        '''
        try:
            reses:list[Result] = analysis.match(addrExp, DwarfType(addrExp.dwarfType), piece_addrs, args.useOffset, showTime)
        except Exception as e:
            print(f"exception {e} in matching")

        if showTime:
            print(f"-- summary vex and match {time.time()-startTime}")
            startTime = time.time()
        
        if len(reses) > 0:
            matchCount += 1
        print(f"len reses {len(reses)}")
        for res in reses:
            try:
                res.piece_num = piece_num
                success = res.construct_expression(all_insts[find_l_ind(all_insts, res.addr)])
                print(f"construct expression {res.expression}")
                if success:
                    all_reses.append(res)
            except Exception as e:
                print(f"meet exception {e}")

        piece_file.close()
        piece_addr_file.close()
        analysis.clear()
        # Delete the generated files after processing the piece
        if os.path.exists(piece_name):
            os.remove(piece_name)  # Delete the binary piece file
        if os.path.exists(piece_name + ".S"):
            os.remove(piece_name + ".S")  # Delete the assembly file
        if os.path.exists(piece_name + ".addr"):
            os.remove(piece_name + ".addr")  # Delete the addresses file
        if os.path.exists(piece_name + ".o"):
            os.remove(piece_name + ".o")  # Delete the object file
        # if os.path.exists(piece_name + ".vex"):
            # os.remove(piece_name + ".vex")
            
    
    ''' output result
    '''
    print(f"match {matchCount} / {count} variable debug info entry")
    if args.output == "":
        for res in all_reses:
            print(res)
    else:
        res_file = open(args.output, "w")
        json.dump(list(map(dict, all_reses)), res_file, indent=4)
        res_file.close()

if __name__ == "__main__":
    main()
   
