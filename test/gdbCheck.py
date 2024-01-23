import gdb
import json
import sys, os
sys.path.append(".")
from util import DetailedDwarfType

# Sample JSON data (replace this with your actual JSON data)

exit = False

def exitHandler(event):
    global exit
    print("set exit")
    exit = True

# Define the GDB command
class CheckVariablesCommand(gdb.Command):
    def __init__(self):
        super(CheckVariablesCommand, self).__init__("check_variables", gdb.COMMAND_USER)


    def load(self, json_path:str):
        # used to calculate the load offset
        ref_func = "main"
        exe_path = gdb.current_progspace().filename
        ref_static_addr = int(os.popen("readelf -s {} | grep {} | awk '{{print $2}}'".format(exe_path, ref_func)).read().strip(), base=16)
        gdb.execute("start")
        ref_runtime_addr = int(gdb.parse_and_eval("&" + ref_func))
        load_offset = ref_runtime_addr - ref_static_addr
        print("offset {:X}".format(load_offset))

        json_file = open(json_path, "r")
        json_list:list[dict] = json.load(json_file)
        json_file.close()

        # use mapped instruction addresss to index variable info
        self.json_map:dict[int, list[dict]] = {}
        self.addrs:list[int] = []
        self.sum = 0
        for var in json_list:
            if var["expression"] == "":
                continue
            addr:int = var["addr"] + load_offset
            if addr not in self.json_map:
                self.json_map[addr] = []
            self.json_map[addr].append(var)
            self.addrs.append(addr)
            self.sum += 1

        self.addrs = list(set(self.addrs))
        self.addrs.sort()
        
        print("load done!")


    def invoke(self, args, from_tty):
        ''' args[0]: match information json file path
            args[1]: output testing result file path
        '''
        global exit
        args = gdb.string_to_argv(args)
        self.load(args[0])
        self.output_file = open(args[1], "w")

        gdb.events.exited.connect(exitHandler)
        correct_cnt:int = 0
        wrong_cnt:int = 0
        hit_cnt:int = 0
        fail_oracle_cnt:int = 0
        outputJson = {}
        breakpointNum = 1
        breakpointMap = {}
        for t in DetailedDwarfType:
            outputJson[t.name] = [0, 0]

        outputContent:str = ""

        def get_pc():
            return int(gdb.parse_and_eval("$pc"))

        def get_value_by_name(name:str):
            return int(gdb.parse_and_eval(name))
        
        def get_type_str(var:dict):
            type_str = str(gdb.lookup_symbol(var["name"])[0].type)
            if var["indirect"] == -1:
                type_str = type_str+" *"
            return type_str

        def get_candidate_values(var:dict, type_str:str) -> set:
            if var["uncertain"] == "false":
                return {gdb.parse_and_eval(expression)}
            candidate_names = [s for s in expression.split("@") if s != ""]
            candidate_values = []
            for name in candidate_names:
                if "xmm" in name:
                    print(f"{name}.v2_int64[0]")
                    candidate_values.append(int(gdb.parse_and_eval(f"({type_str})({name}.v2_int64[0])")))
                
                else:
                    candidate_values.append(int(gdb.parse_and_eval(f"({type_str})({name})")))

            return set(candidate_values)

        # break at all match positions
        for addr in self.addrs:
            gdb.execute(f"b *{addr}")
            breakpointMap[addr] = breakpointNum
            print(f"{addr} : {breakpointNum}")
            breakpointNum += 1

        gdb.execute("c")

        # record last variable and oracle if its `matchPos` is `src_value`
        snapshot = []
        
        while True:
            if len(snapshot) > 0:
                gdb.execute("si")
                for var, oracle, type_str in snapshot:
                    ours:set[int] = get_candidate_values(var, type_str)
                    detailedDwarfType:DetailedDwarfType = DetailedDwarfType(var["detailedDwarfType"])
                    outputJson[detailedDwarfType.name][1] += 1
                    if oracle in ours:
                        outputJson[detailedDwarfType.name][0] += 1
                        correct_cnt += 1
                        print(f"### correct at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n")
                    else:
                        wrong_cnt += 1
                        outputContent += f"    wrong at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n"
                        print(f"### wrong at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n")

            pc = get_pc()
            
            if not (len(snapshot) > 0 and pc in self.addrs):
                gdb.execute("c")
            
            if exit:
                print("use exit")
                break

            hit_cnt += 1
            snapshot:list[tuple] = []
            addr = get_pc()
            print(addr in breakpointMap)
            gdb.execute(f"d {breakpointMap[addr]}")

            if len(self.json_map[addr]) == 0:
                print(f"{addr:X} has no vars")
            for var in self.json_map[addr]:
                name:str = var["name"] if var["indirect"] == 0 else "&" + var["name"]
                matchPos:int = var["matchPos"]
                expression:str = var["expression"]
                print(f"matching {name} {expression} ...")

                try:
                    oracle:int = get_value_by_name(name)
                except Exception:
                    fail_oracle_cnt += 1
                    print(f"\n### fail get oracle of {name} at 0x{var['addr']:X}")
                    continue

                type_str = get_type_str(var)
                if matchPos == 1:
                    # `src_value`, check at next instrucion
                    snapshot.append((var, oracle, type_str))

                else:
                    # our:int = int(gdb.parse_and_eval(expression))
                    ours:set[int] = get_candidate_values(var, type_str)
                    detailedDwarfType:DetailedDwarfType = DetailedDwarfType(var["detailedDwarfType"])
                    outputJson[detailedDwarfType.name][1] += 1
                    if oracle in ours:
                        outputJson[detailedDwarfType.name][0] += 1
                        correct_cnt += 1
                        print(f"### correct at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n")
                    else:
                        wrong_cnt += 1
                        outputContent += f"    wrong at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n"
                        print(f"### wrong at {var['addr']:X} of {var['name']} our:{ours} oracle:{oracle}\n")

            # if hit_cnt > len(self.addrs):
            #     ''' in case the last one is `src_value`, need delayed processing
            #         so don't break when hit_cnt == len(self.addrs)
            #     '''
            #     break

        # outputContent = f"{args[0]} correct {correct_cnt} / {correct_cnt+wrong_cnt}\n" + outputContent
        print(json.dumps(outputJson, indent=4), file=self.output_file)
        self.output_file.close()
        print(f"{args[0]} after record")
            

        

# Register the GDB command
CheckVariablesCommand()