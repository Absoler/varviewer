import gdb
import json
import sys

# Sample JSON data (replace this with your actual JSON data)



# Define the GDB command
class CheckVariablesCommand(gdb.Command):
    def __init__(self):
        super(CheckVariablesCommand, self).__init__("check_variables", gdb.COMMAND_USER)
        
    
    def load(self, json_path:str):
        json_file = open(json_path, "r")
        json_list:list[dict] = json.load(json_file)
        self.json_map:dict[int, list[dict]] = {}
        self.addrs:list[int] = []
        self.sum = 0
        for var in json_list:
            if var["expression"] == "":
                continue
            addr:int = var["addr"]
            if addr not in self.json_map:
                self.json_map[addr] = []
            self.json_map[addr].append(var)
            self.addrs.append(addr)
            self.sum += 1

        self.addrs = list(set(self.addrs))
        self.addrs.sort()
        print("load done!")

        

    def invoke(self, args, from_tty):
        args = gdb.string_to_argv(args)
        self.load(args[0])

        correct_cnt:int = 0
        hit_cnt:int = 0
        fail_oracle_cnt:int = 0

        def get_pc_addr():
            return int(gdb.parse_and_eval("$pc"))

        def get_var_addr_by_name(name:str):
            return int(gdb.parse_and_eval(f"&{name}"))
        
        def get_var_value_by_name(name:str):
            return int(gdb.parse_and_eval(name))

        for addr in self.addrs:
            gdb.execute(f"b *{addr}")

        gdb.execute("start")

        records = []
        
        while True:
            if len(records) > 0:
                gdb.execute("si")
                for var, oracle in records:
                    print(var["expression"])
                    our:int = int(gdb.parse_and_eval(var["expression"]))
                    if oracle == our:
                        correct_cnt += 1
                        print(f"### correct at {var['addr']:X} our:{our} oracle:{oracle}")
                    else:
                        print(f"### wrong at {var['addr']:X} our:{our} oracle:{oracle}")

            if not (len(records) > 0 and get_pc_addr() in self.addrs):
                gdb.execute("c")
            
            hit_cnt += 1
            records:list[dict] = []
            addr = get_pc_addr()

            for var in self.json_map[addr]:
                name:str = var["name"]
                matchPos:int = var["matchPos"]
                expression:str = var["expression"]
                print(expression)

                try:
                    oracle:int = get_var_value_by_name(name) if var["indirect"] == 0 else get_var_addr_by_name(name)
                except Exception:
                    fail_oracle_cnt += 1
                    print(f"### fail get oracle of {name} at 0x{var['addr']:X}")
                    continue

                if matchPos == 1:
                    
                    records.append((var, oracle))

                else:
                    
                    our:int = int(gdb.parse_and_eval(expression))
                    if our == oracle:
                        correct_cnt += 1
                        print(f"### correct at {var['addr']:X} our:{our} oracle:{oracle}")
                    else:
                        print(f"### wrong at {var['addr']:X} our:{our} oracle:{oracle}")

            if hit_cnt == len(self.addrs):
                break

        print(f"correct {correct_cnt} / {self.sum-fail_oracle_cnt}")
            

        



       
# Register the GDB command
CheckVariablesCommand()