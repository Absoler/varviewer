"""
Play this script with:

gdb a.out -q
(gdb) source varchk.py
(gdb) varchk a.json b.json
"""

import gdb
import json
import sys, os
import re
import time

LEVEL_DEBUG = 2
LEVEL_INFO = 1
LEVEL_QUIET = 0

STAT_UNKOWN = 0
STAT_CORRECT = 0x1
STAT_VAGUE = 0x2
STAT_INDIRECT = 0x4
STAT_CONFLICT = 0x10
STAT_ALIAS = 0x20
STAT_DEAD = 0x40
STAT_BAD = 0x80


# quiet, info, debug
debug_level = LEVEL_DEBUG

# is inferior program exited
exited: bool = False
received_signal: bool = False
hit_breakpoint: bool = False


def debug(msg):
    if debug_level >= LEVEL_DEBUG:
        print("DEBUG\t" + msg)


def info(msg):
    if debug_level >= LEVEL_INFO:
        print("INFO\t" + msg)


def exit_handler(event):
    global exited
    exited = True


def stop_handler(event):
    global received_signal
    global hit_breakpoint

    if isinstance(event, gdb.BreakpointEvent):
        hit_breakpoint = True
    elif isinstance(event, gdb.SignalEvent):
        received_signal = True
    else:
        pass


class Result:
    hit_cnt: int = 0
    correct_cnt: int = 0
    wrong_cnt: int = 0
    partially_correct_cnt: int = 0
    fail_cnt: int = 0

    def __init__(self, var_cnt, curr_time):
        self.var_cnt = var_cnt
        self.elapsed = curr_time

    def _build(self):
        self.elapsed = time.time() - self.elapsed

        if self.var_cnt > 0:
            self.coverage = self.hit_cnt / self.var_cnt
        else:
            self.coverage = 0

        if self.hit_cnt > 0:
            self.correct_rate = self.correct_cnt / self.hit_cnt
            self.partially_correct_rate = self.partially_correct_cnt / self.hit_cnt
            self.wrong_rate = self.wrong_cnt / self.hit_cnt
            self.fail_rate = self.fail_cnt / self.hit_cnt
        else:
            self.correct_rate = 0
            self.partially_correct_rate = 0
            self.wrong_rate = 0
            self.fail_rate = 0

    def to_json(self) -> str:
        self._build()
        return json.dumps(self.__dict__, indent=4)

    def to_log(self) -> str:
        self._build()
        return (
            "\n" + "*" * 30 + "\n"
            f"  total: {self.var_cnt}\n"
            f"  hit count: {self.hit_cnt}\n"
            f"  var coverage: {(self.coverage) * 100:.2f}%\n"
            f"  correct rate: {(self.correct_rate) * 100:.2f}%\n"
            f"  partially correct rate: {(self.partially_correct_rate) * 100:.2f}%\n"
            f"  wrong rate: {(self.wrong_rate) * 100:.2f}%\n"
            f"  failure rate: {(self.fail_rate) * 100:.2f}%"
            "\n" + "*" * 30 + "\n"
            f"\ntotal time elapsed: {self.elapsed}\n"
        )


# Define the GDB command
class CheckVariablesCommand(gdb.Command):

    def __init__(self):
        super(CheckVariablesCommand, self).__init__("varchk", gdb.COMMAND_USER)

    def init(self, input_json: str, output_json: str = None):
        """
        input_json: var info provided by SRE framework
        output_json: statistics, if None, output to STDOUT
        """

        self.json_map: dict[int, list[int]] = {}
        self.var_cnt: int = 0
        self.addrs: list[int] = []
        self.bp_map: dict[int, gdb.Breakpoint] = {}

        # calculate the load offset
        ref_func = "main"
        exe_path = gdb.current_progspace().filename
        ref_static_addr = int(
            os.popen(
                "readelf -s {} | grep ' {}$' | awk '{{print $2}}' | head -1".format(
                    exe_path, ref_func
                )
            )
            .read()
            .strip(),
            base=16,
        )

        gdb.execute("start")
        ref_runtime_addr = int(gdb.parse_and_eval("&" + ref_func))
        load_offset = ref_runtime_addr - ref_static_addr

        # get json input
        with open(input_json, "r") as json_file:
            json_list: list[dict] = json.load(json_file)

        # map address to variable
        for var in json_list:
            addr: int = var["addr"] + load_offset
            if addr not in self.json_map:
                self.json_map[addr] = []
                self.addrs.append(addr)
            self.json_map[addr].append(var)
            self.var_cnt += 1

        self.addrs.sort()

        print("\n" + "*" * 30 + "\n")
        print(f"  load offset {load_offset:08x}")
        print(f"  loaded {self.var_cnt} vars")
        print("\n" + "*" * 30 + "\n")

        # break at all match positions
        for addr in self.addrs:
            bp = gdb.Breakpoint(f"*{addr}", temporary=True)
            self.bp_map[addr] = bp

            debug(f"found {len(self.json_map[addr])} vars at {addr:08x}")

        self.output_json = output_json
        self.result = Result(self.var_cnt, time.time())  # new result object

    def fini(self):
        if self.output_json is None:
            print(self.result.to_log())
        else:
            with open(self.output_json, "w") as fp:
                fp.write(self.result.to_json())

        gdb.execute("d breakpoints")

    def invoke(self, args, from_tty):

        def fetch_inferior_value(var: dict) -> bool:
            name = var["name"]
            var["stat"] = STAT_UNKOWN

            try:
                oracle = gdb.parse_and_eval(name)
            except:
                if re.search(r"_(\d)+$", name) is not None:
                    # possibly a conflict var
                    modified = re.sub(r"_(\d)+$", "", name)
                    var["stat"] |= STAT_CONFLICT
                    debug(f"possible conflict var {name} -> {modified}")
                elif re.search(r"-local$", name) is not None:
                    # possibly a var alias
                    modified = re.sub(r"-local$", "", name)
                    var["stat"] |= STAT_ALIAS
                    debug(f"possible alias {name} -> {modified}")

                try:
                    oracle = gdb.parse_and_eval(modified)
                except:
                    oracle = None

            if oracle is None or oracle.is_optimized_out:
                # question: why optimized out
                var["stat"] |= STAT_DEAD
                return False
            else:
                try:
                    oracle.fetch_lazy()
                except:
                    var["stat"] |= STAT_BAD
                    return False
                var["oracle"] = oracle
                return True

        def collect_var_stat(var: dict):
            name = var["name"]
            stat = var["stat"]

            if (stat & STAT_DEAD) != 0:
                info(f"currently no var name {name}")
                self.result.fail_cnt += 1
            elif (stat & STAT_BAD) != 0:
                info(f"invalid var name")
                self.result.fail_cnt += 1
            elif (stat & STAT_CORRECT) != 0:
                if (
                    (stat & STAT_ALIAS) != 0
                    or (stat & STAT_CONFLICT) != 0
                    or (stat & STAT_VAGUE) != 0
                    or (stat & STAT_INDIRECT) != 0
                ):
                    info(f"var {name} is partially correct")
                    self.result.partially_correct_cnt += 1
                else:
                    info(f"var {name} verified")
                    self.result.correct_cnt += 1
            else:
                info(f"var {name} missed")
                self.result.wrong_cnt += 1

        # specify more check functions here

        def check_var_full(var: dict) -> bool:
            oracle: gdb.Value = var["oracle"]
            exprs: list[str] = var["exprs"]

            for expr in exprs:
                try:
                    val = gdb.parse_and_eval(expr)
                except:
                    # bad expression
                    debug(f"full check: confused at {expr}")
                    continue

                try:
                    if val == oracle:
                        var["stat"] |= STAT_CORRECT
                        return True
                    else:
                        debug(f"full check: expecting {oracle} but get {val}")
                except:
                    # error encountered while fetching value of var
                    debug(f"full check: cannot evaluate {expr}")
                    continue
            else:
                return False

        def check_var_vague(var: dict) -> bool:
            oracle: gdb.Value = var["oracle"]
            exprs: list[str] = var["exprs"]

            # fallback, we discard var type and test again
            int_type: gdb.Type = gdb.lookup_type("int")
            try:
                oracle = oracle.cast(int_type)
                debug(f"vague check: using vague oracle -> {oracle}")
            except:
                debug(f"vague check: var does not support vague check")
                return False

            for expr in var["exprs"]:
                try:
                    val = gdb.parse_and_eval(expr)
                    val = val.cast(int_type)
                    debug(f"vague check: using vague val -> (int)({expr})")
                except:
                    # still bad expression
                    debug(f"vague check: confused at {expr}")
                    continue

                try:
                    if val == oracle:
                        # insert a partially correct flag
                        var["stat"] |= STAT_VAGUE | STAT_CORRECT
                        return True
                    else:
                        debug(f"vague check: expecting {oracle} but get {val}")
                except:
                    # still error while fetching value
                    debug(f"vague check: cannot evaluate (int)({expr})")
                    continue
            else:
                return False

        def check_var_indirect(var: dict) -> bool:
            oracle: gdb.Value = var["oracle"]
            exprs: list[str] = var["exprs"]

            # we check whether var is actually address of the oracle
            void_ptr_type: gdb.Type = gdb.lookup_type("void").pointer()
            try:
                oracle = oracle.address.cast(void_ptr_type)
                debug(f"indirect check: using oracle's address -> {oracle}")
            except:
                debug(f"indirect check: trying indirect check but var is not a l-value")
                return False

            for expr in var["exprs"]:
                try:
                    val = gdb.parse_and_eval(expr)
                    val = val.cast(void_ptr_type)
                    debug(f"indirect check: using val -> (void *)({expr})")
                except:
                    # still bad expression
                    debug(f"indirect check: confused at {expr}")
                    continue

                try:
                    if val == oracle:
                        # insert a partially correct flag
                        var["stat"] |= STAT_INDIRECT | STAT_CORRECT
                        return True
                    else:
                        debug(f"indirect check: expecting {oracle} but get {val}")
                except:
                    # still error while fetching value
                    debug(f"indirect check: cannot evaluate (void *)({expr})")
                    continue
            else:
                return False

        def check_var(var: dict):
            checks = [check_var_full, check_var_indirect, check_var_vague]
            for f in checks:
                if f(var) is True:
                    break

        def get_pc() -> int:
            return int(gdb.parse_and_eval("$pc"))

        # script start

        global exited
        global received_signal
        global hit_breakpoint

        gdb.events.exited.connect(exit_handler)
        gdb.events.stop.connect(stop_handler)

        args = gdb.string_to_argv(args)

        if len(args) >= 2:
            self.init(input_json=args[0], output_json=args[1])
        elif len(args) == 1:
            self.init(input_json=args[0], output_json=None)
        else:
            info("usage: check_variables json_path [output_path]")
            return

        exited = False
        hit_breakpoint = False
        received_signal = False

        # normally we stop at main()
        # record vars if they are going to be updated
        snapshot: list[dict] = []

        while True:
            if len(snapshot) > 0:
                gdb.execute("si")

                if exited is True:
                    debug("program exited")
                    break
                elif received_signal is True:
                    debug("program error")
                    break

                addr = get_pc()

                for var in snapshot:
                    name = var["name"]
                    info(f"checking var {name} at {addr:08x} ...")
                    check_var(var)
                    collect_var_stat(var)

            if hit_breakpoint is False:
                debug(f"continuing from {get_pc():08x}")
                gdb.execute("c")

            if exited is True:
                debug("program exited")
                break
            elif received_signal is True:
                # our script could fail when inferior executing
                # if it is not a breakpoint hit
                # i.e. the program fails and received SIGSEGV
                # just output all stats we have so far
                debug("program error, outputing collected stats so far ...")
                break

            # not exited, we stop at a breakpoint
            hit_breakpoint = False

            addr = get_pc()
            snapshot.clear()
            for var in self.json_map[addr]:
                # we hit at a var!!!
                self.result.hit_cnt += 1

                name: str = var["name"]
                update: bool = var["update"]

                if fetch_inferior_value(var) is True:
                    if update is True:
                        debug(f"cached dest var {name} at {addr:08x} into snapshot")
                        snapshot.append(var)
                        continue
                    else:
                        info(f"checking var {name} at {addr:08x} ...")
                        check_var(var)
                        collect_var_stat(var)
                else:
                    collect_var_stat(var)

        self.fini()


# register the GDB command
CheckVariablesCommand()
gdb.execute("set pagination off")

# gdb.execute("set logging redirect on")
# gdb.execute("set logging debugredirect off")
# gdb.execute("set logging overwrite on")
# gdb.execute("set logging file debug.txt")
# gdb.execute("set logging enabled on")
