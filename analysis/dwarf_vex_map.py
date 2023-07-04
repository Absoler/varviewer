from pyvex import *
from enum import Enum

vex_reg_size_names = {(16, 8): 'rax', (16, 4): 'eax', (16, 2): 'ax', (16, 1): 'al', (17, 1): 'ah', (24, 8): 'rcx', (24, 4): 'ecx', (24, 2): 'cx', (24, 1): 'cl', (25, 1): 'ch', (32, 8): 'rdx', (32, 4): 'edx', (32, 2): 'dx', (32, 1): 'dl', (33, 1): 'dh', (40, 8): 'rbx', (40, 4): 'ebx', (40, 2): 'bx', (40, 1): 'bl', (41, 1): 'bh', (48, 8): 'rsp', (48, 4): 'esp', (56, 8): 'rbp', (56, 4): 'ebp', (56, 2): '_bp', (56, 1): 'bpl', (57, 1): 'bph', (64, 8): 'rsi', (64, 4): 'esi', (64, 2): 'si', (64, 1): 'sil', (65, 1): 'sih', (72, 8): 'rdi', (72, 4): 'edi', (72, 2): 'di', (72, 1): 'dil', (73, 1): 'dih', (80, 8): 'r8', (80, 4): 'r8d', (80, 2): 'r8w', (80, 1): 'r8b', (88, 8): 'r9', (88, 4): 'r9d', (88, 2): 'r9w', (88, 1): 'r9b', (96, 8): 'r10', (96, 4): 'r10d', (96, 2): 'r10w', (96, 1): 'r10b', (104, 8): 'r11', (104, 4): 'r11d', (104, 2): 'r11w', (104, 1): 'r11b', (112, 8): 'r12', (112, 4): 'r12d', (112, 2): 'r12w', (112, 1): 'r12b', (120, 8): 'r13', (120, 4): 'r13d', (120, 2): 'r13w', (120, 1): 'r13b', (128, 8): 'r14', (128, 4): 'r14d', (128, 2): 'r14w', (128, 1): 'r14b', (136, 8): 'r15', (136, 4): 'r15d', (136, 2): 'r15w', (136, 1): 'r15b', (144, 8): 'cc_op', (152, 8): 'cc_dep1', (160, 8): 'cc_dep2', (168, 8): 'cc_ndep', (176, 8): 'd', (184, 8): 'rip', (192, 8): 'ac', (200, 8): 'id', (208, 8): 'fs', (216, 8): 'sseround', (768, 8): 'cr0', (784, 8): 'cr2', (792, 8): 'cr3', (800, 8): 'cr4', (832, 8): 'cr8', (224, 32): 'ymm0', (224, 16): 'xmm0', (224, 8): 'xmm0lq', (232, 8): 'xmm0hq', (240, 16): 'ymm0hx', (256, 32): 'ymm1', (256, 16): 'xmm1', (256, 8): 'xmm1lq', (264, 8): 'xmm1hq', (272, 16): 'ymm1hx', (288, 32): 'ymm2', (288, 16): 'xmm2', (288, 8): 'xmm2lq', (296, 8): 'xmm2hq', (304, 16): 'ymm2hx', (320, 32): 'ymm3', (320, 16): 'xmm3', (320, 8): 'xmm3lq', (328, 8): 'xmm3hq', (336, 16): 'ymm3hx', (352, 32): 'ymm4', (352, 16): 'xmm4', (352, 8): 'xmm4lq', (360, 8): 'xmm4hq', (368, 16): 'ymm4hx', (384, 32): 'ymm5', (384, 16): 'xmm5', (384, 8): 'xmm5lq', (392, 8): 'xmm5hq', (400, 16): 'ymm5hx', (416, 32): 'ymm6', (416, 16): 'xmm6', (416, 8): 'xmm6lq', (424, 8): 'xmm6hq', (432, 16): 'ymm6hx', (448, 32): 'ymm7', (448, 16): 'xmm7', (448, 8): 'xmm7lq', (456, 8): 'xmm7hq', (464, 16): 'ymm7hx', (480, 32): 'ymm8', (480, 16): 'xmm8', (480, 8): 'xmm8lq', (488, 8): 'xmm8hq', (496, 16): 'ymm8hx', (512, 32): 'ymm9', (512, 16): 'xmm9', (512, 8): 'xmm9lq', (520, 8): 'xmm9hq', (528, 16): 'ymm9hx', (544, 32): 'ymm10', (544, 16): 'xmm10', (544, 8): 'xmm10lq', (552, 8): 'xmm10hq', (560, 16): 'ymm10hx', (576, 32): 'ymm11', (576, 16): 'xmm11', (576, 8): 'xmm11lq', (584, 8): 'xmm11hq', (592, 16): 'ymm11hx', (608, 32): 'ymm12', (608, 16): 'xmm12', (608, 8): 'xmm12lq', (616, 8): 'xmm12hq', (624, 16): 'ymm12hx', (640, 32): 'ymm13', (640, 16): 'xmm13', (640, 8): 'xmm13lq', (648, 8): 'xmm13hq', (656, 16): 'ymm13hx', (672, 32): 'ymm14', (672, 16): 'xmm14', (672, 8): 'xmm14lq', (680, 8): 'xmm14hq', (688, 16): 'ymm14hx', (704, 32): 'ymm15', (704, 16): 'xmm15', (704, 8): 'xmm15lq', (712, 8): 'xmm15hq', (720, 16): 'ymm15hx', (896, 4): 'ftop', (904, 64): 'fpreg', (904, 8): 'mm0', (912, 8): 'mm1', (920, 8): 'mm2', (928, 8): 'mm3', (936, 8): 'mm4', (944, 8): 'mm5', (952, 8): 'mm6', (960, 8): 'mm7', (968, 8): 'fptag', (976, 8): 'fpround', (984, 8): 'fc3210', (992, 4): 'emnote', (1000, 8): 'cmstart', (1008, 8): 'cmlen', (1016, 8): 'nraddr', (1032, 8): 'gs', (1040, 8): 'ip_at_syscall', (1048, 2): 'cs_seg', (1050, 2): 'ds_seg', (1052, 2): 'es_seg', (1054, 2): 'fs_seg', (1056, 2): 'fs_seg', (1058, 2): 'ss_seg'}
vex_reg_names = {16: 'rax', 24: 'rcx', 32: 'rdx', 40: 'rbx', 48: 'rsp', 56: 'rbp', 64: 'rsi', 72: 'rdi', 80: 'r8', 88: 'r9', 96: 'r10', 104: 'r11', 112: 'r12', 120: 'r13', 128: 'r14', 136: 'r15', 144: 'cc_op', 152: 'cc_dep1', 160: 'cc_dep2', 168: 'cc_ndep', 176: 'd', 184: 'rip', 192: 'ac', 200: 'id', 208: 'fs', 216: 'sseround', 768: 'cr0', 784: 'cr2', 792: 'cr3', 800: 'cr4', 832: 'cr8', 224: 'ymm0', 256: 'ymm1', 288: 'ymm2', 320: 'ymm3', 352: 'ymm4', 384: 'ymm5', 416: 'ymm6', 448: 'ymm7', 480: 'ymm8', 512: 'ymm9', 544: 'ymm10', 576: 'ymm11', 608: 'ymm12', 640: 'ymm13', 672: 'ymm14', 704: 'ymm15', 896: 'ftop', 904: 'fpreg', 968: 'fptag', 976: 'fpround', 984: 'fc3210', 992: 'emnote', 1000: 'cmstart', 1008: 'cmlen', 1016: 'nraddr', 1032: 'gs', 1040: 'ip_at_syscall', 1048: 'cs_seg', 1050: 'ds_seg', 1052: 'es_seg', 1054: 'fs_seg', 1056: 'fs_seg', 1058: 'ss_seg'}
vex_reg_codes = {vex_reg_names[code]:code for code in vex_reg_names}
vex_reg_size_codes = {vex_reg_size_names[code]:code for code in vex_reg_size_names}

vex_to_dwarf = {16: 0, 24: 2, 32: 1, 40: 3, 48: 7, 56: 6, 64: 4, 72: 5, 80: 8, 88: 9, 96: 10, 104: 11, 112: 12, 120: 13, 128: 14, 136: 15}
dwarf_to_vex = {vex_to_dwarf[vex]:vex for vex in vex_to_dwarf}

DW_OP_abs                       = 0x19
DW_OP_and                       = 0x1a
DW_OP_div                       = 0x1b
DW_OP_minus                     = 0x1c
DW_OP_mod                       = 0x1d
DW_OP_mul                       = 0x1e
DW_OP_neg                       = 0x1f
DW_OP_not                       = 0x20
DW_OP_or                        = 0x21
DW_OP_plus                      = 0x22
DW_OP_plus_uconst               = 0x23
DW_OP_shl                       = 0x24
DW_OP_shr                       = 0x25
DW_OP_shra                      = 0x26
DW_OP_xor                       = 0x27
DW_OP_eq                        = 0x29
DW_OP_ge                        = 0x2a
DW_OP_gt                        = 0x2b
DW_OP_le                        = 0x2c
DW_OP_lt                        = 0x2d
DW_OP_ne                        = 0x2e

def isUnary(op:int):
    return op==DW_OP_abs or op==DW_OP_neg or op==DW_OP_not

def op_match(dwarf_op:int, vex_op:str):

    if dwarf_op == None:
        return False
    
    if dwarf_op == DW_OP_abs:
        return vex_op.startswith("Iop_Abs")
    
    elif dwarf_op == DW_OP_and:
        return vex_op.startswith("Iop_And")
    
    elif dwarf_op == DW_OP_div:
        return vex_op.startswith("Iop_Div")
    
    elif dwarf_op == DW_OP_minus:
        return vex_op.startswith("Iop_Sub")
    
    elif dwarf_op == DW_OP_mod:
        return vex_op.startswith("Iop_DivMod")
    
    elif dwarf_op == DW_OP_mul:
        return vex_op.startswith("Iop_Mul")
    
    elif dwarf_op == DW_OP_neg:
        return vex_op.startswith("Iop_Neg")
    
    elif dwarf_op == DW_OP_not:
        return vex_op.startswith("Iop_Not")
    
    elif dwarf_op == DW_OP_or:
        return vex_op.startswith("Iop_Or")
    
    elif dwarf_op == DW_OP_plus or dwarf_op == DW_OP_plus_uconst:
        return vex_op.startswith("Iop_Add")
    
    elif dwarf_op == DW_OP_shl:
        return vex_op.startswith("Iop_Shl")
    
    elif dwarf_op == DW_OP_shr:
        return vex_op.startswith("Iop_Shr")
    
    elif dwarf_op == DW_OP_shra:
        return vex_op.startswith("Iop_Sar")
    
    elif dwarf_op == DW_OP_xor:
        return vex_op.startswith("Iop_Xor")
    
    elif dwarf_op == DW_OP_eq:
        return vex_op.startswith("Iop_CmpEQ")
    
    elif dwarf_op == DW_OP_ge:
        return vex_op.startswith("Iop_CmpGE")
    
    elif dwarf_op == DW_OP_gt:
        return vex_op.startswith("Iop_CmpGT")
    
    elif dwarf_op == DW_OP_le:
        return vex_op.startswith("Iop_CmpLE")
    
    elif dwarf_op == DW_OP_lt:
        return vex_op.startswith("Iop_CmpLT")
    
    elif dwarf_op == DW_OP_ne:
        return vex_op.startswith("Iop_CmpNE")
    
    else:
        print(f"wrong dwarf op {dwarf_op}")


if __name__ == "__main__":
    pass