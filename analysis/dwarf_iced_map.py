from iced_x86 import Register

iced_dwarf_regMap = {
    Register.AL : 0,
    Register.AH : 0,
    Register.AX : 0,
    Register.EAX : 0,
    Register.RAX : 0,

    Register.DL : 1,
    Register.DH : 1,
    Register.DX : 1,
    Register.EDX : 1,
    Register.RDX : 1,

    Register.CL : 2,
    Register.CH : 2,
    Register.CX : 2,
    Register.ECX : 2,
    Register.RCX : 2,

    Register.BL : 3,
    Register.BH : 3,
    Register.BX : 3,
    Register.EBX : 3,
    Register.RBX : 3,

    Register.SIL : 4,
    Register.SI : 4,
    Register.ESI : 4,
    Register.RSI : 4,

    Register.DIL : 5,
    Register.DI : 5,
    Register.EDI : 5,
    Register.RDI : 5,

    Register.BPL : 6,
    Register.BP : 6,
    Register.EBP : 6,
    Register.RBP : 6,

    Register.SPL : 7,
    Register.SP : 7,
    Register.ESP : 7,
    Register.RSP : 7,

    Register.R8L : 8,
    Register.R8W : 8,
    Register.R8D : 8,
    Register.R8 : 8,


    Register.R9L : 9,
    Register.R9W : 9,
    Register.R9D : 9,
    Register.R9 : 9,


    Register.R10L : 10,
    Register.R10W : 10,
    Register.R10D : 10,
    Register.R10 : 10,


    Register.R11L : 11,
    Register.R11W : 11,
    Register.R11D : 11,
    Register.R11 : 11,


    Register.R12L : 12,
    Register.R12W : 12,
    Register.R12D : 12,
    Register.R12 : 12,


    Register.R13L : 13,
    Register.R13W : 13,
    Register.R13D : 13,
    Register.R13 : 13,


    Register.R14L : 14,
    Register.R14W : 14,
    Register.R14D : 14,
    Register.R14 : 14,


    Register.R15L : 15,
    Register.R15W : 15,
    Register.R15D : 15,
    Register.R15 : 15,

    Register.XMM0 : 17,
    Register.XMM1 : 18,
    Register.XMM2 : 19,
    Register.XMM3 : 20,
    Register.XMM4 : 21,
    Register.XMM5 : 22,
    Register.XMM6 : 23,
    Register.XMM7 : 24,
    Register.XMM8 : 25,
    Register.XMM9 : 26,
    Register.XMM10 : 27,
    Register.XMM11 : 28,
    Register.XMM12 : 29,
    Register.XMM13 : 30,
    Register.XMM14 : 31,
    Register.XMM15 : 32,

    Register.ST0 : 33,
    Register.ST1 : 34,
    Register.ST2 : 35,
    Register.ST3 : 36,
    Register.ST4 : 37,
    Register.ST5 : 38,
    Register.ST6 : 39,
    Register.ST7 : 40,

    Register.MM0 : 41,
    Register.MM1 : 42,
    Register.MM2 : 43,
    Register.MM3 : 44,
    Register.MM4 : 45,
    Register.MM5 : 46,
    Register.MM6 : 47,
    Register.MM7 : 48,

    Register.ES : 50,
    Register.CS : 51,
    Register.SS : 52,
    Register.DS : 53,
    Register.FS : 54,
    Register.GS : 55,

}

dwarf_iced_regMap = {
    0 : [Register.AL, Register.AH, Register.AX, Register.EAX, Register.RAX,],

    1 : [Register.DL, Register.DH, Register.DX, Register.EDX, Register.RDX,],

    2 : [Register.CL, Register.CH, Register.CX, Register.ECX, Register.RCX,],

    3 : [Register.BL, Register.BH, Register.BX, Register.EBX, Register.RBX,],

    4 : [Register.SIL, Register.SI, Register.ESI, Register.RSI,],

    5 : [Register.DIL, Register.DI, Register.EDI, Register.RDI,],

    6 : [Register.BPL, Register.BP, Register.EBP, Register.RBP,],

    7 : [Register.SPL, Register.SP, Register.ESP, Register.RSP,],

    8 : [Register.R8L, Register.R8W, Register.R8D, Register.R8],
    9 : [Register.R9L, Register.R9W, Register.R9D, Register.R9],
    10 : [Register.R10L, Register.R10W, Register.R10D, Register.R10],
    11 : [Register.R11L, Register.R11W, Register.R11D, Register.R11],
    12 : [Register.R12L, Register.R12W, Register.R12D, Register.R12],
    13 : [Register.R13L, Register.R13W, Register.R13D, Register.R13],
    14 : [Register.R14L, Register.R14W, Register.R14D, Register.R14],
    15 : [Register.R15L, Register.R15W, Register.R15D, Register.R15],

    17 : [Register.XMM0],
    18 : [Register.XMM1],
    19 : [Register.XMM2],
    20 : [Register.XMM3],
    21 : [Register.XMM4],
    22 : [Register.XMM5],
    23 : [Register.XMM6],
    24 : [Register.XMM7],
    25 : [Register.XMM8],
    26 : [Register.XMM9],
    27 : [Register.XMM10],
    28 : [Register.XMM11],
    29 : [Register.XMM12],
    30 : [Register.XMM13],
    31 : [Register.XMM14],
    32 : [Register.XMM15],

    33 : [Register.ST0],
    34 : [Register.ST1],
    35 : [Register.ST2],
    36 : [Register.ST3],
    37 : [Register.ST4],
    38 : [Register.ST5],
    39 : [Register.ST6],
    40 : [Register.ST7],

    41 : [Register.MM0],
    42 : [Register.MM1],
    43 : [Register.MM2],
    44 : [Register.MM3],
    45 : [Register.MM4],
    46 : [Register.MM5],
    47 : [Register.MM6],
    48 : [Register.MM7],

    50 : [Register.ES],
    51 : [Register.CS],
    52 : [Register.SS],
    53 : [Register.DS],
    54 : [Register.FS],
    55 : [Register.GS],

}

dwarf_reg_names = [
    "rax",
    "rdx",
    "rcx",
    "rbx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "RA",
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",
    "xmm9",
    "xmm10",
    "xmm11",
    "xmm12",
    "xmm13",
    "xmm14",
    "xmm15",
    "st0",
    "st1",
    "st2",
    "st3",
    "st4",
    "st5",
    "st6",
    "st7",
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",
    "rFLAGS",
    "es",
    "cs",
    "ss",
    "ds",
    "fs",
    "gs"
]

