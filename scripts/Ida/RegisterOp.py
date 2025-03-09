import  string
from Instruction import  Instruction
from ResultFormat import  *

'''
return a real register name that is covered by a ida-given name ,two return value
bool indicate whether a name is corvered
'''
def get_real_register_name(register_index:int,showed_register_name:string):
    '''
     Register Number [0,7] represent rax,rcx,rdc,rbx,rsp,rbp,rsi,rdi and also its 16-bit or 32-bit form register
     So need to do some trans
    '''
    if register_index in range(0, 8):
        # ax cx...di
        if len(showed_register_name) == 2 and showed_register_name in Instruction.Register_List[0:8:]:
            return False,Instruction.Register_List[register_index]
        # rax rcx...rdi
        elif len(showed_register_name) == 3 and showed_register_name[1:] in Instruction.Register_List[0:8:]:
            return False,'r' + Instruction.Register_List[register_index]
        # have a recovered name
        else:
            return True,'r' + Instruction.Register_List[register_index]


    elif register_index in range(8, 16):
        '''
        r8 ~ r15 has 4 format,eg: r8b r8w r8d r8(8,32,16,64)
        '''
        if register_index in (8, 9):
            if len(showed_register_name) == 2 and showed_register_name in Instruction.Register_List:
                return False,Instruction.Register_List[register_index]
            elif len(showed_register_name) == 3 and showed_register_name[0:2] in Instruction.Register_List:
                return False,Instruction.Register_List[register_index] + 'w'
            else:
                # recovered
                return True,Instruction.Register_List[register_index]
        else:
            if len(showed_register_name) == 3 and showed_register_name in Instruction.Register_List:
                return False,Instruction.Register_List[register_index]
            elif len(showed_register_name) == 4 and showed_register_name[0:3] in Instruction.Register_List:
                return False,Instruction.Register_List[register_index] + 'w'
            else:
                # recovered
                real_register_name: string = Instruction.get_register_name(register_index)
                # print(f"恢复成功，寄存器为：{real_register_name},恢复的变量名为：{showed_register_name}")
                return True,real_register_name

    else:
        return False,Instruction.Register_List[register_index]