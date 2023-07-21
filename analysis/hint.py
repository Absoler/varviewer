from z3 import *

class Hint:
    def __init__(self) -> None:
        self.conds:list = []
    
    def add(self, cond):
        self.conds.append(cond)