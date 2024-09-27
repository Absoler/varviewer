//@author goudunz1
//@category Test
//@keybinding
//@menupath
//@toolbar

import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;

public class CollectMemoryVariableScript extends CollectVariableScript {

	@Override
	protected String getOutputSuffix() {
		return ".mem.json";
	}

	@Override
	protected boolean isAvailableVariable(VariableOffset varOff, int opTyp) {
		Object replaced = varOff.getReplacedElement();

		if (replaced instanceof Register) {
			return false;
		} else if (replaced instanceof Scalar) {
			return true;
		} else {
			if (OperandType.isRegister(opTyp)) {
				return false;
			} else {
				return true;
			}
		}
	}

}