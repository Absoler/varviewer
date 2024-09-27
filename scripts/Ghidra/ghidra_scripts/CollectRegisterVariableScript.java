//@author goudunz1
//@category Test
//@keybinding
//@menupath
//@toolbar

import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;

public class CollectRegisterVariableScript extends CollectVariableScript {

	@Override
	protected String getOutputSuffix() {
		return ".reg.json";
	}

	@Override
	protected boolean isAvailableVariable(VariableOffset varOff, int opTyp) {
		Object replaced = varOff.getReplacedElement();

		if (replaced instanceof Register) {
			return true;
		} else if (replaced instanceof Scalar) {
			return false;
		} else {
			if (OperandType.isRegister(opTyp)) {
				return true;
			} else {
				return false;
			}
		}
	}

}