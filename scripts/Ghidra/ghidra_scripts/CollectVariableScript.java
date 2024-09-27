//@author goudunz1
//@category Test
//@keybinding
//@menupath
//@toolbar

import java.io.FileWriter;
import java.io.IOException;

import java.lang.reflect.Method;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.*;

import ghidra.app.script.GhidraScript;

import ghidra.program.database.function.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.symbol.*;

import com.fasterxml.jackson.annotation.*;
import com.fasterxml.jackson.core.*;
import com.fasterxml.jackson.databind.*;

public class CollectVariableScript extends GhidraScript {

	class DebugRecord {

		@JsonProperty("name")
		protected String name;

		public String getName() {
			return this.name;
		}

		public void setName(String name) {
			this.name = name;
		}

		@JsonProperty("addr")
		protected long address;

		public long getAddress() {
			return this.address;
		}

		public void setAddress(long address) {
			this.address = address;
		}

		@JsonProperty("update")
		public boolean update;

		public boolean getUpdate() {
			return this.update;
		}

		public void setUpdate(boolean update) {
			this.update = update;
		}

		@JsonProperty("exprs")
		protected String[] expressions;

		public String[] getExpressions() {
			return expressions;
		}

		public void setExpressions(String[] expressions) {
			this.expressions = expressions;
		}

		@Override
		public String toString() {
			return String.format("(%s, %08x)", name, address);
		}

		public DebugRecord(String name, long address, boolean update, String[] expressions) {
			this.name = name;
			this.address = address;
			this.update = update;
			this.expressions = expressions;
		}

	}

	class DebugRecordBuilder {

		// required input
		protected long address = 0;

		protected Instruction instruction;

		protected int operandIndex = -1;

		protected VariableOffset variableOffset;

		// auto-generated
		protected String locationString;

		protected boolean dereferrence; // need to dereferrence location string

		protected List<DataType> dataTypeList; // possible data type

		protected List<Integer> adjustOffsetList; // adjust offset corresponding to data type

		protected String name;

		protected boolean update; // true if value of the variable is going to be set by the instruction

		protected String[] expressions;

		// auxilliary functions

		protected String toGdbExpression(String exprStr) {
			exprStr = exprStr.replaceAll("(\\b[A-Za-z][0-9A-Za-z]*)", "\\$$1").toLowerCase();
			return exprStr.replaceAll("\\s", "");
		}

		protected String toGdbType(DataType dt) {
			if (dt instanceof Pointer) {
				DataType vdt = ((Pointer) dt).getDataType();
				if (vdt instanceof Pointer) {
					return toGdbType(vdt) + "*";
				} else {
					return toGdbType(vdt) + " *";
				}
			} else if (dt instanceof Structure) {
				Structure sdt = (Structure) dt;
				return "struct " + sdt.getDisplayName();
			} else if (dt instanceof Union) {
				Union udt = (Union) dt;
				return "union " + udt.getDisplayName();
			} else if (dt instanceof Undefined) {
				return "unsigned char";
			} else if (dt instanceof Array) {
				DataType vdt = ((Array) dt).getDataType();
				DataType pdt = new PointerDataType(vdt);
				return toGdbType(pdt);
			} else {
				Class<?> clss = dt.getClass();
				Class<?> argTyps[] = null;
				try {
					Method method = clss.getMethod("getCDeclaration", argTyps);
					if (method != null) {
						return (String) method.invoke(dt);
					}
				} catch (Exception e) {
					// let the control flow go
				}
				return dt.getDisplayName();
			}
		}

		protected String toLocationString(String exprStr) {
			String locStr;
			Matcher matcher = Pattern.compile("\\[(.*)\\]").matcher(exprStr);
			if (matcher.find() == true) {
				locStr = matcher.group(1);
			} else {
				locStr = exprStr;
			}

			return toGdbExpression(locStr);
		}

		protected void configOperand() {
			assert instruction != null;
			assert operandIndex != -1;
			assert variableOffset != null;

			String opStr = instruction.getDefaultOperandRepresentation(operandIndex);
			int opTyp = instruction.getOperandType(operandIndex);

			// determine if the addr expression contains value of the variable
			// or the address of the variable
			Object replaced = variableOffset.getReplacedElement();

			if (replaced instanceof Register) {
				// location string is register name
				this.locationString = toLocationString(((Register) replaced).getName());
				this.dereferrence = false;
				this.update = operandIndex == 0 && !OperandType.isDynamic(opTyp);

			} else if (replaced instanceof Scalar) {
				assert OperandType.isDynamic(opTyp);
				this.locationString = toLocationString(opStr);
				this.dereferrence = true;
				this.update = operandIndex == 0;

			} else if (replaced == null) {
				assert variableOffset.isDataAccess() == false;
				this.locationString = toLocationString(opStr);
				this.dereferrence = !OperandType.isDynamic(opTyp);
				this.update = operandIndex == 0;

			} else {
				// should never happpen
				assert false;
			}
		}

		protected void configDataType() {
			assert variableOffset != null;

			this.dataTypeList = new ArrayList<DataType>();
			this.adjustOffsetList = new ArrayList<Integer>();

			// trying to deduce data type from variable
			Variable var = variableOffset.getVariable();
			DataType dt = var.getDataType();
			int off = (int) variableOffset.getOffset();

			assert off >= 0;

			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}

			if (variableOffset.isIndirect() && (dt instanceof Pointer)) {
				dt = ((Pointer) dt).getDataType();
			}

			while (off > 0 || (off == 0 && variableOffset.isDataAccess())) {

				if (dt instanceof TypeDef) {
					dt = ((TypeDef) dt).getBaseDataType();
				}

				if (dt instanceof Structure) {
					DataTypeComponent cdt = ((Structure) dt).getComponentAt(off);

					if (cdt == null) {
						// unable to deduce type
						// fallback: output struct type
						dataTypeList.add(dt);
						adjustOffsetList.add(Integer.valueOf(off));
						return;
					}

					if (cdt.isBitFieldComponent()) {
						// guessing a type
						dt = new UnsignedCharDataType();
					} else {
						dt = cdt.getDataType();
					}

					off -= cdt.getOffset();

				} else if (dt instanceof Array) {
					Array a = (Array) dt;
					dt = a.getDataType();

					int elementLen = a.getElementLength();
					int index = off / elementLen;
					off -= index * elementLen;

				} else if (dt instanceof Union) {
					// because ghidra does not step into union,
					// we directly output union
					dataTypeList.add(dt);
					adjustOffsetList.add(Integer.valueOf(off));
					return;

				} else {
					break;
				}
			}

			// all default cases goes here
			dataTypeList.add(dt);
			adjustOffsetList.add(Integer.valueOf(off));
		}

		// 'set' functions

		public DebugRecordBuilder setAddress(long address) {
			assert address > 0;
			this.address = address;
			return this;
		}

		public DebugRecordBuilder setInstruction(Instruction insn) {
			assert insn != null;
			this.instruction = insn;

			if (operandIndex != -1 && variableOffset != null) {
				configOperand();
			}

			return this;
		}

		public DebugRecordBuilder setOperandIndex(int opIdx) {
			assert opIdx == 0 || opIdx == 1; // x64
			this.operandIndex = opIdx;

			if (instruction != null && variableOffset != null) {
				configOperand();
			}

			return this;
		}

		public DebugRecordBuilder setVariableOffset(VariableOffset varOff) {
			assert varOff != null;

			this.name = varOff.getDataTypeDisplayText();
			this.variableOffset = varOff;
			configDataType();

			if (instruction != null && operandIndex != -1) {
				configOperand();
			}

			return this;
		}

		public void reset() {
			this.address = 0;
			this.instruction = null;
			this.operandIndex = -1;
			this.variableOffset = null;
		}

		public DebugRecord build() {
			assert this.address > 0;
			assert this.instruction != null;
			assert this.operandIndex != -1;
			assert this.variableOffset != null;

			List<String> exprStrList = new ArrayList<String>();
			for (int i = 0; i < dataTypeList.size(); i++) {
				DataType dt = dataTypeList.get(i);
				int adjustOff = adjustOffsetList.get(i).intValue();

				String exprStr = locationString;
				if (adjustOff > 0) {
					exprStr = String.format("(%s)-%d", exprStr, adjustOff);
				} else if (adjustOff < 0) {
					exprStr = String.format("(%s)+%d", exprStr, -adjustOff);
				}

				// some modifications to make it compatible with gdb
				// there's a special case
				// in gdb array name is a pointer
				if (dereferrence && !(dt instanceof Array)) {
					String typStr = toGdbType(new PointerDataType(dt));
					exprStr = String.format("*(%s)(%s)", typStr, exprStr);
				} else {
					String typStr = toGdbType(dt);
					exprStr = String.format("(%s)(%s)", typStr, exprStr);
				}

				exprStrList.add(exprStr);
			}

			this.expressions = exprStrList.toArray(new String[0]);

			return new DebugRecord(name, address, update, expressions);
		}

	}

	protected boolean debugging = false;

	protected void ghidraLog(String log) {
		if (debugging == true) {
			println(log);
		}
	}

	protected List<DebugRecord> debugRecordList;

	protected String getOutputSuffix() {
		return ".json";
	}

	// Override this
	protected boolean isAvailableFunction(Function f) {
		return !f.isExternal() && !f.isThunk() && !f.isDeleted();
	}

	// Override this
	protected boolean isAvailableVariable(VariableOffset varOff, int opTyp) {
		return true;
	}

	@Override
	protected void run() throws Exception {
		debugRecordList = new ArrayList<DebugRecord>();

		// debugging = false;
		debugging = true;

		long startTime = System.currentTimeMillis();

		// get true functions
		FunctionManager fm = currentProgram.getFunctionManager();
		FunctionIterator fi = fm.getFunctionsNoStubs(true);

		// get useful functions
		while (fi.hasNext()) {
			Function f = fi.next();
			if (isAvailableFunction(f)) {
				for (Variable var : f.getAllVariables()) {
					if (var.getSource().equals(SourceType.IMPORTED)) {
						// contains variables that need to collect
						inspectFunction(f);
						break;
					}
				}
			}
		}

		long endTime = System.currentTimeMillis();
		long elapsed = endTime - startTime;
		ghidraLog(String.format("[*] total time elapsed: %dms", elapsed));

		// dump to json file
		String filePath = currentProgram.getExecutablePath();
		filePath = filePath.replaceAll("\\.o$", "") + getOutputSuffix();
		ghidraLog("[*] output is saved to " + filePath);

		try (FileWriter writer = new FileWriter(filePath)) {
			ObjectMapper om = new ObjectMapper();
			om.enable(SerializationFeature.INDENT_OUTPUT);

			String json = om.writeValueAsString(debugRecordList);
			writer.write(json);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void inspectFunction(Function f) {
		long ep = f.getEntryPoint().getOffset();
		String symbol = f.getName();
		ghidraLog(String.format("[+] available function at %08x\t%s", ep, symbol));

		// get and iterate over function chunks
		assert f instanceof FunctionDB;
		AddressSetView asv = ((FunctionDB) f).getBody();

		Listing listing = currentProgram.getListing();
		InstructionIterator ii = listing.getInstructions(asv, true);
		while (ii.hasNext()) {
			Instruction insn = ii.next();
			inspectInstruction(insn);
		}
	}

	protected void inspectInstruction(Instruction insn) {
		CodeUnitFormat cuf = getCodeUnitFormat();

		String assembly = cuf.getRepresentationString(insn);
		ghidraLog(String.format(" [-] %s\t%s", insn.getAddress().toString(), assembly));

		int n = insn.getNumOperands();
		for (int i = 0; i < n; i++) {
			// extract all variable offset from operand
			OperandRepresentationList objList = cuf.getOperandRepresentationList(insn, i);
			List<VariableOffset> varOffList = inspectOperand(objList);

			for (VariableOffset varOff : varOffList) {
				if (isAvailableVariable(varOff, insn.getOperandType(i))) {
					inspectVariable(varOff, insn, i);
				}
			}
		}
	}

	protected List<VariableOffset> inspectOperand(Object obj) {
		List<VariableOffset> varOffList = new ArrayList<VariableOffset>();

		if (obj instanceof OperandRepresentationList) {
			// step into sub-list
			for (Object subObj : (OperandRepresentationList) obj) {
				varOffList.addAll(inspectOperand(subObj));
			}
		} else if (obj instanceof VariableOffset) {
			VariableOffset varOff = (VariableOffset) obj;
			SourceType st = varOff.getVariable().getSource();

			if (st.equals(SourceType.DEFAULT)) {
				// indicated variable
			} else if (st.equals(SourceType.USER_DEFINED)) {
				// variable from user definition
			} else if (st.equals(SourceType.IMPORTED)) {
				// variable from DWARF
				varOffList.add(varOff);
			}
		} else if (obj instanceof Register) {
			// not marked register
		} else if (obj instanceof Address) {
			// an address
		} else if (obj instanceof Scalar) {
			// an instant value
		}

		return varOffList;
	}

	protected void inspectVariable(VariableOffset varOff, Instruction insn, int i) {
		if (debugging == true) {
			ghidraLog(String.format("  [+] variable offset:\t%s", varOff.getDataTypeDisplayText()));
			ghidraLog(String.format("  [+] variable data access:\t%s", varOff.isDataAccess() ? "true" : "false"));
			ghidraLog(String.format("  [+] variable indirect:\t%s", varOff.isIndirect() ? "true" : "false"));
			if (varOff.getReplacedElement() != null) {
				ghidraLog(String.format("  [+] replaced element:\t%s", varOff.getReplacedElement()));
			} else {
				ghidraLog("  [+] no replaced element");
			}
		}

		Address base = currentProgram.getImageBase();
		Address current = insn.getAddress();

		DebugRecordBuilder drb = new DebugRecordBuilder();
		drb.setAddress(current.subtract(base));
		drb.setInstruction(insn);
		drb.setOperandIndex(i);
		drb.setVariableOffset(varOff);
		DebugRecord dr = drb.build();

		debugRecordList.add(dr);
	}

}
