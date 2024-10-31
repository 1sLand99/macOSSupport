/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package macossupport;

import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class MacOSSupportAnalyzer extends AbstractAnalyzer {
	
	private static final String ANALYZER_NAME = "Rename objc_msgSend stubs";
	private static final String FUNCTION_PREFIX_OPTION_NAME = "Function prefix";
	private static final String DEFAULT_FUNCTION_PREFIX = "objc_msgSend_";

	public MacOSSupportAnalyzer() {
		super(
				ANALYZER_NAME,
				"This will rename any functions that only call `objc_msgSend` after the selector.",
				AnalyzerType.FUNCTION_ANALYZER
		);
		this.setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}
	

	@Override
	public boolean canAnalyze(Program program) {
		return 
				program.getLanguage().getProcessor().toString().equals("AARCH64") &&
				program.getExecutableFormat().equals("Mac OS X Mach-O") &&
				program.getLanguage().isBigEndian() == false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(FUNCTION_PREFIX_OPTION_NAME, OptionType.STRING_TYPE, DEFAULT_FUNCTION_PREFIX, null,
			"The prefix to append to the selector name before renaming the function after it.");
	}
	
	private Address rawPointerAddressToActualAddress(long pointerAddress, AddressSpace addressSpace, Memory memory) throws MemoryAccessException {
		Address paramPointerAddress = addressSpace.getAddress(pointerAddress);
		byte[] paramPointer = new byte[8];
		memory.getBytes(paramPointerAddress, paramPointer, 0, 8);
		long rawActualAddress = 0;
		for (int i = 0; i < paramPointer.length; i++) rawActualAddress |= (((long)paramPointer[i] & 0xFF) << (8 * i));
		Address actualAddress = addressSpace.getAddress(rawActualAddress);
		return actualAddress;
	}
	
	
	private String objcMsgSendSelector(Function function, ArrayList<Address> objcMsgSendAddresses) {
		long selectorRawPointerAddress = 0;
		long objcMsgSendRawPointerAddress = 0;
		if (function.getName().startsWith("FUN_") != true) return null;
		if (function.getParameterCount() != 0) return null;
		Listing listing = function.getProgram().getListing();
		Address entryPoint = function.getEntryPoint();
		CodeUnit entryPointCodeUnit = listing.getCodeUnitAt(entryPoint);
		if (!(entryPointCodeUnit instanceof Instruction)) return null;
		Instruction instruction = (Instruction) entryPointCodeUnit;
		int instructionIndex = 1;
		while (instructionIndex <= 6) {
			if (instruction == null) return null;
			String mnemonic = instruction.getMnemonicString();
			Object[] inputObjects = instruction.getInputObjects();
			Object[] resultObjects = instruction.getResultObjects();
			switch (instructionIndex) {
				case 1: {
					if (!mnemonic.equals("adrp")) return null;
					if (inputObjects.length != 1) return null;
					if (!(inputObjects[0] instanceof Scalar)) return null;
					if (((Scalar) inputObjects[0]).isSigned() == true) return null;
					selectorRawPointerAddress = ((Scalar) inputObjects[0]).getValue();
					if (resultObjects.length != 1) return null;
					if (!(resultObjects[0] instanceof Register)) return null;
					if (!((Register) resultObjects[0]).getName().equals("x1")) return null;
					break;
				}
				case 2: {
					if (!mnemonic.equals("ldr")) return null;
					if (inputObjects.length != 2) return null;
					if (!(inputObjects[0] instanceof Register)) return null;
					if (!(((Register) inputObjects[0]).getName().equals("x1"))) return null;
					if (!(inputObjects[1] instanceof Scalar)) return null;
					if (((Scalar) inputObjects[1]).isSigned() == true) return null;
					selectorRawPointerAddress = selectorRawPointerAddress + ((Scalar) inputObjects[1]).getValue();
					if (resultObjects.length != 1) return null;
					if (!(resultObjects[0] instanceof Register)) return null;
					if (!((Register) resultObjects[0]).getName().equals("x1")) return null;
					break;
				}
				// TODO: Add more checks below (just to be safe)
				case 3: {
					if (!mnemonic.equals("adrp")) return null;
					if (inputObjects.length != 1) return null;
					if (!(inputObjects[0] instanceof Scalar)) return null;
					if (((Scalar) inputObjects[0]).isSigned() == true) return null;
					objcMsgSendRawPointerAddress = ((Scalar) inputObjects[0]).getValue();
					if (resultObjects.length != 1) return null;
					if (!(resultObjects[0] instanceof Register)) return null;
					if (!((Register) resultObjects[0]).getName().equals("x17")) return null;
					break;
				}
				case 4: {
					if (!mnemonic.equals("add")) return null;
					if (inputObjects.length != 3) return null;
					if (!(inputObjects[0] instanceof Scalar)) return null;
					if (((Scalar) inputObjects[0]).isSigned() == true) return null;
					if (((Scalar) inputObjects[0]).getValue() != 0) return null;
					if (!(inputObjects[1] instanceof Scalar)) return null;
					if (((Scalar) inputObjects[1]).isSigned() == true) return null;
					objcMsgSendRawPointerAddress = objcMsgSendRawPointerAddress + ((Scalar) inputObjects[1]).getValue();
					if (!(inputObjects[2] instanceof Register)) return null;
					if (!(((Register) inputObjects[2]).getName().equals("x17"))) return null;
					if (resultObjects.length != 5) return null;
					if (!(resultObjects[4] instanceof Register)) return null;
					if (!((Register) resultObjects[4]).getName().equals("x17")) return null;
					break;
				}
				case 5: {
					if (!mnemonic.equals("ldr")) return null;
					if (inputObjects.length != 1) return null;
					if (!(inputObjects[0] instanceof Register)) return null;
					if (!(((Register) inputObjects[0]).getName().equals("x17"))) return null;
					if (resultObjects.length != 1) return null;
					if (!(resultObjects[0] instanceof Register)) return null;
					if (!((Register) resultObjects[0]).getName().equals("x16")) return null;
					break;
				}
				case 6: {
					if (!mnemonic.equals("braa")) return null;
					if (inputObjects.length != 1) return null;
					if (!(inputObjects[0] instanceof Register)) return null;
					if (!(((Register) inputObjects[0]).getName().equals("x16"))) return null;
					break;
				}
				default: return null;
			}
			
			instructionIndex++;	
			instruction = instruction.getNext();
		}
		try {
			Program program = function.getProgram();
			AddressSpace theSpace = function.getEntryPoint().getAddressSpace();
			Memory memory = program.getMemory();
			Address objcMsgSendActualAddress = rawPointerAddressToActualAddress(objcMsgSendRawPointerAddress, theSpace, memory);
			boolean isPointingToObjcMsgSend = false;
			for (Address objcMsgSendAddress: objcMsgSendAddresses) {
				if (objcMsgSendAddress.equals(objcMsgSendActualAddress)) isPointingToObjcMsgSend = true;
			}
			if (!isPointingToObjcMsgSend) return null;
			Address selectorActualAddress = rawPointerAddressToActualAddress(selectorRawPointerAddress, theSpace, memory);
			StringBuilder selectorStringBuilder = new StringBuilder();
			byte b;
			while (true) {
				b = memory.getByte(selectorActualAddress);
				if (b == 0) break;
				selectorStringBuilder.append((char) b);
				selectorActualAddress = selectorActualAddress.add(1); 
			}
			return selectorStringBuilder.toString();
		}
    	catch (MemoryAccessException e) { return null; }
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		String functionPrefix = program
				.getOptions("Analyzers")
				.getOptions(ANALYZER_NAME)
				.getString(FUNCTION_PREFIX_OPTION_NAME, DEFAULT_FUNCTION_PREFIX);
		
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbols = symbolTable.getExternalSymbols("_objc_msgSend");
		ArrayList<Address> objcMsgSendAddresses = new ArrayList<Address>();
		for (Symbol symbol: symbols) {
			for (Reference ref: symbol.getReferences()) {
				objcMsgSendAddresses.add(ref.getFromAddress());
			}
		}
		
		FunctionManager functionManager = program.getFunctionManager();
		for (Function function : functionManager.getFunctionsNoStubs(true)) {
        	try {
        		String selectorString = objcMsgSendSelector(function, objcMsgSendAddresses);
        		if (selectorString == null) continue;
		        if (selectorString.length() != 0) function.setName(functionPrefix + selectorString, SourceType.ANALYSIS);
			}
        	catch (DuplicateNameException e) { continue; }
        	catch (InvalidInputException e) { continue; }
		}
		return true;
	}
}
