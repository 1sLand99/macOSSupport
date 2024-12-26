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

import java.util.Arrays;
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
	private static final String DEFAULT_FUNCTION_PREFIX = "objc_msgSend$";
	private static final String ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS_OPTION_NAME = "Only rename default-named (FUN_*) functions";
	private static final boolean DEFAULT_ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS = true;

	public MacOSSupportAnalyzer() {
		super(
				ANALYZER_NAME,
				"This will rename any functions that only call `objc_msgSend` after the selector.",
				AnalyzerType.FUNCTION_ANALYZER);
		this.setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("AARCH64") &&
				program.getExecutableFormat().equals("Mac OS X Mach-O") &&
				program.getLanguage().isBigEndian() == false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(FUNCTION_PREFIX_OPTION_NAME, OptionType.STRING_TYPE, DEFAULT_FUNCTION_PREFIX, null,
				"The prefix to append to the selector name before renaming the function after it.");
		options.registerOption(ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS_OPTION_NAME, OptionType.BOOLEAN_TYPE,
				DEFAULT_ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS, null,
				"Only rename functions that are named with the default prefix (FUN_*)");
	}

	private Address rawPointerAddressToActualAddress(long pointerAddress, AddressSpace addressSpace, Memory memory)
			throws MemoryAccessException {
		Address paramPointerAddress = addressSpace.getAddress(pointerAddress);
		byte[] paramPointer = new byte[8];
		memory.getBytes(paramPointerAddress, paramPointer, 0, 8);
		long rawActualAddress = 0;
		for (int i = 0; i < paramPointer.length; i++)
			rawActualAddress |= (((long) paramPointer[i] & 0xFF) << (8 * i));
		Address actualAddress = addressSpace.getAddress(rawActualAddress);
		return actualAddress;
	}

	// In many ARM64 binaries on macOS, each `objc_msgSend` call is stubbed out into
	// its own function. This function attempts to identify these functions and
	// return the selector string that is passed to `objc_msgSend`.
	private String objcMsgSendSelector(
			Function function, ArrayList<Address> objcMsgSendAddresses,
			boolean onlyRenameDefaultNamedFunctions) {
		long selectorRawPointerAddress = 0;
		long objcMsgSendRawPointerAddress = 0;
		if (function.getName().startsWith("FUN_") != true && onlyRenameDefaultNamedFunctions)
			return null;
		if (function.getParameterCount() != 0)
			return null;
		Listing listing = function.getProgram().getListing();
		Address entryPoint = function.getEntryPoint();
		CodeUnit entryPointCodeUnit = listing.getCodeUnitAt(entryPoint);
		if (!(entryPointCodeUnit instanceof Instruction))
			return null;
		Instruction instruction = (Instruction) entryPointCodeUnit;
		int instructionIndex = 1;

		// In some cases, the function uses one less instruction. We'll call this the
		// "simpler version" and modify the detection logic accordingly.
		boolean isSimplerVersion = false;
		while (instructionIndex <= 6) {
			if (instruction == null)
				return null;
			String mnemonic = instruction.getMnemonicString();
			Object[] inputObjects = instruction.getInputObjects();
			Object[] resultObjects = instruction.getResultObjects();
			switch (instructionIndex) {
				// The first instruction loads a constant into x1.
				case 1: {
					if (!mnemonic.equals("adrp"))
						return null;

					if (inputObjects.length != 1)
						return null;
					if (!(inputObjects[0] instanceof Scalar))
						return null;
					if (((Scalar) inputObjects[0]).isSigned() == true)
						return null;
					selectorRawPointerAddress = ((Scalar) inputObjects[0]).getValue();

					if (resultObjects.length != 1)
						return null;
					if (!(resultObjects[0] instanceof Register))
						return null;
					if (!((Register) resultObjects[0]).getName().equals("x1"))
						return null;
					break;
				}

				// The second instruction loads the value at the address [x1 + offset] into x1,
				// which loads the pointer to the selector string into x1.
				case 2: {
					if (!mnemonic.equals("ldr"))
						return null;

					Register register = (Register) Arrays.stream(inputObjects)
							.filter(obj -> obj instanceof Register)
							.findFirst()
							.orElse(null);
					if (register == null || !register.getName().equals("x1"))
						return null;

					Scalar scalar = (Scalar) Arrays.stream(inputObjects)
							.filter(obj -> obj instanceof Scalar)
							.findFirst()
							.orElse(null);

					long scalarValue = 0;

					if (scalar != null) {
						scalarValue = scalar.getValue();
					}

					selectorRawPointerAddress = selectorRawPointerAddress + scalarValue;

					if (resultObjects.length != 1)
						return null;
					if (!(resultObjects[0] instanceof Register))
						return null;
					if (!((Register) resultObjects[0]).getName().equals("x1"))
						return null;
					break;
				}

				// The third instruction loads a constant into x17 or x16.
				case 3: {
					if (!mnemonic.equals("adrp"))
						return null;

					if (inputObjects.length != 1)
						return null;
					if (!(inputObjects[0] instanceof Scalar))
						return null;
					if (((Scalar) inputObjects[0]).isSigned() == true)
						return null;
					objcMsgSendRawPointerAddress = ((Scalar) inputObjects[0]).getValue();

					if (resultObjects.length != 1)
						return null;
					if (!(resultObjects[0] instanceof Register))
						return null;
					String resultRegisterName = ((Register) resultObjects[0]).getName();
					if (!resultRegisterName.equals("x17") && !resultRegisterName.equals("x16"))
						return null;
					if (resultRegisterName.equals("x16")) {
						isSimplerVersion = true;
						break;
					}
					break;
				}

				// The fourth instruction adds a constant to x17, which loads a
				// pointer to the `objc_msgSend` function into x17.
				//
				// In simpler functions, this instruction is skipped, and the addition is done
				// in the `ldr` instruction.
				case 4: {
					if (isSimplerVersion) {
						break;
					}
					if (!mnemonic.equals("add"))
						return null;
					// For some reason, Ghidra seems to include a second scalar with a value of 0
					// in the input objects. To cover our bases, we'll sum all the scalar values.
					long scalarSum = Arrays.stream(inputObjects)
							.filter(obj -> obj instanceof Scalar)
							.map(obj -> (Scalar) obj)
							.filter(scalar -> !scalar.isSigned())
							.mapToLong(Scalar::getValue)
							.sum();
					objcMsgSendRawPointerAddress = objcMsgSendRawPointerAddress + scalarSum;

					Register inputRegister = (Register) Arrays.stream(inputObjects)
							.filter(obj -> obj instanceof Register)
							.findFirst()
							.orElse(null);
					if (inputRegister == null || !inputRegister.getName().equals("x17"))
						return null;

					// Ghidra includes many temporary registers in the result objects, but we only
					// want the actual result register. We'll filter out the temporary register.
					Register resultRegister = (Register) Arrays.stream(resultObjects)
							.filter(obj -> obj instanceof Register)
							.filter(register -> !((Register) register).getName().startsWith("tmp"))
							.findFirst()
							.orElse(null);
					if (resultRegister == null || !resultRegister.getName().equals("x17"))
						return null;

					break;
				}

				// The fifth instruction loads the value at the address [x17] into x16,
				// which loads the address of the `objc_msgSend` function into x16.
				//
				// In simpler functions, this is the fourth instruction and it operates only on
				// x16, performing the addition (skipped above) and load in one step.
				case 5: {
					if (!mnemonic.equals("ldr"))
						return null;
					if (isSimplerVersion) {
						// The simpler version combines the addition and load into one instruction.
						Register inputRegister = (Register) Arrays.stream(inputObjects)
								.filter(obj -> obj instanceof Register)
								.findFirst()
								.orElse(null);
						if (!(inputRegister.getName().equals("x16")))
							return null;
						long scalarSum = Arrays.stream(inputObjects)
								.filter(obj -> obj instanceof Scalar)
								.map(obj -> (Scalar) obj)
								.filter(scalar -> !scalar.isSigned())
								.mapToLong(Scalar::getValue)
								.sum();
						objcMsgSendRawPointerAddress = objcMsgSendRawPointerAddress + scalarSum;
					} else {
						if (inputObjects.length != 1)
							return null;
						if (!(inputObjects[0] instanceof Register))
							return null;
						if (!(((Register) inputObjects[0]).getName().equals("x17")))
							return null;
					}

					if (resultObjects.length != 1)
						return null;
					if (!(resultObjects[0] instanceof Register))
						return null;
					if (!((Register) resultObjects[0]).getName().equals("x16"))
						return null;
					break;
				}

				// The sixth instruction branches to the `objc_msgSend` function,
				// using the address in x16. The selector string in x1 is used as
				// the second argument to the `objc_msgSend` call.
				//
				// In simpler functions, this is the fifth instruction, but it is otherwise
				// identical (see above for differences).
				case 6: {
					// While we could be more specific here, as it appears that the actual
					// implementations only use specific branch instructions, we'll try to
					// capture the many branch instructions in ARM64.
					// TODO: Is "starts with 'br'" too broad?
					if (!mnemonic.startsWith("br"))
						return null;

					if (inputObjects.length != 1)
						return null;
					if (!(inputObjects[0] instanceof Register))
						return null;
					if (!(((Register) inputObjects[0]).getName().equals("x16")))
						return null;
					break;
				}
				default:
					return null;
			}

			// In cases where the function is using the simpler version, the instruction
			// index and the index of the actual instruction we're evaluating may be out
			// of sync. While this isn't ideal, it lets us reuse the same logic for both
			// the regular and simpler versions.

			boolean isSkippingInstruction4 = isSimplerVersion && instructionIndex == 4;
			if (!isSkippingInstruction4) {
				// If we're skipping instruction 4, we don't want to get the next instruction as
				// we haven't actually evaluated the current instruction.
				instruction = instruction.getNext();
			}
			instructionIndex++; // We always increment the instruction index, because that's what the case
								// statement is based on. TODO: Maybe handle this better?
		}
		try {
			Program program = function.getProgram();
			AddressSpace theSpace = function.getEntryPoint().getAddressSpace();
			Memory memory = program.getMemory();
			Address objcMsgSendActualAddress = rawPointerAddressToActualAddress(
					objcMsgSendRawPointerAddress, theSpace, memory);

			// Perform a final sanity check to ensure that x16 is actually pointing to
			// `objc_msgSend`, and not some other function.
			boolean isPointingToObjcMsgSend = false;
			for (Address objcMsgSendAddress : objcMsgSendAddresses) {
				if (objcMsgSendAddress.equals(objcMsgSendActualAddress))
					isPointingToObjcMsgSend = true;
			}
			if (!isPointingToObjcMsgSend)
				return null;

			// Parse the selector string from the pointer in x1.
			Address selectorActualAddress = rawPointerAddressToActualAddress(selectorRawPointerAddress, theSpace,
					memory);
			StringBuilder selectorStringBuilder = new StringBuilder();
			byte b;
			while (true) {
				b = memory.getByte(selectorActualAddress);
				if (b == 0)
					break;
				selectorStringBuilder.append((char) b);
				selectorActualAddress = selectorActualAddress.add(1);
			}
			return selectorStringBuilder.toString();
		} catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		String functionPrefix = program
				.getOptions("Analyzers")
				.getOptions(ANALYZER_NAME)
				.getString(FUNCTION_PREFIX_OPTION_NAME, DEFAULT_FUNCTION_PREFIX);

		boolean onlyRenameDefaultNamedFunctions = program
				.getOptions("Analyzers")
				.getOptions(ANALYZER_NAME)
				.getBoolean(ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS_OPTION_NAME,
						DEFAULT_ONLY_RENAME_DEFAULT_NAMED_FUNCTIONS);

		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbols = symbolTable.getExternalSymbols("_objc_msgSend");
		ArrayList<Address> objcMsgSendAddresses = new ArrayList<Address>();
		for (Symbol symbol : symbols) {
			for (Reference ref : symbol.getReferences()) {
				objcMsgSendAddresses.add(ref.getFromAddress());
			}
		}

		FunctionManager functionManager = program.getFunctionManager();
		for (Function function : functionManager.getFunctionsNoStubs(true)) {
			try {
				String selectorString = objcMsgSendSelector(
						function, objcMsgSendAddresses,
						onlyRenameDefaultNamedFunctions);
				if (selectorString == null)
					continue;
				if (selectorString.length() != 0)
					function.setName(functionPrefix + selectorString, SourceType.ANALYSIS);
			} catch (DuplicateNameException e) {
				continue;
			} catch (InvalidInputException e) {
				continue;
			}
		}
		return true;
	}
}
