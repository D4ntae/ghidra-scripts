//TODO write a description for this script
//@author Danko Delimar
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressArrayTableModel;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.ProgramTableModel;
import ghidra.util.task.TaskMonitor;

import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.WindowConstants;
import javax.swing.JScrollPane;
import javax.swing.table.AbstractTableModel;

import docking.widgets.table.GTable;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class FindReferencesScript extends GhidraScript {
	
	private ArrayList<Address> error_addrs = new ArrayList<>();
	private int lookaheadInstructionNum = 24;
 	Address backJump = null; // Used to track where the jump is from
 	Address jumpTo = null; // Used to track where the jump is going
 	
 	private void showGUI(List<TableEntry> entries) {
        CustomTableModel model = new CustomTableModel(entries);
        GTable table = new GTable(model);
        table.setAutoLookupColumn(1);
        
        table.addMouseListener(new MouseAdapter() {
        	public void mouseClicked(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                Address loc = toAddr(Integer.parseInt(((String) table.getValueAt(row, 0)).substring(2), 16));
                println(loc.toString());
                goTo(loc);
        	}
        });
        
        JScrollPane scroll = new JScrollPane(table);

        JFrame frame = new JFrame("References");
        frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        frame.add(scroll);
        frame.setSize(400, 200);
        frame.setVisible(true);
 	}
	
    @Override
    public void run() throws Exception {
        String loggerVtable = "01e022a8";
        String constant = askString("Enter a constant", "Enter the constant in hexadecimal form (0xab): ");
        Address targetAddress = toAddr(loggerVtable);

        List<Reference> validRefs = getReferencesToAddress(targetAddress, constant);
        Set<Reference> refsSet = new HashSet<Reference>();
        for (Reference ref : validRefs) {
        	refsSet.add(ref);
        }

        List<TableEntry> entries = new ArrayList<>();
        Function f;
        for (Reference ref : refsSet) {
        	f = getFunctionFromAddress(ref.getFromAddress());
        	if (f == null) {
        		entries.add(new TableEntry(ref.getFromAddress(), null));
        	} else {
                entries.add(new TableEntry(f.getEntryPoint(), f));
        	}
        }

        showGUI(entries);

    }


    private Address next(Address addr) {
    	return addr.add(4);
    }
    
    private Address previous(Address addr) {
    	return addr.subtract(4);
    }
    
    private Address sendBack(Address addr, int num) {
    	return addr.subtract(4 * num);
    }
    
    private Instruction getInstructionAtAddress(Address address) {
    	// Get the listing object from the current program
    	// Listing is an object to control all code level constructs (https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html)
    	Listing listing = currentProgram.getListing();
    	
    	// Get the instruction at the specified address
        // Instruction object docs (https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Instruction.html)
    	Instruction inst = listing.getInstructionAt(address);
    	
    	return inst;
    }
    
    private Register checkIfCallRegisterWasCopied(Address temp_addr, Register call_reg) {
    	int c = lookaheadInstructionNum;
    	Instruction next_instruction;
     	while (c != 0) {
     		try {
     			next_instruction = getInstructionAtAddress(temp_addr);
     			
         		if (next_instruction.getMnemonicString().equals("b") && next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
         			backJump = temp_addr;
         			jumpTo = (GenericAddress) next_instruction.getOpObjects(0)[0];
         			temp_addr = (GenericAddress) next_instruction.getOpObjects(0)[0];
         			continue;
         		}
     		
         		if (next_instruction.getMnemonicString().startsWith("b") && next_instruction.getRegister(0).getName().equals(call_reg.getName()) ) {
         			break;
         		}
         		
     			if (next_instruction.getMnemonicString().equals("cpy")) {
     				if (next_instruction.getRegister(1).getName().equals(call_reg.getName())) {
     					return next_instruction.getRegister(0);
     				}
     			}
     			temp_addr = next(temp_addr);
     			c -= 1;
     		} catch (Exception e) {
     			temp_addr = next(temp_addr);
     			c -= 1;
     		}
     	}
     	return call_reg;
    }
    
    private Instruction checkIfCallRegisterWasStoredInstruction(Address temp_addr, Register call_reg) {
     	int c = lookaheadInstructionNum;
     	Instruction next_instruction;
    	try {
     		while (c != 0) {
         		next_instruction = getInstructionAtAddress(temp_addr);
         		
         		if (next_instruction.getMnemonicString().equals("b") && next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
         			backJump = temp_addr;
         			jumpTo = (GenericAddress) next_instruction.getOpObjects(0)[0];
         			temp_addr = (GenericAddress) next_instruction.getOpObjects(0)[0];
         			continue;
         		}
         		
         	    if (next_instruction.getMnemonicString().startsWith("b") && next_instruction.getRegister(0).getName().equals(call_reg.getName()) ) {
         			break;
         		}
         		if (next_instruction.getMnemonicString().equals("str")) {
         			if (next_instruction.getRegister(0).getName().equals(call_reg.getName())) {
         				Register store_reg = (Register) next_instruction.getOpObjects(1)[0];
         				Scalar offset = (Scalar) next_instruction.getOpObjects(1)[1];
         				// Find where the register is popped of the stack
         				while (true) {
         					if (next_instruction.getMnemonicString().equals("ldr")) {
         		         		if (((Register)next_instruction.getOpObjects(1)[0]).getName().equals(store_reg.getName()) && ((Scalar)next_instruction.getOpObjects(1)[1]).getValue() == offset.getValue()) {
         	         				return next_instruction;
         		         		}
         					}
         					temp_addr = next(temp_addr);
     						next_instruction = getInstructionAtAddress(temp_addr);
         				}
         			}
         		}
         		temp_addr = next(temp_addr);
         		c -= 1;
     		}

     	} catch (Exception e) {
     		
     	}
    	return null;
    }
    
    private Address findCallAddress(Address temp_addr, Register call_reg) {
    	Instruction next_instruction;
     	while (true) {
     		next_instruction = getInstructionAtAddress(temp_addr);
     		if (next_instruction.getMnemonicString().equals("b") && next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
     			backJump = temp_addr;
     			jumpTo = (GenericAddress) next_instruction.getOpObjects(0)[0];
     			temp_addr = (GenericAddress) next_instruction.getOpObjects(0)[0];
     			continue;
     		}
     		
     		// Ret 3
 			if (!(next_instruction.getMnemonicString().startsWith("bl") || next_instruction.getMnemonicString().startsWith("bx"))) {
 				temp_addr = next(temp_addr);
 				continue;
 			}

     		try {
     			if (next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
     				temp_addr = next(temp_addr);
     				continue;
     			}
         		if (next_instruction.getRegister(0) == null) {
         			temp_addr = next(temp_addr);
         			continue;
         		}
     			
     			if (!next_instruction.getRegister(0).getName().equals(call_reg.getName())) {
     				temp_addr = next(temp_addr);
     				continue;
     			}
     		} catch (Exception e) {
     			temp_addr = next(temp_addr);
     			continue;
     		}
     		
     		return next_instruction.getAddress();
     	}
    }
    
    private String getConstant(Address temp_addr) {
    	Instruction next_instruction;
     	while (true) {
     		if (backJump != null && temp_addr.toString().equals(jumpTo.toString())) {
     			temp_addr = backJump;
     		}

     		next_instruction = getInstructionAtAddress(temp_addr);
     		
     		
     		if (next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
     			temp_addr = previous(temp_addr);
     			continue;
     		}
     		
     		if (next_instruction.getRegister(0) == null) {
     			temp_addr = previous(temp_addr);
     			continue;
     		}
     		
     		if (!next_instruction.getRegister(0).getName().equals("r0")) {
     			temp_addr = previous(temp_addr);
     			continue;
     		}
     		
     		return next_instruction.getOpObjects(1)[0].toString();
     	}
    }
    
    private Instruction getInitialCallRegisterInstruction(Address temp_addr, String reg_name) {
    	Instruction next_instruction;
     	while (true) {
     		next_instruction = getInstructionAtAddress(temp_addr);

     		if (!next_instruction.getMnemonicString().equals("ldr")) {
     			temp_addr = next(temp_addr);
     			continue;
     		}
     		
     		// Check to follow branches.
     		if (next_instruction.getMnemonicString().equals("b") && next_instruction.getOpObjects(0)[0] instanceof GenericAddress) {
     			temp_addr = (GenericAddress) next_instruction.getOpObjects(0)[0];
     			continue;
     		}
     		
     		try {
         		if (!(next_instruction.getOpObjects(1)[0] instanceof Register)) {
         			temp_addr = next(temp_addr);
         			continue;
         		}
     		} catch (Exception e) {
     			temp_addr = next(temp_addr);
     			continue;
     		}

     		
     		if (!((Register)next_instruction.getOpObjects(1)[0]).getName().equals(reg_name)) {
     			temp_addr = next(temp_addr);
     			continue;
     		}
     		return next_instruction;
     	}
    }

    
    private String getConstantFromLoggerFunctionCall(Reference ref) {
    	// Get instruction referencing logger vtable
     	Address from_address = ref.getFromAddress();
     	Address temp_addr = next(from_address);
     	Instruction instruction;
     	
         instruction = getInstructionAtAddress(from_address);
         if (instruction == null) {
        	 return "none";
         }
     	
     	     	
     	if (instruction.getMnemonicString().startsWith("mov") || instruction.getMnemonicString().startsWith("cpy") || instruction.getMnemonicString().startsWith("str")) {
     		instruction = getInstructionAtAddress(next(from_address));
     		return "none";
     	}
     	
     	// Get register into which the logger vtable is loaded
        // Register docs (https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/Register.html)
     	Register reg = instruction.getRegister(0);
     	String reg_name = reg.getName();
     	
     	
        // Register from which the function is called. From here we're gonna look for the call instruction to find the constant.
     	Instruction call_reg_inst = getInitialCallRegisterInstruction(temp_addr, reg_name);
     	Register call_reg = call_reg_inst.getRegister(0);
     	temp_addr = call_reg_inst.getAddress();
     	
     	// Check if the call register was stored on the stack and if so, retrieve the new call register from the stack.
     	call_reg_inst = checkIfCallRegisterWasStoredInstruction(temp_addr, call_reg);
     	if (call_reg_inst != null) {
         	call_reg = call_reg_inst.getRegister(0);
         	temp_addr = call_reg_inst.getAddress();
     	}

     	// Check if the call register was copied to a different register and thus changing the call register.
     	call_reg = checkIfCallRegisterWasCopied(temp_addr, call_reg);

     	
     	// Find the call to the call_register.
     	Address call_addr = findCallAddress(temp_addr, call_reg);

     	// Search back from call_addr to the first mov to r0 beacause the constant is in there
     	return getConstant(call_addr);

       
    }
    

    private Function getFunctionFromAddress(Address addr) {
    	
        FunctionManager functionManager = currentProgram.getFunctionManager();
        Function function = functionManager.getFunctionContaining(addr);
        return function;
    }
    
    private List<Reference> getReferencesToAddress(Address addr, String con) {
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		ReferenceIterator refs = refMgr.getReferencesTo(addr);
		List<Reference> validRefs = new ArrayList<>();
		for (Reference ref : refs) {
			String res = getConstantFromLoggerFunctionCall(ref);
			if (res.equals(con)) {
				validRefs.add(ref);
			}
		}

		return validRefs;
    }

    private class TableEntry {
        private Address address;
        private Function function;

        public TableEntry(Address address, Function function) {
            this.address = address;
            this.function = function;
        }

        public Address getAddress() {
            return address;
        }

        public String getFunctionName() {
            return function != null ? function.getName() : "<unrecognized>";
        }
    }

    private class CustomTableModel extends AbstractTableModel implements ProgramTableModel {
        private List<TableEntry> entries;

        public CustomTableModel(List<TableEntry> entries) {
            this.entries = entries;
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public int getRowCount() {
            return entries.size();
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            TableEntry entry = entries.get(rowIndex);
            if (columnIndex == 0) {
                return "0x" + entry.getAddress().toString();
            } else if (columnIndex == 1) {
                return entry.getFunctionName();
            } else {
                return "unknown";
            }
        }

        @Override
        public String getColumnName(int column) {
            if (column == 0) {
                return "Address";
            } else if (column == 1) {
                return "Function";
            } else {
                return "";
            }
        }

		@Override
		public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
            TableEntry entry = entries.get(modelRow);
            
			return new ProgramLocation(currentProgram, entry.getAddress());
		}

		@Override
		public ProgramSelection getProgramSelection(int[] modelRows) {
			AddressSet as = new AddressSet();
			for (int row : modelRows) {
				as.add(entries.get(row).getAddress());
			}
			return new ProgramSelection(as);
		}

		@Override
		public Program getProgram() {
			return currentProgram;
		}
    }
}
