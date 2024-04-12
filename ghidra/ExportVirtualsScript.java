// Imports virtuals from txt files
// @author Cvolton
// @category GeodeSDK

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;

public class ExportVirtualsScript extends GhidraScript {
    FunctionManager functionManager = null;
    Address autoreleaseAddress = null;
    public void run() throws Exception {
        functionManager = currentProgram.getFunctionManager();

        
        findVtables();
        

    }

    public void findVtables() throws Exception {
        doStuff("vftable");
        doStuff("`vftable'");
        
    }

    public void doStuff(String symbolName) throws Exception {
        int pointerSize = currentProgram.getDefaultPointerSize();

        SymbolTable symbolTable = currentProgram.getSymbolTable();

        SymbolIterator symbolIterator = symbolTable.getSymbols(symbolName);

        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();

            //if(!symbol.getParentNamespace().getName().equals("CustomListView")) continue;
            if(!symbol.getParentNamespace().getParentNamespace().getName().equals("Global")) continue;
            
            // Access properties of the symbol as needed
            //println("Symbol: " + symbol.getName() + ", Namespace: " + symbol.getParentNamespace().getName() + " Address: " + symbol.getAddress());
            // Add any other processing you need to do with the symbol

            /*var path = Paths.get("C:\\Users\\brabe\\Documents\\git\\geode\\_virtuals\\" + symbol.getParentNamespace().getName() + ".txt");
            if (!Files.exists(path)) {
                continue;
            }*/

            //List<String> lines = Files.readAllLines(path, java.nio.charset.StandardCharsets.UTF_8);
            //println("lines: " + lines.size());

            Address addr = symbol.getAddress();
            Data data = getDataAt(addr);
            DataType structDataType = data.getDataType();

            if (structDataType instanceof Structure) {

                Structure struct = (Structure) structDataType;

                //recoverclassesfromrtti gives us the structs in the same order! so this is uniquely identifying enough!!
                String structName = struct.getName();
                String output = "";

                var path = Paths.get("C:\\Users\\brabe\\Documents\\git\\geode\\_windowsVirtuals\\" + structName + ".txt");
                
                // Iterate over the components (members) of the structure
                DataTypeComponent[] components = struct.getDefinedComponents();
                //if(lines.size() != components.length) continue;
                println("Structure name: " + struct.getName());
                println("Number of components: " + components.length);
                for (DataTypeComponent component : components) {
                    println("Member name: " + component.getFieldName() + ", Offset: " + component.getOffset() + ", Address: " + Integer.toHexString(data.getInt(component.getOffset())));
                    Address functionAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(data.getInt(component.getOffset()));
                    Function function = functionManager.getFunctionAt(functionAddress);
                    if (function != null) {
                        output +=  function.getParentNamespace().getName(true) + " : " + function.getName() + "\n";
                    } else {
                        println("NO FUNCTION AT " + functionAddress);
                        break;
                    }
                    
                    
                    // You can access other properties of the component as needed
                }

                Files.write(path, output.getBytes());
            } else {
                println("Data at address is not a structure.");
            }

            /*while(true) {
                println("addr: " + addr.toString());
                //todo: 32bit only
                Data data = getDataAt(addr);
                println("data type: " + data.getDataType());
                if (data == null) {
                    break;
                }
                addr = addr.add(pointerSize);
                Function function = functionManager.getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(data.getInt(0)));
                if (function != null) {
                    println("Function: " + function.getName() + " Address: " + function.getEntryPoint());
                }
            }*/

            //break;
        }
    }

}
