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
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;

public class ImportVirtualsScript extends GhidraScript {
    FunctionManager functionManager = null;
    Address autoreleaseAddress = null;
    ScriptWrapper wrapper;
    public void run() throws Exception {
        this.wrapper = new ScriptWrapper(this);
        functionManager = currentProgram.getFunctionManager();

        
        findVtables();
        

    }

    public void findVtables() throws Exception {
        String emptyReturns = "";
        String namespaceMismatches = "";

        int pointerSize = currentProgram.getDefaultPointerSize();

        // Iterate over each function
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Get an iterator over all symbols with the specified name
        SymbolIterator symbolIterator = symbolTable.getSymbols("vftable");

        // Iterate over each symbol with the specified name
        while (symbolIterator.hasNext()) {
            Symbol symbol = symbolIterator.next();
            //Structure struct = (Structure) structDataType;

            //String structName = struct.getName();
            
            //if(!symbol.getParentNamespace().getName().equals("BoomListView")) continue;
            
            // Access properties of the symbol as needed
            //println("Symbol: " + symbol.getName() + ", Namespace: " + symbol.getParentNamespace().getName() + " Address: " + symbol.getAddress());
            // Add any other processing you need to do with the symbol
            
            //println("lines: " + lines.size());
            
            Address addr = symbol.getAddress();
            Data data = getDataAt(addr);
            DataType structDataType = data.getDataType();
            
            if (structDataType instanceof Structure) {
                Structure struct = (Structure) structDataType;
                String structName = struct.getName();
                if(structName.contains("<")) continue;
                //recoverclassesfromrtti gives us the structs in the same order! so this is uniquely identifying enough!!
                var path = Paths.get("C:\\Users\\brabe\\Documents\\git\\geode\\_windowsVirtuals\\" + structName + ".txt");
                if (!Files.exists(path)) {
                    continue;
                }
    
                List<String> lines = Files.readAllLines(path, java.nio.charset.StandardCharsets.UTF_8);
                
                
                // Iterate over the components (members) of the structure
                DataTypeComponent[] components = struct.getDefinedComponents();
                if(lines.size() != components.length) continue;
                //println("Structure name: " + struct.getName());
                //println("Number of components: " + components.length);
                //println("lines: " + lines.size());
                if(lines.size() != components.length) {
                    println("Structure name: " + struct.getName() + " lines: " + lines.size() + " components: " + components.length);
                    continue;
                }
                int i = -1;
                for (DataTypeComponent component : components) {
                    i++;
                    //println("Member name: " + component.getFieldName() + ", Offset: " + component.getOffset() + ", Address: " + Integer.toHexString(data.getInt(component.getOffset())));
                    int addressNum = data.getInt(component.getOffset());
                    Address functionAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addressNum);
                    Function function = functionManager.getFunctionAt(functionAddress);
                    if (function != null) {
                        String namespaceName = lines.get(i).split(" : ")[0];
                        String functionName = lines.get(i).split(" : ")[1];

                        //println("Namespace: " + namespaceName);
                        //println("Parent namespace: " + function.getParentNamespace().getName(true));
                        int[] emptyReturnAddresses = new int[]{0x41bf90, 0x495c0, 0x41d240, 0x4095c0};
                        boolean emptyReturnFound = false;
                        for(int emptyReturnAddress : emptyReturnAddresses) {
                            if(addressNum == emptyReturnAddress) {
                                emptyReturns += namespaceName + " : " + functionName + "\n";
                                emptyReturnFound = true;
                            }
                        }

                        int[] destructorDontCareAddresses = new int[]{0x41bf90, 0x495c0, 0x41d240, 0x4095c0};
                        boolean destructorDontCareFound = false;
                        for(int destructorDontCareAddress : destructorDontCareAddresses) {
                            if(addressNum == destructorDontCareAddress) {
                                destructorDontCareFound = true;
                            }
                        }

                        if(emptyReturnFound || destructorDontCareFound) {
                            continue;
                        }

                        if(!namespaceName.equals(function.getParentNamespace().getName(true).replace("LIBCOCOS2D.DLL::",""))) {
                            println("Mismatched namespace for " + function.getName() + " : " + functionName + " (" + namespaceName + " vs " + function.getParentNamespace().getName(true) + ") at address " + functionAddress);
                            namespaceMismatches += functionAddress + " : " + namespaceName + " : " + functionName + " : " + function.getParentNamespace().getName(true) + function.getName() + "\n";
                            continue;
                        }
                        //Namespace namespace = namespaces.get(namespaceName);

                        /*if (namespace == null) {
                            namespace = wrapper.addOrGetNamespace(namespaceName);
                            println("Could not find namespace " + namespaceName);
                        }*/

                        println("Function: " + function.getName() + " is: " + functionName + " at Address: " + function.getEntryPoint());
                        function.setName(functionName, SourceType.USER_DEFINED);
                    } else {
                        println("NO FUNCTION AT " + functionAddress);
                        break;
                    }
                    //println("Member name: " + component.getFieldName() + ", Offset: " + component.getOffset() + ", Address: " + Integer.toHexString(data.getInt(component.getOffset())));
                    
                    
                    // You can access other properties of the component as needed
                }
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

            Files.write(Paths.get("C:\\Users\\brabe\\Documents\\git\\geode\\_windowsVirtuals\\_emptyReturns.txt"), emptyReturns.getBytes());
            Files.write(Paths.get("C:\\Users\\brabe\\Documents\\git\\geode\\_windowsVirtuals\\_namespaceMismatches.txt"), namespaceMismatches.getBytes());
        }
    }

}
