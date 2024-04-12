import idautils
import idaapi

def get_all_symbols():
    symbols = []
    #for ea in idautils.Functions():
    #    func_name = idaapi.get_func_name(ea)
    #    symbols.append(func_name)
        
    for segea in idautils.Segments():
        seg = idaapi.getseg(segea)
        seg_end = seg.end_ea
        for head in idautils.Heads(segea, seg_end):
            name = idaapi.get_name(head)
            #if name != "" and not name.startswith("loc_") and not name.startswith("qword_") and not name.startswith("byte_"):
            if name.startswith("_ZTV"):
                symbols.append(f"{idaapi.get_name(head)} : {hex(head)}")
            #if idaapi.isCode(idaapi.getFlags(head)):
            #    if idaapi.has_name(idaapi.get_flags(head)) and not idaapi.get_name(head).startswith("loc_"):
    return symbols

with open("vtables.txt", "w") as f:
    all_symbols = get_all_symbols()
    for symbol in all_symbols:
        f.write(symbol + "\n")