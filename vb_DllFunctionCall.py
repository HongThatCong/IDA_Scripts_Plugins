# pylint: disable=C0103,C0114,C0116

################################################################################
#
#   Copyright (C) 2014  Cisco Systems, Inc./SourceFire, Inc.
#
#   Author: Angel M. Villegas (anvilleg [at] sourcefire [dot] com)
#           Frederick W Sell (frsell [at] cisco [dot] com)
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   Last Modified: July 29, 2022
#   Description:
#       IDA Python script that locates all references to DllFunctionCall,
#       creates structures, applies structures to the argument provided to
#       DllFunctionCall, labels structures based on the API to be loaded,
#       defines and renames functions used to dynamically load API, and
#       registers the function dynamically loaded. Upon completion, a list of
#       all dynamically loaded API is printed out
#
#
#   VB DllFunctionCall(DllFunctionCallStruct * dllInfo);
#   ============================================================================
#           typedef struct _DynamicHandles {
#   0x00
#   0x04        HANDLE hModule;
#   0x08        VOID * fnAddress
#   0x0C
#           } DynamicHandles;
#
#           typedef struct _DllFunctionCallStruct {
#   0x00        LPCSTR lpDllName;
#   0x04        LPTSTR lpExportName;
#   0x08
#   0x09
#               // 4 bytes means it is a LPTSTR *
#               // 2 bytes means it is a WORD (the export's numeric Ordinal)
#   0x0A        char addressAlignment;
#   0x0B
#   0x0C        DynamicHandles * sHandleData;
#   0x10
#           } DllFunctionCallStruct;
#
################################################################################

import idc
import idaapi
import idautils

# Print out dynamically loaded API
def printAPI(data):
    formatStr = '0x{0:<12X} {1:32} {2}'
    for dll in sorted(data.keys()):
        for fn in sorted(data[dll]):
            print(formatStr.format(fn[0], fn[1], dll))

# Find the start of the function
# Expects ea to be the address of loc_XXXXXX
def defineFunction(ea):
    # Move to where we believe the stub starts
    eaStart = ea - 11

    # Do check if this is the stub we support
    if ((idc.get_wide_byte(eaStart) == 0xA1) and (idc.get_wide_word(eaStart + 5) == 0xC00B) and \
        (idc.get_wide_byte(eaStart + 7) == 0x74) and (idc.get_wide_word(eaStart + 9) == 0xE0FF)):

        # Create function if IDA did not create it already
        if not idaapi.get_func(eaStart):
            idc.del_items(eaStart, idc.DELIT_SIMPLE, 0x18)
            idc.create_insn(eaStart)
            if 0 == idc.add_func(eaStart, idc.BADADDR):
                print(f'\t[!] Error: Unable to define function at 0x{eaStart:X}')
    else:
        print(f'\t[!] Error: Unable to find function start address at 0x{eaStart:X}')

    return eaStart

def createDllFunctionCallStruct():
    # Create DynamicHandles argument sub structure
    _subStructId = idc.add_struc(-1, HANDLES_STRUCT_NAME, 0)
    idc.add_struc_member(_subStructId, 'dwErrorCode', 0x0, idc.FF_DWORD | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_subStructId, 'hModule', 0x4, idc.FF_DWORD | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_subStructId, 'pfnFunction', 0x8, idc.FF_DWORD | idc.FF_DATA, -1, 4)

    # Create DllFunctionCall argument structure
    _structId = idc.add_struc(-1, DLL_FUNCTION_CALL_STRUCT_NAME, 0)
    idc.add_struc_member(_structId, 'pszDllName', 0x0, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_structId, 'pszFunctionName', 0x4, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_structId, 'wExportOrd', 0x8, idc.FF_WORD | idc.FF_DATA, -1, 2)
    idc.add_struc_member(_structId, 'fFlags', 0xA, idc.FF_WORD | idc.FF_DATA, -1, 2)
    idc.add_struc_member(_structId, 'pDllTemplateInfo', 0xC, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.SetType(idc.get_member_id(_structId, 0xC), HANDLES_STRUCT_NAME + " *")
    idc.add_struc_member(_structId, 'pResource', 0x10, idc.FF_DWORD | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_structId, 'pEntry', 0x14, idc.FF_DWORD | idc.FF_DATA, -1, 4)

    return _structId

DLL_FUNCTION_CALL_STRUCT_NAME = 'serDllTemplate'
HANDLES_STRUCT_NAME = 'epiDllTemplateInfo'
dynamicAPI = {}
loadAPI = 0

print("Starting...")

# Check if struct exists, if not, create it
structId = idc.get_struc_id(DLL_FUNCTION_CALL_STRUCT_NAME)
if idc.BADADDR == structId:
    print(f'\t[+] Structure "{DLL_FUNCTION_CALL_STRUCT_NAME}" does not exist, creating structure...')
    structId = createDllFunctionCallStruct()

for xref in idautils.CodeRefsTo(idc.get_name_ea_simple('DllFunctionCall'), 1):
    structInstr = xref - 0xA

    # The instruction should be push 0x????????
    if idc.print_insn_mnem(structInstr) == 'push' and idc.get_operand_type(structInstr, 0) == idc.o_imm:
        # Set the operand type to an offset
        idc.op_plain_offset(structInstr, 0, 0)

        # Get struct offset and apply structure to it
        structOffset = idc.get_operand_value(structInstr, 0)
        idc.del_items(structOffset, idc.DELIT_DELNAMES, 0x18)
        idc.create_struct(structOffset, -1, DLL_FUNCTION_CALL_STRUCT_NAME)
        strOffset = idc.get_wide_dword(structOffset)
        lpDllName = idc.get_strlit_contents(strOffset, -1, idc.STRTYPE_C)
        idc.del_items(strOffset, idc.DELIT_SIMPLE, len(lpDllName) + 1)
        idc.create_strlit(strOffset, strOffset + len(lpDllName) + 1)
        strOffset = idc.get_wide_dword(structOffset + 4)
        lpFunctionName = idc.get_strlit_contents(strOffset, -1, idc.STRTYPE_C)
        if not lpFunctionName:
            lpFunctionName = lpDllName
            if idc.get_wide_word(structOffset + 0xA) & 2:
                lpFunctionName = f"{lpDllName}_Ord_{idc.get_wide_word(structOffset + 0x8):d}"
        lpDllName = lpDllName.decode("utf-8")
        lpFunctionName = lpFunctionName.decode("utf-8")
        idc.del_items(strOffset, idc.DELIT_SIMPLE, len(lpFunctionName) + 1)
        idc.create_strlit(strOffset, strOffset + len(lpFunctionName) + 1)
        idc.set_name(structOffset, f'struct_{lpFunctionName}', idaapi.SN_FORCE)

        # Get sub structure address, apply structure, and apply name to it
        subStructAddr = idc.get_wide_dword(structOffset + 0xC)
        idc.del_items(subStructAddr, idc.DELIT_DELNAMES, 0xC)
        idc.create_struct(subStructAddr, 0xC, HANDLES_STRUCT_NAME)
        idc.set_name(subStructAddr, f'subStruct_{lpFunctionName}', idaapi.SN_FORCE)

        # Check if a function is already defined
        pfn = idaapi.get_func(structInstr)
        if not pfn:
            fnAddress = defineFunction(structInstr)
        else:
            fnAddress = pfn.start_ea
        if not idc.set_name(fnAddress, lpFunctionName, idaapi.SN_FORCE):
            print(f'\t[!] Error: Failed to set function name {lpFunctionName} at 0x{fnAddress:X}')

        idc.set_cmt(fnAddress, f'pfn{lpFunctionName}', 0)
        idc.set_func_cmt(fnAddress, f"{lpDllName}_{lpFunctionName}", 0)

        # Add API to dynamically loaded API
        if lpDllName not in dynamicAPI:
            dynamicAPI[lpDllName] = []
        if lpFunctionName not in dynamicAPI[lpDllName]:
            dynamicAPI[lpDllName].append((fnAddress, lpFunctionName))
            loadAPI += 1

if loadAPI == 0:
    print("Not import DllFunctionCall function from msvbvmxx.dll !")
else:
    print(f'Printing dynamically loaded API ({loadAPI} total)...')
    printAPI(dynamicAPI)
