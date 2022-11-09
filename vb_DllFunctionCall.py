# pylint: disable=C0103,C0114,C0116

################################################################################
#
#   Copyright (C) 2014  Cisco Systems, Inc.
#
#   Author: Angel M. Villegas (anvilleg [at] sourcefire [dot] com)
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
#   Last Modified: August 8, 2014
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

#   Print out dynamically loaded API
def printAPI(data):
    formatStr = '0x{0:<12X} {1:32} {2}'
    for dll in sorted(data.keys()):
        for fn in sorted(data[dll]):
            print(formatStr.format(fn[0], fn[1], dll))

#   Find the start of the function
#   Expects ea to be the address of loc_XXXXXX
def defineFunction(ea):
    #   Function follows the format:
    #       mov     eax, dword_ZZZZZZZZ
    #       or      eax, eax
    #       jz      short loc_XXXXXXXX
    #       jmp     eax
    # loc_XXXXXX:
    #       push    YYYYYYYYh
    #       mov     eax, offset DllFunctionCall
    #       call    eax ; DllFunctionCall
    #       jmp     eax

    jmpInstr = idautils.DecodePreviousInstruction(ea).ea
    jzInstr = idautils.DecodePreviousInstruction(jmpInstr).ea
    orInstr = idautils.DecodePreviousInstruction(jzInstr).ea
    movInstr = idautils.DecodePreviousInstruction(orInstr).ea
    if (idc.print_insn_mnem(jmpInstr) != 'jmp') and (idc.print_insn_mnem(jzInstr) != 'jz') and \
        (idc.print_insn_mnem(orInstr) != 'or') and (idc.print_insn_mnem(movInstr) != 'mov'):
        print('\t[!] Error: Unable to find function start address')

    if 0 == idc.add_func(movInstr):
        print(f'\t[!] Error: Unable to define function at 0x{movInstr:X}')

def createDllFunctionCallStruct():
    #   Create DynamicHandles argument sub structure
    _subStructId = idc.add_struc(-1, HANDLES_STRUCT_NAME, 0)
    idc.add_struc_member(_subStructId, 'hModule', 0x0, idc.FF_DWORD | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_subStructId, 'fnAddress', 0x4, idc.FF_DWORD | idc.FF_DATA, -1, 4)

    #   Create DllFunctionCall argument structure
    _structId = idc.add_struc(-1, DLL_FUNCTION_CALL_STRUCT_NAME, 0)
    idc.add_struc_member(_structId, 'lpDllName', 0x0, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_structId, 'lpExportName', 0x4, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.add_struc_member(_structId, 'sizeOfExportName', 0xA, idc.FF_BYTE | idc.FF_DATA, -1, 1)
    idc.add_struc_member(_structId, 'ptrHandles', 0xC, idc.FF_DWORD | idc.FF_0OFF | idc.FF_DATA, -1, 4)

    return _structId

DLL_FUNCTION_CALL_STRUCT_NAME = 'DllFunctionCallStruct'
HANDLES_STRUCT_NAME = 'DynamicHandles'
dynamicAPI = {}
loadAPI = 0

print("Starting...")

#   Check if struct exists, if not, create it
structId = idc.get_struc_id(DLL_FUNCTION_CALL_STRUCT_NAME)
if idc.BADADDR == structId:
    print(f'\t[+] Structure "{DLL_FUNCTION_CALL_STRUCT_NAME}" does not exist, creating structure...')
    structId = createDllFunctionCallStruct()

for xref in idautils.CodeRefsTo(idc.get_name_ea_simple('DllFunctionCall'), 1):
    instr =  xref
    prevInstr = idautils.DecodePreviousInstruction(xref).ea
    structInstr = idautils.DecodePreviousInstruction(prevInstr).ea

    #   The instruction should be push 0x????????
    if idc.print_insn_mnem(structInstr) == 'push' and idc.get_operand_type(structInstr, 0) == 0x05:
        #   Set the operand type to an offset
        idc.op_plain_offset(structInstr, 0, 0)

        #   Get struct offset and apply structure to it
        structOffset = idc.get_operand_value(structInstr, 0)
        idc.del_items(structOffset, idc.DELIT_SIMPLE, 16)
        idc.create_struct(structOffset, 16, DLL_FUNCTION_CALL_STRUCT_NAME)
        strOffset = idc.get_wide_dword(structOffset)
        lpDllName = idc.get_strlit_contents(strOffset, -1, idc.STRTYPE_C)
        idc.del_items(strOffset, idc.DELIT_SIMPLE, len(lpDllName) + 1)
        idc.create_strlit(strOffset, strOffset + len(lpDllName) + 1)
        strOffset = idc.get_wide_dword(structOffset + 4)
        lpFunctionName = idc.get_strlit_contents(strOffset, -1, idc.STRTYPE_C)
        if not lpFunctionName:
            lpFunctionName = lpDllName
        lpDllName = lpDllName.decode("utf-8")
        lpFunctionName = lpFunctionName.decode("utf-8")
        idc.del_items(strOffset, idc.DELIT_SIMPLE, len(lpFunctionName) + 1)
        idc.create_strlit(strOffset, strOffset + len(lpFunctionName) + 1)
        idc.set_name(structOffset, 'struct_{0}'.format(lpFunctionName), idaapi.SN_FORCE)

        #   Get sub structure address, apply structure, and apply name to it
        subStructAddr = idc.get_wide_dword(structOffset + 0xC)
        idc.del_items(subStructAddr, idc.DELIT_SIMPLE, 8)
        idc.create_struct(subStructAddr, 8, HANDLES_STRUCT_NAME)
        idc.set_name(subStructAddr, 'subStruct_{0}'.format(lpFunctionName), idaapi.SN_FORCE)

        #   Check if a function is already defined
        if '' == idc.get_func_name(structInstr):
            print('\t[+] Function was not defined, creating function ...')
            defineFunction(structInstr)

        #   Redefine function name to something more descriptive
        lpFnName = '{0}'.format(lpFunctionName)
        fnAddress = idaapi.get_func(structInstr).start_ea
        if not idc.set_name(fnAddress, lpFnName, idaapi.SN_FORCE):
            print('\t[!] Error: Failed to set function name')
        else:
            print('\t[+] Function "{0}" set at 0x{1:x}'.format(lpFnName, fnAddress))
            idc.set_name(idc.get_operand_value(fnAddress, 1), 'lpfn{0}'.format(lpFunctionName), idaapi.SN_FORCE)

        #   Add API to dynamically loaded API
        if lpDllName not in dynamicAPI:
            dynamicAPI[lpDllName] = []
        if lpFunctionName not in dynamicAPI[lpDllName]:
            dynamicAPI[lpDllName].append((fnAddress, lpFunctionName))
            loadAPI += 1

print('Printing dynamically loaded API ({0} total)...'.format(loadAPI))
printAPI(dynamicAPI)
