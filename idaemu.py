# pylint: disable=C0103,C0114,C0115,C0116,W0401,W0614

# https://github.com/36hours/idaemu

"""
USAGE:

Example1
This is easy function for add.

.text:000000000040052D                 public myadd
.text:000000000040052D myadd           proc near               ; CODE XREF: main+1B?p
.text:000000000040052D
.text:000000000040052D var_4           = dword ptr -4
.text:000000000040052D
.text:000000000040052D                 push    rbp
.text:000000000040052E                 mov     rbp, rsp
.text:0000000000400531                 mov     [rbp+var_4], edi
.text:0000000000400534                 mov     edx, cs:magic	; magic dd 64h
.text:000000000040053A                 mov     eax, [rbp+var_4]
.text:000000000040053D                 add     eax, edx
.text:000000000040053F                 pop     rbp
.text:0000000000400540                 retn
.text:0000000000400540 myadd           endp
Running the idapython scritp:

from idaemu import *
a = Emu(UC_ARCH_X86, UC_MODE_64)
print a.eFunc(0x040052D, None, [7])
Get the function result:

107
Example2
If there is a library function call inner the function, we couldn't call it directly. We should use alt to hook the library function first.

.text:0000000000400560                 public myadd
.text:0000000000400560 myadd           proc near               ; CODE XREF: main+27?p
.text:0000000000400560
.text:0000000000400560 var_8           = dword ptr -8
.text:0000000000400560 var_4           = dword ptr -4
.text:0000000000400560
.text:0000000000400560                 push    rbp
.text:0000000000400561                 mov     rbp, rsp
.text:0000000000400564                 sub     rsp, 10h
.text:0000000000400568                 mov     [rbp+var_4], edi
.text:000000000040056B                 mov     [rbp+var_8], esi
.text:000000000040056E                 mov     eax, [rbp+var_8]
.text:0000000000400571                 mov     edx, [rbp+var_4]
.text:0000000000400574                 add     eax, edx
.text:0000000000400576                 mov     esi, eax
.text:0000000000400578                 mov     edi, offset format ; "a+b=%d\n"
.text:000000000040057D                 mov     eax, 0
.text:0000000000400582                 call    _printf
.text:0000000000400587                 leave
.text:0000000000400588                 retn
.text:0000000000400588 myadd           endp
Running the idapython scritp:

from idaemu import *

a = Emu(UC_ARCH_X86, UC_MODE_64)

def myprint(uc, out, args):
    out.append("this is hook output: %d" % args[1])
    return 0

myadd_addr = 0x00400560
printf_addr = 0x00400410
a.alt(printf_addr, myprint, 2, False)
a.eFunc(myadd_addr, None, [1, 7])
print "---- below is the trace ----"
a.showTrace()
Get the result:

---- below is the trace ----
this is hook output: 8
Well Done. We can alter every function in this way.

Example3
Sometimes it emulates fail with some abort:

Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>print a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
Then we can use setTrace and showTrace for debugging.

Python>from idaemu import *
Python>a = Emu(UC_ARCH_ARM, UC_MODE_THUMB)
Python>a.setTrace(TRACE_CODE)
Python>a.eFunc(here(), 0xbeae, [4])
#ERROR: Invalid instruction (UC_ERR_INSN_INVALID)
1048576
Python>a.showTrace()
### Trace Instruction at 0x13dc, size = 2
### Trace Instruction at 0x13de, size = 2
### Trace Instruction at 0x13e0, size = 2
......
### Trace Instruction at 0x19c6, size = 2
### Trace Instruction at 0x19c8, size = 2
### Trace Instruction at 0x19ca, size = 2
### Trace Instruction at 0xbeae, size = 2
So we found the abort reason (the RA is wrong)
"""

from __future__ import print_function

from struct import unpack, pack, unpack_from, calcsize

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

from idaapi import get_func
from idautils import XrefsTo
from idc import get_qword, get_bytes, read_selection_start, read_selection_end, here, get_item_size

PAGE_ALIGN = 0x1000  # 4k

COMPILE_GCC = 1
COMPILE_MSVC = 2

TRACE_OFF = 0
TRACE_DATA_READ = 1
TRACE_DATA_WRITE = 2
TRACE_CODE = 4


class Emu:
    def __init__(self, arch, mode, compiler=COMPILE_GCC, stack=0xf000000, ssize=3):
        assert (arch in [UC_ARCH_X86, UC_ARCH_ARM, UC_ARCH_ARM64])
        self.arch = arch
        self.mode = mode
        self.compiler = compiler
        self.stack = self._alignAddr(stack)
        self.ssize = ssize
        self.data = []
        self.regs = []
        self.curUC = None
        self.traceOption = TRACE_OFF
        self.logBuffer = []
        self.altFunc = {}
        self._init()

    def _addTrace(self, logInfo):
        self.logBuffer.append(logInfo)

    # callback for tracing invalid memory access (READ or WRITE, FETCH)
    def _hook_mem_invalid(self, uc, _access, address, _size, _value, _user_data):
        addr = self._alignAddr(address)
        uc.mem_map(addr, PAGE_ALIGN)
        data = self._getOriginData(addr, PAGE_ALIGN)
        uc.mem_write(addr, data)
        return True

    def _hook_mem_access(self, _uc, access, address, size, value, _user_data):
        if access == UC_MEM_WRITE and self.traceOption & TRACE_DATA_WRITE:
            self._addTrace(f"### Memory WRITE at 0x{address:X}, data size = {size}, data value = 0x{value:X}")
        elif access == UC_MEM_READ and self.traceOption & TRACE_DATA_READ:
            self._addTrace(f"### Memory READ at 0x{address:X}, data size = {size}")

    def _hook_code(self, uc, address, size, _user_data):
        if self.traceOption & TRACE_CODE:
            self._addTrace(f"### Trace Instruction at 0x{address:X}, size = {size}")
        if address in self.altFunc:
            func, argc, balance = self.altFunc[address]
            try:
                sp = uc.reg_read(self.REG_SP)
                if self.REG_RA == 0:
                    RA = unpack(self.pack_fmt, str(uc.mem_read(sp, self.step)))[0]
                    sp += self.step
                else:
                    RA = uc.reg_read(self.REG_RA)

                args = []
                i = 0
                while i < argc and i < len(self.REG_ARGS):
                    args.append(uc.reg_read(self.REG_ARGS[i]))
                    i += 1
                sp2 = sp
                while i < argc:
                    args.append(unpack(self.pack_fmt, str(uc.mem_read(sp2, self.step)))[0])
                    sp2 += self.step
                    i += 1

                res = func(uc, self.logBuffer, args)
                if not isinstance(res, int):
                    res = 0
                uc.reg_write(self.REG_RES, res)
                uc.reg_write(self.REG_PC, RA)
                if balance:
                    uc.reg_write(self.REG_SP, sp2)
                else:
                    uc.reg_write(self.REG_SP, sp)
            except Exception as e:
                self._addTrace(f"alt exception: {e}")

    def _alignAddr(self, addr):
        return addr // PAGE_ALIGN * PAGE_ALIGN

    def _getOriginData(self, address, size):
        res = []
        for offset in range(0, size, 64):
            tmp = get_bytes(address + offset, 64)
            if tmp is None:
                res.extend([pack("<Q", get_qword(address + offset + i)) for i in range(0, 64, 8)])
            else:
                res.append(tmp)
        res = b"".join(res)
        return res[:size]

    def _init(self):
        if self.arch == UC_ARCH_X86:
            if self.mode == UC_MODE_16:
                self.step = 2
                self.pack_fmt = '<H'
                self.REG_PC = UC_X86_REG_IP
                self.REG_SP = UC_X86_REG_SP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_AX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_32:
                self.step = 4
                self.pack_fmt = '<I'
                self.REG_PC = UC_X86_REG_EIP
                self.REG_SP = UC_X86_REG_ESP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_EAX
                self.REG_ARGS = []
            elif self.mode == UC_MODE_64:
                self.step = 8
                self.pack_fmt = '<Q'
                self.REG_PC = UC_X86_REG_RIP
                self.REG_SP = UC_X86_REG_RSP
                self.REG_RA = 0
                self.REG_RES = UC_X86_REG_RAX
                if self.compiler == COMPILE_GCC:
                    self.REG_ARGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
                                     UC_X86_REG_R8, UC_X86_REG_R9]
                elif self.compiler == COMPILE_MSVC:
                    self.REG_ARGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        elif self.arch == UC_ARCH_ARM:
            if self.mode == UC_MODE_ARM:
                self.step = 4
                self.pack_fmt = '<I'
            elif self.mode == UC_MODE_THUMB:
                self.step = 2
                self.pack_fmt = '<H'
            self.REG_PC = UC_ARM_REG_PC
            self.REG_SP = UC_ARM_REG_SP
            self.REG_RA = UC_ARM_REG_LR
            self.REG_RES = UC_ARM_REG_R0
            self.REG_ARGS = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        elif self.arch == UC_ARCH_ARM64:
            self.step = 8
            self.pack_fmt = '<Q'
            self.REG_PC = UC_ARM64_REG_PC
            self.REG_SP = UC_ARM64_REG_SP
            self.REG_RA = UC_ARM64_REG_LR
            self.REG_RES = UC_ARM64_REG_X0
            self.REG_ARGS = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                             UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]

    def _initStackAndArgs(self, uc, RA, args):
        uc.mem_map(self.stack, (self.ssize + 1) * PAGE_ALIGN)
        sp = self.stack + self.ssize * PAGE_ALIGN
        uc.reg_write(self.REG_SP, sp)

        if self.REG_RA == 0:
            uc.mem_write(sp, pack(self.pack_fmt, RA))
        else:
            uc.reg_write(self.REG_RA, RA)

        ## init the arguments
        i = 0
        while i < len(self.REG_ARGS) and i < len(args):
            uc.reg_write(self.REG_ARGS[i], args[i])
            i += 1

        while i < len(args):
            sp += self.step
            uc.mem_write(sp, pack(self.pack_fmt, args[i]))
            i += 1

    def _getBit(self, value, offset):
        mask = 1 << offset
        return 1 if (value & mask) > 0 else 0

    def _showRegs(self, uc):
        print(">>> regs:")
        try:
            if self.mode == UC_MODE_16:
                ax = uc.reg_read(UC_X86_REG_AX)
                bx = uc.reg_read(UC_X86_REG_BX)
                cx = uc.reg_read(UC_X86_REG_CX)
                dx = uc.reg_read(UC_X86_REG_DX)
                di = uc.reg_read(UC_X86_REG_SI)
                si = uc.reg_read(UC_X86_REG_DI)
                bp = uc.reg_read(UC_X86_REG_BP)
                sp = uc.reg_read(UC_X86_REG_SP)
                ip = uc.reg_read(UC_X86_REG_IP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    AX = 0x%X BX = 0x%X CX = 0x%X DX = 0x%X" % (ax, bx, cx, dx))
                print("    DI = 0x%X SI = 0x%X BP = 0x%X SP = 0x%X" % (di, si, bp, sp))
                print("    IP = 0x%X" % ip)
            elif self.mode == UC_MODE_32:
                eax = uc.reg_read(UC_X86_REG_EAX)
                ebx = uc.reg_read(UC_X86_REG_EBX)
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                edi = uc.reg_read(UC_X86_REG_ESI)
                esi = uc.reg_read(UC_X86_REG_EDI)
                ebp = uc.reg_read(UC_X86_REG_EBP)
                esp = uc.reg_read(UC_X86_REG_ESP)
                eip = uc.reg_read(UC_X86_REG_EIP)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    EAX = 0x%X EBX = 0x%X ECX = 0x%X EDX = 0x%X" % (eax, ebx, ecx, edx))
                print("    EDI = 0x%X ESI = 0x%X EBP = 0x%X ESP = 0x%X" % (edi, esi, ebp, esp))
                print("    EIP = 0x%X" % eip)
            elif self.mode == UC_MODE_64:
                rax = uc.reg_read(UC_X86_REG_RAX)
                rbx = uc.reg_read(UC_X86_REG_RBX)
                rcx = uc.reg_read(UC_X86_REG_RCX)
                rdx = uc.reg_read(UC_X86_REG_RDX)
                rdi = uc.reg_read(UC_X86_REG_RSI)
                rsi = uc.reg_read(UC_X86_REG_RDI)
                rbp = uc.reg_read(UC_X86_REG_RBP)
                rsp = uc.reg_read(UC_X86_REG_RSP)
                rip = uc.reg_read(UC_X86_REG_RIP)
                r8 = uc.reg_read(UC_X86_REG_R8)
                r9 = uc.reg_read(UC_X86_REG_R9)
                r10 = uc.reg_read(UC_X86_REG_R10)
                r11 = uc.reg_read(UC_X86_REG_R11)
                r12 = uc.reg_read(UC_X86_REG_R12)
                r13 = uc.reg_read(UC_X86_REG_R13)
                r14 = uc.reg_read(UC_X86_REG_R14)
                r15 = uc.reg_read(UC_X86_REG_R15)
                eflags = uc.reg_read(UC_X86_REG_EFLAGS)

                print("    RAX = 0x%X RBX = 0x%X RCX = 0x%X RDX = 0x%X" % (rax, rbx, rcx, rdx))
                print("    RDI = 0x%X RSI = 0x%X RBP = 0x%X RSP = 0x%X" % (rdi, rsi, rbp, rsp))
                print("    R8 = 0x%X R9 = 0x%X R10 = 0x%X R11 = 0x%X R12 = 0x%X " \
                      "R13 = 0x%X R14 = 0x%X R15 = 0x%X" % (r8, r9, r10, r11, r12, r13, r14, r15))
                print("    RIP = 0x%X" % rip)
            if eflags:
                print("    EFLAGS:")
                print("    CF=%d PF=%d AF=%d ZF=%d SF=%d TF=%d IF=%d DF=%d OF=%d IOPL=%d " \
                      "NT=%d RF=%d VM=%d AC=%d VIF=%d VIP=%d ID=%d"
                      % (self._getBit(eflags, 0),
                         self._getBit(eflags, 2),
                         self._getBit(eflags, 4),
                         self._getBit(eflags, 6),
                         self._getBit(eflags, 7),
                         self._getBit(eflags, 8),
                         self._getBit(eflags, 9),
                         self._getBit(eflags, 10),
                         self._getBit(eflags, 11),
                         self._getBit(eflags, 12) + self._getBit(eflags, 13) * 2,
                         self._getBit(eflags, 14),
                         self._getBit(eflags, 16),
                         self._getBit(eflags, 17),
                         self._getBit(eflags, 18),
                         self._getBit(eflags, 19),
                         self._getBit(eflags, 20),
                         self._getBit(eflags, 21)))
        except UcError as e:
            print(f"#ERROR: {e}")

    def _initData(self, uc):
        for address, data, init in self.data:
            addr = self._alignAddr(address)
            size = PAGE_ALIGN
            while size < len(data):
                size += PAGE_ALIGN
            uc.mem_map(addr, size)
            if init:
                uc.mem_write(addr, self._getOriginData(addr, size))
            uc.mem_write(address, data)

    def _initRegs(self, uc):
        for reg, value in self.regs:
            uc.reg_write(reg, value)

    def _emulate(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        try:
            self.logBuffer = []
            uc = Uc(self.arch, self.mode)
            self.curUC = uc

            self._initStackAndArgs(uc, stopAddr, args)
            self._initData(uc)
            self._initRegs(uc)

            # add the invalid memory access hook
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | \
                        UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_mem_invalid)

            # add the trace hook
            if self.traceOption & (TRACE_DATA_READ | TRACE_DATA_WRITE):
                uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem_access)
            uc.hook_add(UC_HOOK_CODE, self._hook_code)

            # start emulate
            uc.emu_start(startAddr, stopAddr, timeout=TimeOut, count=Count)
        except UcError as e:
            print(f"#ERROR: {e}")

    # set the data before emulation
    def setData(self, address, data, init=False):
        self.data.append((address, data, init))

    def setReg(self, reg, value):
        self.regs.append((reg, value))

    def showRegs(self, *regs):
        if self.curUC is None:
            print("current uc is None.")
            return
        for reg in regs:
            print(f"0x{self.curUC.reg_read(reg):X}")

    def readStack(self, fmt, count):
        if self.curUC is None:
            print("current uc is none.")
            return None
        stackData = []
        stackPointer = self.curUC.reg_read(self.REG_SP)
        for i in range(count):
            dataSize = calcsize(fmt)
            data = self.curUC.mem_read(stackPointer + i * dataSize, dataSize)
            st = unpack_from(fmt, data)
            stackData.append((stackPointer + i * dataSize, st[0]))
        return stackData

    def showData(self, fmt, addr, count=1):
        if self.curUC is None:
            print("current uc is none.")
            return
        if count > 1:
            print('[')
        for i in range(count):
            dataSize = calcsize(fmt)
            data = self.curUC.mem_read(addr + i * dataSize, dataSize)
            if count > 1:
                print('    ', end='')
            _st = unpack_from(fmt, data)
            if count > 1:
                print(',')
        print(']') if count > 1 else print('')

    def setTrace(self, opt):
        if opt != TRACE_OFF:
            self.traceOption |= opt
        else:
            self.traceOption = TRACE_OFF

    def showTrace(self):
        logs = "\n".join(self.logBuffer)
        print(logs)

    def alt(self, address, func, argc, balance=False):
        """
        If call the address, will call the func instead.
        the arguments of func : func(uc, consoleouput, args)
        """
        assert callable(func)
        self.altFunc[address] = (func, argc, balance)

    def eFunc(self, address=None, retAddr=None, args=[]):
        if address is None:
            address = here()
        func = get_func(address)
        if retAddr is None:
            refs = [ref.frm for ref in XrefsTo(func.startEA, 0)]
            if len(refs) != 0:
                retAddr = refs[0] + get_item_size(refs[0])
            else:
                print("Please offer the return address.")
                return None
        self._emulate(func.startEA, retAddr, args)
        res = self.curUC.reg_read(self.REG_RES)
        return res

    def eBlock(self, codeStart=None, codeEnd=None):
        if codeStart is None:
            codeStart = read_selection_start()
        if codeEnd is None:
            codeEnd = read_selection_end()
        self._emulate(codeStart, codeEnd)
        self._showRegs(self.curUC)

    def eUntilAddress(self, startAddr, stopAddr, args=[], TimeOut=0, Count=0):
        self._emulate(startAddr=startAddr, stopAddr=stopAddr, args=args, TimeOut=TimeOut, Count=Count)
        self._showRegs(self.curUC)
