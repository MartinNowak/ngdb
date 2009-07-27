/*-
 * Copyright (c) 2009 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

module machine.x86;
import machine.machine;
import objfile.debuginfo;
private import machine.x86dis;
import target;

import std.stdio;
import std.stdint;

/**
 * Register numbers are chosen to match Dwarf debug info.
 */
enum X86Reg
{
    EAX		= 0,
    ECX		= 1,
    EDX		= 2,
    EBX		= 3,
    ESP		= 4,
    EBP		= 5,
    ESI		= 6,
    EDI		= 7,
    EIP		= 8,
    EFLAGS,
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
    GR_COUNT,
}

private string[] X86RegNames =
[
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "eip",
    "eflags",
    "cs",
    "ss",
    "ds",
    "es",
    "fs",
    "gs",
];

enum X86_64Reg
{
    RAX		= 0,
    RBX		= 1,
    RCX		= 2,
    RDX		= 3,
    RSI		= 4,
    RDI		= 5,
    RBP		= 6,
    RSP		= 7,
    R8		= 8,
    R9		= 9,
    R10		= 10,
    R11		= 11,
    R12		= 12,
    R13		= 13,
    R14		= 14,
    R15		= 15,
    RIP		= 16,
    RFLAGS	= 17,
    CS		= 18,
    SS		= 19,
    GR_COUNT,
}

private string[] X86_64RegNames =
[
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "rflags",
    "cs",
    "ss",
];

private static uint32_t readle32(ubyte* p)
{
    uint32_t v;
    v = p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
    return v;
}

class X86State: MachineState
{
    this(Target target)
    {
	target_ = target;
    }

    override {
	void dumpState()
	{
	    foreach (i, val; gregs_) {
		writef("%6s:%08x ", X86RegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	}

	void setGR(uint gregno, ulong val)
	{
	    gregs_[gregno] = val;
	}

	void setGR(string gregname, ulong val)
	{
	    return setGR(nameToGRegno(gregname), val);
	}

	ulong getGR(uint gregno)
	{
	    return gregs_[gregno];
	}

	ulong getGR(string gregname)
	{
	    return getGR(nameToGRegno(gregname));
	}

	ubyte[] readGR(uint gregno)
	{
	    ubyte[] v;
	    v.length = 4;
	    v[0..4] = (cast(ubyte*) &gregs_[gregno])[0..4];
	    return v;
	}

	void writeGR(uint gregno, ubyte[] v)
	{
	    assert(v.length == 4);
	    (cast(ubyte*) &gregs_[gregno])[0..4] = v[0..4];
	}

	size_t grWidth(int greg)
	{
	    return 32;
	}

	size_t grCount()
	{
	    return X86Reg.GR_COUNT;
	}

	MachineState dup()
	{
	    X86State newState = new X86State(target_);
	    newState.gregs_[] = gregs_[];
	    return newState;
	}

	int pcregno()
	{
	    return X86Reg.EIP;
	}

	uint pointerSize()
	{
	    return uint.sizeof;
	}

	ubyte[] readMemory(ulong address, size_t bytes)
	{
	    return target_.readMemory(address, bytes);
	}

	void writeMemory(ulong address, ubyte[] toWrite)
	{
	    target_.writeMemory(address, toWrite);
	}

	ulong findFlowControl(ulong start, ulong end)
	{
	    char readByte(ulong loc) {
		ubyte[] t = readMemory(loc, 1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    ulong loc = start;
	    while (loc < end) {
		ulong tloc = loc;
		if (dis.isFlowControl(loc, &readByte))
		    return tloc;
	    }
	    return end;
	}

	string disassemble(ref ulong address,
			   string delegate(ulong) lookupAddress)
	{
	    char readByte(ulong loc) {
		ubyte[] t = readMemory(loc, 1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("intel");
	    return dis.disassemble(address, &readByte);
	}

	string[] contents()
	{
	    return X86RegNames[];
	}

	bool lookup(string reg, out Variable var)
	{
	    foreach (i, s; X86RegNames) {
		if (s == reg) {
		    Location loc = new RegisterLocation(i, grWidth(i) / 8);
		    Type ty = new IntegerType("uint32_t", false,
					      grWidth(i) / 8);
		    var.name = reg;
		    var.value = Value(loc, ty);
		    return true;
		}
	    }
	    return false;
	}
    }

    int nameToGRegno(string regname)
    {
	foreach (i, name; X86RegNames)
	    if (regname == name)
		return i;
	throw new Exception("no such register");
    }

private:
    Target	target_;
    uint32_t	gregs_[X86Reg.GR_COUNT];
}
