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
    EFLAGS	= 9,
    CS		= 10,
    SS		= 11,
    DS		= 12,
    ES		= 13,
    FS		= 14,
    GS		= 15,
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

	void setGR(int gregno, ulong val)
	{
	    gregs_[gregno] = val;
	}

	void setGR(string gregname, ulong val)
	{
	    return setGR(nameToGRegno(gregname), val);
	}

	ulong getGR(int gregno)
	{
	    return gregs_[gregno];
	}

	ulong getGR(string gregname)
	{
	    return getGR(nameToGRegno(gregname));
	}

	size_t grWidth(int greg)
	{
	    return 32;
	}

	size_t grCount()
	{
	    return X86Reg.GR_COUNT;
	}

	MachineState unwind()
	{
	    /*
	     * Bogus version to start with - assume standard stack
	     * frames and only unwind EBP and EIP.
	     */
	    uint32_t ebp = gregs_[X86Reg.EBP];
	    uint32_t eip = gregs_[X86Reg.EIP];
	    uint32_t newebp, neweip;
	    ubyte[] t = target_.readMemory(ebp, 2*uint32_t.sizeof);
	    newebp = readle32(&t[0]);
	    neweip = readle32(&t[newebp.sizeof]);
	    
	    version (DEBUG_UNWIND)
		writefln("{%x,%x} -> {%x,%x}", ebp, eip, newebp, neweip);

	    if (newebp <= ebp)
		return null;

	    X86State newState = new X86State(target_);
	    newState.gregs_[] = gregs_[];
	    newState.gregs_[X86Reg.EBP] = newebp;
	    newState.gregs_[X86Reg.EIP] = neweip;

	    return newState;
	}

	int pcregno()
	{
	    return X86Reg.EIP;
	}

	ubyte[] readMemory(ulong address, size_t bytes)
	{
	    return target_.readMemory(address, bytes);
	}

	void writeMemory(ulong address, ubyte[] toWrite)
	{
	    target_.writeMemory(address, toWrite);
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
