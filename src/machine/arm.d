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

module machine.arm;
import machine.machine;
import objfile.debuginfo;
import language.language;
import target.target;
private import machine.armdis;
import sys.ptrace;

import std.stdio;
import std.stdint;
import std.format;

/**
 * Register numbers are chosen to match Dwarf debug info.
 */
enum ArmReg
{
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    PC,
    GR_COUNT,
}

private string[] ArmRegNames =
[
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "pc",
];

class ArmState: MachineState
{
    this(Target target)
    {
	target_ = target;
    }

    override {
	void dumpState()
	{
	    foreach (i, val; gregs_) {
		writef("%6s:%08x ", ArmRegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	}

	ulong pc()
	{
	    return gregs_[ArmReg.PC];
	}

	ulong tp()
	{
	    return tp_;
	}

	void tp(ulong v)
	{
	    tp_ = v;
	}

	ulong tls_get_addr(uint index, ulong offset)
	{
	    if (!tp_)
		return 0;
	    ulong dtv = readInteger(readMemory(tp_ + 4, 4));
	    ulong base = readInteger( readMemory(dtv + 4 + 4*index, 4));
	    return base + offset;
	}

	size_t gregsSize()
	{
	    return 4 * 16;
	}

	uint grGen()
	{
	    return grGen_;
	}

	void setGRs(ubyte* p)
	{
	    grGen_++;
	}

	void getGRs(ubyte* p)
	{
	}

	void setGR(uint gregno, ulong val)
	{
	    gregs_[gregno] = val;
	    grGen_++;
	}

	ulong getGR(uint gregno)
	{
	    return gregs_[gregno];
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
	    grGen_++;
	}

	size_t grWidth(int greg)
	{
	    return 4;
	}

	uint spregno()
	{
	    return 4;
	}

	size_t grCount()
	{
	    return ArmReg.GR_COUNT;
	}

	MachineState dup()
	{
	    ArmState newState = new ArmState(target_);
	    newState.gregs_[] = gregs_[];
	    newState.tp_ = tp_;
	    return newState;
	}

	void dumpFloat()
	{
	}

	size_t fpregsSize()
	{
	    return 0;
	}

	int ptraceGetFP()
	{
	    return PT_GETFPREGS;
	}

	int ptraceSetFP()
	{
	    return PT_SETFPREGS;
	}

	uint frGen()
	{
	    return 0;
	}

	void setFRs(ubyte* regs)
	{
	}

	void getFRs(ubyte* regs)
	{
	}

	void setFR(uint fpregno, real val)
	{
	}

	real getFR(uint fpregno)
	{
	    return 0;
	}

	ubyte[] readFR(uint fpregno)
	{
	    return null;
	}

	void writeFR(uint fpregno, ubyte[])
	{
	    return 0;
	}

	size_t frWidth(int fpregno)
	{
	    return 8;
	}

	uint pointerWidth()
	{
	    return 4;
	}

	ulong readInteger(ubyte[] bytes)
	{
	    ulong value = 0;
	    foreach (b; bytes.reverse)
		value = (value << 8L) | b;
	    return value;
	}

	void writeInteger(ulong val, ubyte[] bytes)
	{
	    for (int i = 0; i < bytes.length; i++) {
		bytes[i] = val & 0xff;
		val >>= 8;
	    }
	}

	real readFloat(ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
		f32.i = readInteger(bytes);
		return f32.f;
	    case 8:
		f64.i = readInteger(bytes);
		return f64.f;
	    default:
		assert(false);
	    }
	}

	void writeFloat(real val, ubyte[] bytes)
	{
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
	    ulong addr = start;
	    while (start < end) {
		uint insn = readInteger(readMemory(addr, 4));
		if (((insn >> 24) & 7) == 5)	// B, BL
		    break;
		if (((insn >> 20) & 0xff) == 0x12) // BX
		    break;
		if (((insn >> 20) & 0xfe) == 0x36) // MOV
		    if (((insn >> 12) & 15) == 15)
			break;
		if (((insn >> 20) & 0xc5) == 0x41) // LDR
		    if (((insn >> 12) & 15) == 15)
			break;
		addr += 4;
	    }
	    return addr;
	}

	string disassemble(ref ulong address,
			   string delegate(ulong) lookupAddress)
	{
	    uint readWord(ulong address)
	    {
		ubyte[] t = readMemory(address, 4);
		uint v = readInteger(t);
		return v;
	    }
	    return machine.armdis.disasm(address,
		&readWord, lookupAddress);
	}

	string[] contents(MachineState)
	{
	    return ArmRegNames[];
	}

	bool lookup(string reg, MachineState, out DebugItem val)
	{
	    if (reg.length > 0 && reg[0] == '$')
		reg = reg[1..$];
	    foreach (i, s; ArmRegNames) {
		if (s == reg) {
		    val = regAsValue(i);
		    return true;
		}
	    }
	    return false;
	}
    }

    Value regAsValue(uint i)
    {
	auto loc = new RegisterLocation(i, grWidth(i));
	auto ty = CLikeLanguage.instance.integerType(
	    "uint32_t", false, grWidth(i));
	return new Value(loc, ty);
    }

private:
    union float32 {
	uint i;
	float f;
    }
    union float64 {
	ulong i;
	double f;
    }
    Target	target_;
    uint32_t	gregs_[ArmReg.GR_COUNT];
    uint	grGen_ = 1;
    uint32_t	tp_;
}
