/*-
 * Copyright (c) 2009-2010 Doug Rabson
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
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import target.target;
private import machine.armdis;
import sys.ptrace;

import std.conv;
import std.format;
import std.stdint;
import std.stdio;
import std.string;

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
    CPSR,
    GR_COUNT
}

enum string[] ArmRegNames =
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
    "cpsr",
];

alias uint32_t reg_t;

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

	void pc(ulong pc)
	{
            gregs_[ArmReg.PC] = to!reg_t(pc);
	    grdirty_ = true;
	}

	ulong tp()
	{
	    return tp_;
	}

	ulong tls_get_addr(uint index, ulong offset)
	{
	    if (!tp_)
		return 0;
	    ulong dtv = readInteger(readMemory(tp_ + 4, 4));
	    ulong base = readInteger( readMemory(dtv + 4 + 4*index, 4));
	    return base + offset;
	}

	PtraceCommand[] ptraceReadCommands()
	{
	    grdirty_ = false;
	    version (FreeBSD)
		return [PtraceCommand(PT_GETREGS, cast(ubyte*) gregs_.ptr)];
            else
                return null;
	}

	PtraceCommand[] ptraceWriteCommands()
	{
	    if (grdirty_) {
		grdirty_ = false;
		version (FreeBSD)
		    return [PtraceCommand(PT_GETREGS, cast(ubyte*) gregs_.ptr, 0)];
	    }
	    return null;
	}

	void setGRs(ubyte* p)
	{
	    grdirty_ = true;
	}

	void getGRs(ubyte* p)
	{
	}

	void setGR(size_t gregno, ulong val)
	{
            gregs_[gregno] = to!reg_t(val);
	    grdirty_ = true;
	}

	ulong getGR(size_t gregno)
	{
	    return gregs_[gregno];
	}

	uint grWidth(size_t greg)
	{
	    return 4;
	}

	uint spregno()
	{
	    return 4;
	}

	uint grCount()
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

	void setFRs(ubyte* regs)
	{
	}

	void getFRs(ubyte* regs)
	{
	}

	ubyte[] readRegister(size_t regno, size_t bytes)
	{
	    if (regno < ArmReg.GR_COUNT) {
		ubyte[] v;
		assert(bytes <= 4);
		v.length = bytes;
		v[] = (cast(ubyte*) &gregs_[regno])[0..bytes];
		return v;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	void writeRegister(size_t regno, ubyte[] v)
	{
	    if (regno < ArmReg.GR_COUNT) {
		assert(v.length <= 4);
		(cast(ubyte*) &gregs_[regno])[0..v.length] = v[];
		grdirty_ = true;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0x11,0x00,0x00,0xe6 ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    gregs_[ArmReg.PC] -= 4;
	    grdirty_ = true;
	}

	uint pointerWidth()
	{
	    return 4;
	}

	ulong readInteger(ubyte[] bytes)
	{
	    ulong value = 0;
	    foreach_reverse (b; bytes)
		value = (value << 8L) | b;
	    return value;
	}

	void writeInteger(ulong val, ubyte[] bytes)
	{
	    foreach (ref b; bytes) {
		b = val & 0xff;
		val >>= 8;
	    }
	}

	real readFloat(ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
                f32.i = to!uint(readInteger(bytes));
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

	Value call(ulong address, Type returnType, Value[] args)
	{
	    throw new EvalException("function call not supported");
	}

	Value returnValue(Type returnType)
	{
	    // XXX do this properly
	    return new Value(new ConstantLocation(readRegister(0, 4)),
			     returnType);
	}

	ulong findFlowControl(ulong start, ulong end)
	{
	    ulong addr = start;
	    while (start < end) {
                uint insn = to!uint(readInteger(readMemory(addr, 4)));
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

	ulong findJump(ulong start, ulong end)
	{
	    ulong addr = start;
	    while (start < end) {
                uint insn = to!uint(readInteger(readMemory(addr, 4)));
		if (((insn >> 24) & 7) == 5)	// B, BL
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
		uint v = to!uint(readInteger(readMemory(address, 4)));
		return v;
	    }
	    return machine.armdis.disasm(address,
		&readWord, lookupAddress);
	}

	string[] contents(MachineState)
	{
	    return ArmRegNames[];
	}

	DebugItem lookup(string reg, MachineState)
	{
	    if (reg.length > 0 && reg[0] == '$')
		reg = reg[1..$];
	    foreach (i, s; ArmRegNames) {
		if (s == reg) {
		    return regAsValue(i);
		}
	    }
	    return null;
	}
	Type lookupStruct(string reg) { return null; }
	Type lookupUnion(string reg) { return null; }
	Type lookupTypedef(string reg) { return null; }
    }

    Value regAsValue(size_t i)
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
    reg_t	gregs_[ArmReg.GR_COUNT];
    bool	grdirty_;
    uint32_t	tp_;
}
