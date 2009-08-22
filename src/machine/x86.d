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
import language.language;
private import machine.x86dis;
import target.target;
import sys.ptrace;

import std.math;
import std.stdio;
import std.stdint;
import std.string;

version (LittleEndian)
{
    static if (real.sizeof == 10 || real.sizeof == 12)
	version = nativeFloat80;
}

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

class X86State: MachineState
{
    this(Target target)
    {
	target_ = target;
    }

    static this()
    {
	auto lang = CLikeLanguage.instance;
	grType_ = lang.integerType("uint32_t", false, 4);
	frType_ = lang.floatType("real", 10);

	void addXmmP(string name, Type ty)
	{
	    auto aTy = new ArrayType(lang, ty);
	    aTy.addDim(0, 16 / ty.byteWidth);
	    (cast(CompoundType) xmmType_).addField(new Variable(name,
		new Value(new FirstFieldLocation(16), aTy)));
	}

	void addXmmS(string name, Type ty)
	{
	    (cast(CompoundType) xmmType_).addField(new Variable(name,
		new Value(new FirstFieldLocation(ty.byteWidth), ty)));
	}

	xmmType_ = new CompoundType(lang, "union", "xmmreg_t", 16);
	addXmmS("ss", lang.floatType("float", 4));
	addXmmS("sd", lang.floatType("float", 8));
	addXmmP("ps", lang.floatType("float", 4));
	addXmmP("pd", lang.floatType("float", 8));
	addXmmP("pb", lang.integerType("uint8_t", false, 1));
	addXmmP("pw", lang.integerType("uint16_t", false, 2));
	addXmmP("pi", lang.integerType("uint32_t", false, 4));
	addXmmP("psb", lang.integerType("int8_t", true, 1));
	addXmmP("psw", lang.integerType("int16_t", true, 2));
	addXmmP("psi", lang.integerType("int32_t", true, 4));

	void addMmP(string name, Type ty)
	{
	    auto aTy = new ArrayType(lang, ty);
	    aTy.addDim(0, 8 / ty.byteWidth);
	    (cast(CompoundType) mmType_).addField(new Variable(name,
		new Value(new FirstFieldLocation(8), aTy)));
	}

	mmType_ = new CompoundType(lang, "union", "mmreg_t", 16);
	addMmP("pb", lang.integerType("uint8_t", false, 1));
	addMmP("pw", lang.integerType("uint16_t", false, 2));
	addMmP("pi", lang.integerType("uint32_t", false, 4));
	addMmP("psb", lang.integerType("int8_t", true, 1));
	addMmP("psw", lang.integerType("int16_t", true, 2));
	addMmP("psi", lang.integerType("int32_t", true, 4));
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

	ulong pc()
	{
	    return gregs_[X86Reg.EIP];
	}

	void pc(ulong pc)
	{
	    gregs_[X86Reg.EIP] = pc;
	    grGen_++;
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
	    return reg.sizeof;
	}

	uint grGen()
	{
	    return grGen_;
	}

	void setGRs(ubyte* p)
	{
	    foreach (map; regmap_) {
		gregs_[map.gregno] = *cast(uint32_t*) (p + map.regoff);
	    }
	    grGen_++;
	}

	void getGRs(ubyte* p)
	{
	    foreach (map; regmap_) {
		*cast(uint32_t*) (p + map.regoff) = gregs_[map.gregno];
	    }
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
	    return X86Reg.GR_COUNT;
	}

	MachineState dup()
	{
	    X86State newState = new X86State(target_);
	    newState.gregs_[] = gregs_[];
	    newState.tp_ = tp_;
	    return newState;
	}

	void dumpFloat()
	{
	    uint control = fpregs_.xmm_env[0] & 0xffff;
	    uint status = fpregs_.xmm_env[0] >> 16;
	    uint tag = fpregs_.xmm_env[1] & 0xffff;
	    uint top = (status >> 11) & 7;
	    static string tagNames[] = [
		"Valid",
		"Zero",
		"Special",
		"Empty"];
	    static string precisionNames[] = [
		"Single Precision (24 bits),",
		"Reserved",
		"Double Precision (53 bits),",
		"Double Extended Precision (64 bits),",
		];
	    static string roundingNames[] = [
		"Round to nearest",
		"Round down",
		"Roumnd up",
		"Round toward zero",
		];

	    /*
	     * Regenerate the tag word from its abridged version
	     */
	    ushort newtag = 0;
	    for (auto i = 0; i < 8; i++) {
		if (tag & (1 << i)) {
		    auto fi = (i - top) & 7;
		    auto exp = readInteger(fpregs_.xmm_acc[fi][8..10]);
		    auto frac = readInteger(fpregs_.xmm_acc[fi][0..8]);
		    if ((exp & 0x7fff) == 0x7fff)
			newtag |= 2 << (2*i); // special
		    else if (exp == 0 && frac == 0)
			newtag |= 1 << (2*i); // zero
		    else
			newtag |= 0 << (2*i); // valid
		} else {
		    newtag |= 3 << (2*i);
		}
	    }
	    tag = newtag;

	    for (auto i = 7; i >= 0; i--) {
		auto fi = (i - top) & 7;
		writef("%sR%d: %-7s 0x%04x%016x ",
		       i == top ? "=>" : "  ",
		       i,
		       tagNames[(tag >> 2*i) & 3],
		       readInteger(fpregs_.xmm_acc[fi][8..10]),
		       readInteger(fpregs_.xmm_acc[fi][0..8]));
		switch ((tag >> (2*i)) & 3) {
		case 0:
		    writefln("%g", readFloat(fpregs_.xmm_acc[fi]));
		    break;
		case 1:
		    writefln("+0");
		    break;
		case 2:
		    writefln("%g", readFloat(fpregs_.xmm_acc[fi]));
		    break;
		case 3:
		    writefln("");
		}
	    }
	    writefln("");
	    writefln("%-22s0x%04x", "Status Word:", status);
	    writefln("%-22s  TOP: %d", "", top);
	    writef("%-22s0x%04x   ", "Control Word:", control);
	    if (control & 1) writef("IM ");
	    if (control & 2) writef("DM ");
	    if (control & 4) writef("ZM ");
	    if (control & 8) writef("OM ");
	    if (control & 16) writef("UM ");
	    if (control & 32) writef("PM ");
	    if (control & (1<<12)) writef("X");
	    writefln("");
	    writefln("%-22s  PC: %s", "",
		     precisionNames[(control >> 8) & 3]);
	    writefln("%-22s  RC: %s", "",
		     roundingNames[(control >> 10) & 3]);
	    writefln("%-22s0x%04x", "Tag Word:", tag);
	    writefln("%-22s0x%02x:0x%08x", "Instruction Pointer:",
		   fpregs_.xmm_env[3] & 0xffff, fpregs_.xmm_env[2]);
	    writefln("%-22s0x%02x:0x%08x", "Operand Pointer:",
		   fpregs_.xmm_env[5] & 0xffff, fpregs_.xmm_env[4]);
	    writefln("%-22s0x%04x", "Opcode:",
		     0xd800 + (fpregs_.xmm_env[1] >> 16));
	}

	size_t fpregsSize()
	{
	    return xmmreg.sizeof;
	}

	int ptraceGetFP()
	{
	    return PT_GETXMMREGS;
	}

	int ptraceSetFP()
	{
	    return PT_SETXMMREGS;
	}

	uint frGen()
	{
	    return frGen_;
	}

	void setFRs(ubyte* regs)
	{
	    fpregs_ = *cast(xmmreg*) regs;
	}

	void getFRs(ubyte* regs)
	{
	    *cast(xmmreg*) regs = fpregs_;
	}

	void setFR(uint fpregno, real val)
	{
	    writeFloat(val, fpregs_.xmm_acc[fpregno]);
	    frGen_++;
	}

	real getFR(uint fpregno)
	{
	    return readFloat(fpregs_.xmm_acc[fpregno]);
	}

	ubyte[] readFR(uint fpregno)
	{
	    return fpregs_.xmm_acc[fpregno];
	}

	void writeFR(uint fpregno, ubyte[] val)
	{
	    fpregs_.xmm_acc[fpregno][] = val[];
	    frGen_++;
	}

	size_t frWidth(int fpregno)
	{
	    return 10;
	}

	ubyte[] readRegister(uint regno, size_t bytes)
	{
	    ubyte[] v;
	    if (regno < 10) {
		assert(bytes <= 4);
		v.length = bytes;
		v[] = (cast(ubyte*) &gregs_[regno])[0..bytes];
	    } else if (regno >= 11 && regno <= 18) {
		ubyte* reg = fpregs_.xmm_acc[regno-11].ptr;
		assert(bytes <= 10);
		v.length = bytes;
		switch (v.length) {
		case 4:
		case 8:
		    auto f = readFloat(reg[0..10]);
		    writeFloat(f, v);
		    break;
		default:
		    v[] = reg[0..bytes];
		}
	    } else if (regno >= 21 && regno <= 28) {
		assert(bytes <= 16);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_reg[regno-21])[0..bytes];
	    } else if (regno >= 29 && regno <= 36) {
		assert(bytes <= 8);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_acc[regno-29])[0..bytes];
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	    return v;
	}

	void writeRegister(uint regno, ubyte[] v)
	{
	    if (regno < 10) {
		assert(v.length <= 4);
		(cast(ubyte*) &gregs_[regno])[0..v.length] = v[];
		grGen_++;
	    } else if (regno >= 11 && regno <= 18) {
		ubyte* reg = fpregs_.xmm_acc[regno-11].ptr;
		assert(v.length <= 10);
		switch (v.length) {
		case 4:
		case 8:
		    auto f = readFloat(v);
		    writeFloat(f, reg[0..10]);
		    break;
		default:
		    reg[0..v.length] = v[];
		}
		frGen_++;
	    } else if (regno >= 21 && regno <= 28) {
		assert(v.length <= 16);
		(cast(ubyte*) &fpregs_.xmm_reg[regno-21])[0..v.length] = v[];
		frGen_++;
	    } else if (regno >= 29 && regno <= 36) {
		assert(v.length <= 8);
		(cast(ubyte*) &fpregs_.xmm_acc[regno-29])[0..v.length] = v[];
		frGen_++;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
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
		f32.i = readInteger(bytes);
		return f32.f;
	    case 8:
		f64.i = readInteger(bytes);
		return f64.f;
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    return *cast(real*) &bytes[0];
		} else {
		    ulong frac = readInteger(bytes[0..8]);
		    ushort exp = readInteger(bytes[8..10]);
		    real sign = 1;
		    if (exp & 0x8000) {
			sign = -1;
			exp &= 0x7fff;
		    }
		    return sign * ldexp(cast(real) frac / cast(real) ~0UL,
					cast(int) exp - 16382);
		}
		break;
	    default:
		assert(false);
	    }
	}

	void writeFloat(real val, ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
		f32.f = val;
		writeInteger(f32.i, bytes);
		break;
	    case 8:
		f64.f = val;
		writeInteger(f64.i, bytes);
		break;
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    int sign = 0;
		    if (val < 0) {
			sign = 0x8000;
			val = -val;
		    }
		    int exp;
		    ulong frac = cast(ulong)
			(frexp(val, exp) * cast(real) ~0UL);
		    writeInteger(frac, bytes[0..8]);
		    writeInteger(exp + 16382 + sign, bytes[8..10]);
		} else {
		    assert(false);
		}
		break;
	    default:
		assert(false);
	    }
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

	ulong findJump(ulong start, ulong end)
	{
	    char readByte(ulong loc) {
		ubyte[] t = readMemory(loc, 1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    ulong loc = start;
	    while (loc < end) {
		ulong tloc = loc;
		ulong target;
		if (dis.isJump(loc, target, &readByte))
		    return target;
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
	    return dis.disassemble(address, &readByte, lookupAddress);
	}

	string[] contents(MachineState)
	{
	    string[] res;
	    res = X86RegNames[];
	    for (auto i = 0; i < 8; i++)
		res ~= format("st%d", i);
	    for (auto i = 0; i < 8; i++)
		res ~= format("mm%d", i);
	    for (auto i = 0; i < 8; i++)
		res ~= format("xmm%d", i);
	    return res;
	}

	bool lookup(string reg, MachineState, out DebugItem val)
	{
	    if (reg.length > 0 && reg[0] == '$')
		reg = reg[1..$];
	    if (reg == "pc") reg = "eip";
	    foreach (i, s; X86RegNames) {
		if (s == reg) {
		    val = regAsValue(i, grType_);
		    return true;
		}
	    }
	    if (reg.length == 3 && reg[0..2] == "st"
		&& reg[2] >= '0' && reg[2] <= '7') {
		val = regAsValue(11 + reg[2] - '0', frType_);
		return true;
	    }
	    if (reg.length == 4 && reg[0..3] == "xmm"
		&& reg[3] >= '0' && reg[3] <= '7') {
		val = regAsValue(21 + reg[3] - '0', xmmType_);
		return true;
	    }
	    if (reg.length == 3 && reg[0..2] == "mm"
		&& reg[2] >= '0' && reg[2] <= '7') {
		val = regAsValue(29 + reg[2] - '0', mmType_);
		return true;
	    }
		
	    return false;
	}
	bool lookupStruct(string reg, out Type)
	{
	    return false;
	}
	bool lookupUnion(string reg, out Type)
	{
	    return false;
	}
	bool lookupTypedef(string reg, out Type)
	{
	    return false;
	}
    }

    Value regAsValue(uint i, Type ty)
    {
	auto loc = new RegisterLocation(i, grWidth(i));
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
    struct regmap {
	int gregno;		// machine gregno
	size_t regoff;		// offset struct reg
    }
    static regmap[] regmap_ = [
	{ X86Reg.EAX, reg.r_eax.offsetof },
	{ X86Reg.ECX, reg.r_ecx.offsetof },
	{ X86Reg.EDX, reg.r_edx.offsetof },
	{ X86Reg.EBX, reg.r_ebx.offsetof },
	{ X86Reg.ESP, reg.r_esp.offsetof },
	{ X86Reg.EBP, reg.r_ebp.offsetof },
	{ X86Reg.ESI, reg.r_esi.offsetof },
	{ X86Reg.EDI, reg.r_edi.offsetof },
	{ X86Reg.EIP, reg.r_eip.offsetof },
	{ X86Reg.EFLAGS, reg.r_eflags.offsetof },
	{ X86Reg.CS, reg.r_cs.offsetof },
	{ X86Reg.SS, reg.r_ss.offsetof },
	{ X86Reg.DS, reg.r_ds.offsetof },
	{ X86Reg.ES, reg.r_es.offsetof },
	{ X86Reg.FS, reg.r_fs.offsetof },
	{ X86Reg.GS, reg.r_gs.offsetof },
	];
    Target	target_;
    uint32_t	gregs_[X86Reg.GR_COUNT];
    uint	grGen_ = 1;
    uint32_t	tp_;
    xmmreg	fpregs_;
    uint	frGen_ = 1;

    static Type	grType_;
    static Type	frType_;
    static Type	xmmType_;
    static Type	mmType_;
}

private:
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)reg.h	5.5 (Berkeley) 1/18/91
 * $FreeBSD: src/sys/i386/include/reg.h,v 1.33 2006/11/17 19:20:32 jhb Exp $
 */

/*
 * Register set accessible via /proc/$pid/regs and PT_{SET,GET}REGS.
 */
struct reg {
	uint	r_fs;
	uint	r_es;
	uint	r_ds;
	uint	r_edi;
	uint	r_esi;
	uint	r_ebp;
	uint	r_isp;
	uint	r_ebx;
	uint	r_edx;
	uint	r_ecx;
	uint	r_eax;
	uint	r_trapno;
	uint	r_err;
	uint	r_eip;
	uint	r_cs;
	uint	r_eflags;
	uint	r_esp;
	uint	r_ss;
	uint	r_gs;
};

/*
 * Register set accessible via /proc/$pid/fpregs.
 */
struct fpreg {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of unsigned longs is best.
	 */
	uint	fpr_env[7];
	ubyte	fpr_acc[8][10];
	uint	fpr_ex_sw;
	ubyte	fpr_pad[64];
};

struct xmmreg {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[8][16];
	ubyte	xmm_pad[224];
};

/*
 * Register set accessible via /proc/$pid/dbregs.
 */
struct dbreg {
	uint  dr[8];	/* debug registers */
				/* Index 0-3: debug address registers */
				/* Index 4-5: reserved */
				/* Index 6: debug status */
				/* Index 7: debug control */
};

/+
#define	DBREG_DR7_LOCAL_ENABLE	0x01
#define	DBREG_DR7_GLOBAL_ENABLE	0x02
#define	DBREG_DR7_LEN_1		0x00	/* 1 byte length          */
#define	DBREG_DR7_LEN_2		0x01
#define	DBREG_DR7_LEN_4		0x03
#define	DBREG_DR7_EXEC		0x00	/* break on execute       */
#define	DBREG_DR7_WRONLY	0x01	/* break on write         */
#define	DBREG_DR7_RDWR		0x03	/* break on read or write */
#define	DBREG_DR7_MASK(i)	(0xf << ((i) * 4 + 16) | 0x3 << (i) * 2)
#define	DBREG_DR7_SET(i, len, access, enable)				\
	(((len) << 2 | (access)) << ((i) * 4 + 16) | (enable) << (i) * 2)
#define	DBREG_DR7_GD		0x2000
#define	DBREG_DR7_ENABLED(d, i)	(((d) & 0x3 << (i) * 2) != 0)
#define	DBREG_DR7_ACCESS(d, i)	((d) >> ((i) * 4 + 16) & 0x3)
#define	DBREG_DR7_LEN(d, i)	((d) >> ((i) * 4 + 18) & 0x3)

#define	DBREG_DRX(d,x)	((d)->dr[(x)])	/* reference dr0 - dr7 by
					   register number */
+/
