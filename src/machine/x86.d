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

module machine.x86;
import machine.machine;
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
private import machine.x86dis;
import target.target;
import sys.ptrace;

import std.math;
import std.stdio;
import std.stdint;
import std.string;

version (LittleEndian)
{
    static if (real.sizeof == 10 || real.sizeof == 12 || real.sizeof == 16)
	version = nativeFloat80;
}

class X86State: MachineState
{
    /**
     * Register numbers are chosen to match Dwarf debug info.
     */
    enum
    {
	EAX	= 0,
	ECX	= 1,
	EDX	= 2,
	EBX	= 3,
	ESP	= 4,
	EBP	= 5,
	ESI	= 6,
	EDI	= 7,
	EIP	= 8,
	EFLAGS	= 9,
	TRAPNO	= 10,

	ST0	= 11,
	ST1	= 12,
	ST2	= 13,
	ST3	= 14,
	ST4	= 15,
	ST5	= 16,
	ST6	= 17,
	ST7	= 18,

	XMM0	= 21,
	XMM1	= 22,
	XMM2	= 23,
	XMM3	= 24,
	XMM4	= 25,
	XMM5	= 26,
	XMM6	= 27,
	XMM7	= 28,

	MM0	= 29,
	MM1	= 30,
	MM2	= 31,
	MM3	= 32,
	MM4	= 33,
	MM5	= 34,
	MM6	= 35,
	MM7	= 36,
    }

    enum string[] RegNames = [
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
	"trapno",
	];

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
	addXmmS("sd", lang.floatType("double", 8));
	addXmmP("ps", lang.floatType("float", 4));
	addXmmP("pd", lang.floatType("double", 8));
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
	    for (auto i = 0; i <= EFLAGS; i++) {
		auto val = getGR(i);
		writef("%6s:%08x ", RegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	    writef("%6s:%08x ", "cs", regs_.r_cs);
	    writefln("%6s:%08x ", "ss", regs_.r_ss);
	    writef("%6s:%08x ", "ds", regs_.r_ds);
	    writef("%6s:%08x ", "es", regs_.r_es);
	    writef("%6s:%08x ", "fs", regs_.r_fs);
	    writefln("%6s:%08x ", "gs", regs_.r_gs);
	}

	ulong pc()
	{
	    return regs_.r_eip;
	}

	void pc(ulong pc)
	{
            regs_.r_eip = to!uint(pc);
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
	    fpdirty_ = false;
	    version (FreeBSD) {
		return [PtraceCommand(PT_GETREGS, cast(ubyte*) &regs_, 0),
			PtraceCommand(PT_GETXMMREGS, cast(ubyte*) &fpregs_, 0),
			PtraceCommand(PT_GETGSBASE, cast(ubyte*) &tp_, 0)];
	    }
	    version (linux) {
		return [PtraceCommand(PTRACE_GETREGS, null, cast(uint) &regs_)];
	    }
	}

	PtraceCommand[] ptraceWriteCommands()
	{
	    PtraceCommand[] res;
	    version (FreeBSD) {
		if (grdirty_) {
		    res ~= PtraceCommand(PT_SETREGS, cast(ubyte*) &regs_, 0);
		    grdirty_ = false;
		}
		if (fpdirty_) {
		    res ~= PtraceCommand(PT_SETXMMREGS, cast(ubyte*) &fpregs_, 0);
		    fpdirty_ = false;
		}
	    }
	    version (linux) {
		if (grdirty_) {
		    res ~= PtraceCommand(PTRACE_SETREGS, null, cast(uint) &regs_);
		    grdirty_ = false;
		}
		if (fpdirty_) {
		    //res ~= PtraceCommand(PT_SETXMMREGS, cast(ubyte*) &fpregs_);
		    fpdirty_ = false;
		}
	    }
	    return res;
	}

	void setGRs(ubyte* p)
	{
	    regs_ = *cast(reg32*) p;
	    grdirty_ = true;
	}

	void getGRs(ubyte* p)
	{
	    *cast(reg32*) p = regs_;
	}

	void setGR(size_t gregno, ulong val)
	{
            *grAddr(gregno) = to!uint(val);
	    grdirty_ = true;
	}

	ulong getGR(size_t gregno)
	{
	    return *grAddr(gregno);
	}

	uint grWidth(size_t greg)
	{
	    return 4;
	}

	size_t spregno()
	{
	    return 4;
	}

	uint grCount()
	{
	    return EFLAGS + 1;
	}

	MachineState dup()
	{
	    X86State newState = new X86State(target_);
	    newState.regs_ = regs_;
	    newState.fpregs_ = fpregs_;
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
                    break;
                default:
                    assert(0);
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

	void setFRs(ubyte* regs)
	{
	    fpregs_ = *cast(xmmreg32*) regs;
	}

	void getFRs(ubyte* regs)
	{
	    *cast(xmmreg32*) regs = fpregs_;
	}

	ubyte[] readRegister(size_t regno, size_t bytes)
	{
	    ubyte[] v;
	    if (regno <= TRAPNO) {
		assert(bytes <= 4);
		v.length = bytes;
		v[] = (cast(ubyte*) grAddr(regno))[0..bytes];
	    } else if (regno >= ST0 && regno <= ST7) {
		ubyte* reg = fpregs_.xmm_acc[regno-ST0].ptr;
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
	    } else if (regno >= XMM0 && regno <= XMM7) {
		assert(bytes <= 16);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_reg[regno-XMM0])
		    [0..bytes];
	    } else if (regno >= MM0 && regno <= MM7) {
		assert(bytes <= 8);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_acc[regno-MM0])
		    [0..bytes];
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	    return v;
	}

	void writeRegister(size_t regno, ubyte[] v)
	{
	    if (regno < 10) {
		assert(v.length <= 4);
		(cast(ubyte*) grAddr(regno))[0..v.length] = v[];
		grdirty_ = true;
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
		fpdirty_ = true;
	    } else if (regno >= 21 && regno <= 28) {
		assert(v.length <= 16);
		(cast(ubyte*) &fpregs_.xmm_reg[regno-21])[0..v.length] = v[];
		fpdirty_ = true;
	    } else if (regno >= 29 && regno <= 36) {
		assert(v.length <= 8);
		(cast(ubyte*) &fpregs_.xmm_acc[regno-29])[0..v.length] = v[];
		fpdirty_ = true;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0xcc ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    regs_.r_eip--;
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

	Value call(ulong address, Type returnType, Value[] args)
	{
	    X86State saveState = new X86State(target_);
	    saveState.regs_ = regs_;
	    saveState.fpregs_ = fpregs_;

	    /*
	     * If the return value is a structure, reserve some space
	     * on the stack and add a hidden first argument to point
	     * at it.
	     */
	    auto cTy = cast(CompoundType) returnType;
	    version (FreeBSD)
		auto regStructSize = 8;
	    version (linux)
		auto regStructSize = 0;
	    if (cTy && cTy.byteWidth > regStructSize) {
		regs_.r_esp -= cTy.byteWidth;
		ubyte[4] v;
		writeInteger(regs_.r_esp, v);
		args = new Value(new ConstantLocation(v), grType_) ~ args;
	    }

	    ubyte[] argval;
	    foreach(arg; args) {
		if (arg.type.isIntegerType) {
		    /*
		     * Pad small integers
		     */
		    auto val = arg.loc.readValue(this);
		    if (val.length < 4) {
			static ubyte[4] zeros;
			val ~= zeros[0..4-val.length];
		    }
		    argval ~= val;
		} else {
		    auto val = arg.loc.readValue(this);
		    argval ~= val;
		}
	    }

	    /*
	     * Allocate the new stack frame including space for the
	     * return address and arguments. We arrange things so that
	     * ebp will be aligned to a 16-byte boundard after the
	     * called function executes its prologue.
	     */
	    auto newFrame = regs_.r_esp - (argval.length + 8);
	    newFrame &= ~15;
	    regs_.r_esp = to!uint(newFrame + 4);

	    /*
	     * Put arguments on the stack. Possibly we should keep the
	     * stack 16-byte aligned here.
	     */
	    if (argval.length > 0)
		writeMemory(newFrame + 8, argval);

	    static class callBreakpoint: TargetBreakpointListener
	    {
		bool onBreakpoint(Target, TargetThread, ulong)
		{
		    callBpHit_ = true;
		    return true;
		}
		bool callBpHit_ = false;
	    }

	    /*
	     * Write the return address. We arrange for the function to
	     * return to _start and we set a breakpoint there to catch
	     * it.
	     */
	    ubyte[4] ret;
	    writeInteger(target_.entry, ret);
	    writeMemory(newFrame + 4, ret);
	    auto bpl = new callBreakpoint;
	    target_.setBreakpoint(target_.entry, bpl);

	    /*
	     * Set the thing running at the start of the function.
	     */
	    regs_.r_eip = to!uint(address);
	    grdirty_ = true;
	    target_.cont(0);
	    target_.wait;

	    target_.clearBreakpoint(target_.entry, bpl);

	    if (!bpl.callBpHit_)
		throw new EvalException(
		    "Function call terminated unexpectedly");

	    /*
	     * Get the return value first then restore the machine state.
	     */
	    Value retval;
	    try {
		retval = returnValue(returnType);
	    } catch (EvalException e) {
		regs_ = saveState.regs_;
		fpregs_ = saveState.fpregs_;
		grdirty_ = true;
		fpdirty_= true;
		throw e;
	    }

	    regs_ = saveState.regs_;
	    fpregs_ = saveState.fpregs_;
	    grdirty_ = true;
	    fpdirty_= true;

	    return retval;
	}

	Value returnValue(Type returnType)
	{
	    ubyte[] retval;
	    auto cTy = cast(CompoundType) returnType;
	    version (FreeBSD)
		auto regStructSize = 8;
	    version (linux)
		auto regStructSize = 0;
	    if (cTy && cTy.byteWidth > regStructSize) {
		retval = readMemory(regs_.r_eax, cTy.byteWidth);
	    } else if (returnType.isNumericType && !returnType.isIntegerType) {
		retval = readRegister(ST0, returnType.byteWidth);
	    } else if (returnType.byteWidth <= 4) {
		retval = readRegister(EAX, returnType.byteWidth);
	    } else if (returnType.byteWidth <= 8) {
		retval = readRegister(EAX, 4)
		    ~ readRegister(EDX, returnType.byteWidth - 4);
	    } else
		throw new EvalException(
		    "Can't read return value for function call");

	    return new Value(new ConstantLocation(retval), returnType);
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
	    string[] res = RegNames;
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
	    foreach (i, s; RegNames) {
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

    Value regAsValue(size_t i, Type ty)
    {
	auto loc = new RegisterLocation(i, grWidth(i));
	return new Value(loc, ty);
    }

private:
    uint32_t* grAddr(size_t gregno)
    {
	assert(gregno <= TRAPNO);
	if (regmap_[gregno] == ~0)
	    return null;
	return cast(uint32_t*) (cast(ubyte*) &regs_ + regmap_[gregno]);
    }

    union float32 {
	uint i;
	float f;
    }
    union float64 {
	ulong i;
	double f;
    }
    version (FreeBSD) {
	static uint[] regmap_ = [
	    reg32.r_eax.offsetof,	// EAX
	    reg32.r_ecx.offsetof,	// ECX
	    reg32.r_edx.offsetof,	// EDX
	    reg32.r_ebx.offsetof,	// EBX
	    reg32.r_esp.offsetof,	// ESP
	    reg32.r_ebp.offsetof,	// EBP
	    reg32.r_esi.offsetof,	// ESI
	    reg32.r_edi.offsetof,	// EDI
	    reg32.r_eip.offsetof,	// EIP
	    reg32.r_eflags.offsetof,	// EFLAGS
	    reg32.r_trapno.offsetof	// TRAPNO
	    ];
    }
    version (linux) {
	static uint[] regmap_ = [
	    reg32.r_eax.offsetof,	// EAX
	    reg32.r_ecx.offsetof,	// ECX
	    reg32.r_edx.offsetof,	// EDX
	    reg32.r_ebx.offsetof,	// EBX
	    reg32.r_esp.offsetof,	// ESP
	    reg32.r_ebp.offsetof,	// EBP
	    reg32.r_esi.offsetof,	// ESI
	    reg32.r_edi.offsetof,	// EDI
	    reg32.r_eip.offsetof,	// EIP
	    reg32.r_eflags.offsetof,	// EFLAGS
	    reg32.r_orig_eax.offsetof,	// TRAPNO (??)
	    ];
    }
    Target	target_;
    bool	grdirty_;
    uint32_t	tp_;
    reg32	regs_;
    xmmreg32	fpregs_;
    bool	fpdirty_;

    static Type	grType_;
    static Type	frType_;
    static Type	xmmType_;
    static Type	mmType_;
}

class X86_64State: MachineState
{
    enum
    {
	RAX	= 0,
	RDX	= 1,
	RCX	= 2,
	RBX	= 3,
	RSI	= 4,
	RDI	= 5,
	RBP	= 6,
	RSP	= 7,
	R8	= 8,
	R9	= 9,
	R10	= 10,
	R11	= 11,
	R12	= 12,
	R13	= 13,
	R14	= 14,
	R15	= 15,
	RIP	= 16,

	XMM0	= 17,
	XMM1	= 18,
	XMM2	= 19,
	XMM3	= 20,
	XMM4	= 21,
	XMM5	= 22,
	XMM6	= 23,
	XMM7	= 24,
	XMM8	= 25,
	XMM9	= 26,
	XMM10	= 27,
	XMM11	= 28,
	XMM12	= 29,
	XMM13	= 30,
	XMM14	= 31,
	XMM15	= 32,

	ST0	= 33,
	ST1	= 34,
	ST2	= 35,
	ST3	= 36,
	ST4	= 37,
	ST5	= 38,
	ST6	= 39,
	ST7	= 40,

	MM0	= 41,
	MM1	= 42,
	MM2	= 43,
	MM3	= 44,
	MM4	= 45,
	MM5	= 46,
	MM6	= 47,
	MM7	= 48,

	RFLAGS	= 49,
	CS	= 50,
	SS	= 51,
	DS	= 52,
	ES	= 53,
	FS	= 54,
	GS	= 55,

	FSBASE	= 58,
	GSBASE	= 59,

	TR	= 62,
	LDTR	= 63,
	MXCSR	= 64,
	FCW	= 65,
	FSW	= 66,
    }

    enum string[] RegNames = [
	"rax",
	"rdx",
	"rcx",
	"rbx",
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
	];

    this(Target target)
    {
	target_ = target;
    }

    static this()
    {
	auto lang = CLikeLanguage.instance;
	grType_ = lang.integerType("uint64_t", false, 8);
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
	addXmmS("sd", lang.floatType("double", 8));
	addXmmP("ps", lang.floatType("float", 4));
	addXmmP("pd", lang.floatType("double", 8));
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
	    for (auto i = 0; i <= RIP; i++) {
		uint64_t val = getGR(i);
		writef("%6s:%016x ", RegNames[i], val);
		if ((i & 1) == 1)
		    writefln("");
	    }
	    writefln("%6s:%016x ", "rflags", regs_.r_rflags);
	    writefln("    cs:%04x ss:%04x ds:%04x es:%04x gs:%04x fs:%04x",
		   regs_.r_cs, regs_.r_ss, regs_.r_ds,
		   regs_.r_es, regs_.r_fs, regs_.r_gs);
	}

	ulong pc()
	{
	    return regs_.r_rip;
	}

	void pc(ulong pc)
	{
	    regs_.r_rip = pc;
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
	    ulong dtv = readInteger(readMemory(tp_ + 8, 8));
	    ulong base = readInteger( readMemory(dtv + 8 + 8*index, 8));
	    return base + offset;
	}

	PtraceCommand[] ptraceReadCommands()
	{
	    grdirty_ = false;
	    fpdirty_ = false;
	    version (FreeBSD) {
		return [PtraceCommand(PT_GETREGS, cast(ubyte*) &regs_, 0),
			PtraceCommand(PT_GETFPREGS, cast(ubyte*) &fpregs_, 0)];
	    }
	    version (linux) {
		return [PtraceCommand(PTRACE_GETREGS, null, cast(uint) &regs_)];
	    }
	}

	PtraceCommand[] ptraceWriteCommands()
	{
	    PtraceCommand[] res;
	    version (FreeBSD) {
		if (grdirty_) {
		    res ~= PtraceCommand(PT_SETREGS, cast(ubyte*) &regs_, 0);
		    grdirty_ = false;
		}
		if (fpdirty_) {
		    res ~= PtraceCommand(PT_SETFPREGS, cast(ubyte*) &fpregs_, 0);
		    fpdirty_ = false;
		}
	    }
	    version (linux) {
		if (grdirty_) {
		    res ~= PtraceCommand(PTRACE_SETREGS, null, cast(uint) &regs_);
		    grdirty_ = false;
		}
		if (fpdirty_) {
		    //res ~= PtraceCommand(PT_SETXMMREGS, cast(ubyte*) &fpregs_);
		    fpdirty_ = false;
		}
	    }
	    return res;
	}

	void setGRs(ubyte* p)
	{
	    regs_ = *cast(reg64*) p;
	    grdirty_ = true;
	}

	void getGRs(ubyte* p)
	{
	    *cast(reg64*) p = regs_;
	}

	void setGR(size_t gregno, ulong val)
	{
	    *grAddr(gregno) = val;
	    grdirty_ = true;
	}

	ulong getGR(size_t gregno)
	{
	    return *grAddr(gregno);
	}

	uint grWidth(size_t greg)
	{
	    return 8;
	}

	size_t spregno()
	{
	    return 7;
	}

	uint grCount()
	{
	    return RIP + 1;
	}

	MachineState dup()
	{
	    X86_64State newState = new X86_64State(target_);
	    newState.regs_ = regs_;
	    newState.fpregs_ = fpregs_;
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
                    break;
                default:
                    assert(0);
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

	void setFRs(ubyte* regs)
	{
	    fpregs_ = *cast(xmmreg64*) regs;
	}

	void getFRs(ubyte* regs)
	{
	    *cast(xmmreg64*) regs = fpregs_;
	}

	ubyte[] readRegister(size_t regno, size_t bytes)
	{
	    ubyte[] v;
	    if (regno <= RIP) {
		assert(bytes <= 8);
		v.length = bytes;
		v[] = (cast(ubyte*) grAddr(regno))[0..bytes];
	    } else if (regno >= ST0 && regno <= ST7) {
		ubyte* reg = fpregs_.xmm_acc[regno-ST0].ptr;
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
	    } else if (regno >= XMM0 && regno <= XMM15) {
		assert(bytes <= 16);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_reg[regno-XMM0])[0..bytes];
	    } else if (regno >= MM0 && regno <= MM7) {
		assert(bytes <= 8);
		v.length = bytes;
		v[] = (cast(ubyte*) &fpregs_.xmm_acc[regno-MM0])[0..bytes];
	    } else if (regno == RFLAGS) {
		v[] = (cast(ubyte*) &regs_.r_rflags)[0..bytes];
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	    return v;
	}

	void writeRegister(size_t regno, ubyte[] v)
	{
	    if (regno <= RIP) {
		assert(v.length <= 8);
		(cast(ubyte*) grAddr(regno))[0..v.length] = v[];
		grdirty_ = true;
	    } else if (regno >= ST0 && regno <= ST7) {
		ubyte* reg = fpregs_.xmm_acc[regno-ST0].ptr;
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
		fpdirty_ = true;
	    } else if (regno >= XMM0 && regno <= XMM15) {
		assert(v.length <= 16);
		(cast(ubyte*) &fpregs_.xmm_reg[regno-XMM0])[0..v.length] = v[];
		fpdirty_ = true;
	    } else if (regno >= MM0 && regno <= MM7) {
		assert(v.length <= 8);
		(cast(ubyte*) &fpregs_.xmm_acc[regno-MM0])[0..v.length] = v[];
		fpdirty_ = true;
	    } else if (regno == RFLAGS) {
		(cast(ubyte*) &regs_.r_rflags)[0..v.length] = v[];
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0xcc ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    regs_.r_rip--;
	    grdirty_ = true;
	}

	uint pointerWidth()
	{
	    return 8;
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

	Value call(ulong address, Type returnType, Value[] args)
	{
	    X86_64State saveState = new X86_64State(target_);
	    saveState.regs_ = regs_;
	    saveState.fpregs_ = fpregs_;

	    /*
	     * If the return value is a structure, reserve some space
	     * on the stack and add a hidden first argument to point
	     * at it.
	     */
	    auto retcls = classify(returnType);
	    if (retcls[0] == MEMORY) {
		regs_.r_rsp -= 8 * retcls.length;
		ubyte[8] v;
		writeInteger(regs_.r_rsp, v);
		args = new Value(new ConstantLocation(v), grType_) ~ args;
	    }

	    /*
	     * Classify the arguments and divide the values into
	     * eightbyte pieces.
	     */
	    alias ubyte[8] eightbyte;
	    int[] argclass;
	    eightbyte[] argval;
	    argclass.length = args.length;
	    argval.length = args.length;
	    int j = 0;
	    foreach(i, arg; args) {
		static ubyte[8] zeros;
		auto val = arg.loc.readValue(this);
		if (val.length & 7)
		    val ~= zeros[0..8-(val.length & 7)];
		auto cls = classify(arg.type);
		debug (call) {
		    writefln("val.length = %d", val.length);
		    foreach (ci, cl; cls)
			writefln("class %d = %d", ci, cl);
		}
		if (cls.length != val.length / 8)
		    throw new EvalException("Can't classify arguments");
		while (val.length > 0) {
		    eightbyte piece = val[0..8];
		    argclass ~= cls[0];
		    argval ~= piece;
		    cls = cls[1..$];
		    val = val[8..$];
		    j++;
		}
	    }

	    /*
	     * Now assign the pieces to their correct places.
	     */
	    static auto intregs = [RDI, RSI, RDX, RCX, R8, R9];
	    int intreg = 0;
	    static auto sseregs = [XMM0, XMM1, XMM2, XMM3,
				   XMM4, XMM5, XMM7, XMM7];
	    int ssereg = 0;
	    ubyte[] memargs;

	    foreach (i, ac; argclass) {
		if (ac == MEMORY)
		    memargs ~= argval[i];
		else if (ac == INTEGER) {
		    if (intreg < intregs.length)
			writeRegister(intregs[intreg++], argval[i]);
		    else
			memargs ~= argval[i];
		} else if (ac == SSE) {
		    if (ssereg < sseregs.length)
			writeRegister(sseregs[ssereg++], argval[i]);
		    else
			memargs ~= argval[i];
		} else if (ac == SSEUP) {
		    if (ssereg == 0)
			memargs ~= argval[i];
		    else {
			auto v = readRegister(sseregs[ssereg - 1], 8);
			v ~= argval[i];
			writeRegister(sseregs[ssereg - 1], v);
		    }
		} else {
		    memargs ~= argval[i];
		}
	    }

	    /*
	     * Allocate the new stack frame including space for the
	     * return address and arguments. We arrange things so that
	     * rbp will be aligned to a 16-byte boundard after the
	     * called function executes its prologue. We also make
	     * sure we avoid the red zone of the current function.
	     */
	    auto newFrame = regs_.r_rsp - 128 - (memargs.length + 16);
	    newFrame &= ~15;
	    regs_.r_rsp = newFrame + 8;

	    /*
	     * Put arguments on the stack. Possibly we should keep the
	     * stack 16-byte aligned here.
	     */
	    if (memargs.length > 0)
		writeMemory(newFrame + 16, memargs);

	    static class callBreakpoint: TargetBreakpointListener
	    {
                override bool onBreakpoint(Target, TargetThread, ulong)
		{
		    callBpHit_ = true;
		    return true;
		}
		bool callBpHit_ = false;
	    }

	    /*
	     * Write the return address. We arrange for the function to
	     * return to _start and we set a breakpoint there to catch
	     * it.
	     */
	    ubyte[8] ret;
	    writeInteger(target_.entry, ret);
	    writeMemory(newFrame + 8, ret);
	    auto bpl = new callBreakpoint;
	    target_.setBreakpoint(target_.entry, bpl);

	    /*
	     * Set the thing running at the start of the function.
	     */
	    regs_.r_rip = address;
	    grdirty_ = true;
	    fpdirty_ = true;
	    target_.cont(0);
	    target_.wait;

	    target_.clearBreakpoint(target_.entry, bpl);

	    if (!bpl.callBpHit_)
		throw new EvalException(
		    "Function call terminated unexpectedly");

	    /*
	     * Get the return value first then restore the machine state.
	     */
	    Value retval;
	    try {
		retval = returnValue(returnType);
	    } catch (EvalException e) {
		regs_ = saveState.regs_;
		fpregs_ = saveState.fpregs_;
		grdirty_ = true;
		fpdirty_= true;
		throw e;
	    }

	    regs_ = saveState.regs_;
	    fpregs_ = saveState.fpregs_;
	    grdirty_ = true;
	    fpdirty_= true;

	    return retval;
	}

	Value returnValue(Type returnType)
	{
	    auto retcls = classify(returnType);
	    ubyte[] retval;
	    int intreg = 0;
	    int ssereg = 0;
	    foreach (i, cl; retcls) {
		if (cl == INTEGER) {
		    if (intreg == 0)
			retval ~= readRegister(RAX, 8);
		    else
			retval ~= readRegister(RDX, 8);
		    intreg++;
		}
		else if (cl == SSE) {
		    if (ssereg == 0)
			retval ~= readRegister(XMM0, 8);
		    else
			retval ~= readRegister(XMM1, 8);
		    ssereg++;
		}
		else if (cl == SSEUP) {
		    if (ssereg == 1)
			retval ~= readRegister(XMM0, 16)[8..$];
		    else
			retval ~= readRegister(XMM1, 16)[8..$];
		}
		else if (cl == X87) {
		    if (i < retcls.length - 1
			&& retcls[i + 1] == X87UP)
			retval ~= readRegister(ST0, 16);
		    else
			retval ~= readRegister(ST0, returnType.byteWidth);
		} else if (cl == MEMORY) {
		    retval = readMemory(regs_.r_rax, returnType.byteWidth);
		    break;
		}
		else {
		    throw new EvalException(
			"Can't read return value for function call");
		}
		if (retval.length > returnType.byteWidth)
		    retval.length = returnType.byteWidth;
	    }

	    return new Value(new ConstantLocation(retval), returnType);
	}

	ulong findFlowControl(ulong start, ulong end)
	{
	    char readByte(ulong loc) {
		ubyte[] t = readMemory(loc, 1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("x86_64");
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
	    dis.setOption("x86_64");
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
	    dis.setOption("x86_64");
	    return dis.disassemble(address, &readByte, lookupAddress);
	}

	string[] contents(MachineState)
	{
	    string[] res = RegNames;
	    res ~= "rflags";
	    for (auto i = 0; i < 8; i++)
		res ~= format("st%d", i);
	    for (auto i = 0; i < 8; i++)
		res ~= format("mm%d", i);
	    for (auto i = 0; i < 16; i++)
		res ~= format("xmm%d", i);
	    return res;
	}

	bool lookup(string reg, MachineState, out DebugItem val)
	{
	    if (reg.length > 0 && reg[0] == '$')
		reg = reg[1..$];
	    if (reg == "pc") reg = "rip";
	    foreach (i, s; RegNames) {
		if (s == reg) {
		    val = regAsValue(i, grType_);
		    return true;
		}
	    }
	    if (reg == "rflags") {
		val = regAsValue(RFLAGS, grType_);
	    }
	    if (reg.length == 3 && reg[0..2] == "st"
		&& reg[2] >= '0' && reg[2] <= '7') {
		val = regAsValue(33 + reg[2] - '0', frType_);
		return true;
	    }
	    if (reg.length == 4 && reg[0..3] == "xmm"
		&& reg[3] >= '0' && reg[3] <= '9') {
		val = regAsValue(17 + reg[3] - '0', xmmType_);
		return true;
	    }
	    if (reg.length == 5 && reg[0..3] == "xmm"
		&& reg[3] == '1'
		&& reg[4] >= '0' && reg[4] <= '5') {
		val = regAsValue(17 + 10 + reg[4] - '0', xmmType_);
		return true;
	    }
	    if (reg.length == 3 && reg[0..2] == "mm"
		&& reg[2] >= '0' && reg[2] <= '7') {
		val = regAsValue(41 + reg[2] - '0', mmType_);
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

    Value regAsValue(size_t i, Type ty)
    {
	auto loc = new RegisterLocation(i, grWidth(i));
	return new Value(loc, ty);
    }

private:
    uint64_t* grAddr(size_t gregno)
    {
	assert(gregno <= RIP);
	if (regmap_[gregno] == ~0)
	    return null;
	return cast(uint64_t*) (cast(ubyte*) &regs_ + regmap_[gregno]);
    }

    enum {
	INTEGER, SSE, SSEUP, X87, X87UP, COMPLEX_X87, NO_CLASS, MEMORY,
    }

    int[] classify(Type ty)
    {
	if (ty.isIntegerType)
	    return [INTEGER];
	if (cast(PointerType) ty)
	    return [INTEGER];
	if (ty.isNumericType && ty.byteWidth <= 8)
	    return [SSE];
	if (ty.isNumericType)
	    return [X87, X87UP];
	auto aTy = cast(ArrayType) ty;
	if (aTy) {
	    /*
	     * XXX need a better way of recognising vector
	     * types.
	     */
	    if (!aTy.baseType.isIntegerType
		&& aTy.baseType.isNumericType
		&& aTy.baseType.byteWidth == 4
		&& aTy.byteWidth == 128) {
		return [SSE, SSEUP];
	    }
	    /*
	     * XXX need to pass a pointer
	     */
	}
	auto cTy = cast(CompoundType) ty;
	if (cTy) {
	    int[] classes;
	    classes.length = (cTy.byteWidth + 7) / 8;
	    foreach (ref cl; classes)
		cl = NO_CLASS;

	    if (cTy.byteWidth > 4 * 8) {
	    inmemory:
		foreach (ref cl; classes)
		    cl = MEMORY;
		return classes;
	    }

	    for (auto i = 0; i < cTy.length; i++) {
		auto f = cTy[i].value;
		Location loc = new MemoryLocation(0, 0);
		loc = f.loc.fieldLocation(loc, this);
		auto start = loc.address(this) / 8;
		auto end = (loc.address(this)
			    + f.type.byteWidth + 7) / 8;
		auto fieldClass = classify(f.type);
		for (auto j = start; j < end; j++) {
		    auto k = j - start;
		    if (classes[j] == NO_CLASS)
			classes[j] = fieldClass[k];
		    else if (classes[j] == MEMORY
			     || fieldClass[k] == MEMORY)
			classes[j] = MEMORY;
		    else if (classes[j] == INTEGER
			     || fieldClass[k] == INTEGER)
			classes[j] = INTEGER;
		    else if (classes[j] == X87
			     || classes[j] == X87UP
			     || classes[j] == COMPLEX_X87
			     || fieldClass[k] == X87
			     || fieldClass[k] == X87UP
			     || fieldClass[k] == COMPLEX_X87)
			classes[j] = MEMORY;
		    else
			classes[j] = SSE;
		}
	    }
	    foreach (i, cl; classes) {
		if (cl == MEMORY)
		    goto inmemory;
		if (cl == X87UP
		    && (i == 0 || classes[i - 1] != X87))
		    goto inmemory;
	    }
	    if (classes.length > 1) {
		foreach (i, ref cl; classes) {
		    if (i == 0 && cl != SSE)
			goto inmemory;
		    if (i > 0) {
			if (cl != SSEUP)
			    goto inmemory;
			if (classes[i - 1] != SSE
			    || classes[i - 1] != SSEUP)
			    cl = SSE;
		    }
		}
	    }
	    return classes;
	}
	auto n = (ty.byteWidth + 7) / 8;
	int[] classes;
	classes.length = n;
	foreach (ref cl; classes)
	    cl = MEMORY;
	return classes;
    }

    union float32 {
	uint i;
	float f;
    }
    union float64 {
	ulong i;
	double f;
    }
    version (FreeBSD) {
	static uint[] regmap_ = [
	    reg64.r_rax.offsetof,	// X86_64Reg.RAX
	    reg64.r_rdx.offsetof,	// X86_64Reg.RDX
	    reg64.r_rcx.offsetof,	// X86_64Reg.RCX
	    reg64.r_rbx.offsetof,	// X86_64Reg.RBX
	    reg64.r_rsi.offsetof,	// X86_64Reg.RSI
	    reg64.r_rdi.offsetof,	// X86_64Reg.RDI
	    reg64.r_rbp.offsetof,	// X86_64Reg.RBP
	    reg64.r_rsp.offsetof,	// X86_64Reg.RSP
	    reg64.r_r8.offsetof,	// X86_64Reg.R8
	    reg64.r_r9.offsetof,	// X86_64Reg.R9
	    reg64.r_r10.offsetof,	// X86_64Reg.R10
	    reg64.r_r11.offsetof,	// X86_64Reg.R11
	    reg64.r_r12.offsetof,	// X86_64Reg.R12
	    reg64.r_r13.offsetof,	// X86_64Reg.R13
	    reg64.r_r14.offsetof,	// X86_64Reg.R14
	    reg64.r_r15.offsetof,	// X86_64Reg.R15
	    reg64.r_rip.offsetof,	// X86_64Reg.RIP
	    ];
    }
    version (linux) {
	static uint[] regmap_ = [
	    reg64.r_rax.offsetof,	// X86_64Reg.RAX
	    reg64.r_rdx.offsetof,	// X86_64Reg.RDX
	    reg64.r_rcx.offsetof,	// X86_64Reg.RCX
	    reg64.r_rbx.offsetof,	// X86_64Reg.RBX
	    reg64.r_rsi.offsetof,	// X86_64Reg.RSI
	    reg64.r_rdi.offsetof,	// X86_64Reg.RDI
	    reg64.r_rbp.offsetof,	// X86_64Reg.RBP
	    reg64.r_rsp.offsetof,	// X86_64Reg.RSP
	    reg64.r_r8.offsetof,	// X86_64Reg.R8
	    reg64.r_r9.offsetof,	// X86_64Reg.R9
	    reg64.r_r10.offsetof,	// X86_64Reg.R10
	    reg64.r_r11.offsetof,	// X86_64Reg.R11
	    reg64.r_r12.offsetof,	// X86_64Reg.R12
	    reg64.r_r13.offsetof,	// X86_64Reg.R13
	    reg64.r_r14.offsetof,	// X86_64Reg.R14
	    reg64.r_r15.offsetof,	// X86_64Reg.R15
	    reg64.r_rip.offsetof,	// X86_64Reg.RIP
	    ];
    }

    Target	target_;
    bool	grdirty_;
    uint32_t	tp_;
    reg64	regs_;
    xmmreg64	fpregs_;
    bool	fpdirty_;

    static Type	grType_;
    static Type	frType_;
    static Type	xmmType_;
    static Type	mmType_;
}

private:

version (FreeBSD) {
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
    struct reg32 {
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

    struct reg64 {
	ulong	r_r15;
	ulong	r_r14;
	ulong	r_r13;
	ulong	r_r12;
	ulong	r_r11;
	ulong	r_r10;
	ulong	r_r9;
	ulong	r_r8;
	ulong	r_rdi;
	ulong	r_rsi;
	ulong	r_rbp;
	ulong	r_rbx;
	ulong	r_rdx;
	ulong	r_rcx;
	ulong	r_rax;
	uint	r_trapno;
	ushort	r_fs;
	ushort	r_gs;
	uint	r_err;
	ushort	r_es;
	ushort	r_ds;
	ulong	r_rip;
	ulong	r_cs;
	ulong	r_rflags;
	ulong	r_rsp;
	ulong	r_ss;
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

    struct xmmreg32 {
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

    struct xmmreg64 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[16][16];
	ulong	xmm_pad[12];
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

    enum
    {
	PT_GETXMMREGS = PT_FIRSTMACH + 0,
	PT_SETXMMREGS = PT_FIRSTMACH + 1,
	PT_GETFSBASE = PT_FIRSTMACH + 2,
	PT_GETGSBASE = PT_FIRSTMACH + 3
    }
}
version (linux) {
/* this struct defines the way the registers are stored on the
   stack during a system call. */

    struct reg32 {
	uint r_ebx;
	uint r_ecx;
	uint r_edx;
	uint r_esi;
	uint r_edi;
	uint r_ebp;
	uint r_eax;
	uint r_ds;
	uint r_es;
	uint r_fs;
	uint r_gs;
	uint r_orig_eax;
	uint r_eip;
	uint r_cs;
	uint r_eflags;
	uint r_esp;
	uint r_ss;
    }
    struct reg64 {
	ulong	r_r15;
	ulong	r_r14;
	ulong	r_r13;
	ulong	r_r12;
	ulong	r_r11;
	ulong	r_r10;
	ulong	r_r9;
	ulong	r_r8;
	ulong	r_rdi;
	ulong	r_rsi;
	ulong	r_rbp;
	ulong	r_rbx;
	ulong	r_rdx;
	ulong	r_rcx;
	ulong	r_rax;
	uint	r_trapno;
	ushort	r_fs;
	ushort	r_gs;
	uint	r_err;
	ushort	r_es;
	ushort	r_ds;
	ulong	r_rip;
	ulong	r_cs;
	ulong	r_rflags;
	ulong	r_rsp;
	ulong	r_ss;
    };
    struct xmmreg32 {
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
    struct xmmreg64 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[16][16];
	ulong	xmm_pad[12];
    };
    enum {
	PTRACE_GETREGS =            12,
	    PTRACE_SETREGS =            13,
	    PTRACE_GETFPREGS =          14,
	    PTRACE_SETFPREGS =          15,
	    PTRACE_GETFPXREGS =         18,
	    PTRACE_SETFPXREGS =         19,

	    PTRACE_OLDSETOPTIONS =      21,

	    PTRACE_GET_THREAD_AREA =    25,

	    PTRACE_SET_THREAD_AREA =    26,

	    PTRACE_SYSEMU =		31,
	    PTRACE_SYSEMU_SINGLESTEP =  32
    }
}
