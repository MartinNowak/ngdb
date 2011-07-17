module machine.x86dis;

import std.algorithm;
import std.string;
import std.stdio;
import std.conv : to, octal;

private enum
{
    REGISTER	= 0,		// General register
    FLOATREG	= 1,		// 387 floating point register 
    MMXREG	= 2,		// MMX register
    XMMREG	= 3		// SSE registrer
}

private enum
{
    BYTE	= 0,		// byte sized operands
    WORD	= 1,		// word sized operands
    LONG	= 2,		// double word sized operands
    QWORD	= 3,		// quad word sized operands
    DQWORD	= 5,		// double quad word sized operands
    FLOAT	= 6,		// single-precision floating point
    DOUBLE	= 7,		// double-precision floating point
    LDOUBLE	= 8,		// long double-precision floating point
    PREFIX	= 9,		// set instruction size based on prefix
    NONE	= 10,		// don't add size suffix
    SIZE	= 15,		// mask size bits
    VALID32	= 1<<4,		// instruction is valid in 32bit mode
    VALID64	= 1<<5,		// instruction is valid in 64bit mode
    MODRM	= 1<<6,		// instruction has modrm byte
    REGONLY	= 1<<7,		// instruction matches only modrm.mod == 3
    MEMONLY	= 1<<8,		// instruction matches only modrm.mod != 3
    PREFIX66	= 1<<9,		// mandatory 66 prefix
    PREFIXF2	= 1<<10,	// mandatory F2 prefix
    PREFIXF3	= 1<<11,	// mandatory F3 prefix
    MODRMMASK	= octal!77 << 12,	// mask for matching modrm rm and reg fields
    MODRMMASKSHIFT = 12,	// mask for matching modrm rm and reg fields
    MODRMMATCH	= octal!77 << 18,	// value for matching modrm rm and reg fields
    MODRMMATCHSHIFT = 18,	// value for matching modrm rm and reg fields
    FLOW	= 1<<24		// instruction is a branch, call or ret
}

class Disassembler
{
    void setOption(string opt)
    {
	if (opt == "intel")
	    attMode_ = false;
	if (opt == "att")
	    attMode_ = true;
	if (opt == "x86_64")
	    mode_ = 64;
    }

    bool isFlowControl(ref ulong loc, char delegate(ulong) readByte)
    {
	DecodeState ds;
	Instruction ip[];
	ulong iloc = loc;

	bool morePrefixes = true;
	while (morePrefixes) {
	    char b = readByte(loc);

	    if (mode_ == 64 && (b & 0xf0) == 0x40) {
		/*
		 * This is a REX prefix in 64bit mode.
		 */
		ds.rex_ = b;
		loc++;
		continue;
	    }

	    switch (b) {
	    case 0xf0:
		ds.lockPrefix_ = true;
		loc++;
		break;

	    case 0xf2:
		ds.repnePrefix_ = true;
		loc++;
		break;

	    case 0xf3:
		ds.repePrefix_ = true;
		loc++;
		break;

	    case 0x2e:
	    case 0x36:
	    case 0x3e:
	    case 0x26:
	    case 0x64:
	    case 0x65:
		// segment prefix
		loc++;
		break;

	    case 0x67:
		ds.addressSizePrefix_ = true;
		loc++;
		break;

	    case 0x66:
		ds.operandSizePrefix_ = true;
		loc++;
		break;

	    default:
		morePrefixes = false;
	    }
	}

	ds.readByte_ = readByte;
	ds.mode_ = mode_;

	Instruction insn;
	ds.loc_ = loc;
	if (table_.lookup(&ds, insn)) {
	    insn.skipImmediate(&ds);
	    loc = ds.loc_;
	    return insn.flags_ & FLOW ? true : false;
	}
	return false;
    }

    bool isJump(ref ulong loc, out ulong target, char delegate(ulong) readByte)
    {
	DecodeState ds;
	Instruction ip[];
	ulong iloc = loc;

	bool morePrefixes = true;
	while (morePrefixes) {
	    char b = readByte(loc);

	    if (mode_ == 64 && (b & 0xf0) == 0x40) {
		/*
		 * This is a REX prefix in 64bit mode.
		 */
		ds.rex_ = b;
		loc++;
		continue;
	    }

	    switch (readByte(loc)) {
	    case 0xf0:
		ds.lockPrefix_ = true;
		loc++;
		break;

	    case 0xf2:
		ds.repnePrefix_ = true;
		loc++;
		break;

	    case 0xf3:
		ds.repePrefix_ = true;
		loc++;
		break;

	    case 0x2e:
	    case 0x36:
	    case 0x3e:
	    case 0x26:
	    case 0x64:
	    case 0x65:
		// segment prefix
		loc++;
		break;

	    case 0x67:
		ds.addressSizePrefix_ = true;
		loc++;
		break;

	    case 0x66:
		ds.operandSizePrefix_ = true;
		loc++;
		break;

	    default:
		morePrefixes = false;
	    }
	}

	ds.readByte_ = readByte;
	ds.mode_ = mode_;

	Instruction insn;
	ds.loc_ = loc;
	if (table_.lookup(&ds, insn)) {
	    if (insn.opcodes_[0] == 0xe9) {
		auto off = ds.fetchImmediate(
		    ds.operandSizePrefix_ ? WORD : LONG);
		if (ds.operandSizePrefix_) {
		    if (off & 0x8000)
			off |= -(1L << 16);
		} else {
		    if (off & 0x80000000)
			off |= -(1L << 32);
		}
		loc = ds.loc_;
		target = loc + off;
		return true;
	    }
	    if (insn.opcodes_[0] == 0xeb) {
		auto off = ds.fetchImmediate(BYTE);
		if (off & 0x80)
		    off |= -(1L << 8);
		loc = ds.loc_;
		target = loc + off;
		return true;
	    }
	    insn.skipImmediate(&ds);
	    loc = ds.loc_;
	}
	return false;
    }

    string disassemble(ref ulong loc, char delegate(ulong) readByte,
	string delegate(ulong) lookupAddress)
    {
	DecodeState ds;
	Instruction ip[];
	ulong iloc = loc;

	bool morePrefixes = true;
	while (morePrefixes) {
	    char b = readByte(loc);

	    if (mode_ == 64 && (b & 0xf0) == 0x40) {
		/*
		 * This is a REX prefix in 64bit mode.
		 */
		ds.rex_ = b;
		loc++;
		continue;
	    }

	    switch (readByte(loc)) {
	    case 0xf0:
		ds.lockPrefix_ = true;
		loc++;
		break;

	    case 0xf2:
		ds.repnePrefix_ = true;
		loc++;
		break;

	    case 0xf3:
		ds.repePrefix_ = true;
		loc++;
		break;

	    case 0x2e:
		ds.seg_ = "cs";
		loc++;
		break;

	    case 0x36:
		ds.seg_ = "ss";
		loc++;
		break;

	    case 0x3e:
		ds.seg_ = "ds";
		loc++;
		break;

	    case 0x26:
		ds.seg_ = "es";
		loc++;
		break;

	    case 0x64:
		ds.seg_ = "fs";
		loc++;
		break;

	    case 0x65:
		ds.seg_ = "gs";
		loc++;
		break;

	    case 0x67:
		ds.addressSizePrefix_ = true;
		loc++;
		break;

	    case 0x66:
		ds.operandSizePrefix_ = true;
		loc++;
		break;

	    default:
		morePrefixes = false;
	    }
	}
	if (ds.seg_.length > 0 && attMode_)
	    ds.seg_ = "%" ~ ds.seg_;

	ds.readByte_ = readByte;
	ds.lookupAddress_ = lookupAddress;
	ds.attMode_ = attMode_;
	ds.mode_ = mode_;

	Instruction insn;
	ds.loc_ = loc;
	if (table_.lookup(&ds, insn)) {
	    string prefixString = "";
	    if (ds.lockPrefix_)
		prefixString ~= "lock ";
	    if (ds.repnePrefix_)
		prefixString ~= "repne ";
	    if (ds.repePrefix_)
		prefixString ~= "repe ";
	    string res = prefixString ~ insn.display(&ds);
	    loc = ds.loc_;
	    return res;
	}

	string s = ".byte\t";
	for (ulong i = iloc; i < loc; i++) {
	    if (i > iloc)
		s ~= ",";
	    s ~= format("%#x", readByte(i));
	}
	return s;
    }

private:
    static this()
    {
	table_ = new InstructionTable;

	alias addInstruction ins;
	alias VALID32 V_;
	alias VALID64 _V;
	alias NONE N;
	alias BYTE B;
	alias WORD W;
	alias LONG L;
	alias QWORD Q;
	alias FLOAT S;
	alias DOUBLE D;
	alias LDOUBLE LD;
	alias PREFIX P;
	const int F = NONE|FLOW;
	const int VV = VALID32|VALID64;

	ins(VV|B, "00 /r",		"ADD Eb,Gb");
	ins(VV|P, "01 /r",		"ADD Ev,Gv");
	ins(VV|B, "02 /r",		"ADD Gb,Eb");
	ins(VV|P, "03 /r",		"ADD Gv,Ev");
	ins(VV|B, "04",			"ADD AL,Ib");
	ins(VV|P, "05",			"ADD rAX,Iz");
	ins(V_|N, "06",			"PUSH ES");
	ins(V_|N, "07",			"POP ES");

	ins(VV|B, "08 /r",		"OR Eb,Gb");
	ins(VV|P, "09 /r",		"OR Ev,Gv");
	ins(VV|B, "0A /r",		"OR Gb,Eb");
	ins(VV|P, "0B /r",		"OR Gv,Ev");
	ins(VV|B, "0C",			"OR AL,Ib");
	ins(VV|P, "0D",			"OR rAX,Iz");
	ins(V_|N, "0E",			"PUSH CS");
	// 2 byte table escape

	ins(VV|B, "10 /r",		"ADC Eb,Gb");
	ins(VV|P, "11 /r",		"ADC Ev,Gv");
	ins(VV|B, "12 /r",		"ADC Gb,Eb");
	ins(VV|P, "13 /r",		"ADC Gv,Ev");
	ins(VV|B, "14",			"ADC AL,Ib");
	ins(VV|P, "15",			"ADC rAX,Iz");
	ins(V_|N, "16",			"PUSH SS");
	ins(V_|N, "17",			"POP SS");

	ins(VV|B, "18 /r",		"SBB Eb,Gb");
	ins(VV|P, "19 /r",		"SBB Ev,Gv");
	ins(VV|B, "1A /r",		"SBB Gb,Eb");
	ins(VV|P, "1B /r",		"SBB Gv,Ev");
	ins(VV|B, "1C",			"SBB AL,Ib");
	ins(VV|P, "1D",			"SBB rAX,Iz");
	ins(V_|N, "1E",			"PUSH DS");
	ins(V_|N, "1F",			"POP DS");

	ins(VV|B, "20 /r",		"AND Eb,Gb");
	ins(VV|P, "21 /r",		"AND Ev,Gv");
	ins(VV|B, "22 /r",		"AND Gb,Eb");
	ins(VV|P, "23 /r",		"AND Gv,Ev");
	ins(VV|B, "24",			"AND AL,Ib");
	ins(VV|P, "25",			"AND rAX,Iz");
	// prefix SEG=ES 
	ins(V_|N, "27",			"DAA");

	ins(VV|B, "28 /r",		"SUB Eb,Gb");
	ins(VV|P, "29 /r",		"SUB Ev,Gv");
	ins(VV|B, "2A /r",		"SUB Gb,Eb");
	ins(VV|P, "2B /r",		"SUB Gv,Ev");
	ins(VV|B, "2C",			"SUB AL,Ib");
	ins(VV|P, "2D",			"SUB rAX,Iz");
	// prefix SEG=CS 
	ins(V_|N, "2F",			"DAS");

	ins(VV|B, "30 /r",		"XOR Eb,Gb");
	ins(VV|P, "31 /r",		"XOR Ev,Gv");
	ins(VV|B, "32 /r",		"XOR Gb,Eb");
	ins(VV|P, "33 /r",		"XOR Gv,Ev");
	ins(VV|B, "34",			"XOR AL,Ib");
	ins(VV|P, "35",			"XOR rAX,Iz");
	// prefix SEG=SS 
	ins(V_|N, "37",			"AAA");

	ins(VV|B, "38 /r",		"CMP Eb,Gb");
	ins(VV|P, "39 /r",		"CMP Ev,Gv");
	ins(VV|B, "3A /r",		"CMP Gb,Eb");
	ins(VV|P, "3B /r",		"CMP Gv,Ev");
	ins(VV|B, "3C",			"CMP AL,Ib");
	ins(VV|P, "3D",			"CMP rAX,Iz");
	// prefix SEG=DS 
	ins(V_|N, "3F",			"AAS");

	ins(V_|P, "40",			"INC eAX");
	ins(V_|P, "41",			"INC eCX");
	ins(V_|P, "42",			"INC eDX");
	ins(V_|P, "43",			"INC eBX");
	ins(V_|P, "44",			"INC eSP");
	ins(V_|P, "45",			"INC eBP");
	ins(V_|P, "46",			"INC eSI");
	ins(V_|P, "47",			"INC eDI");

	ins(V_|P, "48",			"DEC eAX");
	ins(V_|P, "49",			"DEC eCX");
	ins(V_|P, "4A",			"DEC eDX");
	ins(V_|P, "4B",			"DEC eBX");
	ins(V_|P, "4C",			"DEC eSP");
	ins(V_|P, "4D",			"DEC eBP");
	ins(V_|P, "4E",			"DEC eSI");
	ins(V_|P, "4F",			"DEC eDI");

	ins(V_|P, "50",			"PUSH rAX");
	ins(V_|P, "51",			"PUSH rCX");
	ins(V_|P, "52",			"PUSH rDX");
	ins(V_|P, "53",			"PUSH rBX");
	ins(V_|P, "54",			"PUSH rSP");
	ins(V_|P, "55",			"PUSH rBP");
	ins(V_|P, "56",			"PUSH rSI");
	ins(V_|P, "57",			"PUSH rDI");

	ins(_V|Q, "50",			"PUSH rAX");
	ins(_V|Q, "51",			"PUSH rCX");
	ins(_V|Q, "52",			"PUSH rDX");
	ins(_V|Q, "53",			"PUSH rBX");
	ins(_V|Q, "54",			"PUSH rSP");
	ins(_V|Q, "55",			"PUSH rBP");
	ins(_V|Q, "56",			"PUSH rSI");
	ins(_V|Q, "57",			"PUSH rDI");

	ins(V_|P, "58",			"POP rAX");
	ins(V_|P, "59",			"POP rCX");
	ins(V_|P, "5A",			"POP rDX");
	ins(V_|P, "5B",			"POP rBX");
	ins(V_|P, "5C",			"POP rSP");
	ins(V_|P, "5D",			"POP rBP");
	ins(V_|P, "5E",			"POP rSI");
	ins(V_|P, "5F",			"POP rDI");

	ins(_V|Q, "58",			"POP rAX");
	ins(_V|Q, "59",			"POP rCX");
	ins(_V|Q, "5A",			"POP rDX");
	ins(_V|Q, "5B",			"POP rBX");
	ins(_V|Q, "5C",			"POP rSP");
	ins(_V|Q, "5D",			"POP rBP");
	ins(_V|Q, "5E",			"POP rSI");
	ins(_V|Q, "5F",			"POP rDI");

	ins(V_|P, "60",			"PUSHA");
	ins(V_|P, "61",			"POPA");
	ins(V_|P, "62 /r",		"BOUND Gv,Ma");
	ins(V_|N, "63 /r",		"ARPL Ew,Gw");
	ins(_V|P, "63 /r",		"MOVSXD Gv,Ev");
	// prefix SEG=FS
	// prefix SEG=GS
	// prefix Operand Size
	// prefix Address Size

	ins(V_|P, "68",			"PUSH Iz");
	ins(_V|Q, "68",			"PUSH Iz");
	ins(VV|P, "69 /r",		"IMUL Gv,Ev,Iz");
	ins(V_|P, "6A",			"PUSH Ib");
	ins(_V|Q, "6A",			"PUSH Ib");
	ins(VV|P, "6B /r",		"IMUL Gv,Ev,Ib");
	ins(VV|B, "6C",			"INS Yb,DX");
	ins(VV|P, "6D",			"INS Yz,DX");
	ins(VV|B, "6E",			"OUTS DX,Xb");
	ins(VV|P, "6F",			"OUTS DX,Xz");

	ins(VV|F, "70",			"JO Jb");
	ins(VV|F, "71",			"JNO Jb");
	ins(VV|F, "72",			"JB Jb");
	ins(VV|F, "73",			"JNB Jb");
	ins(VV|F, "74",			"JZ Jb");
	ins(VV|F, "75",			"JNZ Jb");
	ins(VV|F, "76",			"JBE Jb");
	ins(VV|F, "77",			"JNBE Jb");

	ins(VV|F, "78",			"JS Jb");
	ins(VV|F, "79",			"JNS Jb");
	ins(VV|F, "7A",			"JP Jb");
	ins(VV|F, "7B",			"JNP Jb");
	ins(VV|F, "7C",			"JL Jb");
	ins(VV|F, "7D",			"JNL Jb");
	ins(VV|F, "7E",			"JLE Jb");
	ins(VV|F, "7F",			"JNLE Jb");

	ins(VV|B, "80 /0",		"ADD Eb,Ib");
	ins(VV|B, "80 /1",		"OR Eb,Ib");
	ins(VV|B, "80 /2",		"ADC Eb,Ib");
	ins(VV|B, "80 /3",		"SBB Eb,Ib");
	ins(VV|B, "80 /4",		"AND Eb,Ib");
	ins(VV|B, "80 /5",		"SUB Eb,Ib");
	ins(VV|B, "80 /6",		"XOR Eb,Ib");
	ins(VV|B, "80 /7",		"CMP Eb,Ib");
	ins(VV|P, "81 /0",		"ADD Ev,Iz");
	ins(VV|P, "81 /1",		"OR Ev,Iz");
	ins(VV|P, "81 /2",		"ADC Ev,Iz");
	ins(VV|P, "81 /3",		"SBB Ev,Iz");
	ins(VV|P, "81 /4",		"AND Ev,Iz");
	ins(VV|P, "81 /5",		"SUB Ev,Iz");
	ins(VV|P, "81 /6",		"XOR Ev,Iz");
	ins(VV|P, "81 /7",		"CMP Ev,Iz");
	// 82 same as 80 in 32 bit mode?
	ins(VV|P, "83 /0",		"ADD Ev,Ib");
	ins(VV|P, "83 /1",		"OR Ev,Ib");
	ins(VV|P, "83 /2",		"ADC Ev,Ib");
	ins(VV|P, "83 /3",		"SBB Ev,Ib");
	ins(VV|P, "83 /4",		"AND Ev,Ib");
	ins(VV|P, "83 /5",		"SUB Ev,Ib");
	ins(VV|P, "83 /6",		"XOR Ev,Ib");
	ins(VV|P, "83 /7",		"CMP Ev,Ib");
	ins(VV|B, "84 /r",		"TEST Eb,Gb");
	ins(VV|P, "85 /r",		"TEST Ev,Gv");
	ins(VV|B, "86 /r",		"XCHG Eb,Gb");
	ins(VV|P, "87 /r",		"XCHG Ev,Gv");

	ins(VV|B, "88 /r",		"MOV Eb,Gb");
	ins(VV|P, "89 /r",		"MOV Ev,Gv");
	ins(VV|B, "8A /r",		"MOV Gb,Eb");
	ins(VV|P, "8B /r",		"MOV Gv,Ev");
	ins(VV|N, "8C /r",		"MOV Ew,Sw");
	ins(VV|P, "8D /r",		"LEA Gv,Mn");
	ins(VV|N, "8E /r",		"MOV Sw,Ew");
	ins(V_|P, "8F /0",		"POP Ev");
	ins(_V|Q, "8F /0",		"POP Ev");

	ins(VV|N, "F3 90",		"PAUSE");
	ins(VV|N, "90",			"NOP");
	ins(VV|P, "91",			"XCHG rCX,rAXnorex");
	ins(VV|P, "92",			"XCHG rDX,rAXnorex");
	ins(VV|P, "93",			"XCHG rBX,rAXnorex");
	ins(VV|P, "94",			"XCHG rSP,rAXnorex");
	ins(VV|P, "95",			"XCHG rBP,rAXnorex");
	ins(VV|P, "96",			"XCHG rSI,rAXnorex");
	ins(VV|P, "97",			"XCHG rDI,rAXnorex");

	ins(VV|P, "98",			"CBW/CWDE/CDQE");
	ins(VV|P, "99",			"CWD/CDQ/CQO");
	ins(V_|F, "9A",			"LCALL Ap");
	//ins(VV|N, "9B D9 /7",		"FSTCW Mb");
	//ins(VV|N, "9B D9 /6",		"FSTENV Mb");
	//ins(VV|N, "9B DB E2",		"FCLEX");
	//ins(VV|N, "9B DB E3",		"FINIT");
	//ins(VV|N, "9B DD /6",		"FSAVE Mb");
	//ins(VV|N, "9B DD /7",		"FSTSW Mb");
	//ins(VV|N, "9B DF E0",		"FSTSW AX");
	ins(VV|N, "9B",			"WAIT");
	ins(V_|P, "9C",			"PUSHF");
	ins(_V|Q, "9C",			"PUSHF");
	ins(V_|P, "9D",			"POPF");
	ins(_V|Q, "9D",			"POPF");
	ins(VV|N, "9E",			"SAHF");
	ins(VV|N, "9F",			"LAHF");

	ins(VV|B, "A0",			"MOV AL,Ob");
	ins(VV|P, "A1",			"MOV rAX,Ov");
	ins(VV|B, "A2",			"MOV Ob,AL");
	ins(VV|P, "A3",			"MOV Ov,rAX");
	ins(VV|B, "A4",			"MOVS Yb,Xb");
	ins(VV|P, "A5",			"MOVS Yv,Xv");
	ins(VV|B, "A6",			"CMPS Yb,Xb");
	ins(VV|P, "A7",			"CMPS Yv,Xv");

	ins(VV|B, "A8",			"TEST AL,Ib");
	ins(VV|P, "A9",			"TEST rAX,Iz");
	ins(VV|B, "AA",			"STOS Yb");
	ins(VV|P, "AB",			"STOS Yv");
	ins(VV|B, "AC",			"LODS Xb");
	ins(VV|P, "AD",			"LODS Xv");
	ins(VV|B, "AE",			"SCAS Xb");
	ins(VV|P, "AF",			"SCAS Xv");

	ins(VV|B, "B0",			"MOV AL,Ib");
	ins(VV|B, "B1",			"MOV CL,Ib");
	ins(VV|B, "B2",			"MOV DL,Ib");
	ins(VV|B, "B3",			"MOV BL,Ib");
	ins(VV|B, "B4",			"MOV AH,Ib");
	ins(VV|B, "B5",			"MOV CH,Ib");
	ins(VV|B, "B6",			"MOV DH,Ib");
	ins(VV|B, "B7",			"MOV BH,Ib");

	ins(VV|P, "B8",			"MOV rAX,Iv");
	ins(VV|P, "B9",			"MOV rCX,Iv");
	ins(VV|P, "BA",			"MOV rDX,Iv");
	ins(VV|P, "BB",			"MOV rBX,Iv");
	ins(VV|P, "BC",			"MOV rSP,Iv");
	ins(VV|P, "BD",			"MOV rBP,Iv");
	ins(VV|P, "BE",			"MOV rSI,Iv");
	ins(VV|P, "BF",			"MOV rDI,Iv");

	ins(VV|B, "C0 /0",		"ROL Eb,Ib");
	ins(VV|B, "C0 /1",		"ROR Eb,Ib");
	ins(VV|B, "C0 /2",		"RCL Eb,Ib");
	ins(VV|B, "C0 /3",		"RCR Eb,Ib");
	ins(VV|B, "C0 /4",		"SHL Eb,Ib");
	ins(VV|B, "C0 /5",		"SHR Eb,Ib");
	ins(VV|B, "C0 /7",		"SAR Eb,Ib");
	ins(VV|P, "C1 /0",		"ROL Ev,Ib");
	ins(VV|P, "C1 /1",		"ROR Ev,Ib");
	ins(VV|P, "C1 /2",		"RCL Ev,Ib");
	ins(VV|P, "C1 /3",		"RCR Ev,Ib");
	ins(VV|P, "C1 /4",		"SHL Ev,Ib");
	ins(VV|P, "C1 /5",		"SHR Ev,Ib");
	ins(VV|P, "C1 /7",		"SAR Ev,Ib");
	ins(VV|F, "C2",			"RET Iw");
	ins(VV|F, "C3",			"RET");
	ins(V_|P, "C4 /r",		"LES Gz,Md"); // XXX Mp
	ins(V_|P, "C5 /r",		"LDS Gz,Md"); // XXX Mp
	ins(VV|B, "C6 /0",		"MOV Eb,Ib");
	ins(VV|P, "C7 /0",		"MOV Ev,Iz");

	ins(VV|N, "C8",			"ENTER Kw,Kb");
	ins(VV|N, "C9",			"LEAVE");
	ins(VV|F, "CA",			"LRET Iw");
	ins(VV|F, "CB",			"LRET");
	ins(VV|N, "CC",			"INT 3");
	ins(VV|N, "CD",			"INT Kb");
	ins(V_|N, "CE",			"INTO");
	ins(VV|N, "CF",			"IRET");

	ins(VV|B, "D0 /0",		"ROL Eb,1");
	ins(VV|B, "D0 /1",		"ROR Eb,1");
	ins(VV|B, "D0 /2",		"RCL Eb,1");
	ins(VV|B, "D0 /3",		"RCR Eb,1");
	ins(VV|B, "D0 /4",		"SHL Eb,1");
	ins(VV|B, "D0 /5",		"SHR Eb,1");
	ins(VV|B, "D0 /7",		"SAR Eb,1");
	ins(VV|P, "D1 /0",		"ROL Ev,1");
	ins(VV|P, "D1 /1",		"ROR Ev,1");
	ins(VV|P, "D1 /2",		"RCL Ev,1");
	ins(VV|P, "D1 /3",		"RCR Ev,1");
	ins(VV|P, "D1 /4",		"SHL Ev,1");
	ins(VV|P, "D1 /5",		"SHR Ev,1");
	ins(VV|P, "D1 /7",		"SAR Ev,1");
	ins(VV|B, "D2 /0",		"ROL Eb,CLnorex");
	ins(VV|B, "D2 /1",		"ROR Eb,CLnorex");
	ins(VV|B, "D2 /2",		"RCL Eb,CLnorex");
	ins(VV|B, "D2 /3",		"RCR Eb,CLnorex");
	ins(VV|B, "D2 /4",		"SHL Eb,CLnorex");
	ins(VV|B, "D2 /5",		"SHR Eb,CLnorex");
	ins(VV|B, "D2 /7",		"SAR Eb,CLnorex");
	ins(VV|P, "D3 /0",		"ROL Ev,CLnorex");
	ins(VV|P, "D3 /1",		"ROR Ev,CLnorex");
	ins(VV|P, "D3 /2",		"RCL Ev,CLnorex");
	ins(VV|P, "D3 /3",		"RCR Ev,CLnorex");
	ins(VV|P, "D3 /4",		"SHL Ev,CLnorex");
	ins(VV|P, "D3 /5",		"SHR Ev,CLnorex");
	ins(VV|P, "D3 /7",		"SAR Ev,CLnorex");
	ins(V_|N, "D4",			"AAM Kb");
	ins(V_|N, "D4",			"AAM Kb");
	ins(V_|N, "D5 0A",		"AAD");
	ins(V_|N, "D5",			"AAD Kb");
	// D6 unused
	ins(VV|B, "D7",			"XLAT");

	ins(VV|N, "D8 /r0",		"FADD ST(0),ST(i)");
	ins(VV|N, "D8 /r1",		"FMUL ST(0),ST(i)");
	ins(VV|N, "D8 /r2",		"FCOM ST(0),ST(i)");
	ins(VV|N, "D8 /r3",		"FCOMP ST(0),ST(i)");
	ins(VV|N, "D8 /r4",		"FSUB ST(0),ST(i)");
	ins(VV|N, "D8 /r5",		"FSUBR ST(0),ST(i)");
	ins(VV|N, "D8 /r6",		"FDIV ST(0),ST(i)");
	ins(VV|N, "D8 /r7",		"FDIVR ST(0),ST(i)");

	ins(VV|S, "D8 /0",		"FADD Md");
	ins(VV|S, "D8 /1",		"FMUL Md");
	ins(VV|S, "D8 /2",		"FCOM Md");
	ins(VV|S, "D8 /3",		"FCOMP Md");
	ins(VV|S, "D8 /4",		"FSUB Md");
	ins(VV|S, "D8 /5",		"FSUBR Md");
	ins(VV|S, "D8 /6",		"FDIV Md");
	ins(VV|S, "D8 /7",		"FDIVR Md");

	ins(VV|N, "D9 /r0",		"FLD ST(i)");
	ins(VV|N, "D9 /r1",		"FXCH ST(i)");
	ins(VV|N, "D9 /r11",		"FXCH");

	ins(VV|N, "D9 /r20",		"FNOP");

	ins(VV|N, "D9 /r40",		"FCHS");
	ins(VV|N, "D9 /r41",		"FABS");
	ins(VV|N, "D9 /r44",		"FTST");
	ins(VV|N, "D9 /r45",		"FXAM");
	ins(VV|N, "D9 /r50",		"FLD1");
	ins(VV|N, "D9 /r51",		"FLDL2T");
	ins(VV|N, "D9 /r52",		"FLDL2E");
	ins(VV|N, "D9 /r53",		"FLDPI");
	ins(VV|N, "D9 /r54",		"FLDLG2");
	ins(VV|N, "D9 /r55",		"FLDLN2");
	ins(VV|N, "D9 /r56",		"FLDZ");

	ins(VV|N, "D9 /r60",		"F2XM1");
	ins(VV|N, "D9 /r61",		"FYL2X");
	ins(VV|N, "D9 /r62",		"FPTAN");
	ins(VV|N, "D9 /r63",		"FPATAN");
	ins(VV|N, "D9 /r64",		"FXTRACT");
	ins(VV|N, "D9 /r65",		"FPREM1");
	ins(VV|N, "D9 /r66",		"FDECSTP");
	ins(VV|N, "D9 /r67",		"FINCSTP");
	ins(VV|N, "D9 /r70",		"FPREM");
	ins(VV|N, "D9 /r71",		"FYL2XP1");
	ins(VV|N, "D9 /r72",		"FSQRT");
	ins(VV|N, "D9 /r73",		"FSINCOS");
	ins(VV|N, "D9 /r74",		"FRNDINT");
	ins(VV|N, "D9 /r75",		"FSCALE");
	ins(VV|N, "D9 /r76",		"FSIN");
	ins(VV|N, "D9 /r77",		"FCOS");

	ins(VV|S, "D9 /0",		"FLD Mf");
	ins(VV|S, "D9 /2",		"FST Mf");
	ins(VV|S, "D9 /3",		"FSTP Mf");
	ins(VV|S, "D9 /4",		"FLDENV Mb");
	ins(VV|S, "D9 /5",		"FLDCW Mw");
	ins(VV|S, "D9 /6",		"FNSTENV Mb");
	ins(VV|S, "D9 /7",		"FNSTCW Mb");

	ins(VV|N, "DA /r0",		"FCMOVB ST(0),ST(i)");
	ins(VV|N, "DA /r1",		"FCMOVE ST(0),ST(i)");
	ins(VV|N, "DA /r2",		"FCMOVBE ST(0),ST(i)");
	ins(VV|N, "DA /r3",		"FCMOVU ST(0),ST(i)");
	ins(VV|N, "DA /r51",		"FUCOMPP");
	ins(VV|L, "DA /0",		"FIADD Md");
	ins(VV|L, "DA /1",		"FIMUL Md");
	ins(VV|L, "DA /2",		"FICOM Md");
	ins(VV|L, "DA /3",		"FICOMP Md");
	ins(VV|L, "DA /4",		"FISUB Md");
	ins(VV|L, "DA /5",		"FISUBR Md");
	ins(VV|L, "DA /6",		"FIDIV Md");
	ins(VV|L, "DA /7",		"FIDIVR Md");

	ins(VV|N, "DB /r0",		"FCMOVNB ST(0),ST(i)");
	ins(VV|N, "DB /r1",		"FCMOVNE ST(0),ST(i)");
	ins(VV|N, "DB /r2",		"FCMOVNBE ST(0),ST(i)");
	ins(VV|N, "DB /r3",		"FCMOVNU ST(0),ST(i)");
	ins(VV|N, "DB /r42",		"FNCLEX");
	ins(VV|N, "DB /r43",		"FNINIT");
	ins(VV|N, "DB /r5",		"FUCOMI ST(0),ST(i)");
	ins(VV|N, "DB /r6",		"FCOMI ST(0),ST(i)");
	ins(VV|L, "DB /0",		"FILD Md");
	ins(VV|L, "DB /1",		"FISTTP Md");
	ins(VV|L, "DB /2",		"FIST Md");
	ins(VV|L, "DB /3",		"FISTP Md");
	ins(VV|LD, "DB /5",		"FLD Mld");
	ins(VV|LD, "DB /7",		"FSTP Mld");

	ins(VV|N, "DC /r0",		"FADD ST(i),ST(0)");
	ins(VV|N, "DC /r1",		"FMUL ST(i),ST(0)");
	ins(VV|N, "DC /r2",		"FCOM ST(i),ST(0)");
	ins(VV|N, "DC /r3",		"FCOMP ST(i),ST(0)");
	ins(VV|N, "DC /r4",		"FSUBR ST(i),ST(0)");
	ins(VV|N, "DC /r5",		"FSUB ST(i),ST(0)");
	ins(VV|N, "DC /r6",		"FDIVR ST(i),ST(0)");
	ins(VV|N, "DC /r7",		"FDIV ST(i),ST(0)");
	ins(VV|D, "DC /0",		"FADD Mq");
	ins(VV|D, "DC /1",		"FMUL Mq");
	ins(VV|D, "DC /2",		"FCOM Mq");
	ins(VV|D, "DC /3",		"FCOMP Mq");
	ins(VV|D, "DC /4",		"FSUB Mq");
	ins(VV|D, "DC /5",		"FSUBR Mq");
	ins(VV|D, "DC /6",		"FDIV Mq");
	ins(VV|D, "DC /7",		"FDIVR Mq");

	ins(VV|N, "DD /r0",		"FFREE ST(i)");
	ins(VV|N, "DD /r2",		"FST ST(i)");
	ins(VV|N, "DD /r3",		"FSTP ST(i)");
	ins(VV|N, "DD /r4",		"FUCOM ST(i)");
	ins(VV|N, "DD /r41",		"FUCOM");
	ins(VV|N, "DD /r5",		"FUCOMP ST(i)");
	ins(VV|N, "DD /r51",		"FUCOMP");
	ins(VV|N, "DD /6",		"FNSAVE Mb");
	ins(VV|N, "DD /7",		"FNSTSW Mb");

	ins(VV|D, "DD /0",		"FLD Mq");
	ins(VV|Q, "DD /1",		"FISTTP Mq");
	ins(VV|D, "DD /2",		"FST Mq");
	ins(VV|D, "DD /3",		"FSTP Mq");
	ins(VV|N, "DD /4",		"FRSTOR Mb");
	ins(VV|N, "DD /6",		"FNSAVE Mb");
	ins(VV|N, "DD /7",		"FNSTSW Mb");

	ins(VV|N, "DE /r0",		"FADDP ST(i),ST(0)");
	ins(VV|N, "DE /r01",		"FADDP");
	ins(VV|N, "DE /r1",		"FMULP ST(i),ST(0)");
	ins(VV|N, "DE /r11",		"FMULP");
	ins(VV|N, "DE /r31",		"FCOMPP");
	ins(VV|N, "DE /r4",		"FSUBRP ST(i),ST(0)");
	ins(VV|N, "DE /r41",		"FSUBRP");
	ins(VV|N, "DE /r5",		"FSUBP ST(i),ST(0)");
	ins(VV|N, "DE /r51",		"FSUBP");
	ins(VV|N, "DE /r6",		"FDIVRP ST(i),ST(0)");
	ins(VV|N, "DE /r61",		"FDIVRP");
	ins(VV|N, "DE /r7",		"FDIVP ST(i),ST(0)");
	ins(VV|N, "DE /r71",		"FDIVP");
	ins(VV|W, "DE /0",		"FIADD Mw");
	ins(VV|Q, "DE /1",		"FIMUL Mq");
	ins(VV|W, "DE /2",		"FICOM Mw");
	ins(VV|W, "DE /3",		"FICOMP Mw");
	ins(VV|W, "DE /4",		"FISUB Mw");
	ins(VV|W, "DE /5",		"FISUBR Mw");
	ins(VV|Q, "DE /7",		"FIDIVR Mq");
	ins(VV|Q, "DE /6",		"FIDIV Mq");

	ins(VV|N, "DF /r40",		"FNSTSW AX");
	ins(VV|N, "DF /r5",		"FUCOMIP ST(0),ST(i)");
	ins(VV|N, "DF /r6",		"FCOMIP ST(0),ST(i)");
	ins(VV|D, "DF /6",		"FBSTP Mb"); // m80
	ins(VV|W, "DF /0",		"FILD Mw");
	ins(VV|W, "DF /1",		"FISTTP Mw");
	ins(VV|W, "DF /2",		"FIST Mw");
	ins(VV|W, "DF /3",		"FISTP Mw");
	ins(VV|D, "DF /4",		"FBLD Mb"); // m80
	ins(VV|Q, "DF /5",		"FILD Mq");
	ins(VV|Q, "DF /7",		"FISTP Mq");

	ins(VV|F, "E0",			"LOOPNE Jb");
	ins(VV|F, "E1",			"LOOPZ Jb");
	ins(VV|F, "E2",			"LOOP Jb");
	ins(VV|P|FLOW, "E3",		"JCXZ/JECXZ/JRCXZ Jb");
	ins(VV|B, "E4",			"IN AL,Kb");
	ins(VV|P, "E5",			"IN eAX,Kb");
	ins(VV|B, "E6",			"OUT Kb,AL");
	ins(VV|P, "E7",			"OUT eAX,Kb");

	ins(VV|F, "E8",			"CALL Jz");
	ins(VV|F, "E9",			"JMP Jz");
	ins(V_|F, "EA",			"LJMP Ap");
	ins(VV|F, "EB",			"JMP Jb");
	ins(VV|B, "EC",			"IN AL,DX");
	ins(VV|P, "ED",			"IN eAX,DX");
	ins(VV|B, "EE",			"OUT DX,AL");
	ins(VV|P, "EF",			"OUT DX,eAX");

	// lock prefix
	// F1 unused
	// repne prefix
	// repe prefix
	ins(VV|N, "F4",			"HLT");
	ins(VV|N, "F5",			"CMC");
	ins(VV|B, "F6 /0",		"TEST Mb,Ib");
	ins(VV|B, "F6 /2",		"NOT Eb");
	ins(VV|B, "F6 /3",		"NEG Eb");
	ins(VV|B, "F6 /4",		"MUL AL,Eb");
	ins(VV|B, "F6 /5",		"IMUL AL,Eb");
	ins(VV|B, "F6 /6",		"DIV Eb");
	ins(VV|B, "F6 /7",		"IDIV Eb");
	ins(VV|P, "F7 /0",		"TEST Mv,Iz");
	ins(VV|P, "F7 /2",		"NOT Ev");
	ins(VV|P, "F7 /3",		"NEG Ev");
	ins(VV|P, "F7 /4",		"MUL rAXnorex,Ev");
	ins(VV|P, "F7 /5",		"IMUL rAXnorex,Ev");
	ins(VV|P, "F7 /6",		"DIV rAXnorex,Ev");
	ins(VV|P, "F7 /7",		"IDIV rAXnorex,Ev");

	ins(VV|N, "F8",			"CLC");
	ins(VV|N, "F9",			"STC");
	ins(VV|N, "FA",			"CLI");
	ins(VV|N, "FB",			"STI");
	ins(VV|N, "FC",			"CLD");
	ins(VV|N, "FD",			"STD");
	ins(VV|B, "FE /0",		"INC Eb");
	ins(VV|B, "FE /1",		"DEC Eb");
	ins(VV|P, "FF /0",		"INC Ev");
	ins(VV|P, "FF /1",		"DEC Ev");
	ins(VV|P|FLOW, "FF /2",		"CALL Hv");
	ins(VV|P|FLOW, "FF /3",		"LCALL Hb"); // XXX Ep
	ins(VV|P|FLOW, "FF /4",		"JMP Hv");
	ins(VV|P|FLOW, "FF /5",		"LJMP Hb"); // XXX Ep
	ins(V_|P, "FF /6",		"PUSH Ev");
	ins(_V|Q, "FF /6",		"PUSH Ev");

	ins(VV|N, "0F 00 /0",		"SLDT Ew");
	ins(VV|N, "0F 00 /1",		"STR Ew");
	ins(VV|N, "0F 00 /2",		"LLDT Ew");
	ins(VV|N, "0F 00 /3",		"LTR Ew");
	ins(VV|N, "0F 00 /4",		"VERR Ew");
	ins(VV|N, "0F 00 /5",		"VERW Ew");

	ins(VV|N, "0F 01 C1",		"VMCALL");
	ins(VV|N, "0F 01 C2",		"VMLAUNCH");
	ins(VV|N, "0F 01 C3",		"VMRESUME");
	ins(VV|N, "0F 01 C4",		"VMXOFF");
	ins(VV|N, "0F 01 C8",		"MONITOR");
	ins(VV|N, "0F 01 C9",		"MWAIT");
	ins(VV|N, "0F 01 D0",		"XGETBV");
	ins(VV|N, "0F 01 D1",		"XSETBV");
	ins(_V|N, "0F 01 F8",		"SWAPGS");
	ins(VV|N, "0F 01 F9",		"RDTSCP");
	ins(VV|N, "0F 01 /m0",		"SGDT Mb");
	ins(VV|N, "0F 01 /m1",		"SIDT Mb");
	ins(VV|N, "0F 01 /m2",		"LGDT Mb");
	ins(VV|N, "0F 01 /m3",		"LIDT Mb");
	ins(VV|N, "0F 01 /4",		"SMSW Ew");
	ins(VV|N, "0F 01 /6",		"LMSW Ew");
	ins(VV|N, "0F 01 /m7",		"INVLPG Mb");
	ins(VV|N, "0F 02 /r",		"LAR Gv,Ew");
	ins(VV|N, "0F 03 /r",		"LSL Gv,Ew");
	ins(VV|N, "0F 05",		"SYSCALL");
	ins(VV|N, "0F 06",		"CLTS");
	ins(VV|N, "0F 07",		"SYSRET");

	ins(VV|N, "0F 08",		"INVD");
	ins(VV|N, "0F 09",		"WBINVD");
	ins(VV|N, "0F 0D /r",		"NOP Ev");

	ins(VV|N, "0F 10 /r",		"MOVUPS Vps,Wps");
	ins(VV|N, "66 0F 10 /r",	"MOVUPD Vpd,Wpd");
	ins(VV|N, "F2 0F 10 /r",	"MOVSD Vsd,Wsd");
	ins(VV|N, "F3 0F 10 /r",	"MOVSS Vss,Wss");
	ins(VV|N, "0F 11 /r",		"MOVUPS Wps,Vps");
	ins(VV|N, "66 0F 11 /r",	"MOVUPD Wpd,Vpd");
	ins(VV|N, "F2 0F 11 /r",	"MOVSD Wsd,Vsd");
	ins(VV|N, "F3 0F 11 /r",	"MOVSS Wss,Vss");
	ins(VV|N, "0F 12 /m",		"MOVLPS Vq,Mq");
	ins(VV|N, "0F 12 /r",		"MOVHLPS Vq,Uq");
	ins(VV|N, "66 0F 12 /m",	"MOVLPD Vq,Mq");
	ins(VV|N, "F2 0F 12 /r",	"MOVDDUP Vq,Wq");
	ins(VV|N, "F3 0F 12 /r",	"MOVSLDUP Vq,Wq");
	ins(VV|N, "0F 13 /m",		"MOVLPS Mq,Vq");
	ins(VV|N, "66 0F 13 /m",	"MOVLPD Mq,Vq");
	ins(VV|N, "0F 14 /r",		"UNPCKLPS Mq,Vq");
	ins(VV|N, "66 0F 14 /r",	"UNPCKLPD Mq,Vq");
	ins(VV|N, "0F 15 /r",		"UNPCKHPS Mq,Vq");
	ins(VV|N, "66 0F 15 /r",	"UNPCKHPD Mq,Vq");
	ins(VV|N, "0F 16 /m",		"MOVHPS Vq,Mq");
	ins(VV|N, "0F 16 /r",		"MOVLHPS Vq,Uq");
	ins(VV|N, "66 0F 16 /m",	"MOVHPD Vq,Mq");
	ins(VV|N, "F3 0F 16 /r",	"MOVSHDUP Vq,Wq");
	ins(VV|N, "0F 17 /m",		"MOVHPS Mq,Vq");
	ins(VV|N, "66 0F 17 /m",	"MOVHPD Mq,Vq");

	ins(VV|N, "0F 18 /0",		"PREFETCHNTA Mb");
	ins(VV|N, "0F 18 /1",		"PREFETCHT0 Mb");
	ins(VV|N, "0F 18 /2",		"PREFETCHT1 Mb");
	ins(VV|N, "0F 18 /3",		"PREFETCHT2 Mb");
	ins(VV|N, "0F 1F /r",		"NOP Ev");

	ins(VV|L, "0F 20 /r",		"MOV Rd,Cd");
	ins(VV|L, "0F 21 /r",		"MOV Rd,Dd");
	ins(VV|L, "0F 22 /r",		"MOV Cd,Rd");
	ins(VV|L, "0F 23 /r",		"MOV Dd,Rd");

	ins(VV|N, "0F 28 /r",		"MOVAPS Vps,Wps");
	ins(VV|N, "66 0F 28 /r",	"MOVAPD Vpd,Wpd");
	ins(VV|N, "0F 29 /r",		"MOVAPS Wps,Vps");
	ins(VV|N, "66 0F 29 /r",	"MOVAPD Wps,Vpd");
	ins(VV|N, "0F 2A /r",		"CVTPI2PS Vps,Qpi");
	ins(VV|N, "66 0F 2A /r",	"CVTPI2PD Vpd,Qpi");
	ins(VV|N, "F2 0F 2A /r",	"CVTSI2SD Vsd,Ed");
	ins(VV|N, "F3 0F 2A /r",	"CVTSI2SS Vps,Ed");
	ins(VV|N, "0F 2B /r",		"MOVNTPS Mps,Vps");
	ins(VV|N, "66 0F 2B /r",	"MOVNTPS Mps,Vps");
	ins(VV|N, "0F 2C /r",		"CVTTPS2PI Ppi,Wps");
	ins(VV|N, "66 0F 2C /r",	"CVTTPD2PI Ppi,Wpd");
	ins(VV|N, "F3 0F 2C /r",	"CVTTSS2SI Gd,Wss");
	ins(VV|N, "F2 0F 2C /r",	"CVTTSD2SI Gd,Wsd");
	ins(VV|N, "0F 2D /r",		"CVTPS2PI Ppi,Wps");
	ins(VV|N, "66 0F 2D /r",	"CVTPD2PI Ppi,Wpd");
	ins(VV|N, "F2 0F 2D /r",	"CVTSD2SI Gd,Wsd");
	ins(VV|N, "F2 0F 2D /r",	"CVTSS2SI Gd,Wss");
	ins(VV|N, "0F 2E /r",		"UCOMISS Vss,Wss");
	ins(VV|N, "66 0F 2E /r",	"UCOMISD Vsd,Wsd");
	ins(VV|N, "0F 2F /r",		"COMISS Vss,Wss");
	ins(VV|N, "66 0F 2F /r",	"COMISD Vsd,Wsd");

	ins(VV|N, "0F 30",		"WRMSR");
	ins(VV|N, "0F 31",		"RDTSC");
	ins(VV|N, "0F 32",		"RDMSR");
	ins(VV|N, "0F 33",		"RDPMC");
	ins(VV|N, "0F 34",		"SYSENTER");
	ins(VV|N, "0F 35",		"SYSEXIT");
	ins(VV|N, "0F 37",		"GETSEC");

	ins(VV|N, "0F 40 /r",		"CMOVO Gv,Ev");
	ins(VV|N, "0F 41 /r",		"CMOVNO Gv,Ev");
	ins(VV|N, "0F 42 /r",		"CMOVB Gv,Ev");
	ins(VV|N, "0F 43 /r",		"CMOVNB Gv,Ev");
	ins(VV|N, "0F 44 /r",		"CMOVZ Gv,Ev");
	ins(VV|N, "0F 45 /r",		"CMOVNZ Gv,Ev");
	ins(VV|N, "0F 46 /r",		"CMOVBE Gv,Ev");
	ins(VV|N, "0F 47 /r",		"CMOVNBE Gv,Ev");

	ins(VV|N, "0F 48 /r",		"CMOVS Gv,Ev");
	ins(VV|N, "0F 49 /r",		"CMOVNS Gv,Ev");
	ins(VV|N, "0F 4A /r",		"CMOVP Gv,Ev");
	ins(VV|N, "0F 4B /r",		"CMOVNP Gv,Ev");
	ins(VV|N, "0F 4C /r",		"CMOVL Gv,Ev");
	ins(VV|N, "0F 4D /r",		"CMOVNL Gv,Ev");
	ins(VV|N, "0F 4E /r",		"CMOVLE Gv,Ev");
	ins(VV|N, "0F 4F /r",		"CMOVNLE Gv,Ev");

	ins(VV|P, "0F 50 /r",		"MOVMSKPS Gd,Ups");
	ins(VV|P, "66 0F 50 /r",	"MOVMSKPD Gd,Upd");
	ins(VV|P, "0F 51 /r",		"SQRTPS Vps,Wps");
	ins(VV|P, "66 0F 51 /r",	"SQRTPD Vpd,Wpd");
	ins(VV|P, "F3 0F 51 /r",	"SQRTSS Vss,Wss");
	ins(VV|P, "F2 0F 51 /r",	"SQRTSD Vsd,Wsd");
	ins(VV|P, "0F 52 /r",		"RSQRTPS Vps,Wps");
	ins(VV|P, "F3 0F 52 /r",	"RSQRTSS Vss,Wss");
	ins(VV|P, "0F 53 /r",		"RCPPS Vps,Wps");
	ins(VV|P, "F3 0F 53 /r",	"RCPSS Vss,Wss");
	ins(VV|N, "0F 54 /r",		"ANDPS Vps,Wps");
	ins(VV|N, "66 0F 54 /r",	"ANDPD Vpd,Wpd");
	ins(VV|N, "0F 55 /r",		"ANDNPS Vps,Wps");
	ins(VV|N, "66 0F 55 /r",	"ANDNPD Vpd,Wpd");
	ins(VV|N, "0F 56 /r",		"ORPS Vps,Wps");
	ins(VV|N, "66 0F 56 /r",	"ORPD Vpd,Wpd");
	ins(VV|N, "0F 57 /r",		"XORPS Vps,Wps");
	ins(VV|N, "66 0F 57 /r",	"XORPD Vpd,Wpd");

	ins(VV|N, "0F 58 /r",		"ADDPS Vps,Wps");
	ins(VV|N, "66 0F 58 /r",	"ADDPD Vpd,Wpd");
	ins(VV|N, "F3 0F 58 /r",	"ADDSS Vss,Wss");
	ins(VV|N, "F2 0F 58 /r",	"ADDSD Vsd,Wsd");
	ins(VV|N, "0F 59 /r",		"MULPS Vps,Wps");
	ins(VV|N, "66 0F 59 /r",	"MULPD Vpd,Wpd");
	ins(VV|N, "F3 0F 59 /r",	"MULSS Vss,Wss");
	ins(VV|N, "F2 0F 59 /r",	"MULSD Vsd,Wsd");
	ins(VV|N, "0F 5A /r",		"CVTPS2PD Vpd,Wps");
	ins(VV|N, "66 0F 5A /r",	"CVTPD2PS Vps,Wpd");
	ins(VV|N, "F3 0F 5A /r",	"CVTSS2SD Vsd,Wss");
	ins(VV|N, "F2 0F 5A /r",	"CVTSD2SS Vss,Wsd");
	ins(VV|N, "0F 5B /r",		"CVTDQ2PS Vps,Wdq");
	ins(VV|N, "66 0F 5B /r",	"CVTPS2DQ Vdq,Wps");
	ins(VV|N, "F3 0F 5B /r",	"CVTTPS2DQ Vdq,Wps");
	ins(VV|N, "0F 5C /r",		"SUBPS Vps,Wps");
	ins(VV|N, "66 0F 5C /r",	"SUBPD Vpd,Wpd");
	ins(VV|N, "F3 0F 5C /r",	"SUBSS Vss,Wss");
	ins(VV|N, "F2 0F 5C /r",	"SUBSD Vsd,Wsd");
	ins(VV|N, "0F 5D /r",		"MINPS Vps,Wps");
	ins(VV|N, "66 0F 5D /r",	"MINPD Vpd,Wpd");
	ins(VV|N, "F3 0F 5D /r",	"MINSS Vss,Wss");
	ins(VV|N, "F2 0F 5D /r",	"MINSD Vsd,Wsd");
	ins(VV|N, "0F 5E /r",		"DIVPS Vps,Wps");
	ins(VV|N, "66 0F 5E /r",	"DIVPD Vpd,Wpd");
	ins(VV|N, "F3 0F 5E /r",	"DIVSS Vss,Wss");
	ins(VV|N, "F2 0F 5E /r",	"DIVSD Vsd,Wsd");
	ins(VV|N, "0F 5F /r",		"MAXPS Vps,Wps");
	ins(VV|N, "66 0F 5F /r",	"MAXPD Vpd,Wpd");
	ins(VV|N, "F3 0F 5F /r",	"MAXSS Vss,Wss");
	ins(VV|N, "F2 0F 5F /r",	"MAXSD Vsd,Wsd");

	ins(VV|N, "0F 60 /r",		"PUNPCKLBW Pq,Qd");
	ins(VV|N, "66 0F 60 /r",	"PUNPCKLBW Vdq,Wdq");
	ins(VV|N, "0F 61 /r",		"PUNPCKLWD Pq,Qd");
	ins(VV|N, "66 0F 61 /r",	"PUNPCKLWD Vdq,Wdq");
	ins(VV|N, "0F 62 /r",		"PUNPCKLDQ Pq,Qd");
	ins(VV|N, "66 0F 62 /r",	"PUNPCKLDQ Vdq,Wdq");
	ins(VV|N, "0F 63 /r",		"PACKSSWB Pq,Qd");
	ins(VV|N, "66 0F 63 /r",	"PACKSSWB Vdq,Wdq");
	ins(VV|N, "0F 64 /r",		"PCMPGTB Pq,Qd");
	ins(VV|N, "66 0F 64 /r",	"PCMPGTB Vdq,Wdq");
	ins(VV|N, "0F 65 /r",		"PCMPGTW Pq,Qd");
	ins(VV|N, "66 0F 65 /r",	"PCMPGTW Vdq,Wdq");
	ins(VV|N, "0F 66 /r",		"PCMPGTD Pq,Qd");
	ins(VV|N, "66 0F 66 /r",	"PCMPGTD Vdq,Wdq");
	ins(VV|N, "0F 67 /r",		"PACKUSWB Pq,Qd");
	ins(VV|N, "66 0F 67 /r",	"PACKUSWB Vdq,Wdq");

	ins(VV|N, "0F 68 /r",		"PUNPCKHBW Pq,Qd");
	ins(VV|N, "66 0F 68 /r",	"PUNPCKHBW Vdq,Wdq");
	ins(VV|N, "0F 69 /r",		"PUNPCKHWD Pq,Qd");
	ins(VV|N, "66 0F 69 /r",	"PUNPCKHWD Vdq,Wdq");
	ins(VV|N, "0F 6A /r",		"PUNPCKHDQ Pq,Qd");
	ins(VV|N, "66 0F 6A /r",	"PUNPCKHDQ Vdq,Wdq");
	ins(VV|N, "0F 6B /r",		"PACKSSDW Pq,Qd");
	ins(VV|N, "66 0F 6B /r",	"PACKSSDW Vdq,Wdq");
	ins(VV|N, "66 0F 6C /r",	"PUNPCKLQDQ Vdq,Wdq");
	ins(VV|N, "66 0F 6D /r",	"PUNPCKHQDQ Vdq,Wdq");
	ins(VV|N, "0F 6E /r",		"MOVD Pd,Ed");
	ins(VV|N, "66 0F 6E /r",	"MOVD Vdq,Ed");
	ins(VV|N, "0F 6F /r",		"MOVQ Pq,Qq");
	ins(VV|N, "66 0F 6F /r",	"MOVDQA Vdq,Wdq");
	ins(VV|N, "F3 0F 6F /r",	"MOVDQU Vdq,Wdq");

	ins(VV|N, "0F 70 /r",		"PSHUFW Pq,Qq,Ib");
	ins(VV|N, "66 0F 70 /r",	"PSHUFD Vdq,Wdq,Ib");
	ins(VV|N, "F3 0F 70 /r",	"PSHUFHW Vdq,Wdq,Ib");
	ins(VV|N, "F2 0F 70 /r",	"PSHUFLW Vdq,Wdq,Ib");
	ins(VV|N, "0F 71 /2",		"PSRLW Nq,Ib");
	ins(VV|N, "66 0F 71 /2",	"PSRLW Udq,Ib");
	ins(VV|N, "0F 71 /4",		"PSRAW Nq,Ib");
	ins(VV|N, "66 0F 71 /4",	"PSRAW Udq,Ib");
	ins(VV|N, "0F 71 /6",		"PSLLW Nq,Ib");
	ins(VV|N, "66 0F 71 /6",	"PSLLW Udq,Ib");
	ins(VV|N, "0F 72 /2",		"PSRLD Nq,Ib");
	ins(VV|N, "66 0F 72 /2",	"PSRLD Udq,Ib");
	ins(VV|N, "0F 72 /4",		"PSRAD Nq,Ib");
	ins(VV|N, "66 0F 72 /4",	"PSRAD Udq,Ib");
	ins(VV|N, "0F 72 /6",		"PSLLD Nq,Ib");
	ins(VV|N, "66 0F 72 /6",	"PSLLD Udq,Ib");
	ins(VV|N, "0F 73 /2",		"PSRLQ Nq,Ib");
	ins(VV|N, "66 0F 73 /2",	"PSRLQ Udq,Ib");
	ins(VV|N, "66 0F 73 /3",	"PSRLDQ Udq,Ib");
	ins(VV|N, "0F 73 /4",		"PSRAQ Nq,Ib");
	ins(VV|N, "66 0F 73 /4",	"PSRAQ Udq,Ib");
	ins(VV|N, "0F 73 /6",		"PSLLQ Nq,Ib");
	ins(VV|N, "66 0F 73 /6",	"PSLLQ Udq,Ib");
	ins(VV|N, "66 0F 73 /7",	"PSLLDQ Udq,Ib");

	ins(VV|N, "0F 74 /r",		"PCMPEQB Pq,Qd");
	ins(VV|N, "66 0F 74 /r",	"PCMPEQB Vdq,Wdq");
	ins(VV|N, "0F 75 /r",		"PCMPEQW Pq,Qd");
	ins(VV|N, "66 0F 75 /r",	"PCMPEQW Vdq,Wdq");
	ins(VV|N, "0F 76 /r",		"PCMPEQD Pq,Qd");
	ins(VV|N, "66 0F 76 /r",	"PCMPEQD Vdq,Wdq");
	ins(VV|N, "0F 77",		"EMMS");

	ins(VV|N, "0F 78 /r",		"VMREAD Ed,Gd");
	ins(VV|N, "0F 79 /r",		"VMREAD Gd,Ed");
	ins(VV|N, "0F 7C /r",		"HADDPS Vps,Wps");
	ins(VV|N, "66 0F 7C /r",	"HADDPS Vpd,Wpd");
	ins(VV|N, "0F 7D /r",		"HSUBPS Vps,Wps");
	ins(VV|N, "66 0F 7D /r",	"HSUBPS Vpd,Wpd");
	ins(VV|N, "0F 7E /r",		"MOVD Ed,Pd");
	ins(VV|N, "66 0F 7E /r",	"MOVD Ed,Vdq");
	ins(VV|N, "F3 0F 7E /r",	"MOVQ Vq,Wq");
	ins(VV|N, "0F 7F /r",		"MOVQ Qq,Pq");
	ins(VV|N, "66 0F 7F /r",	"MOVDQA Wdq,Vdq");
	ins(VV|N, "F3 0F 7F /r",	"MOVDQU Wdq,Vdq");

	ins(VV|F, "0F 80",		"JO Jz");
	ins(VV|F, "0F 81",		"JNO Jz");
	ins(VV|F, "0F 82",		"JB Jz");
	ins(VV|F, "0F 83",		"JNB Jz");
	ins(VV|F, "0F 84",		"JZ Jz");
	ins(VV|F, "0F 85",		"JNZ Jz");
	ins(VV|F, "0F 86",		"JBE Jz");
	ins(VV|F, "0F 87",		"JNBE Jz");

	ins(VV|F, "0F 88",		"JS Jz");
	ins(VV|F, "0F 89",		"JNS Jz");
	ins(VV|F, "0F 8A",		"JP Jz");
	ins(VV|F, "0F 8B",		"JNP Jz");
	ins(VV|F, "0F 8C",		"JL Jz");
	ins(VV|F, "0F 8D",		"JNL Jz");
	ins(VV|F, "0F 8E",		"JLE Jz");
	ins(VV|F, "0F 8F",		"JNLE Jz");

	ins(VV|N, "0F 90 /r",		"SETO Eb");
	ins(VV|N, "0F 91 /r",		"SETNO Eb");
	ins(VV|N, "0F 92 /r",		"SETB Eb");
	ins(VV|N, "0F 93 /r",		"SETNB Eb");
	ins(VV|N, "0F 94 /r",		"SETZ Eb");
	ins(VV|N, "0F 95 /r",		"SETNZ Eb");
	ins(VV|N, "0F 96 /r",		"SETBE Eb");
	ins(VV|N, "0F 97 /r",		"SETNBE Eb");

	ins(VV|N, "0F 98 /r",		"SETS Eb");
	ins(VV|N, "0F 99 /r",		"SETNS Eb");
	ins(VV|N, "0F 9A /r",		"SETP Eb");
	ins(VV|N, "0F 9B /r",		"SETNP Eb");
	ins(VV|N, "0F 9C /r",		"SETL Eb");
	ins(VV|N, "0F 9D /r",		"SETNL Eb");
	ins(VV|N, "0F 9E /r",		"SETLE Eb");
	ins(VV|N, "0F 9F /r",		"SETNLE Eb");

	ins(VV|N, "0F A0",		"PUSH FS");
	ins(VV|N, "0F A1",		"POP FS");
	ins(VV|N, "0F A2",		"CPUID");
	ins(VV|P, "0F A3 /r",		"BT Ev,Gv");
	ins(VV|P, "0F A4 /r",		"SHLD Ev,Gv,Ib");
	ins(VV|P, "0F A5 /r",		"SHLD Ev,Gv,CLnorex");
	ins(VV|N, "F3 0F A6 C8",	"XSHA1");
	ins(VV|N, "F3 0F A6 D0",	"XSHA256");
	ins(VV|N, "0F A7 C0",		"XSTORE");
	ins(VV|N, "F3 0F A7 C8",	"XCRYPTECB");
	ins(VV|N, "F3 0F A7 D0",	"XCRYPTCBC");
	ins(VV|N, "F3 0F A7 D8",	"XCRYPTCTR");
	ins(VV|N, "F3 0F A7 E0",	"XCRYPTCFB");
	ins(VV|N, "F3 0F A7 E8",	"XCRYPTOFB");


	ins(VV|N, "0F A8",		"PUSH GS");
	ins(VV|N, "0F A9",		"POP GS");
	ins(VV|N, "0F AA",		"RSM");
	ins(VV|P, "0F AB /r",		"BTS Ev,Gv");
	ins(VV|P, "0F AC /r",		"SHRD Ev,Gv,Ib");
	ins(VV|P, "0F AD /r",		"SHRD Ev,Gv,CLnorex");
	ins(VV|L, "0F AE /0",		"FXSAVE Mb");
	ins(VV|L, "0F AE /1",		"FXRSTOR Mb");
	ins(VV|L, "0F AE /2",		"LDMXCSR Md");
	ins(VV|L, "0F AE /3",		"STMXCSR Md");
	ins(VV|N, "0F AE /4",		"XSAVE Mb");
	ins(VV|N, "0F AE E8",		"LFENCE");
	ins(VV|N, "0F AE /5",		"XRSTOR Mb");
	ins(VV|N, "0F AE F0",		"MFENCE");
	ins(VV|N, "0F AE F8",		"SFENCE");
	ins(VV|N, "0F AE /7",		"CLFLUSH Mb");
	ins(VV|P, "0F AF /r",		"IMUL Gv,Ev");

	ins(VV|B, "0F B0 /r",		"CMPXCHG Eb,Gb");
	ins(VV|P, "0F B1 /r",		"CMPXCHG Ev,Gv");
	ins(VV|P, "0F B2 /r",		"LSS Gv,Mb"); // XXX Mp
	ins(VV|P, "0F B3 /r",		"BTR Ev,Gv");
	ins(VV|P, "0F B4 /r",		"LFS Gv,Mb"); // XXX Mp
	ins(VV|P, "0F B5 /r",		"LGS Gv,Mb"); // XXX Mp
	ins(VV|P, "0F B6 /r",		"MOVZX Gv,Eb");
	ins(VV|P, "0F B7 /r",		"MOVZX Gv,Ew");

	ins(VV|P, "0F B8",		"JMPE");
	ins(VV|P, "F3 0F B8 /r",	"POPCNT Gv,Ev");
	ins(VV|P, "0F BA /4",		"BT Ev,Ib");
	ins(VV|P, "0F BA /5",		"BTS Ev,Ib");
	ins(VV|P, "0F BA /6",		"BTR Ev,Ib");
	ins(VV|P, "0F BA /7",		"BTC Ev,Ib");
	ins(VV|P, "0F BB /r",		"BTC Ev,Gv");
	ins(VV|P, "0F BC /r",		"BSF Gv,Ev");
	ins(VV|P, "0F BD /r",		"BSR Gv,Ev");
	ins(VV|P, "0F BE /r",		"MOVSX Gv,Eb");
	ins(VV|P, "0F BF /r",		"MOVSX Gv,Ew");

	ins(VV|B, "0F C0 /r",		"XADD Eb,Gb");
	ins(VV|P, "0F C1 /r",		"XADD Ev,Gv");
	ins(VV|N, "0F C2 /r",		"CMPPS Vps,Wps,Ib");
	ins(VV|N, "66 0F C2 /r",	"CMPPD Vpd,Wpd,Ib");
	ins(VV|N, "F3 0F C2 /r",	"CMPSS Vss,Wss,Ib");
	ins(VV|N, "F2 0F C2 /r",	"CMPSD Vsd,Wsd,Ib");
	ins(V_|N, "0F C3 /r",		"MOVNTI Md,Gd");
	ins(_V|N, "0F C3 /r",		"MOVNTI Mq,Gq");
	ins(VV|N, "0F C4 /r",		"PINSRW Pq,Gd,Ib");
	ins(VV|N, "0F C5 /r",		"PEXTRW Gd,Nq,Ib");
	ins(VV|N, "66 0F C5 /r",	"PEXTRW Gd,Udq,Ib");
	ins(VV|N, "0F C6 /r",		"SHUFPS Vps,Wps,Ib");
	ins(VV|N, "66 0F C6 /r",	"SHUFPD Vpd,Wpd,Ib");
	ins(V_|N, "0F C7 /1",		"CMPXCH8B Mq");
	ins(_V|N, "0F C7 /1",		"CMPXCH16B Mq");
	ins(VV|N, "0F C7 /6",		"VMPTRLD Mq");
	ins(VV|N, "66 0F C7 /6",	"VMCLEAR Mq");
	ins(VV|N, "F3 0F C7 /6",	"VMXON Mq");
	ins(VV|N, "0F C7 /7",		"VMPTRST Mq");

	ins(VV|P, "0F C8",		"BSWAP rAX");
	ins(VV|P, "0F C9",		"BSWAP rCX");
	ins(VV|P, "0F CA",		"BSWAP rDX");
	ins(VV|P, "0F CB",		"BSWAP rBX");
	ins(VV|P, "0F CC",		"BSWAP rSP");
	ins(VV|P, "0F CD",		"BSWAP rBP");
	ins(VV|P, "0F CE",		"BSWAP rSI");
	ins(VV|P, "0F CF",		"BSWAP rDI");

	ins(VV|N, "F2 0F D0 /r",	"ADDSUBPS Vps,Wps");
	ins(VV|N, "66 0F D0 /r",	"ADDSUBPD Vpd,Wpd");
	ins(VV|N, "0F D1 /r",		"PSRLW Pq,Qq");
	ins(VV|N, "66 0F D1 /r",	"PSRLW Vdq,Wdq");
	ins(VV|N, "0F D2 /r",		"PSRLD Pq,Qq");
	ins(VV|N, "66 0F D2 /r",	"PSRLD Vdq,Wdq");
	ins(VV|N, "0F D3 /r",		"PSRLQ Pq,Qq");
	ins(VV|N, "66 0F D3 /r",	"PSRLQ Vdq,Wdq");
	ins(VV|N, "0F D4 /r",		"PADDQ Pq,Qq");
	ins(VV|N, "66 0F D4 /r",	"PADDQ Vdq,Wdq");
	ins(VV|N, "0F D5 /r",		"PMULW Pq,Qq");
	ins(VV|N, "66 0F D5 /r",	"PMULW Vdq,Wdq");
	ins(VV|N, "66 0F D6 /r",	"MOVQ Wq,Vq");
	ins(VV|N, "F3 0F D6 /r",	"MOVQ2DQ Vdq,Nq");
	ins(VV|N, "F2 0F D6 /r",	"MOVDQ2Q Pq,Uq");
	ins(VV|N, "0F D7 /r",		"PMOVMSKB Gd,Nq");
	ins(VV|N, "66 0F D7 /r",	"PMOVMSKB Gd,Udq");

	ins(VV|N, "0F D8 /r",		"PSUBUSB Pq,Qq");
	ins(VV|N, "66 0F D8 /r",	"PSUBUSB Vdq,Wdq");
	ins(VV|N, "0F D9 /r",		"PSUBUSW Pq,Qq");
	ins(VV|N, "66 0F D9 /r",	"PSUBUSW Vdq,Wdq");
	ins(VV|N, "0F DA /r",		"PMINUB Pq,Qq");
	ins(VV|N, "66 0F DA /r",	"PMINUB Vdq,Wdq");
	ins(VV|N, "0F DB /r",		"PAND Pq,Qq");
	ins(VV|N, "66 0F DB /r",	"PAND Vdq,Wdq");
	ins(VV|N, "0F DC /r",		"PADDUSB Pq,Qq");
	ins(VV|N, "66 0F DC /r",	"PADDUSB Vdq,Wdq");
	ins(VV|N, "0F DD /r",		"PADDUSW Pq,Qq");
	ins(VV|N, "66 0F DD /r",	"PADDUSW Vdq,Wdq");
	ins(VV|N, "0F DE /r",		"PMAXUB Pq,Qq");
	ins(VV|N, "66 0F DE /r",	"PMAXUB Vdq,Wdq");
	ins(VV|N, "0F DF /r",		"PANDN Pq,Qq");
	ins(VV|N, "66 0F DF /r",	"PANDN Vdq,Wdq");

	ins(VV|N, "0F E0 /r",		"PAVGB Pq,Qq");
	ins(VV|N, "66 0F E0 /r",	"PAVGB Vdq,Wdq");
	ins(VV|N, "0F E1 /r",		"PSRAW Pq,Qq");
	ins(VV|N, "66 0F E1 /r",	"PSRAW Vdq,Wdq");
	ins(VV|N, "0F E2 /r",		"PSRAD Pq,Qq");
	ins(VV|N, "66 0F E2 /r",	"PSRAD Vdq,Wdq");
	ins(VV|N, "0F E3 /r",		"PAVGW Pq,Qq");
	ins(VV|N, "66 0F E3 /r",	"PAVGW Vdq,Wdq");
	ins(VV|N, "0F E4 /r",		"PMULHUW Pq,Qq");
	ins(VV|N, "66 0F E4 /r",	"PMULHUW Vdq,Wdq");
	ins(VV|N, "0F D5 /r",		"PMULHW Pq,Qq");
	ins(VV|N, "66 0F E5 /r",	"PMULHW Vdq,Wdq");
	ins(VV|N, "F2 0F E6 /r",	"CVTPD2DQ Vdq,Wpd");
	ins(VV|N, "66 0F E6 /r",	"CVTTPD2DQ Vdq,Wpd");
	ins(VV|N, "F3 0F E6 /r",	"CVTDQ2PD Vpd,Wdq");
	ins(VV|N, "0F E7 /r",		"MOVNTQ Mq,Pq");
	ins(VV|N, "66 0F E7 /r",	"MOVNTDQ Mdq,Vdq");

	ins(VV|N, "0F E8 /r",		"PSUBSB Pq,Qq");
	ins(VV|N, "66 0F E8 /r",	"PSUBSB Vdq,Wdq");
	ins(VV|N, "0F E9 /r",		"PSUBSW Pq,Qq");
	ins(VV|N, "66 0F E9 /r",	"PSUBSW Vdq,Wdq");
	ins(VV|N, "0F EA /r",		"PMINSW Pq,Qq");
	ins(VV|N, "66 0F EA /r",	"PMINSW Vdq,Wdq");
	ins(VV|N, "0F EB /r",		"POR Pq,Qq");
	ins(VV|N, "66 0F EB /r",	"POR Vdq,Wdq");
	ins(VV|N, "0F EC /r",		"PADDSB Pq,Qq");
	ins(VV|N, "66 0F EC /r",	"PADDSB Vdq,Wdq");
	ins(VV|N, "0F ED /r",		"PADDSW Pq,Qq");
	ins(VV|N, "66 0F ED /r",	"PADDSW Vdq,Wdq");
	ins(VV|N, "0F EE /r",		"PMAXSW Pq,Qq");
	ins(VV|N, "66 0F EE /r",	"PMAXSW Vdq,Wdq");
	ins(VV|N, "0F EF /r",		"PXOR Pq,Qq");
	ins(VV|N, "66 0F EF /r",	"PXOR Vdq,Wdq");

	ins(VV|N, "F2 0F F0 /r",	"LDDQU Vdq,Mdq");
	ins(VV|N, "0F F1 /r",		"PSLLW Pq,Qq");
	ins(VV|N, "66 0F F1 /r",	"PSLLW Vdq,Wdq");
	ins(VV|N, "0F F2 /r",		"PSLLD Pq,Qq");
	ins(VV|N, "66 0F F2 /r",	"PSLLD Vdq,Wdq");
	ins(VV|N, "0F F3 /r",		"PSLLQ Pq,Qq");
	ins(VV|N, "66 0F F3 /r",	"PSLLQ Vdq,Wdq");
	ins(VV|N, "0F F4 /r",		"PMULUDQ Pq,Qq");
	ins(VV|N, "66 0F F4 /r",	"PMULUDQ Vdq,Wdq");
	ins(VV|N, "0F F5 /r",		"PMADDWD Pq,Qq");
	ins(VV|N, "66 0F F5 /r",	"PMADDWD Vdq,Wdq");
	ins(VV|N, "0F F6 /r",		"PSADBW Pq,Qq");
	ins(VV|N, "66 0F F6 /r",	"PSADBW Vdq,Wdq");
	ins(VV|N, "0F F7 /r",		"MASKMOVQ Pq,Nq");
	ins(VV|N, "66 0F F7 /r",	"MASKMOVDQU Vdq,Udq");

	ins(VV|N, "0F F8 /r",		"PSUBB Pq,Qq");
	ins(VV|N, "66 0F F8 /r",	"PSUBB Vdq,Wdq");
	ins(VV|N, "0F F9 /r",		"PSUBW Pq,Qq");
	ins(VV|N, "66 0F F9 /r",	"PSUBW Vdq,Wdq");
	ins(VV|N, "0F FA /r",		"PSUBD Pq,Qq");
	ins(VV|N, "66 0F FA /r",	"PSUBD Vdq,Wdq");
	ins(VV|N, "0F FB /r",		"PSUBQ Pq,Qq");
	ins(VV|N, "66 0F FB /r",	"PSUBQ Vdq,Wdq");
	ins(VV|N, "0F FC /r",		"PADDB Pq,Qq");
	ins(VV|N, "66 0F FC /r",	"PADDB Vdq,Wdq");
	ins(VV|N, "0F FD /r",		"PADDW Pq,Qq");
	ins(VV|N, "66 0F FD /r",	"PADDW Vdq,Wdq");
	ins(VV|N, "0F FE /r",		"PADDD Pq,Qq");
	ins(VV|N, "66 0F FE /r",	"PADDD Vdq,Wdq");

	ins(VV|N, "0F 38 00 /r",	"PSHUFB Pq,Qq");
	ins(VV|N, "66 0F 38 00 /r",	"PSHUFB Vdq,Wdq");
	ins(VV|N, "0F 38 01 /r",	"PHADDW Pq,Qq");
	ins(VV|N, "66 0F 38 01 /r",	"PHADDW Vdq,Wdq");
	ins(VV|N, "0F 38 02 /r",	"PHADDD Pq,Qq");
	ins(VV|N, "66 0F 38 02 /r",	"PHADDD Vdq,Wdq");
	ins(VV|N, "0F 38 03 /r",	"PHADDSW Pq,Qq");
	ins(VV|N, "66 0F 38 03 /r",	"PHADDSW Vdq,Wdq");
	ins(VV|N, "0F 38 04 /r",	"PMADDUBSW Pq,Qq");
	ins(VV|N, "66 0F 38 04 /r",	"PMADDUBSW Vdq,Wdq");
	ins(VV|N, "0F 38 05 /r",	"PHSUBW Pq,Qq");
	ins(VV|N, "66 0F 38 06 /r",	"PHSUBW Vdq,Wdq");
	ins(VV|N, "0F 38 06 /r",	"PHSUBD Pq,Qq");
	ins(VV|N, "66 0F 38 06 /r",	"PHSUBD Vdq,Wdq");
	ins(VV|N, "0F 38 07 /r",	"PHSUBSW Pq,Qq");
	ins(VV|N, "66 0F 38 07 /r",	"PHSUBSW Vdq,Wdq");

	ins(VV|N, "0F 38 08 /r",	"PSIGNB Pq,Qq");
	ins(VV|N, "66 0F 38 08 /r",	"PSIGNB Vdq,Wdq");
	ins(VV|N, "0F 38 09 /r",	"PSIGNW Pq,Qq");
	ins(VV|N, "66 0F 38 09 /r",	"PSIGNW Vdq,Wdq");
	ins(VV|N, "0F 38 0A /r",	"PSIGND Pq,Qq");
	ins(VV|N, "66 0F 38 0A /r",	"PSIGND Vdq,Wdq");
	ins(VV|N, "0F 38 0B /r",	"PMULHRSW Pq,Qq");
	ins(VV|N, "66 0F 38 0B /r",	"PMULHRSW Vdq,Wdq");

	ins(VV|N, "66 0F 38 10 /r",	"PBLENDVB Vdq,Wdq");
	ins(VV|N, "66 0F 38 14 /r",	"BLENDVPS Vdq,Wdq");
	ins(VV|N, "66 0F 38 15 /r",	"BLENDVPD Vdq,Wdq");
	ins(VV|N, "66 0F 38 17 /r",	"PTEST Vdq,Wdq");

	ins(VV|N, "0F 38 1C /r",	"PABSB Vdq,Wdq");
	ins(VV|N, "66 0F 38 1C /r",	"PABSB Vdq,Wdq");
	ins(VV|N, "0F 38 1D /r",	"PABSW Vdq,Wdq");
	ins(VV|N, "66 0F 38 1D /r",	"PABSW Vdq,Wdq");
	ins(VV|N, "0F 38 1E /r",	"PABSD Vdq,Wdq");
	ins(VV|N, "66 0F 38 1E /r",	"PABSD Vdq,Wdq");

	ins(VV|N, "66 0F 38 20 /r",	"PMOVSXBW Vdq,Wdq");
	ins(VV|N, "66 0F 38 21 /r",	"PMOVSXBD Vdq,Wdq");
	ins(VV|N, "66 0F 38 22 /r",	"PMOVSXBQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 23 /r",	"PMOVSXWD Vdq,Wdq");
	ins(VV|N, "66 0F 38 24 /r",	"PMOVSXWQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 25 /r",	"PMOVSXDQ Vdq,Wdq");

	ins(VV|N, "66 0F 38 28 /r",	"PMULDQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 29 /r",	"PCMPEQQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 2A /r",	"MOVNTDQA Vdq,Wdq");
	ins(VV|N, "66 0F 38 2B /r",	"PACKUSDW Vdq,Wdq");

	ins(VV|N, "66 0F 38 30 /r",	"PMOVZXBW Vdq,Wdq");
	ins(VV|N, "66 0F 38 31 /r",	"PMOVZXBD Vdq,Wdq");
	ins(VV|N, "66 0F 38 32 /r",	"PMOVZXBQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 33 /r",	"PMOVZXWD Vdq,Wdq");
	ins(VV|N, "66 0F 38 34 /r",	"PMOVZXWQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 35 /r",	"PMOVZXDQ Vdq,Wdq");
	ins(VV|N, "66 0F 38 37 /r",	"PCMPGTQ Vdq,Wdq");

	ins(VV|N, "66 0F 38 38 /r",	"PMINSB Vdq,Wdq");
	ins(VV|N, "66 0F 38 39 /r",	"PMINSD Vdq,Wdq");
	ins(VV|N, "66 0F 38 3A /r",	"PMINUW Vdq,Wdq");
	ins(VV|N, "66 0F 38 3B /r",	"PMINUD Vdq,Wdq");
	ins(VV|N, "66 0F 38 3C /r",	"PMAXSB Vdq,Wdq");
	ins(VV|N, "66 0F 38 3D /r",	"PMAXSD Vdq,Wdq");
	ins(VV|N, "66 0F 38 3E /r",	"PMAXUW Vdq,Wdq");
	ins(VV|N, "66 0F 38 3F /r",	"PMAXUD Vdq,Wdq");

	ins(VV|N, "66 0F 38 40 /r",	"PMULLD Vdq,Wdq");
	ins(VV|N, "66 0F 38 41 /r",	"PHMINPOSUW Vdq,Wdq");

	ins(VV|N, "66 0F 38 80 /r",	"NVEPT Gd,Mdq");
	ins(VV|N, "66 0F 38 81 /r",	"NVVPID Gd,Mdq");

	ins(VV|P, "0F 38 F0 /r",	"MOVBE Gv,Mw");
	ins(VV|B, "F2 0F 38 F0 /r",	"CRC32 Gd,Eb");
	ins(VV|P, "0F 38 F1 /r",	"MOVBE Mv,Gw");
	ins(VV|B, "F2 0F 38 F1 /r",	"CRC32 Gd,Ev");

	ins(VV|N, "66 0F 3A 08 /r",	"ROUNDPS Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 09 /r",	"ROUNDPD Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 0A /r",	"ROUNDSS Vss,Wss,Ib");
	ins(VV|N, "66 0F 3A 0B /r",	"ROUNDSD Vsd,Wsd,Ib");
	ins(VV|N, "66 0F 3A 0C /r",	"BLENDPS Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 0D /r",	"BLENDPD Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 0E /r",	"PBLENDW Vdq,Wdq,Ib");
	ins(VV|N, "0F 3A 0E /r",	"PALIGNR Pq,Qq,Ib");
	ins(VV|N, "66 0F 3A 0F /r",	"PALIGNR Vdq,Wdq,Ib");

	ins(VV|N, "66 0F 3A 14 /r",	"PEXTRB Ed,Vdq,Ib");
	ins(VV|N, "66 0F 3A 15 /r",	"PEXTRW Ed,Vdq,Ib");
	ins(VV|N, "66 0F 3A 16 /r",	"PEXTRD Ed,Vdq,Ib");
	ins(VV|N, "66 0F 3A 17 /r",	"EXTRACTPS Ed,Vdq,Ib");

	ins(VV|N, "66 0F 3A 20 /r",	"PINSRB Vdq,Ed,Ib");
	ins(VV|N, "66 0F 3A 21 /r",	"INSERTPS Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 22 /r",	"PINSRD Vdq,Ed,Ib");

	ins(VV|N, "66 0F 3A 40 /r",	"DPPS Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 41 /r",	"DPPD Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 42 /r",	"MPSADBW Vdq,Wdq,Ib");

	ins(VV|N, "66 0F 3A 60 /r",	"PCMPESTRM Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 61 /r",	"PCMPESTRI Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 62 /r",	"PCMPISTRM Vdq,Wdq,Ib");
	ins(VV|N, "66 0F 3A 63 /r",	"PCMPISTRI Vdq,Wdq,Ib");
    }

    static void addInstruction(Instruction i)
    {
	table_.add(i, 0);
	static if (false) {
	    //writefln("registering %s -> %s", i.match_, i.assembler_);
	    Instruction[][256]* tab;
	    char op;
	    if (i.opcodes_[0] == 0x0f) {
		tab = &table0f_;
		op = i.opcodes_[1];
	    } else {
		tab = &table_;
		op = i.opcodes_[0];
	    }
	    // make sure that mandatory prefix instructions are checked first
	    if (i.prefix_) {
		Instruction[] il = (*tab)[op];
		(*tab)[op] = i ~ il;
	    } else {
		(*tab)[op] ~= i;
	    }
	}
    }

    static void addInstruction(int flags, string m, string a)
    {
	int fromhex(char c)
	{
	    if (c >= '0' && c <= '9')
		return c - '0';
	    else
		return c - 'A' + 10;
	}
	string extractOpcodes(string s)
	{
	    int i, j;
	    i = j = 0;
	    while (i < s.length && ishex(s[i]) && ishex(s[i+1])) {
		i += 2;
		j = i;
		if (i < s.length && s[i] == ' ') i++;
	    }
	    return s[0..j];
	}

	flags |= decode(m);
	string s = extractOpcodes(m);
	if (flags & (PREFIX66|PREFIXF2|PREFIXF3))
	    s = s[3..$];
	ubyte[] opcodes;
	while (s.length > 0) {
	    if (s[0] == ' ') {
		s = s[1..$];
	    } else {
                ubyte opcode = to!ubyte(fromhex(s[0]) << 4 | fromhex(s[1]));
		opcodes ~= opcode;
		s = s[2..$];
	    }
	}

	string opname;
	string[] operands;
	auto i = countUntil(a, ' ');
	if (i > 0) {
	    opname = toLower(a[0..i]);
	    operands = split(a[i + 1..$], ",");
	} else {
            opname = toLower(a);
        }

	addInstruction(Instruction(flags, opcodes, opname, operands));
    }

    /**
     * True if c is valid hex (uppercase only)
     */
    static bool ishex(char c)
    {
	return (c >= '0' && c <= '9')
	    || (c >= 'A' && c <= 'F');
    }

    /**
     * Examine the match string and return a set of flags to match with
     */
    static int decode(string s)
    {
	/**
	 * True if s[0..p.length] == p
	 */
	bool startsWith(string p, string s)
	{
	    return s.length >= p.length && s[0..p.length] == p;
	}

	/**
	 * True if c is valid octal
	 */
	bool isoctal(char c)
	{
	    return (c >= '0' && c <= '7');
	}

	int flags = 0;

	if (startsWith("66", s)) {
	    flags |= PREFIX66;
	    s = s[2..$];
	} else if (startsWith("F2", s)) {
	    flags |= PREFIXF2;
	    s = s[2..$];
	} else if (startsWith("F3", s)) {
	    flags |= PREFIXF3;
	    s = s[2..$];
	}
	while (s.length > 0) {
	    if (s[0] == ' ') {
		s = s[1..$];
	    } else if (s.length >= 2 && ishex(s[0]) && ishex(s[1])) {
		s = s[2..$];
	    } else if (s.length >= 3 && s[0..2] == "/m" && isoctal(s[2])) {
		/*
		 * Match a modrm byte with mod!=3 and reg==s[2].
		 */
		flags |= (MODRM | MEMONLY);
		flags |= octal!70 << MODRMMASKSHIFT;
		flags |= (s[2] - '0') << (MODRMMATCHSHIFT + 3);
		s = s[3..$];
	    } else if (s.length >= 3 && s[0..2] == "/r" && isoctal(s[2])) {
		/*
		 * Match a modrm byte with mod==3 and reg==s[2]. If s[3] is
		 * also octal, additionally check rm==s[3].
		 */
		flags |= (MODRM | REGONLY);
		flags |= octal!70 << MODRMMASKSHIFT;
		flags |= (s[2] - '0') << (MODRMMATCHSHIFT + 3);
		if (s.length >= 4 && isoctal(s[3])) {
		    flags |= 007 << MODRMMASKSHIFT;
		    flags |= (s[3] - '0') << MODRMMATCHSHIFT;
		    s = s[4..$];
		} else {
		    s = s[3..$];
		}
	    } else if (s.length >= 2 && s[0] == '/' && isoctal(s[1])) {
		/*
		 * Match a modrm byte with reg==s[2].
		 */
		flags |= MODRM;
		flags |= octal!70 << MODRMMASKSHIFT;
		flags |= (s[1] - '0') << (MODRMMATCHSHIFT + 3);
		s = s[2..$];
	    } else if (startsWith("/r", s)) {
		flags |= MODRM;
		s = s[2..$];
	    } else if (startsWith("/m", s)) {
		flags |= (MODRM | MEMONLY);
		s = s[2..$];
	    } else {
		return 0;
	    }
	}
	return flags;
    }

    static InstructionTable table_;
    bool attMode_ = true;
    int mode_ = 32;
}

private:

class InstructionTable
{
    InstructionTable[] subTables_;
    Instruction[] insns_;
    bool modrm_ = false;

    void add(Instruction i, int off)
    {
	if (off == i.opcodes_.length) {
	    if (insns_.length == 0) {
		if (i.flags_ & MODRM)
		    modrm_ = true;
	    } else {
		if (modrm_)
		    assert(i.flags_ & MODRM);
	    }
	    if (i.flags_ & (PREFIX66|PREFIXF2|PREFIXF3)) {
		Instruction[] t = i ~ insns_;
		insns_ = t;
	    } else
		insns_ ~= i;
	} else {
	    char b = i.opcodes_[off];
	    if (b >= subTables_.length)
		subTables_.length = b + 1;
	    if (!subTables_[b])
		subTables_[b] = new InstructionTable;
	    subTables_[b].add(i, off + 1);
	}
    }

    bool lookup(DecodeState* ds, out Instruction insn)
    {
	if (subTables_.length) {
	    char b = ds.nextByte;
	    if (b < subTables_.length && subTables_[b]) {
		if (subTables_[b].lookup(ds, insn))
		    return true;
	    }
	    ds.loc_--;
	}
	if (modrm_) {
	    ds.modrm_ = ds.nextByte;
	    ds.decodeModrm;
	}
	foreach (i; insns_) {
	    if (ds.mode_ == 32) {
		if (!(i.flags_ & VALID32))
		    continue;
	    } else {
		if (!(i.flags_ & VALID64))
		    continue;
	    }
	    if (i.flags_ & REGONLY) {
		if (ds.mod != 3)
		    continue;
	    }
	    if (i.flags_ & MEMONLY) {
		if (ds.mod == 3)
		    continue;
	    }
	    if (i.flags_ & MODRMMASK) {
		int mask = (i.flags_ & MODRMMASK) >> MODRMMASKSHIFT;
		int match = (i.flags_ & MODRMMATCH) >> MODRMMATCHSHIFT;
		if ((ds.modrm_ & mask) != match)
		    continue;
	    }
	    if (i.flags_ & PREFIX66) {
		if (!ds.operandSizePrefix_)
		    continue;
		ds.operandSizePrefix_ = false;
	    }
	    if (i.flags_ & PREFIXF2) {
		if (!ds.repnePrefix_)
		    continue;
		ds.repnePrefix_ = false;
	    }
	    if (i.flags_ & PREFIXF3) {
		if (!ds.repePrefix_)
		    continue;
		ds.repePrefix_ = false;
	    }
	    ds.size_ = i.flags_ & SIZE;
	    if (ds.size_ == PREFIX)
		ds.size_ = ds.operandSize;
	    insn = i;
	    return true;
	}
	return false;
    }
}

struct Instruction
{
    int flags_;
    ubyte[] opcodes_;
    string opname_;
    string[] operands_;

    void skipImmediate(DecodeState* ds)
    {
	ds.skipImmediate(operands_);
    }

    string display(DecodeState* ds)
    {
	return ds.displayInstruction(opname_, ds.displayOperands(operands_));
    }
}

struct Operand
{
    int type;
    string value;
}

struct DecodeState
{
    static string regNames[][16] = [
	// BYTE
	["al","cl","dl","bl","ah","ch","dh","bh",
	 "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"],
	// WORD
	["ax","cx","dx","bx","sp","bp","si","di",
	 "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"],
	// LONG
	["eax","ecx","edx","ebx","esp","ebp","esi","edi",
	 "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"],
	// QWORD
	["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
	 "r8","r9","r10","r11","r12","r13","r14","r15"],
	];
    static string mmxNames[] =
	["mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7"];
    static string xmmNames[] =
	["xmm0","xmm1","xmm2","xmm3", "xmm4","xmm5","xmm6","xmm7",
	 "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"];
    static string floatNames[] =
	["st(0)","st(1)","st(2)","st(3)","st(4)","st(5)","st(6)","st(7)"];
    static string regbNames[] =
	["al","cl","dl","bl","spl","bpl","sil","dil",
	 "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"];
    static string[] segNames = ["es","cs","ss","ds","fs","gs"];

    char nextByte()
    {
	char c = readByte_(loc_);
	loc_++;
	return c;
    }
    ushort nextWord()
    {
	ushort v = readByte_(loc_) | (readByte_(loc_ + 1) << 8);
	loc_ += 2;
	return v;
    }
    uint nextDWord()
    {
	uint v = readByte_(loc_) | (readByte_(loc_ + 1) << 8)
	    | (readByte_(loc_ + 2) << 16) | (readByte_(loc_ + 3) << 24);
	loc_ += 4;
	return v;
    }
    ulong nextQWord()
    {
	ulong v;
	int bit = 0;
	for (int i = 0; i < 8; i++) {
	    v |= cast(ulong) readByte_(loc_ + i) << bit;
	    bit += 8;
	}
	loc_ += 8;
	return v;
    }
    int operandSize()
    {
	if (mode_ == 64 && rexW)
	    return QWORD;
	if (operandSizePrefix_)
	    return WORD;
	else
	    return LONG;
    }
    int addressSize()
    {
	if (mode_ == 32)
	    if (addressSizePrefix_)
		return WORD;
	    else
		return LONG;
	else
	    if (addressSizePrefix_)
		return LONG;
	    else
		return QWORD;
    }
    void decodeModrm()
    {
	disp_ = 0;
	havedisp_ = false;
	baseReg_ = -1;
	indexReg_ = -1;
	scale_ = 0;
	if (mod == 3)
	    return;
	if (mode_ == 32 && addressSizePrefix_) {
	    int baseReg16[] = [3,3,5,5,6,7,5,3];
	    int indexReg16[] = [6,7,6,7,-1,-1,-1,-1];
	    switch (mod) {
	    case 0:
		if (rm == 6) {
		    disp_ = nextWord;
		    havedisp_ = true;
		} else {
		    baseReg_ = baseReg16[rm];
		    indexReg_ = indexReg16[rm];
		}
		break;

	    case 1:
		/*
		 * Sign extend to 16 bits.
		 */
		baseReg_ = baseReg16[rm];
		indexReg_ = indexReg16[rm];
		disp_ = nextByte;
		havedisp_ = true;
		if (disp_ & 0x80)
		    disp_ |= 0xff00;
		break;

	    case 2:
		baseReg_ = baseReg16[rm];
		indexReg_ = indexReg16[rm];
		disp_ = nextWord;
		havedisp_ = true;
		break;

            default:
                break;
	    }
	} else {
	    /*
	     * Note: mod != 3 at this point.
	     */
	    if (rm == 4) {
		char sib = nextByte;
		baseReg_ = (sib & 7);
		if (baseReg_ == 5 && mod == 0) {
		    disp_ = nextDWord;
		    if (mode_ == 64 && disp_ & 0x80000000
			&& !addressSizePrefix_)
			disp_ |= 0xffffffff00000000L;
		    baseReg_ = -1;
		} else {
		    baseReg_ += rexB;
		}
		indexReg_ = ((sib >> 3) & 7) + rexX;
		if (indexReg_ == 4)
		    indexReg_ = -1;
		scale_ = 1 << (sib >> 6);
	    }
	    switch (mod) {
	    case 0:
		if (rm != 4 && rm != 5)
		    baseReg_ = rm + rexB;
		if (rm == 5) {
		    if (mode_ == 64)
			baseReg_ = 16;
		    disp_ = nextDWord;
		    havedisp_ = true;
		}
		break;

	    case 1:
		if (rm != 4)
		    baseReg_ = rm + rexB;
		/*
		 * Sign extend to 32 bits.
		 */
		disp_ = nextByte;
		havedisp_ = true;
		if (disp_ & 0x80)
		    if (mode_ == 32)
			disp_ |= 0xffffff00;
		    else
			disp_ |= 0xffffffffffffff00L;
		break;

	    case 2:
		if (rm != 4)
		    baseReg_ = rm + rexB;
		disp_ = nextDWord;
		havedisp_ = true;
		if (mode_ == 64 && disp_ & 0x80000000)
		    disp_ |= 0xffffffff00000000L;
		break;

            default:
                break;
	    }
	}
    }
    int mod()
    {
	return modrm_ >> 6;
    }
    int rm()
    {
	return modrm_ & 7;
    }
    int reg()
    {
	return (modrm_ >> 3) & 7;
    }
    void reg(int r)
    {
	modrm_ = (r & 7) << 3;
    }
    int rexR()
    {
	if (mode_ == 64 && rex_)
	    return rex_ & 4 ? 8 : 0;
	return 0;
    }
    int rexX()
    {
	if (mode_ == 64 && rex_)
	    return rex_ & 2 ? 8 : 0;
	return 0;
    }
    int rexB()
    {
	if (mode_ == 64 && rex_)
	    return rex_ & 1 ? 8 : 0;
	return 0;
    }
    bool rexW()
    {
	if (mode_ == 64 && rex_)
	    return rex_ & 8 ? true : false;
	return false;
    }
    int typeWidth(int size)
    {
	switch (size) {
	case BYTE:
	    return 8;
	case WORD:
	    return 16;
	case LONG:
	    return 32;
	case QWORD:
            return 64;
	default:
            assert(0, std.conv.to!string(size));
	}
    }
    string regName(int rt, int size, int regno)
    {
	switch (rt) {
	case REGISTER:
	    if (regno == 16) {
		if (size == LONG)
		    return "eip";
		else
		    return "rip";
	    }
	    if (mode_ == 64 && rex_ && size == BYTE)
		return regbNames[regno];
	    return regNames[size][regno];
	case FLOATREG:
	    return floatNames[regno];
	case MMXREG:
	    return mmxNames[regno];
	case XMMREG:
	    return xmmNames[regno];
        default:
            assert(0);
	}
    }
    ulong fetchImmediate(int size)
    {
	switch (size) {
	case BYTE:
	    return nextByte();
	case WORD:
	    return nextWord();
	case LONG:
	    return nextDWord();
	case QWORD:
	    return nextQWord();
	default:
	    assert(false);
	}
    }
    Operand displayImmediate(int size, long val)
    {
	int iwidth = typeWidth(size);
	int width = typeWidth(size_);
	if (iwidth < 64 && (val & (1L << (iwidth - 1))))
	    val |= -(1L << iwidth);
	if (width < 64)
	    val &= (1L << width) - 1;
	string s;
	s = std.string.format("%#x", val);
	if (attMode_)
	    s = "$" ~ s;
	return Operand(size, s);
    }
    Operand displayUnsignedImmediate(int size, long val)
    {
	string s;
	s = std.string.format("%#x", val);
	if (attMode_)
	    s = "$" ~ s;
	return Operand(size, s);
    }
    Operand displayRelative(int size, long val)
    {
	int width = typeWidth(size);
	if (val & (1L << (width - 1)))
	    val |= -(1L << width);
	return displayAddress(size, loc_ + val);
    }
    Operand displayFarcall(int size, ulong addr, uint callseg)
    {
	string s;
	if (attMode_)
	    s = std.string.format("$%#x,%#x", callseg, addr);
	else
	    s = std.string.format("%#x:%#x", callseg, addr);
	return Operand(size, s);
    }
    Operand displaySegment(int segno)
    {
	if (segno >= segNames.length)
	    return Operand(NONE, "???");
	string s = segNames[segno];
	if (attMode_)
	    s = "%" ~ s;
	return Operand(NONE, s);
    }
    Operand displayControl(int crno)
    {
	if (attMode_)
	    return Operand(NONE, std.string.format("%%cr%d", crno));
	else
	    return Operand(NONE, std.string.format("cr%d", crno));
    }
    Operand displayDebug(int drno)
    {
	if (attMode_)
	    return Operand(NONE, std.string.format("%%dr%d", drno));
	else
	    return Operand(NONE, std.string.format("dr%d", drno));
    }
    Operand displayRegister(int rt, int size, int regno)
    {
	if (attMode_)
	    return Operand(size, "%" ~ regName(rt, size, regno));
	else
	    return Operand(size, regName(rt, size, regno));
    }
    Operand displayIndirect(int rt, int size, int segno, int regno)
    {
	string res;
	if (attMode_)
	    if (segno >= 0)
		res =  std.string.format("%%%s:(%%%s)",
					 segNames[segno],
					 regName(rt, size, regno));
	    else
		res =  std.string.format("(%%%s)",
					 regName(rt, size, regno));
	else
	    if (segno >= 0)
		res =  std.string.format("%s:[%s]",
					 segNames[segno],
					 regName(rt, size, regno));
	    else
		res =  std.string.format("[%s]",
					 regName(rt, size, regno));
	return Operand(size, res);
    }
    Operand displayReg(int rt, int size)
    {
	return displayRegister(rt, size, reg + rexR);
    }
    Operand displayRM(int rt, int size, bool indirect)
    {
	if (indirect) {
	    Operand op = displayRM(rt, size, false);
	    if (attMode_)
		op.value = "*" ~ op.value;
	    return op;
	}

	string basePlusIndexAtt()
	{
	    string res;

	    if (baseReg_ >= 0) {
		int disp = cast(int) disp_;	// XXX 64bit?
		res = std.string.format("%d", disp);
	    } else
		res = _displayAddress(size, disp_);

	    int mode = addressSize;

	    if (indexReg_ >= 0) {
		string br = "";
		if (baseReg_ >= 0)
		    br = "%" ~ regName(REGISTER, mode, baseReg_);
		if (scale_ > 0)
		    res ~= std.string.format("(%s,%%%s,%d)",
					     br,
					     regName(REGISTER, mode, indexReg_),
					     scale_);
		else
		    res ~= std.string.format("(%s,%%%s)",
					     br,
					     regName(REGISTER, mode, indexReg_));
	    } else if (baseReg_ >= 0) {
		res ~= std.string.format("(%%%s)",
					 regName(REGISTER, mode, baseReg_));
	    }
	    return res;
	}

	string basePlusIndexIntel()
	{
	    string s;

	    if (havedisp_
		&& (disp_ || (indexReg_ < 0 && baseReg_ < 0))) {
		if (baseReg_ >= 0) {
		    int disp = cast(int) disp_;	// XXX 64bit?
		    if (disp > 0)
			s = std.string.format("+%d", disp);
		    else
			s = std.string.format("%d", disp);
		} else
		    s = "+" ~ _displayAddress(size, disp_);
		if (baseReg_ < 0 && indexReg_ < 0)
		    return s[1..$];
	    }

	    int mode = addressSize;

	    if (indexReg_ >= 0) {
		if (scale_ && scale_ != 1)
		    if (baseReg_ >= 0)
			return std.string.format("[%s+%s*%d%s]",
						 regName(REGISTER, mode, baseReg_),
						 regName(REGISTER, mode, indexReg_),
						 scale_, s);
		    else
			return std.string.format("[%s*%d%s]",
						 regName(REGISTER, mode, indexReg_),
						 scale_, s);
		else
		    return std.string.format("[%s+%s%s]",
					     regName(REGISTER, mode, baseReg_),
					     regName(REGISTER, mode, indexReg_), s);
	    } else if (baseReg_ >= 0) {
		return std.string.format("[%s%s]",
					 regName(REGISTER, mode, baseReg_), s);
	    }
            assert(0);
	}

	if (mod == 3) {
	    return displayRegister(rt, size, rm + rexB);
	} else {
	    string res;

	    if (!attMode_) {
		switch (size) {
		case BYTE:
		    res = "byte ptr ";
		    break;
		case WORD:
		    res = "word ptr ";
		    break;
		case LONG:
		case FLOAT:
		    res = "dword ptr ";
		    break;
		case QWORD:
		case DOUBLE:
		    res = "qword ptr ";
		    break;
		case LDOUBLE:
		    res = "xword ptr ";
		    break;
		case DQWORD:
		    res = "xmmword ptr ";
		    break;
		default:
		}
	    }
	    if (seg_.length > 0)
		res ~= seg_ ~ ":";
	    if (attMode_)
		res ~= basePlusIndexAtt;
	    else
		res ~= basePlusIndexIntel;

	    return Operand(size, res);
	}
    }
    string _displayAddress(int size, ulong addr)
    {
	if (mode_ == 32)
	    addr &= 0xffffffff;
	return lookupAddress_(addr);
    }
    Operand displayAddress(int size, ulong addr)
    {
	string s = _displayAddress(size, addr);
	if (seg_.length > 0)
	    s = seg_ ~ ":" ~ s;
	return Operand(size, s);
    }
    void skipImmediate(string[] s)
    {
	foreach (operand; s) {
	    /*
	     * SDM Vol 2b A.2.1
	     */

	    if (operand.length < 2)
		continue;
	    string opsize = operand[1..$];
	    int size;
	    switch (opsize) {
	    case "a":
		size = operandSizePrefix_ ? LONG : QWORD;
		break;
	    case "b":
		size = BYTE;
		break;
	    case "c":
		size = operandSizePrefix_ ? BYTE : WORD;
		break;
	    case "d":
		size = LONG;
		break;
	    case "dq":
		size = DQWORD;
		break;
	    case "n":
		size = NONE;
		break;
	    case "p":
		size = BYTE;	// XXX
		break;
	    case "pd":
		size = DQWORD;
		break;
	    case "pi":
		size = QWORD;
		break;
	    case "ps":
		size = DQWORD;
		break;
	    case "q":
		size = QWORD;
		break;
	    case "s":
		break;
	    case "sd":
		size = QWORD;
		break;
	    case "ss":
		size = LONG;
		break;
	    case "si":
		size = LONG;
		break;
	    case "v":
		size = operandSize;
		break;
	    case "w":
		size = WORD;
		break;
	    case "z":	    
		size = operandSizePrefix_ ? WORD : LONG;
		break;
	    default:
		continue;
	    }

	    switch (operand[0]) {
	    case 'A':
		assert(opsize == "p");
		fetchImmediate(operandSize);
		fetchImmediate(WORD);
		continue;
	    case 'I':
		fetchImmediate(size);
		continue;
	    case 'J':
		fetchImmediate(size);
		continue;
	    case 'K':
		fetchImmediate(size);
		continue;
	    case 'O':
		if (addressSizePrefix_)
		    nextWord;
		else
		    nextDWord;
		continue;
	    default:
		continue;
	    }
	}
    }
    Operand[] displayOperands(string[] s)
    {
	Operand[] operands;

	foreach (operand; s) {
	    /*
	     * SDM Vol 2b A.2.1
	     */
	    switch (operand) {
	    case "0":
		 operands ~= displayImmediate(NONE, 0);
		 continue;
	    case "1":
		 operands ~= displayImmediate(NONE, 1);
		 continue;
	    case "3":
		 operands ~= displayImmediate(NONE, 3);
		 continue;
	    case "AL":
		operands ~= displayRegister(REGISTER, BYTE, 0 + rexB);
		continue;
	    case "CL":
		operands ~= displayRegister(REGISTER, BYTE, 1 + rexB);
		continue;
	    case "CLnorex":
		operands ~= displayRegister(REGISTER, BYTE, 1);
		continue;
	    case "DL":
		operands ~= displayRegister(REGISTER, BYTE, 2 + rexB);
		continue;
	    case "BL":
		operands ~= displayRegister(REGISTER, BYTE, 3 + rexB);
		continue;
	    case "AH":
		operands ~= displayRegister(REGISTER, BYTE, 4 + rexB);
		continue;
	    case "CH":
		operands ~= displayRegister(REGISTER, BYTE, 5 + rexB);
		continue;
	    case "DH":
		operands ~= displayRegister(REGISTER, BYTE, 6 + rexB);
		continue;
	    case "BH":
		operands ~= displayRegister(REGISTER, BYTE, 7 + rexB);
		continue;
	    case "AX":
		operands ~= displayRegister(REGISTER, WORD, 0);
		continue;
	    case "DX":
		operands ~= displayRegister(REGISTER, WORD, 2);
		continue;
	    case "eAX":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 0);
		continue;
	    case "eCX":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 1);
		continue;
	    case "eDX":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 2);
		continue;
	    case "eBX":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 3);
		continue;
	    case "eSP":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 4);
		continue;
	    case "eBP":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 5);
		continue;
	    case "eSI":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 6);
		continue;
	    case "eDI":
		operands ~= displayRegister(REGISTER, operandSizePrefix_ ? WORD : LONG, 7);
		continue;
	    case "rAXnorex":
		operands ~= displayRegister(REGISTER, operandSize, 0);
		continue;
	    case "rAX":
		operands ~= displayRegister(REGISTER, size_, 0 + rexB);
		continue;
	    case "rCX":
		operands ~= displayRegister(REGISTER, size_, 1 + rexB);
		continue;
	    case "rDX":
		operands ~= displayRegister(REGISTER, size_, 2 + rexB);
		continue;
	    case "rBX":
		operands ~= displayRegister(REGISTER, size_, 3 + rexB);
		continue;
	    case "rSP":
		operands ~= displayRegister(REGISTER, size_, 4 + rexB);
		continue;
	    case "rBP":
		operands ~= displayRegister(REGISTER, size_, 5 + rexB);
		continue;
	    case "rSI":
		operands ~= displayRegister(REGISTER, size_, 6 + rexB);
		continue;
	    case "rDI":
		operands ~= displayRegister(REGISTER, size_, 7 + rexB);
		continue;
	    case "ES":
		operands ~= displaySegment(0);
		continue;
	    case "CS":
		operands ~= displaySegment(1);
		continue;
	    case "SS":
		operands ~= displaySegment(2);
		continue;
	    case "DS":
		operands ~= displaySegment(3);
		continue;
	    case "FS":
		operands ~= displaySegment(4);
		continue;
	    case "GS":
		operands ~= displaySegment(5);
		continue;
	    case "ST(0)":
		operands ~= displayRegister(FLOATREG, LDOUBLE, 0);
		continue;
	    case "ST(i)":
		operands ~= displayRegister(FLOATREG, LDOUBLE, rm);
		continue;
	    default:
		break;
	    }

	    string sizeexp;
	    if (operand.length < 2)
		    goto mess;
	    string opsize = operand[1..$];
	    int size;
	    switch (opsize) {
	    case "a":
		size = operandSizePrefix_ ? LONG : QWORD;
		break;
	    case "b":
		size = BYTE;
		break;
	    case "c":
		size = operandSizePrefix_ ? BYTE : WORD;
		break;
	    case "d":
		size = LONG;
		break;
	    case "dq":
		size = DQWORD;
		break;
	    case "f":
		size = FLOAT;
		break;
	    case "ld":
		size = LDOUBLE;
		break;
	    case "n":
		size = NONE;
		break;
	    case "p":
		size = BYTE;	// XXX
		break;
	    case "pd":
		size = DQWORD;
		break;
	    case "pi":
		size = QWORD;
		break;
	    case "ps":
		size = DQWORD;
		break;
	    case "q":
		size = QWORD;
		break;
	    case "s":
		break;
	    case "sd":
		size = QWORD;
		break;
	    case "ss":
		size = LONG;
		break;
	    case "si":
		size = LONG;
		break;
	    case "v":
		size = operandSize;
		break;
	    case "w":
		size = WORD;
		break;
	    case "z":	    
		size = operandSizePrefix_ ? WORD : LONG;
		break;
	    default:
		goto mess;
	    }

	    switch (operand[0]) {
	    case 'A':
		assert(opsize == "p");
		operands ~= displayFarcall(operandSize, fetchImmediate(operandSize), to!uint(fetchImmediate(WORD)));
		continue;
	    case 'C':
		operands ~= displayControl(reg);
		continue;
	    case 'D':
		operands ~= displayDebug(reg);
		continue;
	    case 'E':
		operands ~= displayRM(REGISTER, size, false);
		continue;
	    case 'F':
		operands ~= Operand(NONE, "%eflags");
		continue;
	    case 'G':
		operands ~= displayReg(REGISTER, size);
		continue;
	    case 'H':
		operands ~= displayRM(REGISTER, size, true);
		continue;
	    case 'I':
		operands ~= displayImmediate(size, fetchImmediate(size));
		continue;
	    case 'J':
		operands ~= displayRelative(size, fetchImmediate(size));
		continue;
	    case 'K':
		operands ~= displayUnsignedImmediate(size, fetchImmediate(size));
		continue;
	    case 'M':
		operands ~= displayRM(REGISTER, size, false);
		continue;
	    case 'N':
		operands ~= displayRegister(MMXREG, QWORD, rm);
		continue;
	    case 'O':
		operands ~= displayAddress(size, addressSizePrefix_ ? nextWord : nextDWord);
		continue;
	    case 'P':
		operands ~= displayRegister(MMXREG, QWORD, reg);
		continue;
	    case 'Q':
		operands ~= displayRM(MMXREG, QWORD, false);
		continue;
	    case 'R':
		operands ~= displayRegister(REGISTER, size, rm + rexB);
		continue;
	    case 'S':
		operands ~= displaySegment(reg);
		continue;
	    case 'U':
		operands ~= displayRegister(XMMREG, DQWORD, rm + rexB);
		continue;
	    case 'V':
		operands ~= displayRegister(XMMREG, DQWORD, reg + rexR);
		continue;
	    case 'W':
		operands ~= displayRM(XMMREG, size, false);
		continue;
	    case 'X':
		if (mode_ == 64) operands ~= displayIndirect(REGISTER, QWORD, -1, 6);
		else if (addressSizePrefix_) operands ~= displayIndirect(REGISTER, WORD, -1, 6);
		else operands ~= displayIndirect(REGISTER, LONG, -1, 6);
		continue;
	    case 'Y':
		if (mode_ == 64) operands ~= displayIndirect(REGISTER, QWORD, 0, 7);
		else if (addressSizePrefix_) operands ~= displayIndirect(REGISTER, WORD, 0, 7);
		else operands ~= displayIndirect(REGISTER, LONG, 0, 7);
		continue;
            default:
                assert(0);
	    }

	mess:
	    assert(false);
	    break;
	}

	return operands;
    }
    string displayInstruction(string opcode, Operand[] operands)
    {
	if (countUntil(opcode, '/') >= 0) {
	    string[] ops = split(opcode, "/");
	    if (size_ >= 1 && size_ <= ops.length)
		opcode = ops[size_ - 1];
	} else {
	    if (attMode_) {
		if (opcode == "movsx" || opcode == "movzx") {
		    opcode = opcode[0..4];
		    if (operands[1].type == BYTE)
			opcode ~= 'b';
		    else if (operands[1].type == WORD)
			opcode ~= 'w';
		    else
			assert(false);
		}
		if (opcode == "movsxd")
		    opcode = "movsl";
		if (size_ == BYTE)
		    opcode ~= 'b';
		else if (size_ == WORD)
		    opcode ~= 'w';
		else if (size_ == LONG)
		    opcode ~= 'l';
		else if (size_ == QWORD)
		    opcode ~= 'q';
		else if (size_ == FLOAT)
		    opcode ~= 's';
		else if (size_ == DOUBLE)
		    opcode ~= 'l';
		else if (size_ == LDOUBLE)
		    opcode ~= 't';
	    }
	}
	if (operands.length) {
	    string[] ops;
	    foreach (op; operands)
		ops ~= op.value;
	    if (attMode_ && opcode != "enter")
		ops = ops.reverse;
	    return opcode ~ "\t" ~ join(ops, ",");
	} else
	    return opcode;
    }

    char delegate(ulong) readByte_;
    string delegate(ulong) lookupAddress_;
    ulong loc_;
    bool attMode_;
    int mode_;

    /*
     * Prefixes
     */
    string seg_ = "";
    char rex_ = 0;
    bool lockPrefix_ = false;
    bool repnePrefix_ = false;
    bool repePrefix_ = false;
    bool operandSizePrefix_ = false;
    bool addressSizePrefix_ = false;

    /*
     * Results from decoding operands.
     */
    int size_;
    char modrm_;
    int baseReg_;
    int indexReg_;
    int scale_;
    bool havedisp_;
    long disp_;
}

