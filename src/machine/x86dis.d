/*-
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

module machine.x86dis;

import machine.machine;
import std.string;

/*
 * Size attributes
 */
enum {
    BYTE = 0,
    WORD = 1,
    LONG = 2,
    QUAD = 3,
    SNGL = 4,
    DBLR = 5,
    EXTR = 6,
    SDEP = 7,
    NONE = 8,
}

/*
 * Addressing modes
 */
enum {
    E = 1,			/* general effective address */
    Eind = 2,			/* indirect address (jump, call) */
    Ew = 3,			/* address, word size */
    Eb = 4,			/* address, byte size */
    R = 5,			/* register, in 'reg' field */
    Rw = 6,			/* word register, in 'reg' field */
    Ri = 7,			/* register in instruction */
    S = 8,			/* segment reg, in 'reg' field */
    Si = 9,			/* segment reg, in instruction */
    A = 10,			/* accumulator */
    BX = 11,			/* (bx) */
    CL = 12,			/* cl, for shifts */
    DX = 13,			/* dx, for IO */
    SI = 14,			/* si */
    DI = 15,			/* di */
    CR = 16,			/* control register */
    DR = 17,			/* debug register */
    TR = 18,			/* test register */
    I = 19,			/* immediate, unsigned */
    Is = 20,			/* immediate, signed */
    Ib = 21,			/* byte immediate, unsigned */
    Ibs = 22,			/* byte immediate, signed */
    Iw = 23,			/* word immediate, unsigned */
    O = 25,			/* direct address */
    Db = 26,			/* byte displacement from EIP */
    Dl = 27,			/* long displacement from EIP */
    o1 = 28,			/* constant 1 */
    o3 = 29,			/* constant 3 */
    OS = 30,			/* immediate offset/segment */
    ST = 31,			/* FP stack top */
    STI = 32,			/* FP stack */
    X = 33,			/* extended FP op */
    XA = 34,			/* for 'fstcw %ax' */
    El = 35,			/* address, long size */
    Ril = 36,			/* long register in instruction */
    Iba = 37,			/* byte immediate, don't print if 0xa */
}

struct instT {
	string	i_name;			/* name */
	bool	i_has_modrm;		/* has regmodrm byte */
	short	i_size;			/* operand size */
	int	i_mode;			/* addressing modes */
	union {				/* pointer to extra opcode table */
		instT*	i_extrai;
		finstT*	i_extraf;
		string*	i_extrat;
		string	i_extras;
	}
};

static int op1(int x) { return x; }
static int op2(int x, int y) { return x | (y << 8); }
static int op3(int x, int y, int z) { return x | (y << 8) | (z << 16); }

struct finstT {
    string	f_name;			/* name for memory instruction */
    int		f_size;			/* size for memory instruction */
    int		f_rrmode;		/* mode for rr instruction */
    union {
	string	f_rrname;		/* name for rr instruction */
	string*	f_rrnames;		/* pointer to table */
    }
}

static string db_Grp6[8] = [
	"sldt",
	"str",
	"lldt",
	"ltr",
	"verr",
	"verw",
	"",
	""
];

static string db_Grp7[8] = [
	"sgdt",
	"sidt",
	"lgdt",
	"lidt",
	"smsw",
	"",
	"lmsw",
	"invlpg"
];

static string db_Grp8[8] = [
	"",
	"",
	"",
	"",
	"bt",
	"bts",
	"btr",
	"btc"
];

static string db_Grp9[8] = [
	"",
	"cmpxchg8b",
	"",
	"",
	"",
	"",
	"",
	""
];

static string db_Grp15[8] = [
	"fxsave",
	"fxrstor",
	"ldmxcsr",
	"stmxcsr",
	"",
	"",
	"",
	"clflush"
];

static string db_Grp15b[8] = [
	"",
	"",
	"",
	"",
	"",
	"lfence",
	"mfence",
	"sfence"
];

static instT db_inst_0f0x[16] = [
/*00*/	{ "",	   true,  NONE,  op1(Ew),     i_extrat:&db_Grp6[0] },
/*01*/	{ "",	   true,  NONE,  op1(Ew),     i_extrat:&db_Grp7[0] },
/*02*/	{ "lar",   true,  LONG,  op2(E,R),    null },
/*03*/	{ "lsl",   true,  LONG,  op2(E,R),    null },
/*04*/	{ "",      false, NONE,  0,	      null },
/*05*/	{ "syscall",false,NONE,  0,	      null },
/*06*/	{ "clts",  false, NONE,  0,	      null },
/*07*/	{ "sysret",false, NONE,  0,	      null },

/*08*/	{ "invd",  false, NONE,  0,	      null },
/*09*/	{ "wbinvd",false, NONE,  0,	      null },
/*0a*/	{ "",      false, NONE,  0,	      null },
/*0b*/	{ "",      false, NONE,  0,	      null },
/*0c*/	{ "",      false, NONE,  0,	      null },
/*0d*/	{ "",      false, NONE,  0,	      null },
/*0e*/	{ "",      false, NONE,  0,	      null },
/*0f*/	{ "",      false, NONE,  0,	      null },
];

static instT db_inst_0f2x[16] = [
/*20*/	{ "mov",   true,  LONG,  op2(CR,El),  null },
/*21*/	{ "mov",   true,  LONG,  op2(DR,El),  null },
/*22*/	{ "mov",   true,  LONG,  op2(El,CR),  null },
/*23*/	{ "mov",   true,  LONG,  op2(El,DR),  null },
/*24*/	{ "mov",   true,  LONG,  op2(TR,El),  null },
/*25*/	{ "",      false, NONE,  0,	      null },
/*26*/	{ "mov",   true,  LONG,  op2(El,TR),  null },
/*27*/	{ "",      false, NONE,  0,	      null },

/*28*/	{ "",      false, NONE,  0,	      null },
/*29*/	{ "",      false, NONE,  0,	      null },
/*2a*/	{ "",      false, NONE,  0,	      null },
/*2b*/	{ "",      false, NONE,  0,	      null },
/*2c*/	{ "",      false, NONE,  0,	      null },
/*2d*/	{ "",      false, NONE,  0,	      null },
/*2e*/	{ "",      false, NONE,  0,	      null },
/*2f*/	{ "",      false, NONE,  0,	      null },
];

static instT db_inst_0f3x[16] = [
/*30*/	{ "wrmsr", false, NONE,  0,	      null },
/*31*/	{ "rdtsc", false, NONE,  0,	      null },
/*32*/	{ "rdmsr", false, NONE,  0,	      null },
/*33*/	{ "rdpmc", false, NONE,  0,	      null },
/*34*/	{ "sysenter",false,NONE,  0,	      null },
/*35*/	{ "sysexit",false,NONE,  0,	      null },
/*36*/	{ "",	   false, NONE,  0,	      null },
/*37*/	{ "getsec",false, NONE,  0,	      null },

/*38*/	{ "",	   false, NONE,  0,	      null },
/*39*/	{ "",	   false, NONE,  0,	      null },
/*3a*/	{ "",	   false, NONE,  0,	      null },
/*3b*/	{ "",	   false, NONE,  0,	      null },
/*3c*/	{ "",	   false, NONE,  0,	      null },
/*3d*/	{ "",	   false, NONE,  0,	      null },
/*3e*/	{ "",	   false, NONE,  0,	      null },
/*3f*/	{ "",	   false, NONE,  0,	      null },
];

static instT db_inst_0f4x[16] = [
/*40*/	{ "cmovo",  true, NONE,  op2(E, R),   null },
/*41*/	{ "cmovno", true, NONE,  op2(E, R),   null },
/*42*/	{ "cmovb",  true, NONE,  op2(E, R),   null },
/*43*/	{ "cmovnb", true, NONE,  op2(E, R),   null },
/*44*/	{ "cmovz",  true, NONE,  op2(E, R),   null },
/*45*/	{ "cmovnz", true, NONE,  op2(E, R),   null },
/*46*/	{ "cmovbe", true, NONE,  op2(E, R),   null },
/*47*/	{ "cmovnbe",true, NONE,  op2(E, R),   null },

/*48*/	{ "cmovs",  true, NONE,  op2(E, R),   null },
/*49*/	{ "cmovns", true, NONE,  op2(E, R),   null },
/*4a*/	{ "cmovp",  true, NONE,  op2(E, R),   null },
/*4b*/	{ "cmovnp", true, NONE,  op2(E, R),   null },
/*4c*/	{ "cmovl",  true, NONE,  op2(E, R),   null },
/*4d*/	{ "cmovnl", true, NONE,  op2(E, R),   null },
/*4e*/	{ "cmovle", true, NONE,  op2(E, R),   null },
/*4f*/	{ "cmovnle",true, NONE,  op2(E, R),   null },
];

static instT db_inst_0f8x[16] = [
/*80*/	{ "jo",    false, NONE,  op1(Dl),     null },
/*81*/	{ "jno",   false, NONE,  op1(Dl),     null },
/*82*/	{ "jb",    false, NONE,  op1(Dl),     null },
/*83*/	{ "jnb",   false, NONE,  op1(Dl),     null },
/*84*/	{ "jz",    false, NONE,  op1(Dl),     null },
/*85*/	{ "jnz",   false, NONE,  op1(Dl),     null },
/*86*/	{ "jbe",   false, NONE,  op1(Dl),     null },
/*87*/	{ "jnbe",  false, NONE,  op1(Dl),     null },

/*88*/	{ "js",    false, NONE,  op1(Dl),     null },
/*89*/	{ "jns",   false, NONE,  op1(Dl),     null },
/*8a*/	{ "jp",    false, NONE,  op1(Dl),     null },
/*8b*/	{ "jnp",   false, NONE,  op1(Dl),     null },
/*8c*/	{ "jl",    false, NONE,  op1(Dl),     null },
/*8d*/	{ "jnl",   false, NONE,  op1(Dl),     null },
/*8e*/	{ "jle",   false, NONE,  op1(Dl),     null },
/*8f*/	{ "jnle",  false, NONE,  op1(Dl),     null },
];

static instT db_inst_0f9x[16] = [
/*90*/	{ "seto",  true,  NONE,  op1(Eb),     null },
/*91*/	{ "setno", true,  NONE,  op1(Eb),     null },
/*92*/	{ "setb",  true,  NONE,  op1(Eb),     null },
/*93*/	{ "setnb", true,  NONE,  op1(Eb),     null },
/*94*/	{ "setz",  true,  NONE,  op1(Eb),     null },
/*95*/	{ "setnz", true,  NONE,  op1(Eb),     null },
/*96*/	{ "setbe", true,  NONE,  op1(Eb),     null },
/*97*/	{ "setnbe",true,  NONE,  op1(Eb),     null },

/*98*/	{ "sets",  true,  NONE,  op1(Eb),     null },
/*99*/	{ "setns", true,  NONE,  op1(Eb),     null },
/*9a*/	{ "setp",  true,  NONE,  op1(Eb),     null },
/*9b*/	{ "setnp", true,  NONE,  op1(Eb),     null },
/*9c*/	{ "setl",  true,  NONE,  op1(Eb),     null },
/*9d*/	{ "setnl", true,  NONE,  op1(Eb),     null },
/*9e*/	{ "setle", true,  NONE,  op1(Eb),     null },
/*9f*/	{ "setnle",true,  NONE,  op1(Eb),     null },
];

static instT db_inst_0fax[16] = [
/*a0*/	{ "push",  false, NONE,  op1(Si),     null },
/*a1*/	{ "pop",   false, NONE,  op1(Si),     null },
/*a2*/	{ "cpuid", false, NONE,  0,	      null },
/*a3*/	{ "bt",    true,  LONG,  op2(R,E),    null },
/*a4*/	{ "shld",  true,  LONG,  op3(Ib,R,E), null },
/*a5*/	{ "shld",  true,  LONG,  op3(CL,R,E), null },
/*a6*/	{ "",      false, NONE,  0,	      null },
/*a7*/	{ "",      false, NONE,  0,	      null },

/*a8*/	{ "push",  false, NONE,  op1(Si),     null },
/*a9*/	{ "pop",   false, NONE,  op1(Si),     null },
/*aa*/	{ "rsm",   false, NONE,  0,	      null },
/*ab*/	{ "bts",   true,  LONG,  op2(R,E),    null },
/*ac*/	{ "shrd",  true,  LONG,  op3(Ib,R,E), null },
/*ad*/	{ "shrd",  true,  LONG,  op3(CL,R,E), null },
/*ae*/	{ "",      true,  LONG,  op1(E),      i_extrat:&db_Grp15[0] },
/*af*/	{ "imul",  true,  LONG,  op2(E,R),    null },
];

static instT db_inst_0fbx[16] = [
/*b0*/	{ "cmpxchg",true, BYTE,	 op2(R, E),   null },
/*b0*/	{ "cmpxchg",true, LONG,	 op2(R, E),   null },
/*b2*/	{ "lss",   true,  LONG,  op2(E, R),   null },
/*b3*/	{ "btr",   true,  LONG,  op2(R, E),   null },
/*b4*/	{ "lfs",   true,  LONG,  op2(E, R),   null },
/*b5*/	{ "lgs",   true,  LONG,  op2(E, R),   null },
/*b6*/	{ "movzb", true,  LONG,  op2(Eb, R),  null },
/*b7*/	{ "movzw", true,  LONG,  op2(Ew, R),  null },

/*b8*/	{ "",      false, NONE,  0,	      null },
/*b9*/	{ "",      false, NONE,  0,	      null },
/*ba*/	{ "",      true,  LONG,  op2(Ib, E),  i_extrat:&db_Grp8[0] },
/*bb*/	{ "btc",   true,  LONG,  op2(R, E),   null },
/*bc*/	{ "bsf",   true,  LONG,  op2(E, R),   null },
/*bd*/	{ "bsr",   true,  LONG,  op2(E, R),   null },
/*be*/	{ "movsb", true,  LONG,  op2(Eb, R),  null },
/*bf*/	{ "movsw", true,  LONG,  op2(Ew, R),  null },
];

static instT db_inst_0fcx[16] = [
/*c0*/	{ "xadd",  true,  BYTE,	 op2(R, E),   null },
/*c1*/	{ "xadd",  true,  LONG,	 op2(R, E),   null },
/*c2*/	{ "",	   false, NONE,	 0,	      null },
/*c3*/	{ "",	   false, NONE,	 0,	      null },
/*c4*/	{ "",	   false, NONE,	 0,	      null },
/*c5*/	{ "",	   false, NONE,	 0,	      null },
/*c6*/	{ "",	   false, NONE,	 0,	      null },
/*c7*/	{ "",	   true,  NONE,  op1(E),      i_extrat:&db_Grp9[0] },
/*c8*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*c9*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*ca*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*cb*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*cc*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*cd*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*ce*/	{ "bswap", false, LONG,  op1(Ril),    null },
/*cf*/	{ "bswap", false, LONG,  op1(Ril),    null },
];

static instT* db_inst_0f[16] = [
	&db_inst_0f0x[0],
	null,
	&db_inst_0f2x[0],
	&db_inst_0f3x[0],
	&db_inst_0f4x[0],
	null,
	null,
	null,
	&db_inst_0f8x[0],
	&db_inst_0f9x[0],
	&db_inst_0fax[0],
	&db_inst_0fbx[0],
	&db_inst_0fcx[0],
	null,
	null,
	null
];

static string db_Esc92[8] = [
	"fnop",	"",	"",	"",	"",	"",	"",	""
];
static string db_Esc94[8] = [
	"fchs",	"fabs",	"",	"",	"ftst",	"fxam",	"",	""
];
static string db_Esc95[8] = [
	"fld1",	"fldl2t","fldl2e","fldpi","fldlg2","fldln2","fldz",""
];
static string db_Esc96[8] = [
	"f2xm1","fyl2x","fptan","fpatan","fxtract","fprem1","fdecstp",
	"fincstp"
];
static string db_Esc97[8] = [
	"fprem","fyl2xp1","fsqrt","fsincos","frndint","fscale","fsin","fcos"
];

static string db_Esca5[8] = [
	"",	"fucompp","",	"",	"",	"",	"",	""
];

static string db_Escb4[8] = [
	"fneni","fndisi",	"fnclex","fninit","fsetpm",	"",	"",	""
];

static string db_Esce3[8] = [
	"",	"fcompp","",	"",	"",	"",	"",	""
];

static string db_Escf4[8] = [
	"fnstsw","",	"",	"",	"",	"",	"",	""
];

static finstT db_Esc8[8] = [
/*0*/	{ "fadd",   SNGL,  op2(STI,ST),	null },
/*1*/	{ "fmul",   SNGL,  op2(STI,ST),	null },
/*2*/	{ "fcom",   SNGL,  op2(STI,ST),	null },
/*3*/	{ "fcomp",  SNGL,  op2(STI,ST),	null },
/*4*/	{ "fsub",   SNGL,  op2(STI,ST),	null },
/*5*/	{ "fsubr",  SNGL,  op2(STI,ST),	null },
/*6*/	{ "fdiv",   SNGL,  op2(STI,ST),	null },
/*7*/	{ "fdivr",  SNGL,  op2(STI,ST),	null },
];

static finstT db_Esc9[8] = [
/*0*/	{ "fld",    SNGL,  op1(STI),	null },
/*1*/	{ "",       NONE,  op1(STI),	f_rrname:"fxch" },
/*2*/	{ "fst",    SNGL,  op1(X),	f_rrnames:&db_Esc92[0] },
/*3*/	{ "fstp",   SNGL,  0,		null },
/*4*/	{ "fldenv", NONE,  op1(X),	f_rrnames:&db_Esc94[0] },
/*5*/	{ "fldcw",  NONE,  op1(X),	f_rrnames:&db_Esc95[0] },
/*6*/	{ "fnstenv",NONE,  op1(X),	f_rrnames:&db_Esc96[0] },
/*7*/	{ "fnstcw", NONE,  op1(X),	f_rrnames:&db_Esc97[0] },
];

static finstT db_Esca[8] = [
/*0*/	{ "fiadd",  LONG,  0,		null },
/*1*/	{ "fimul",  LONG,  0,		null },
/*2*/	{ "ficom",  LONG,  0,		null },
/*3*/	{ "ficomp", LONG,  0,		null },
/*4*/	{ "fisub",  LONG,  0,		null },
/*5*/	{ "fisubr", LONG,  op1(X),	f_rrnames:&db_Esca5[0] },
/*6*/	{ "fidiv",  LONG,  0,		null },
/*7*/	{ "fidivr", LONG,  0,		null }
];

static finstT db_Escb[8] = [
/*0*/	{ "fild",   LONG,  0,		null },
/*1*/	{ "",       NONE,  0,		null },
/*2*/	{ "fist",   LONG,  0,		null },
/*3*/	{ "fistp",  LONG,  0,		null },
/*4*/	{ "",       WORD,  op1(X),	f_rrnames:&db_Escb4[0] },
/*5*/	{ "fld",    EXTR,  0,		null },
/*6*/	{ "",       WORD,  0,		null },
/*7*/	{ "fstp",   EXTR,  0,		null },
];

static finstT db_Escc[8] = [
/*0*/	{ "fadd",   DBLR,  op2(ST,STI),	null },
/*1*/	{ "fmul",   DBLR,  op2(ST,STI),	null },
/*2*/	{ "fcom",   DBLR,  0,		null },
/*3*/	{ "fcomp",  DBLR,  0,		null },
/*4*/	{ "fsub",   DBLR,  op2(ST,STI),	f_rrname:"fsubr" },
/*5*/	{ "fsubr",  DBLR,  op2(ST,STI),	f_rrname:"fsub" },
/*6*/	{ "fdiv",   DBLR,  op2(ST,STI),	f_rrname:"fdivr" },
/*7*/	{ "fdivr",  DBLR,  op2(ST,STI),	f_rrname:"fdiv" },
];

static finstT db_Escd[8] = [
/*0*/	{ "fld",    DBLR,  op1(STI),	f_rrname:"ffree" },
/*1*/	{ "",       NONE,  0,		null },
/*2*/	{ "fst",    DBLR,  op1(STI),	null },
/*3*/	{ "fstp",   DBLR,  op1(STI),	null },
/*4*/	{ "frstor", NONE,  op1(STI),	f_rrname:"fucom" },
/*5*/	{ "",       NONE,  op1(STI),	f_rrname:"fucomp" },
/*6*/	{ "fnsave", NONE,  0,		null },
/*7*/	{ "fnstsw", NONE,  0,		null },
];

static finstT db_Esce[8] = [
/*0*/	{ "fiadd",  WORD,  op2(ST,STI),	f_rrname:"faddp" },
/*1*/	{ "fimul",  WORD,  op2(ST,STI),	f_rrname:"fmulp" },
/*2*/	{ "ficom",  WORD,  0,		null },
/*3*/	{ "ficomp", WORD,  op1(X),	f_rrnames:&db_Esce3[0] },
/*4*/	{ "fisub",  WORD,  op2(ST,STI),	f_rrname:"fsubrp" },
/*5*/	{ "fisubr", WORD,  op2(ST,STI),	f_rrname:"fsubp" },
/*6*/	{ "fidiv",  WORD,  op2(ST,STI),	f_rrname:"fdivrp" },
/*7*/	{ "fidivr", WORD,  op2(ST,STI),	f_rrname:"fdivp" },
];

static finstT db_Escf[8] = [
/*0*/	{ "fild",   WORD,  0,		null },
/*1*/	{ "",       NONE,  0,		null },
/*2*/	{ "fist",   WORD,  0,		null },
/*3*/	{ "fistp",  WORD,  0,		null },
/*4*/	{ "fbld",   NONE,  op1(XA),	f_rrnames:&db_Escf4[0] },
/*5*/	{ "fild",   QUAD,  0,		null },
/*6*/	{ "fbstp",  NONE,  0,		null },
/*7*/	{ "fistp",  QUAD,  0,		null },
];

static finstT* db_Esc_inst[] = [
	&db_Esc8[0], &db_Esc9[0], &db_Esca[0], &db_Escb[0],
	&db_Escc[0], &db_Escd[0], &db_Esce[0], &db_Escf[0]
];

static string db_Grp1[8] = [
	"add",
	"or",
	"adc",
	"sbb",
	"and",
	"sub",
	"xor",
	"cmp"
];

static string db_Grp2[8] = [
	"rol",
	"ror",
	"rcl",
	"rcr",
	"shl",
	"shr",
	"shl",
	"sar"
];

static instT db_Grp3[8] = [
	{ "test",  true, NONE, op2(I,E), null },
	{ "test",  true, NONE, op2(I,E), null },
	{ "not",   true, NONE, op1(E),   null },
	{ "neg",   true, NONE, op1(E),   null },
	{ "mul",   true, NONE, op2(E,A), null },
	{ "imul",  true, NONE, op2(E,A), null },
	{ "div",   true, NONE, op2(E,A), null },
	{ "idiv",  true, NONE, op2(E,A), null },
];

static instT db_Grp4[8] = [
	{ "inc",   true, BYTE, op1(E),   null },
	{ "dec",   true, BYTE, op1(E),   null },
	{ "",      true, NONE, 0,	 null },
	{ "",      true, NONE, 0,	 null },
	{ "",      true, NONE, 0,	 null },
	{ "",      true, NONE, 0,	 null },
	{ "",      true, NONE, 0,	 null },
	{ "",      true, NONE, 0,	 null }
];

static instT db_Grp5[8] = [
	{ "inc",   true, LONG, op1(E),   null },
	{ "dec",   true, LONG, op1(E),   null },
	{ "call",  true, LONG, op1(Eind),null },
	{ "lcall", true, LONG, op1(Eind),null },
	{ "jmp",   true, LONG, op1(Eind),null },
	{ "ljmp",  true, LONG, op1(Eind),null },
	{ "push",  true, LONG, op1(E),   null },
	{ "",      true, NONE, 0,	 null }
];

static instT db_inst_table[256] = [
/*00*/	{ "add",   true,  BYTE,  op2(R, E),  null },
/*01*/	{ "add",   true,  LONG,  op2(R, E),  null },
/*02*/	{ "add",   true,  BYTE,  op2(E, R),  null },
/*03*/	{ "add",   true,  LONG,  op2(E, R),  null },
/*04*/	{ "add",   false, BYTE,  op2(I, A),  null },
/*05*/	{ "add",   false, LONG,  op2(Is, A), null },
/*06*/	{ "push",  false, NONE,  op1(Si),    null },
/*07*/	{ "pop",   false, NONE,  op1(Si),    null },

/*08*/	{ "or",    true,  BYTE,  op2(R, E),  null },
/*09*/	{ "or",    true,  LONG,  op2(R, E),  null },
/*0a*/	{ "or",    true,  BYTE,  op2(E, R),  null },
/*0b*/	{ "or",    true,  LONG,  op2(E, R),  null },
/*0c*/	{ "or",    false, BYTE,  op2(I, A),  null },
/*0d*/	{ "or",    false, LONG,  op2(I, A),  null },
/*0e*/	{ "push",  false, NONE,  op1(Si),    null },
/*0f*/	{ "",      false, NONE,  0,	     null },

/*10*/	{ "adc",   true,  BYTE,  op2(R, E),  null },
/*11*/	{ "adc",   true,  LONG,  op2(R, E),  null },
/*12*/	{ "adc",   true,  BYTE,  op2(E, R),  null },
/*13*/	{ "adc",   true,  LONG,  op2(E, R),  null },
/*14*/	{ "adc",   false, BYTE,  op2(I, A),  null },
/*15*/	{ "adc",   false, LONG,  op2(Is, A), null },
/*16*/	{ "push",  false, NONE,  op1(Si),    null },
/*17*/	{ "pop",   false, NONE,  op1(Si),    null },

/*18*/	{ "sbb",   true,  BYTE,  op2(R, E),  null },
/*19*/	{ "sbb",   true,  LONG,  op2(R, E),  null },
/*1a*/	{ "sbb",   true,  BYTE,  op2(E, R),  null },
/*1b*/	{ "sbb",   true,  LONG,  op2(E, R),  null },
/*1c*/	{ "sbb",   false, BYTE,  op2(I, A),  null },
/*1d*/	{ "sbb",   false, LONG,  op2(Is, A), null },
/*1e*/	{ "push",  false, NONE,  op1(Si),    null },
/*1f*/	{ "pop",   false, NONE,  op1(Si),    null },

/*20*/	{ "and",   true,  BYTE,  op2(R, E),  null },
/*21*/	{ "and",   true,  LONG,  op2(R, E),  null },
/*22*/	{ "and",   true,  BYTE,  op2(E, R),  null },
/*23*/	{ "and",   true,  LONG,  op2(E, R),  null },
/*24*/	{ "and",   false, BYTE,  op2(I, A),  null },
/*25*/	{ "and",   false, LONG,  op2(I, A),  null },
/*26*/	{ "",      false, NONE,  0,	     null },
/*27*/	{ "daa",   false, NONE,  0,	     null },

/*28*/	{ "sub",   true,  BYTE,  op2(R, E),  null },
/*29*/	{ "sub",   true,  LONG,  op2(R, E),  null },
/*2a*/	{ "sub",   true,  BYTE,  op2(E, R),  null },
/*2b*/	{ "sub",   true,  LONG,  op2(E, R),  null },
/*2c*/	{ "sub",   false, BYTE,  op2(I, A),  null },
/*2d*/	{ "sub",   false, LONG,  op2(Is, A), null },
/*2e*/	{ "",      false, NONE,  0,	     null },
/*2f*/	{ "das",   false, NONE,  0,	     null },

/*30*/	{ "xor",   true,  BYTE,  op2(R, E),  null },
/*31*/	{ "xor",   true,  LONG,  op2(R, E),  null },
/*32*/	{ "xor",   true,  BYTE,  op2(E, R),  null },
/*33*/	{ "xor",   true,  LONG,  op2(E, R),  null },
/*34*/	{ "xor",   false, BYTE,  op2(I, A),  null },
/*35*/	{ "xor",   false, LONG,  op2(I, A),  null },
/*36*/	{ "",      false, NONE,  0,	     null },
/*37*/	{ "aaa",   false, NONE,  0,	     null },

/*38*/	{ "cmp",   true,  BYTE,  op2(R, E),  null },
/*39*/	{ "cmp",   true,  LONG,  op2(R, E),  null },
/*3a*/	{ "cmp",   true,  BYTE,  op2(E, R),  null },
/*3b*/	{ "cmp",   true,  LONG,  op2(E, R),  null },
/*3c*/	{ "cmp",   false, BYTE,  op2(I, A),  null },
/*3d*/	{ "cmp",   false, LONG,  op2(Is, A), null },
/*3e*/	{ "",      false, NONE,  0,	     null },
/*3f*/	{ "aas",   false, NONE,  0,	     null },

/*40*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*41*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*42*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*43*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*44*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*45*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*46*/	{ "inc",   false, LONG,  op1(Ri),    null },
/*47*/	{ "inc",   false, LONG,  op1(Ri),    null },

/*48*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*49*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4a*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4b*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4c*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4d*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4e*/	{ "dec",   false, LONG,  op1(Ri),    null },
/*4f*/	{ "dec",   false, LONG,  op1(Ri),    null },

/*50*/	{ "push",  false, LONG,  op1(Ri),    null },
/*51*/	{ "push",  false, LONG,  op1(Ri),    null },
/*52*/	{ "push",  false, LONG,  op1(Ri),    null },
/*53*/	{ "push",  false, LONG,  op1(Ri),    null },
/*54*/	{ "push",  false, LONG,  op1(Ri),    null },
/*55*/	{ "push",  false, LONG,  op1(Ri),    null },
/*56*/	{ "push",  false, LONG,  op1(Ri),    null },
/*57*/	{ "push",  false, LONG,  op1(Ri),    null },

/*58*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*59*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5a*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5b*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5c*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5d*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5e*/	{ "pop",   false, LONG,  op1(Ri),    null },
/*5f*/	{ "pop",   false, LONG,  op1(Ri),    null },

/*60*/	{ "pusha", false, LONG,  0,	     null },
/*61*/	{ "popa",  false, LONG,  0,	     null },
/*62*/  { "bound", true,  LONG,  op2(E, R),  null },
/*63*/	{ "arpl",  true,  NONE,  op2(Rw,Ew), null },

/*64*/	{ "",      false, NONE,  0,	     null },
/*65*/	{ "",      false, NONE,  0,	     null },
/*66*/	{ "",      false, NONE,  0,	     null },
/*67*/	{ "",      false, NONE,  0,	     null },

/*68*/	{ "push",  false, LONG,  op1(I),     null },
/*69*/  { "imul",  true,  LONG,  op3(I,E,R), null },
/*6a*/	{ "push",  false, LONG,  op1(Ibs),   null },
/*6b*/  { "imul",  true,  LONG,  op3(Ibs,E,R),null },
/*6c*/	{ "ins",   false, BYTE,  op2(DX, DI), null },
/*6d*/	{ "ins",   false, LONG,  op2(DX, DI), null },
/*6e*/	{ "outs",  false, BYTE,  op2(SI, DX), null },
/*6f*/	{ "outs",  false, LONG,  op2(SI, DX), null },

/*70*/	{ "jo",    false, NONE,  op1(Db),     null },
/*71*/	{ "jno",   false, NONE,  op1(Db),     null },
/*72*/	{ "jb",    false, NONE,  op1(Db),     null },
/*73*/	{ "jnb",   false, NONE,  op1(Db),     null },
/*74*/	{ "jz",    false, NONE,  op1(Db),     null },
/*75*/	{ "jnz",   false, NONE,  op1(Db),     null },
/*76*/	{ "jbe",   false, NONE,  op1(Db),     null },
/*77*/	{ "jnbe",  false, NONE,  op1(Db),     null },

/*78*/	{ "js",    false, NONE,  op1(Db),     null },
/*79*/	{ "jns",   false, NONE,  op1(Db),     null },
/*7a*/	{ "jp",    false, NONE,  op1(Db),     null },
/*7b*/	{ "jnp",   false, NONE,  op1(Db),     null },
/*7c*/	{ "jl",    false, NONE,  op1(Db),     null },
/*7d*/	{ "jnl",   false, NONE,  op1(Db),     null },
/*7e*/	{ "jle",   false, NONE,  op1(Db),     null },
/*7f*/	{ "jnle",  false, NONE,  op1(Db),     null },

/*80*/  { "",	   true,  BYTE,  op2(I, E),   i_extrat:&db_Grp1[0] },
/*81*/  { "",	   true,  LONG,  op2(I, E),   i_extrat:&db_Grp1[0] },
/*82*/  { "",	   true,  BYTE,  op2(I, E),   i_extrat:&db_Grp1[0] },
/*83*/  { "",	   true,  LONG,  op2(Ibs,E),  i_extrat:&db_Grp1[0] },
/*84*/	{ "test",  true,  BYTE,  op2(R, E),   null },
/*85*/	{ "test",  true,  LONG,  op2(R, E),   null },
/*86*/	{ "xchg",  true,  BYTE,  op2(R, E),   null },
/*87*/	{ "xchg",  true,  LONG,  op2(R, E),   null },

/*88*/	{ "mov",   true,  BYTE,  op2(R, E),   null },
/*89*/	{ "mov",   true,  LONG,  op2(R, E),   null },
/*8a*/	{ "mov",   true,  BYTE,  op2(E, R),   null },
/*8b*/	{ "mov",   true,  LONG,  op2(E, R),   null },
/*8c*/  { "mov",   true,  NONE,  op2(S, Ew),  null },
/*8d*/	{ "lea",   true,  LONG,  op2(E, R),   null },
/*8e*/	{ "mov",   true,  NONE,  op2(Ew, S),  null },
/*8f*/	{ "pop",   true,  LONG,  op1(E),      null },

/*90*/	{ "nop",   false, NONE,  0,	      null },
/*91*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*92*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*93*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*94*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*95*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*96*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },
/*97*/	{ "xchg",  false, LONG,  op2(A, Ri),  null },

/*98*/	{ "cbw",   false, SDEP,  0,	      i_extras:"cwde" },	/* cbw/cwde */
/*99*/	{ "cwd",   false, SDEP,  0,	      i_extras:"cdq" },	/* cwd/cdq */
/*9a*/	{ "lcall", false, NONE,  op1(OS),     null },
/*9b*/	{ "wait",  false, NONE,  0,	      null },
/*9c*/	{ "pushf", false, LONG,  0,	      null },
/*9d*/	{ "popf",  false, LONG,  0,	      null },
/*9e*/	{ "sahf",  false, NONE,  0,	      null },
/*9f*/	{ "lahf",  false, NONE,  0,	      null },

/*a0*/	{ "mov",   false, BYTE,  op2(O, A),   null },
/*a1*/	{ "mov",   false, LONG,  op2(O, A),   null },
/*a2*/	{ "mov",   false, BYTE,  op2(A, O),   null },
/*a3*/	{ "mov",   false, LONG,  op2(A, O),   null },
/*a4*/	{ "movs",  false, BYTE,  op2(SI,DI),  null },
/*a5*/	{ "movs",  false, LONG,  op2(SI,DI),  null },
/*a6*/	{ "cmps",  false, BYTE,  op2(SI,DI),  null },
/*a7*/	{ "cmps",  false, LONG,  op2(SI,DI),  null },

/*a8*/	{ "test",  false, BYTE,  op2(I, A),   null },
/*a9*/	{ "test",  false, LONG,  op2(I, A),   null },
/*aa*/	{ "stos",  false, BYTE,  op1(DI),     null },
/*ab*/	{ "stos",  false, LONG,  op1(DI),     null },
/*ac*/	{ "lods",  false, BYTE,  op1(SI),     null },
/*ad*/	{ "lods",  false, LONG,  op1(SI),     null },
/*ae*/	{ "scas",  false, BYTE,  op1(SI),     null },
/*af*/	{ "scas",  false, LONG,  op1(SI),     null },

/*b0*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b1*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b2*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b3*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b4*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b5*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b6*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },
/*b7*/	{ "mov",   false, BYTE,  op2(I, Ri),  null },

/*b8*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*b9*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*ba*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*bb*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*bc*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*bd*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*be*/	{ "mov",   false, LONG,  op2(I, Ri),  null },
/*bf*/	{ "mov",   false, LONG,  op2(I, Ri),  null },

/*c0*/	{ "",	   true,  BYTE,  op2(Ib, E),  i_extrat:&db_Grp2[0] },
/*c1*/	{ "",	   true,  LONG,  op2(Ib, E),  i_extrat:&db_Grp2[0] },
/*c2*/	{ "ret",   false, NONE,  op1(Iw),     null },
/*c3*/	{ "ret",   false, NONE,  0,	      null },
/*c4*/	{ "les",   true,  LONG,  op2(E, R),   null },
/*c5*/	{ "lds",   true,  LONG,  op2(E, R),   null },
/*c6*/	{ "mov",   true,  BYTE,  op2(I, E),   null },
/*c7*/	{ "mov",   true,  LONG,  op2(I, E),   null },

/*c8*/	{ "enter", false, NONE,  op2(Iw, Ib), null },
/*c9*/	{ "leave", false, NONE,  0,           null },
/*ca*/	{ "lret",  false, NONE,  op1(Iw),     null },
/*cb*/	{ "lret",  false, NONE,  0,	      null },
/*cc*/	{ "int",   false, NONE,  op1(o3),     null },
/*cd*/	{ "int",   false, NONE,  op1(Ib),     null },
/*ce*/	{ "into",  false, NONE,  0,	      null },
/*cf*/	{ "iret",  false, NONE,  0,	      null },

/*d0*/	{ "",	   true,  BYTE,  op2(o1, E),  i_extrat:&db_Grp2[0] },
/*d1*/	{ "",	   true,  LONG,  op2(o1, E),  i_extrat:&db_Grp2[0] },
/*d2*/	{ "",	   true,  BYTE,  op2(CL, E),  i_extrat:&db_Grp2[0] },
/*d3*/	{ "",	   true,  LONG,  op2(CL, E),  i_extrat:&db_Grp2[0] },
/*d4*/	{ "aam",   false, NONE,  op1(Iba),    null },
/*d5*/	{ "aad",   false, NONE,  op1(Iba),    null },
/*d6*/	{ ".byte\t0xd6", false, NONE, 0,      null },
/*d7*/	{ "xlat",  false, BYTE,  op1(BX),     null },

/*d8*/  { "",      true,  NONE,  0,	      i_extraf:&db_Esc8[0] },
/*d9*/  { "",      true,  NONE,  0,	      i_extraf:&db_Esc9[0] },
/*da*/  { "",      true,  NONE,  0,	      i_extraf:&db_Esca[0] },
/*db*/  { "",      true,  NONE,  0,	      i_extraf:&db_Escb[0] },
/*dc*/  { "",      true,  NONE,  0,	      i_extraf:&db_Escc[0] },
/*dd*/  { "",      true,  NONE,  0,	      i_extraf:&db_Escd[0] },
/*de*/  { "",      true,  NONE,  0,	      i_extraf:&db_Esce[0] },
/*df*/  { "",      true,  NONE,  0,	      i_extraf:&db_Escf[0] },

/*e0*/	{ "loopne",false, NONE,  op1(Db),     null },
/*e1*/	{ "loope", false, NONE,  op1(Db),     null },
/*e2*/	{ "loop",  false, NONE,  op1(Db),     null },
/*e3*/	{ "jcxz",  false, SDEP,  op1(Db),     i_extras:"jecxz" },
/*e4*/	{ "in",    false, BYTE,  op2(Ib, A),  null },
/*e5*/	{ "in",    false, LONG,  op2(Ib, A) , null },
/*e6*/	{ "out",   false, BYTE,  op2(A, Ib),  null },
/*e7*/	{ "out",   false, LONG,  op2(A, Ib) , null },

/*e8*/	{ "call",  false, NONE,  op1(Dl),     null },
/*e9*/	{ "jmp",   false, NONE,  op1(Dl),     null },
/*ea*/	{ "ljmp",  false, NONE,  op1(OS),     null },
/*eb*/	{ "jmp",   false, NONE,  op1(Db),     null },
/*ec*/	{ "in",    false, BYTE,  op2(DX, A),  null },
/*ed*/	{ "in",    false, LONG,  op2(DX, A) , null },
/*ee*/	{ "out",   false, BYTE,  op2(A, DX),  null },
/*ef*/	{ "out",   false, LONG,  op2(A, DX) , null },

/*f0*/	{ "",      false, NONE,  0,	     null },
/*f1*/	{ ".byte\t0xf1", false, NONE, 0,     null },
/*f2*/	{ "",      false, NONE,  0,	     null },
/*f3*/	{ "",      false, NONE,  0,	     null },
/*f4*/	{ "hlt",   false, NONE,  0,	     null },
/*f5*/	{ "cmc",   false, NONE,  0,	     null },
/*f6*/	{ "",      true,  BYTE,  0,	     i_extrai:&db_Grp3[0] },
/*f7*/	{ "",	   true,  LONG,  0,	     i_extrai:&db_Grp3[0] },

/*f8*/	{ "clc",   false, NONE,  0,	     null },
/*f9*/	{ "stc",   false, NONE,  0,	     null },
/*fa*/	{ "cli",   false, NONE,  0,	     null },
/*fb*/	{ "sti",   false, NONE,  0,	     null },
/*fc*/	{ "cld",   false, NONE,  0,	     null },
/*fd*/	{ "std",   false, NONE,  0,	     null },
/*fe*/	{ "",	   true,  NONE,  0,	     i_extrai:&db_Grp4[0] },
/*ff*/	{ "",	   true,  NONE,  0,	     i_extrai:&db_Grp5[0] },
];

static instT db_bad_inst =
	{ "???",   false, NONE,  0,	      null };

int f_mod(int b)	{ return b>>6; }
int f_reg(int b)	{ return (b>>3) & 0x7; }
int f_rm(int b)		{ return b & 0x7; }

int sib_ss(int b)	{ return b>>6; }
int sib_index(int b)	{ return (b>>3) & 0x7; }
int sib_base(int b)	{ return b & 0x7; }

struct i_addr {
    int		is_reg;	/* if reg, reg number is in 'disp' */
    int		disp;
    string	base;
    string	index;
    int		ss;
};

static string db_index_reg_16[8] = [
	"%bx,%si",
	"%bx,%di",
	"%bp,%si",
	"%bp,%di",
	"%si",
	"%di",
	"%bp",
	"%bx"
];

static string db_reg[3][8] = [
	[ "%al",  "%cl",  "%dl",  "%bl",  "%ah",  "%ch",  "%dh",  "%bh" ],
	[ "%ax",  "%cx",  "%dx",  "%bx",  "%sp",  "%bp",  "%si",  "%di" ],
	[ "%eax", "%ecx", "%edx", "%ebx", "%esp", "%ebp", "%esi", "%edi" ]
];

static string db_seg_reg[8] = [
	"%es", "%cs", "%ss", "%ds", "%fs", "%gs", "", ""
];

/*
 * lengths for size attributes
 */
static int db_lengths[] = [
	1,	/* BYTE */
	2,	/* WORD */
	4,	/* LONG */
	8,	/* QUAD */
	4,	/* SNGL */
	8,	/* DBLR */
	10,	/* EXTR */
];


/*
#define	get_value_inc(result, loc, size, is_signed) \
	result = db_get_value((loc), (size), (is_signed)); \
	(loc) += (size);
*/

ulong
readUnsigned(ubyte[] bytes)
{
    uint bit = 0;
    ulong value = 0;

    foreach (b; bytes) {
	value |= b << bit;
	bit += 8;
    }
    return value;
}

long
readSigned(ubyte[] bytes)
{
    uint bit = 0;
    long value = 0;

    foreach (b; bytes) {
	value |= b << bit;
	bit += 8;
    }
    if (bytes[bytes.length - 1] & 0x80)
	value |= -(1 << bit);
    return value;
}



/**
 * Disassemble instruction at 'loc'. Return address of start of next
 * instruction.
 */
static string
db_disasm(MachineState state, ref ulong loc,
	  string delegate(ulong) lookupAddress)
{
    string	res = "";
    int		inst;
    int		size;
    bool	short_addr;
    string	seg;
    instT*	ip;
    string	i_name;
    int		i_size;
    int		i_mode;
    int		regmodrm = 0;
    bool	first;
    int		displ;
    int		prefix;
    int		rep;
    int		imm;
    int		imm2;
    int		len;
    i_addr	address;

    int get_value_inc(uint size, bool is_signed)
    {
	ubyte[] mem = state.readMemory(loc, size);
	loc += size;
	return is_signed ? readSigned(mem) : readUnsigned(mem);
    }

    /*
     * Read address at location and return updated location.
     */
    ulong db_read_address(bool short_addr, int regmodrm, out i_addr addr)
    {
	int	mod, rm, sib, index, disp;

	mod = f_mod(regmodrm);
	rm  = f_rm(regmodrm);

	if (mod == 3) {
	    addr.is_reg = true;
	    addr.disp = rm;
	    return (loc);
	}
	addr.is_reg = false;
	addr.index = null;

	if (short_addr) {
	    addr.index = null;
	    addr.ss = 0;
	    switch (mod) {
	    case 0:
		if (rm == 6) {
		    disp = get_value_inc(2, false);
		    addr.disp = disp;
		    addr.base = null;
		}
		else {
		    addr.disp = 0;
		    addr.base = db_index_reg_16[rm];
		}
		break;
	    case 1:
		disp = get_value_inc(1, true);
		disp &= 0xFFFF;
		addr.disp = disp;
		addr.base = db_index_reg_16[rm];
		break;
	    case 2:
		disp = get_value_inc(2, false);
		addr.disp = disp;
		addr.base = db_index_reg_16[rm];
		break;
	    }
	}
	else {
	    if (mod != 3 && rm == 4) {
		sib = get_value_inc(1, false);
		rm = sib_base(sib);
		index = sib_index(sib);
		if (index != 4)
		    addr.index = db_reg[LONG][index];
		addr.ss = sib_ss(sib);
	    }

	    switch (mod) {
	    case 0:
		if (rm == 5) {
		    addr.disp = get_value_inc(4, false);
		    addr.base = null;
		}
		else {
		    addr.disp = 0;
		    addr.base = db_reg[LONG][rm];
		}
		break;

	    case 1:
		disp = get_value_inc(1, true);
		addr.disp = disp;
		addr.base = db_reg[LONG][rm];
		break;

	    case 2:
		disp = get_value_inc(4, false);
		addr.disp = disp;
		addr.base = db_reg[LONG][rm];
		break;
	    }
	}
	return (loc);
    }

    string db_print_address(string seg, int size, i_addr* addrp)
    {
	string res = "";

	if (addrp.is_reg) {
	    return db_reg[size][addrp.disp];
	}

	if (seg) {
	    res = seg ~ ":";
	}

	res ~= lookupAddress(addrp.disp);
	if (addrp.base || addrp.index) {
	    res ~= "(";
	    if (addrp.base)
		res ~= std.string.format("%s", addrp.base);
	    if (addrp.index)
		res ~= std.string.format(",%s,%d", addrp.index, 1<<addrp.ss);
	    res ~= ")";
	}
	return res;
    }
    /*
     * Disassemble floating-point ("escape") instruction
     */
    string db_disasm_esc(int inst, bool short_addr, int size, string seg)
    {
	string	res = "";
	int		regmodrm;
	finstT*	fp;
	int		mod;
	i_addr	address;
	string	name;

	regmodrm = get_value_inc(1, false);
	fp = &db_Esc_inst[inst - 0xd8][f_reg(regmodrm)];
	mod = f_mod(regmodrm);
	if (mod != 3) {
	    if (*fp.f_name == '\0') {
		res ~= std.string.format("<bad instruction>");
		return (res);
	    }
	    /*
	     * Normal address modes.
	     */
	    loc = db_read_address(short_addr, regmodrm, address);
	    res ~= std.string.format("%s", fp.f_name);
	    switch(fp.f_size) {
	    case SNGL:
		res ~= std.string.format("s");
		break;
	    case DBLR:
		res ~= std.string.format("l");
		break;
	    case EXTR:
		res ~= std.string.format("t");
		break;
	    case WORD:
		res ~= std.string.format("s");
		break;
	    case LONG:
		res ~= std.string.format("l");
		break;
	    case QUAD:
		res ~= std.string.format("q");
		break;
	    default:
		break;
	    }
	    res ~= std.string.format("\t");
	    res ~= db_print_address(seg, BYTE, &address);
	}
	else {
	    /*
	     * 'reg-reg' - special formats
	     */
	    switch (fp.f_rrmode) {
	    case op2(ST,STI):
		name = (fp.f_rrname) ? fp.f_rrname : fp.f_name;
		res ~= std.string.format("%s\t%%st,%%st(%d)",name,f_rm(regmodrm));
		break;
	    case op2(STI,ST):
		name = (fp.f_rrname) ? fp.f_rrname : fp.f_name;
		res ~= std.string.format("%s\t%%st(%d),%%st",name, f_rm(regmodrm));
		break;
	    case op1(STI):
		name = (fp.f_rrname) ? fp.f_rrname : fp.f_name;
		res ~= std.string.format("%s\t%%st(%d)",name, f_rm(regmodrm));
		break;
	    case op1(X):
		name = fp.f_rrnames[f_rm(regmodrm)];
		if (*name == '\0')
		    goto bad;
		res ~= std.string.format("%s", name);
		break;
	    case op1(XA):
		name = fp.f_rrnames[f_rm(regmodrm)];
		if (*name == '\0')
		    goto bad;
		res ~= std.string.format("%s\t%%ax", name);
		break;
	    default:
	    bad:
		res ~= std.string.format("<bad instruction>");
		break;
	    }
	}

	return (res);
    }
    inst = get_value_inc(1, false);
    short_addr = false;
    size = LONG;
    seg = null;

    /*
     * Get prefixes
     */
    rep = false;
    prefix = true;
    do {
	switch (inst) {
	case 0x66:		/* data16 */
	    size = WORD;
	    break;
	case 0x67:
	    short_addr = true;
	    break;
	case 0x26:
	    seg = "%es";
	    break;
	case 0x36:
	    seg = "%ss";
	    break;
	case 0x2e:
	    seg = "%cs";
	    break;
	case 0x3e:
	    seg = "%ds";
	    break;
	case 0x64:
	    seg = "%fs";
	    break;
	case 0x65:
	    seg = "%gs";
	    break;
	case 0xf0:
	    res ~= std.string.format("lock ");
	    break;
	case 0xf2:
	    res ~= std.string.format("repne ");
	    break;
	case 0xf3:
	    rep = true;
	    break;
	default:
	    prefix = false;
	    break;
	}
	if (prefix) {
	    inst = get_value_inc(1, false);
	}
	if (rep == true) {
	    if (inst == 0x90) {
		res ~= std.string.format("pause\n");
		return (res);
	    }
	    res ~= std.string.format("repe ");	/* XXX repe VS rep */
	    rep = false;
	}
    } while (prefix);

    if (inst >= 0xd8 && inst <= 0xdf) {
	res = db_disasm_esc(inst, short_addr, size, seg);
	return (res);
    }

    if (inst == 0x0f) {
	inst = get_value_inc(1, false);
	ip = db_inst_0f[inst>>4];
	if (ip == null) {
	    ip = &db_bad_inst;
	}
	else {
	    ip = &ip[inst&0xf];
	}
    }
    else
	ip = &db_inst_table[inst];

    if (ip.i_has_modrm) {
	regmodrm = get_value_inc(1, false);
	loc = db_read_address(short_addr, regmodrm, address);
    }

    i_name = ip.i_name;
    i_size = ip.i_size;
    i_mode = ip.i_mode;

    if (ip.i_extrat == &db_Grp1[0] || ip.i_extrat == &db_Grp2[0] ||
	ip.i_extrat == &db_Grp6[0] || ip.i_extrat == &db_Grp7[0] ||
	ip.i_extrat == &db_Grp8[0] || ip.i_extrat == &db_Grp9[0] ||
	ip.i_extrat == &db_Grp15[0]) {
	i_name = ip.i_extrat[f_reg(regmodrm)];
    }
    else if (ip.i_extrai == &db_Grp3[0]) {
	ip = ip.i_extrai;
	ip = &ip[f_reg(regmodrm)];
	i_name = ip.i_name;
	i_mode = ip.i_mode;
    }
    else if (ip.i_extrai == &db_Grp4[0] || ip.i_extrai == &db_Grp5[0]) {
	ip = ip.i_extrai;
	ip = &ip[f_reg(regmodrm)];
	i_name = ip.i_name;
	i_mode = ip.i_mode;
	i_size = ip.i_size;
    }

    /* Special cases that don't fit well in the tables. */
    if (ip.i_extrat == &db_Grp7[0] && f_mod(regmodrm) == 3) {
	switch (regmodrm) {
	case 0xc8:
	    i_name = "monitor";
	    i_size = NONE;
	    i_mode = 0;			
	    break;
	case 0xc9:
	    i_name = "mwait";
	    i_size = NONE;
	    i_mode = 0;
	    break;
	}
    }
    if (ip.i_extrat == &db_Grp15[0] && f_mod(regmodrm) == 3) {
	i_name = db_Grp15b[f_reg(regmodrm)];
	i_size = NONE;
	i_mode = 0;
    }

    if (i_size == SDEP) {
	if (size == WORD)
	    res ~= std.string.format("%s", i_name);
	else
	    res ~= std.string.format("%s", ip.i_extras);
    }
    else {
	res ~= std.string.format("%s", i_name);
	if (i_size != NONE) {
	    if (i_size == BYTE) {
		res ~= std.string.format("b");
		size = BYTE;
	    }
	    else if (i_size == WORD) {
		res ~= std.string.format("w");
		size = WORD;
	    }
	    else if (size == WORD)
		res ~= std.string.format("w");
	    else
		res ~= std.string.format("l");
	}
    }
    res ~= std.string.format("\t");
    for (first = true;
	 i_mode != 0;
	 i_mode >>= 8, first = false)
    {
	if (!first)
	    res ~= std.string.format(",");

	switch (i_mode & 0xFF) {

	case E:
	    res ~= db_print_address(seg, size, &address);
	    break;

	case Eind:
	    res ~= std.string.format("*");
	    res ~= db_print_address(seg, size, &address);
	    break;

	case El:
	    res ~= db_print_address(seg, LONG, &address);
	    break;

	case Ew:
	    res ~= db_print_address(seg, WORD, &address);
	    break;

	case Eb:
	    res ~= db_print_address(seg, BYTE, &address);
	    break;

	case R:
	    res ~= std.string.format("%s", db_reg[size][f_reg(regmodrm)]);
	    break;

	case Rw:
	    res ~= std.string.format("%s", db_reg[WORD][f_reg(regmodrm)]);
	    break;

	case Ri:
	    res ~= std.string.format("%s", db_reg[size][f_rm(inst)]);
	    break;

	case Ril:
	    res ~= std.string.format("%s", db_reg[LONG][f_rm(inst)]);
	    break;

	case S:
	    res ~= std.string.format("%s", db_seg_reg[f_reg(regmodrm)]);
	    break;

	case Si:
	    res ~= std.string.format("%s", db_seg_reg[f_reg(inst)]);
	    break;

	case A:
	    res ~= std.string.format("%s", db_reg[size][0]);	/* acc */
	    break;

	case BX:
	    if (seg)
		res ~= std.string.format("%s:", seg);
	    res ~= std.string.format("(%s)", short_addr ? "%bx" : "%ebx");
	    break;

	case CL:
	    res ~= std.string.format("%%cl");
	    break;

	case DX:
	    res ~= std.string.format("%%dx");
	    break;

	case SI:
	    if (seg)
		res ~= std.string.format("%s:", seg);
	    res ~= std.string.format("(%s)", short_addr ? "%si" : "%esi");
	    break;

	case DI:
	    res ~= std.string.format("%%es:(%s)", short_addr ? "%di" : "%edi");
	    break;

	case CR:
	    res ~= std.string.format("%%cr%d", f_reg(regmodrm));
	    break;

	case DR:
	    res ~= std.string.format("%%dr%d", f_reg(regmodrm));
	    break;

	case TR:
	    res ~= std.string.format("%%tr%d", f_reg(regmodrm));
	    break;

	case I:
	    len = db_lengths[size];
	    imm = get_value_inc(len, false);
	    res ~= std.string.format("$%#r", imm);
	    break;

	case Is:
	    len = db_lengths[size];
	    imm = get_value_inc(len, false);
	    res ~= std.string.format("$%+#r", imm);
	    break;

	case Ib:
	    imm = get_value_inc(1, false);
	    res ~= std.string.format("$%#r", imm);
	    break;

	case Iba:
	    imm = get_value_inc(1, false);
	    if (imm != 0x0a)
		res ~= std.string.format("$%#r", imm);
	    break;

	case Ibs:
	    imm = get_value_inc(1, true);
	    if (size == WORD)
		imm &= 0xFFFF;
	    res ~= std.string.format("$%+#r", imm);
	    break;

	case Iw:
	    imm = get_value_inc(2, false);
	    res ~= std.string.format("$%#r", imm);
	    break;

	case O:
	    len = (short_addr ? 2 : 4);
	    displ = get_value_inc(len, false);
	    if (seg)
		res ~= std.string.format("%s:%+#r",seg, displ);
	    else
		res ~= lookupAddress(displ);
	    break;

	case Db:
	    displ = get_value_inc(1, true);
	    displ += loc;
	    if (size == WORD)
		displ &= 0xFFFF;
	    res ~= lookupAddress(displ);
	    break;

	case Dl:
	    len = db_lengths[size];
	    displ = get_value_inc(len, false);
	    displ += loc;
	    if (size == WORD)
		displ &= 0xFFFF;
	    res ~= lookupAddress(displ);
	    break;

	case o1:
	    res ~= std.string.format("$1");
	    break;

	case o3:
	    res ~= std.string.format("$3");
	    break;

	case OS:
	    len = db_lengths[size];
	    imm = get_value_inc(len, false);	/* offset */
	    imm2 = get_value_inc(2, false);	/* segment */
	    res ~= std.string.format("$%#r,%#r", imm2, imm);
	    break;
	}
    }
    return (res);
}
