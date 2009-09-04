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
/*-
 * Copyright (c) 1998 John D. Polstra.
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

module objfile.elf;

//debug = elf;

import std.stdint;

version (GDC)
import std.c.unix.unix;
else
import std.c.posix.posix;
import std.c.string;

import endian;
import target.target;
import objfile.objfile;
import machine.machine;
import machine.x86;
import machine.arm;

struct Note {
    uint32_t	n_namesz;
    uint32_t	n_descsz;
    uint32_t	n_type;
}

struct Ident {
    uint8_t	ei_magic[4];	// Magic number 0x7f, 'E', 'L', 'F'
    uint8_t	ei_class;	// Machine class
    uint8_t	ei_data;	// Data formant
    uint8_t	ei_version;	// ELF format version
    uint8_t	ei_osabi;	// OS / ABI identification
    uint8_t	ei_abiversion;	// ABI version
    uint8_t	ei_pad[7];	// pad to 16 bytes
}

bool IsElf(Ident* i)
{
    return i.ei_magic[0] == 0x7f
	&& i.ei_magic[1] == 'E'
	&& i.ei_magic[2] == 'L'
	&& i.ei_magic[3] == 'F';
}

// Values for Ident.ei_version
enum {
    EV_NONE = 0,
    EV_CURRENT = 1,
}

// Values for Ident.ei_class
enum {
    ELFCLASSNONE = 0,		// Unknown class
    ELFCLASS32 = 1,		// 32-bit architecture
    ELFCLASS64 = 2		// 64-bit architecture
}

// Values for Ident.ei_data
enum {
    ELFDATANONE = 0,		// Unknown data formst
    ELFDATA2LSB = 1,		// 2's complement little-endian
    ELFDATA2MSB = 2		// 2's complement big-endian
}

// Values for Ident.ei_osabi
enum {
    ELFOSABI_NONE = 0,		// UNIX System V ABI
    ELFOSABI_HPUX = 1,		// HP-UX operating system
    ELFOSABI_NETBSD = 2,	// NetBSD
    ELFOSABI_LINUX = 3,		// GNU/Linux
    ELFOSABI_HURD = 4,		// GNU/Hurd
    ELFOSABI_86OPEN = 5,	// 86Open common IA32 ABI
    ELFOSABI_SOLARIS = 6,	// Solaris
    ELFOSABI_AIX = 7,		// AIX
    ELFOSABI_IRIX = 8,		// IRIX
    ELFOSABI_FREEBSD = 9,	// FreeBSD
    ELFOSABI_TRU64 = 10,	// TRU64 UNIX
    ELFOSABI_MODESTO = 11,	// Novell Modesto
    ELFOSABI_OPENBSD = 12,	// OpenBSD
    ELFOSABI_OPENVMS = 13,	// Open VMS
    ELFOSABI_NSK = 14,		// HP Non-Stop Kernel
    ELFOSABI_ARM = 97,		// ARM
    ELFOSABI_STANDALONE = 255	// Standalone (embedded) application
}

// Values for e_type.
enum {
    ET_NONE = 0,		// Unknown type.
    ET_REL = 1,			// Relocatable.
    ET_EXEC = 2,		// Executable.
    ET_DYN = 3,			// Shared object.
    ET_CORE = 4,		// Core file.
    ET_LOOS = 0xfe00,		// First operating system specific.
    ET_HIOS = 0xfeff,		// Last operating system-specific.
    ET_LOPROC = 0xff00,		// First processor-specific.
    ET_HIPROC = 0xffff,		// Last processor-specific.
}

// Values for e_machine.
enum {
    EM_NONE = 0,	     // Unknown machine.
    EM_M32 = 1,		     // AT&T WE32100.
    EM_SPARC = 2,	     // Sun SPARC.
    EM_386 = 3,		     // Intel i386.
    EM_68K = 4,		     // Motorola 68000.
    EM_88K = 5,		     // Motorola 88000.
    EM_860 = 7,		     // Intel i860.
    EM_MIPS = 8,	     // MIPS R3000 Big-Endian only.
    EM_S370 = 9,	     // IBM System/370.
    EM_MIPS_RS3_LE = 10,     // MIPS R3000 Little-Endian.
    EM_PARISC = 15,	     // HP PA-RISC.
    EM_VPP500 = 17,	     // Fujitsu VPP500.
    EM_SPARC32PLUS = 18,     // SPARC v8plus.
    EM_960 = 19,	     // Intel 80960.
    EM_PPC = 20,	     // PowerPC 32-bit.
    EM_PPC64 = 21,	     // PowerPC 64-bit.
    EM_S390 = 22,	     // IBM System/390.
    EM_V800 = 36,	     // NEC V800.
    EM_FR20 = 37,	     // Fujitsu FR20.
    EM_RH32 = 38,	     // TRW RH-32.
    EM_RCE = 39,	     // Motorola RCE.
    EM_ARM = 40,	     // ARM.
    EM_SH = 42,		     // Hitachi SH.
    EM_SPARCV9 = 43,	     // SPARC v9 64-bit.
    EM_TRICORE = 44,	     // Siemens TriCore embedded processor.
    EM_ARC = 45,	     // Argonaut RISC Core.
    EM_H8_300 = 46,	     // Hitachi H8/300.
    EM_H8_300H = 47,	     // Hitachi H8/300H.
    EM_H8S = 48,	     // Hitachi H8S.
    EM_H8_500 = 49,	     // Hitachi H8/500.
    EM_IA_64 = 50,	     // Intel IA-64 Processor.
    EM_MIPS_X = 51,	     // Stanford MIPS-X.
    EM_COLDFIRE = 52,	     // Motorola ColdFire.
    EM_68HC12 = 53,	     // Motorola M68HC12.
    EM_MMA = 54,	     // Fujitsu MMA.
    EM_PCP = 55,	     // Siemens PCP.
    EM_NCPU = 56,	     // Sony nCPU.
    EM_NDR1 = 57,	     // Denso NDR1 microprocessor.
    EM_STARCORE = 58,	     // Motorola Star*Core processor.
    EM_ME16 = 59,	     // Toyota ME16 processor.
    EM_ST100 = 60,	     // STMicroelectronics ST100 processor.
    EM_TINYJ = 61,	     // Advanced Logic Corp. TinyJ processor.
    EM_X86_64 = 62,	     // Advanced Micro Devices x86-64
    EM_AMD64 =	EM_X86_64,   // Advanced Micro Devices x86-64 (compat)

    // Non-standard or deprecated.
    EM_486 = 6,		   // Intel i486.
    EM_MIPS_RS4_BE = 10,   // MIPS R4000 Big-Endian
    EM_ALPHA_STD = 41,	   // Digital Alpha (standard value).
    EM_ALPHA = 0x9026,	   // Alpha (written in the absence of an ABI)
}

// Special section indexes.
enum {
    SHN_UNDEF = 0,		// Undefined, missing, irrelevant.
    SHN_LORESERVE = 0xff00,	// First of reserved range.
    SHN_LOPROC = 0xff00,	// First processor-specific.
    SHN_HIPROC = 0xff1f,	// Last processor-specific.
    SHN_LOOS = 0xff20,		// First operating system-specific.
    SHN_HIOS = 0xff3f,		// Last operating system-specific.
    SHN_ABS = 0xfff1,		// Absolute values.
    SHN_COMMON = 0xfff2,	// Common data.
    SHN_XINDEX = 0xffff,	// Escape -- index stored elsewhere.
    SHN_HIRESERVE = 0xffff,	// Last of reserved range.
}

// sh_type
enum {
    SHT_NULL = 0,		// inactive
    SHT_PROGBITS = 1,		// program defined information
    SHT_SYMTAB = 2,		// symbol table section
    SHT_STRTAB = 3,		// string table section
    SHT_RELA = 4,		// relocation section with addends
    SHT_HASH = 5,		// symbol hash table section
    SHT_DYNAMIC = 6,		// dynamic section 
    SHT_NOTE = 7,		// note section
    SHT_NOBITS = 8,		// no space section
    SHT_REL = 9,		// relocation section - no addends
    SHT_SHLIB = 10,		// reserved - purpose unknown
    SHT_DYNSYM = 11,		// dynamic symbol table section 
    SHT_INIT_ARRAY = 14,	// Initialization function pointers.
    SHT_FINI_ARRAY = 15,	// Termination function pointers.
    SHT_PREINIT_ARRAY = 16,	// Pre-initialization function ptrs.
    SHT_GROUP = 17,		// Section group.
    SHT_SYMTAB_SHNDX = 18,	// Section indexes (see SHN_XINDEX).
    SHT_LOOS = 0x60000000,	// First of OS specific semantics
    SHT_LOSUNW = 0x6ffffff4,
    SHT_SUNW_dof = 0x6ffffff4,
    SHT_SUNW_cap = 0x6ffffff5,
    SHT_SUNW_SIGNATURE = 0x6ffffff6,
    SHT_SUNW_ANNOTATE = 0x6ffffff7,
    SHT_SUNW_DEBUGSTR = 0x6ffffff8,
    SHT_SUNW_DEBUG = 0x6ffffff9,
    SHT_SUNW_move = 0x6ffffffa,
    SHT_SUNW_COMDAT = 0x6ffffffb,
    SHT_SUNW_syminfo = 0x6ffffffc,
    SHT_SUNW_verdef = 0x6ffffffd,
    SHT_GNU_verdef = 0x6ffffffd, // Symbol versions provided
    SHT_SUNW_verneed = 0x6ffffffe,
    SHT_GNU_verneed = 0x6ffffffe, // Symbol versions required
    SHT_SUNW_versym = 0x6fffffff,
    SHT_GNU_versym = 0x6fffffff, // Symbol version table
    SHT_HISUNW = 0x6fffffff,
    SHT_HIOS = 0x6fffffff,	   // Last of OS specific semantics
    SHT_LOPROC = 0x70000000,	   // reserved range for processor
    SHT_AMD64_UNWIND = 0x70000001, // unwind information
    SHT_HIPROC = 0x7fffffff,	   // specific section header types
    SHT_LOUSER = 0x80000000,	   // reserved range for application
    SHT_HIUSER = 0xffffffff,	   // specific indexes
}

// Flags for sh_flags.
enum {
    SHF_WRITE = 0x1,		  // Section contains writable data.
    SHF_ALLOC = 0x2,		  // Section occupies memory.
    SHF_EXECINSTR = 0x4,	  // Section contains instructions.
    SHF_MERGE = 0x10,		  // Section may be merged.
    SHF_STRINGS = 0x20,		  // Section contains strings.
    SHF_INFO_LINK = 0x40,	  // sh_info holds section index.
    SHF_LINK_ORDER = 0x80,	  // Special ordering requirements.
    SHF_OS_NONCONFORMING = 0x100, // OS-specific processing required.
    SHF_GROUP = 0x200,		  // Member of section group.
    SHF_TLS = 0x400,		  // Section contains TLS data.
    SHF_MASKOS = 0x0ff00000,	  // OS-specific semantics.
    SHF_MASKPROC = 0xf0000000,	  // Processor-specific semantics.
}

// Values for p_type.
enum {
    PT_NULL = 0,	       // Unused entry.
    PT_LOAD = 1,	       // Loadable segment.
    PT_DYNAMIC = 2,	       // Dynamic linking information segment.
    PT_INTERP = 3,	       // Pathname of interpreter.
    PT_NOTE = 4,	       // Auxiliary information.
    PT_SHLIB = 5,	       // Reserved (not used).
    PT_PHDR = 6,	       // Location of program header itself.
    PT_TLS = 7,		       // Thread local storage segment
    PT_LOOS = 0x60000000,      // First OS-specific.
    PT_SUNW_UNWIND = 0x6464e550, // amd64 UNWIND program header
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_LOSUNW = 0x6ffffffa,
    PT_SUNWBSS = 0x6ffffffa,	// Sun Specific segment
    PT_SUNWSTACK = 0x6ffffffb,	// describes the stack segment
    PT_SUNWDTRACE = 0x6ffffffc,	// private
    PT_SUNWCAP = 0x6ffffffd,	// hard/soft capabilities segment
    PT_HISUNW = 0x6fffffff,
    PT_HIOS = 0x6fffffff,	// Last OS-specific.
    PT_LOPROC = 0x70000000,	// First processor-specific type.
    PT_HIPROC = 0x7fffffff,	// Last processor-specific type.
}

// Values for p_flags.
enum {
    PF_X = 0x1,			// Executable.
    PF_W = 0x2,			// Writable.
    PF_R = 0x4,			// Readable.
    PF_MASKOS = 0x0ff00000,	// Operating system-specific.
    PF_MASKPROC = 0xf0000000,	// Processor-specific.
}

// Extended program header index.
const int PN_XNUM = 0xffff;

// Values for d_tag.
enum {
    DT_NULL = 0,	// Terminating entry.
    DT_NEEDED = 1,	// String table offset of a needed shared library.
    DT_PLTRELSZ = 2,	// Total size in bytes of PLT relocations.
    DT_PLTGOT = 3,	// Processor-dependent address.
    DT_HASH = 4,	// Address of symbol hash table.
    DT_STRTAB = 5,	// Address of string table.
    DT_SYMTAB = 6,	// Address of symbol table.
    DT_RELA = 7,	// Address of ElfNN_Rela relocations.
    DT_RELASZ = 8,	// Total size of ElfNN_Rela relocations.
    DT_RELAENT = 9,	// Size of each ElfNN_Rela relocation entry.
    DT_STRSZ = 10,	// Size of string table.
    DT_SYMENT = 11,	// Size of each symbol table entry.
    DT_INIT = 12,	// Address of initialization function.
    DT_FINI = 13,	// Address of finalization function.
    DT_SONAME = 14,	// String table offset of shared object name.
    DT_RPATH = 15,	// String table offset of library path. [sup]
    DT_SYMBOLIC = 16,	// Indicates "symbolic" linking. [sup]
    DT_REL = 17,	// Address of ElfNN_Rel relocations.
    DT_RELSZ = 18,	// Total size of ElfNN_Rel relocations.
    DT_RELENT = 19,	// Size of each ElfNN_Rel relocation.
    DT_PLTREL = 20,	// Type of relocation used for PLT.
    DT_DEBUG = 21,	// Reserved (not used).
    DT_TEXTREL = 22,	// Indicates there may be relocations in
			// non-writable segments. [sup]
    DT_JMPREL = 23,	// Address of PLT relocations.
    DT_BIND_NOW = 24,	// [sup]
    DT_INIT_ARRAY = 25,	// Address of the array of pointers to
			// initialization functions
    DT_FINI_ARRAY = 26,	// Address of the array of pointers to
			// termination functions
    DT_INIT_ARRAYSZ = 27,  // Size in bytes of the array of
				// initialization functions.
    DT_FINI_ARRAYSZ = 28,	// Size in bytes of the array of
				// terminationfunctions.
    DT_RUNPATH = 29,   // String table offset of a null-terminated
				// library search path string.
    DT_FLAGS = 30,		// Object specific flag values.
    DT_ENCODING = 32,  // Values greater than or equal to DT_ENCODING
				// and less than DT_LOOS follow the rules for
				// the interpretation of the d_un union
				// as follows: even == 'd_ptr', even == 'd_val'
				// or none
    DT_PREINIT_ARRAY =32,	// Address of the array of pointers to
				// pre-initialization functions.
    DT_PREINIT_ARRAYSZ = 33,	// Size in bytes of the array of
				// pre-initialization functions.
    DT_MAXPOSTAGS = 34,		// number of positive tags
    DT_LOOS = 0x6000000d,	// First OS-specific
    DT_SUNW_AUXILIARY = 0x6000000d, // symbol auxiliary name
    DT_SUNW_RTLDINF = 0x6000000e,   // ld.so.1 info (private)
    DT_SUNW_FILTER = 0x6000000f,    // symbol filter name
    DT_SUNW_CAP = 0x60000010,	    // hardware/software
    DT_HIOS = 0x6ffff000,	    // Last OS-specific

				// DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use
				// the Dyn.d_un.d_val field of the Elf*_Dyn structure.

    DT_VALRNGLO = 0x6ffffd00,
    DT_CHECKSUM = 0x6ffffdf8,	// elf checksum
    DT_PLTPADSZ = 0x6ffffdf9,	// pltpadding size
    DT_MOVEENT = 0x6ffffdfa,	// move table entry size
    DT_MOVESZ = 0x6ffffdfb,	// move table size
    DT_FEATURE_1 = 0x6ffffdfc,	// feature holder
    DT_POSFLAG_1 = 0x6ffffdfd,	// flags for DT_* entries, effecting
				//	the following DT_* entry.
				//	See DF_P1_* definitions
    DT_SYMINSZ = 0x6ffffdfe,	// syminfo table size (in bytes)
    DT_SYMINENT = 0x6ffffdff,	// syminfo entry size (in bytes)
    DT_VALRNGHI = 0x6ffffdff,


// DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
// Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
//
// If any adjustment is made to the ELF object after it has been
// built, these entries will need to be adjusted.

    DT_ADDRRNGLO = 0x6ffffe00,
    DT_CONFIG = 0x6ffffefa,	// configuration information
    DT_DEPAUDIT = 0x6ffffefb,	// dependency auditing
    DT_AUDIT = 0x6ffffefc,	// object auditing
    DT_PLTPAD = 0x6ffffefd,	// pltpadding (sparcv9)
    DT_MOVETAB = 0x6ffffefe,	// move table
    DT_SYMINFO = 0x6ffffeff,	// syminfo table
    DT_ADDRRNGHI = 0x6ffffeff,

    DT_VERSYM = 0x6ffffff0,	// Address of versym section.
    DT_RELACOUNT = 0x6ffffff9,	// number of RELATIVE relocations
    DT_RELCOUNT = 0x6ffffffa,	// number of RELATIVE relocations
    DT_FLAGS_1 = 0x6ffffffb,	// state flags - see DF_1_* defs
    DT_VERDEF = 0x6ffffffc,	// Address of verdef section.
    DT_VERDEFNUM = 0x6ffffffd,	// Number of elems in verdef section
    DT_VERNEED = 0x6ffffffe,	// Address of verneed section.
    DT_VERNEEDNUM = 0x6fffffff,	// Number of elems in verneed section

    DT_LOPROC = 0x70000000,	// First processor-specific type.
    DT_DEPRECATED_SPARC_REGISTER = 0x7000001,
    DT_AUXILIARY = 0x7ffffffd,	// shared library auxiliary name
    DT_USED = 0x7ffffffe,	// ignored - same as needed
    DT_FILTER = 0x7fffffff,	// shared library filter name
    DT_HIPROC = 0x7fffffff,	// Last processor-specific type.

// Values for DT_FLAGS
    DF_ORIGIN = 0x0001,	 // Indicates that the object being loaded may
				// make reference to the $ORIGIN substitution
				// string
    DF_SYMBOLIC = 0x0002,	// Indicates "symbolic" linking.
    DF_TEXTREL = 0x0004,  // Indicates there may be relocations in
				// non-writable segments.
    DF_BIND_NOW = 0x0008, // Indicates that the dynamic linker should
				// process all relocations for the object
				// containing this entry before transferring
				// control to the program.
    DF_STATIC_TLS = 0x0010,	// Indicates that the shared object or
				// executable contains code using a static
				// thread-local storage scheme.
}

// Values for n_type.  Used in core files.
enum {
    NT_PRSTATUS = 1,		// Process status.
    NT_FPREGSET = 2,		// Floating point registers.
    NT_PRPSINFO = 3,		// Process state info.
}

// Symbol Binding - ELFNN_ST_BIND - st_info
enum {
    STB_LOCAL = 0,		// Local symbol
    STB_GLOBAL = 1,		// Global symbol
    STB_WEAK = 2,		// like global - lower precedence
    STB_LOOS = 10,		// Reserved range for operating system
    STB_HIOS = 12,		//   specific semantics.
    STB_LOPROC = 13,		// reserved range for processor
    STB_HIPROC = 15,		//   specific semantics.
}

// Symbol type - ELFNN_ST_TYPE - st_info
enum {
    STT_NOTYPE = 0,		// Unspecified type.
    STT_OBJECT = 1,		// Data object.
    STT_FUNC = 2,		// Function.
    STT_SECTION = 3,		// Section.
    STT_FILE = 4,		// Source file.
    STT_COMMON = 5,		// Uninitialized common block.
    STT_TLS = 6,		// TLS object.
    STT_NUM = 7,
    STT_LOOS = 10,		// Reserved range for operating system
    STT_HIOS = 12,		//   specific semantics.
    STT_LOPROC = 13,		// reserved range for processor
    STT_HIPROC = 15,		//   specific semantics.
}

// Symbol visibility - ELFNN_ST_VISIBILITY - st_other
enum {
    STV_DEFAULT = 0x0,	    // Default visibility (see binding).
    STV_INTERNAL = 0x1,	    // Special meaning in relocatable objects.
    STV_HIDDEN = 0x2,	    // Not visible.
    STV_PROTECTED = 0x3,    // Visible but not preemptible.
    STV_EXPORTED = 0x4,
    STV_SINGLETON = 0x5,
    STV_ELIMINATE = 0x6,
}

// Special symbol table indexes.
const int STN_UNDEF = 0;	// Undefined symbol index.

// Symbol versioning flags.
const int VER_NDX_LOCAL = 0;
const int VER_NDX_GLOBAL = 1;
const int VER_NDX_GIVEN = 2;

const int VER_NDX_HIDDEN = (1u << 15);
int VER_NDX(int x)
{
    return x & ~(1u << 15);
}

const int VER_DEF_CURRENT = 1;
int VER_DEF_IDX(int x)
{
    return VER_NDX(x);
}

const int VER_FLG_BASE = 0x01;
const int VER_FLG_WEAK = 0x02;

const int VER_NEED_CURRENT = 1;
const int VER_NEED_WEAK = (1u << 15);
const int VER_NEED_HIDDEN = VER_NDX_HIDDEN;

int VER_NEED_IDX(int x)
{
    return VER_NDX(x);
}

enum {
    CA_SUNW_NULL = 0,
    CA_SUNW_HW_1 = 1,		// first hardware capabilities entry
    CA_SUNW_SF_1 = 2,		// first software capabilities entry
}
    
// Syminfo flag values
enum {
    SYMINFO_FLG_DIRECT = 0x0001, // symbol ref has direct association
				//	to object containing defn.
    SYMINFO_FLG_PASSTHRU = 0x0002, // ignored - see SYMINFO_FLG_FILTER
    SYMINFO_FLG_COPY = 0x0004,     // symbol is a copy-reloc
    SYMINFO_FLG_LAZYLOAD = 0x0008, // object containing defn should be
    //	lazily-loaded
    SYMINFO_FLG_DIRECTBIND = 0x0010, // ref should be bound directly to
    //	object containing defn.
    SYMINFO_FLG_NOEXTDIRECT = 0x0020, // don't let an external reference
    //	directly bind to this symbol
    SYMINFO_FLG_FILTER = 0x0002, // symbol ref is associated to a
    SYMINFO_FLG_AUXILIARY = 0x0040,	// 	standard or auxiliary filter
}

// Syminfo.si_boundto values.
enum {
    SYMINFO_BT_SELF = 0xffff,	    // symbol bound to self
    SYMINFO_BT_PARENT = 0xfffe,	    // symbol bound to parent
    SYMINFO_BT_NONE = 0xfffd,	    // no special symbol binding
    SYMINFO_BT_EXTERN = 0xfffc,	    // symbol defined as external
    SYMINFO_BT_LOWRESERVE = 0xff00, // beginning of reserved entries
}

// Syminfo version values.
enum {
    SYMINFO_NONE = 0,		// Syminfo version
    SYMINFO_CURRENT = 1,
    SYMINFO_NUM = 2,
}

//
// Relocation types.
//
// All machine architectures are defined here to allow tools on one to
// handle others.
enum {
    R_386_NONE = 0,		// No relocation.
    R_386_32 = 1,		// Add symbol value.
    R_386_PC32 = 2,		// Add PC-relative symbol value.
    R_386_GOT32 = 3,		// Add PC-relative GOT offset.
    R_386_PLT32 = 4,		// Add PC-relative PLT offset.
    R_386_COPY = 5,		// Copy data from shared object.
    R_386_GLOB_DAT = 6,		// Set GOT entry to data address.
    R_386_JMP_SLOT = 7,		// Set GOT entry to code address.
    R_386_RELATIVE = 8,		// Add load address of shared object.
    R_386_GOTOFF = 9,		// Add GOT-relative symbol address.
    R_386_GOTPC = 10,		// Add PC-relative GOT table address.
    R_386_TLS_TPOFF = 14,	// Negative offset in static TLS block
    R_386_TLS_IE = 15,	 // Absolute address of GOT for -ve static TLS
    R_386_TLS_GOTIE = 16,   // GOT entry for negative static TLS block
    R_386_TLS_LE = 17,	    // Negative offset relative to static TLS
    R_386_TLS_GD = 18,	    // 32 bit offset to GOT (index,off) pair
    R_386_TLS_LDM = 19,	    // 32 bit offset to GOT (index,zero) pair
    R_386_TLS_GD_32 = 24,   // 32 bit offset to GOT (index,off) pair
    R_386_TLS_GD_PUSH = 25, // pushl instruction for Sun ABI GD sequence
    R_386_TLS_GD_CALL = 26, // call instruction for Sun ABI GD sequence
    R_386_TLS_GD_POP = 27, // popl instruction for Sun ABI GD sequence
    R_386_TLS_LDM_32 = 28, // 32 bit offset to GOT (index,zero) pair
    R_386_TLS_LDM_PUSH = 29, // pushl instruction for Sun ABI LD sequence
    R_386_TLS_LDM_CALL = 30, // call instruction for Sun ABI LD sequence
    R_386_TLS_LDM_POP = 31, // popl instruction for Sun ABI LD sequence
    R_386_TLS_LDO_32 = 32,  // 32 bit offset from start of TLS block
    R_386_TLS_IE_32 = 33, // 32 bit offset to GOT static TLS offset entry
    R_386_TLS_LE_32 = 34, // 32 bit offset within static TLS block
    R_386_TLS_DTPMOD32 = 35,	// GOT entry containing TLS index
    R_386_TLS_DTPOFF32 = 36,	// GOT entry containing TLS offset
    R_386_TLS_TPOFF32 = 37,	// GOT entry of -ve static TLS offset

    R_ARM_NONE = 0,		// No relocation.
    R_ARM_PC24 = 1,
    R_ARM_ABS32 = 2,
    R_ARM_REL32 = 3,
    R_ARM_PC13 = 4,
    R_ARM_ABS16 = 5,
    R_ARM_ABS12 = 6,
    R_ARM_THM_ABS5 = 7,
    R_ARM_ABS8 = 8,
    R_ARM_SBREL32 = 9,
    R_ARM_THM_PC22 = 10,
    R_ARM_THM_PC8 = 11,
    R_ARM_AMP_VCALL9 = 12,
    R_ARM_SWI24 = 13,
    R_ARM_THM_SWI8 = 14,
    R_ARM_XPC25 = 15,
    R_ARM_THM_XPC22 = 16,
    R_ARM_COPY = 20,		// Copy data from shared object.
    R_ARM_GLOB_DAT = 21,	// Set GOT entry to data address.
    R_ARM_JUMP_SLOT = 22,	// Set GOT entry to code address.
    R_ARM_RELATIVE = 23,	// Add load address of shared object.
    R_ARM_GOTOFF = 24,		// Add GOT-relative symbol address.
    R_ARM_GOTPC = 25,		// Add PC-relative GOT table address.
    R_ARM_GOT32 = 26,		// Add PC-relative GOT offset.
    R_ARM_PLT32 = 27,		// Add PC-relative PLT offset.
    R_ARM_GNU_VTENTRY = 100,
    R_ARM_GNU_VTINHERIT = 101,
    R_ARM_RSBREL32 = 250,
    R_ARM_THM_RPC22 = 251,
    R_ARM_RREL32 = 252,
    R_ARM_RABS32 = 253,
    R_ARM_RPC24 = 254,
    R_ARM_RBASE = 255,

//	Name			Value	   Field	Calculation
    R_IA_64_NONE = 0,		  // None
    R_IA_64_IMM14 = 0x21,	  // immediate14	S + A
    R_IA_64_IMM22 = 0x22,	  // immediate22	S + A
    R_IA_64_IMM64 = 0x23,	  // immediate64	S + A
    R_IA_64_DIR32MSB = 0x24,	  // word32 MSB	S + A
    R_IA_64_DIR32LSB = 0x25,	  // word32 LSB	S + A
    R_IA_64_DIR64MSB = 0x26,	  // word64 MSB	S + A
    R_IA_64_DIR64LSB = 0x27,	  // word64 LSB	S + A
    R_IA_64_GPREL22 = 0x2a,	  // immediate22	@gprel(S + A)
    R_IA_64_GPREL64I = 0x2b,	  // immediate64	@gprel(S + A)
    R_IA_64_GPREL32MSB = 0x2c,	  // word32 MSB	@gprel(S + A)
    R_IA_64_GPREL32LSB = 0x2d,	  // word32 LSB	@gprel(S + A)
    R_IA_64_GPREL64MSB = 0x2e,	  // word64 MSB	@gprel(S + A)
    R_IA_64_GPREL64LSB = 0x2f,	  // word64 LSB	@gprel(S + A)
    R_IA_64_LTOFF22 = 0x32,	  // immediate22	@ltoff(S + A)
    R_IA_64_LTOFF64I = 0x33,	  // immediate64	@ltoff(S + A)
    R_IA_64_PLTOFF22 = 0x3a,	  // immediate22	@pltoff(S + A)
    R_IA_64_PLTOFF64I = 0x3b,	  // immediate64	@pltoff(S + A)
    R_IA_64_PLTOFF64MSB = 0x3e,	  // word64 MSB	@pltoff(S + A)
    R_IA_64_PLTOFF64LSB = 0x3f,	  // word64 LSB	@pltoff(S + A)
    R_IA_64_FPTR64I = 0x43,	  // immediate64	@fptr(S + A)
    R_IA_64_FPTR32MSB = 0x44,	  // word32 MSB	@fptr(S + A)
    R_IA_64_FPTR32LSB = 0x45,	  // word32 LSB	@fptr(S + A)
    R_IA_64_FPTR64MSB = 0x46,	  // word64 MSB	@fptr(S + A)
    R_IA_64_FPTR64LSB = 0x47,	  // word64 LSB	@fptr(S + A)
    R_IA_64_PCREL60B = 0x48,	  // immediate60 form1 S + A - P
    R_IA_64_PCREL21B = 0x49,	  // immediate21 form1 S + A - P
    R_IA_64_PCREL21M = 0x4a,	  // immediate21 form2 S + A - P
    R_IA_64_PCREL21F = 0x4b,	  // immediate21 form3 S + A - P
    R_IA_64_PCREL32MSB = 0x4c,	  // word32 MSB	S + A - P
    R_IA_64_PCREL32LSB = 0x4d,	  // word32 LSB	S + A - P
    R_IA_64_PCREL64MSB = 0x4e,	  // word64 MSB	S + A - P
    R_IA_64_PCREL64LSB = 0x4f,	  // word64 LSB	S + A - P
    R_IA_64_LTOFF_FPTR22 = 0x52,  // immediate22	@ltoff(@fptr(S + A))
    R_IA_64_LTOFF_FPTR64I = 0x53, // immediate64	@ltoff(@fptr(S + A))
    R_IA_64_LTOFF_FPTR32MSB = 0x54, // word32 MSB	@ltoff(@fptr(S + A))
    R_IA_64_LTOFF_FPTR32LSB = 0x55, // word32 LSB	@ltoff(@fptr(S + A))
    R_IA_64_LTOFF_FPTR64MSB = 0x56, // word64 MSB	@ltoff(@fptr(S + A))
    R_IA_64_LTOFF_FPTR64LSB = 0x57, // word64 LSB	@ltoff(@fptr(S + A))
    R_IA_64_SEGREL32MSB = 0x5c,	    // word32 MSB	@segrel(S + A)
    R_IA_64_SEGREL32LSB = 0x5d,	    // word32 LSB	@segrel(S + A)
    R_IA_64_SEGREL64MSB = 0x5e,	    // word64 MSB	@segrel(S + A)
    R_IA_64_SEGREL64LSB = 0x5f,	    // word64 LSB	@segrel(S + A)
    R_IA_64_SECREL32MSB = 0x64,	    // word32 MSB	@secrel(S + A)
    R_IA_64_SECREL32LSB = 0x65,	    // word32 LSB	@secrel(S + A)
    R_IA_64_SECREL64MSB = 0x66,	    // word64 MSB	@secrel(S + A)
    R_IA_64_SECREL64LSB = 0x67,	    // word64 LSB	@secrel(S + A)
    R_IA_64_REL32MSB = 0x6c,	    // word32 MSB	BD + A
    R_IA_64_REL32LSB = 0x6d,	    // word32 LSB	BD + A
    R_IA_64_REL64MSB = 0x6e,	    // word64 MSB	BD + A
    R_IA_64_REL64LSB = 0x6f,	    // word64 LSB	BD + A
    R_IA_64_LTV32MSB = 0x74,	    // word32 MSB	S + A
    R_IA_64_LTV32LSB = 0x75,	    // word32 LSB	S + A
    R_IA_64_LTV64MSB = 0x76,	    // word64 MSB	S + A
    R_IA_64_LTV64LSB = 0x77,	    // word64 LSB	S + A
    R_IA_64_PCREL21BI = 0x79,	    // immediate21 form1 S + A - P
    R_IA_64_PCREL22 = 0x7a,	    // immediate22	S + A - P
    R_IA_64_PCREL64I = 0x7b,	    // immediate64	S + A - P
    R_IA_64_IPLTMSB = 0x80,	    // function descriptor MSB special
    R_IA_64_IPLTLSB = 0x81,	   // function descriptor LSB speciaal
    R_IA_64_SUB = 0x85,		   // immediate64	A - S
    R_IA_64_LTOFF22X = 0x86,	   // immediate22	special
    R_IA_64_LDXMOV = 0x87,	   // immediate22	special
    R_IA_64_TPREL14 = 0x91,	   // imm14	@tprel(S + A)
    R_IA_64_TPREL22 = 0x92,	   // imm22	@tprel(S + A)
    R_IA_64_TPREL64I = 0x93,	   // imm64	@tprel(S + A)
    R_IA_64_TPREL64MSB = 0x96,	   // word64 MSB	@tprel(S + A)
    R_IA_64_TPREL64LSB = 0x97,	   // word64 LSB	@tprel(S + A)
    R_IA_64_LTOFF_TPREL22 = 0x9a,  // imm22	@ltoff(@tprel(S+A))
    R_IA_64_DTPMOD64MSB = 0xa6,	   // word64 MSB	@dtpmod(S + A)
    R_IA_64_DTPMOD64LSB = 0xa7,	   // word64 LSB	@dtpmod(S + A)
    R_IA_64_LTOFF_DTPMOD22 = 0xaa, // imm22	@ltoff(@dtpmod(S+A))
    R_IA_64_DTPREL14 = 0xb1,	   // imm14	@dtprel(S + A)
    R_IA_64_DTPREL22 = 0xb2,	   // imm22	@dtprel(S + A)
    R_IA_64_DTPREL64I = 0xb3,	   // imm64	@dtprel(S + A)
    R_IA_64_DTPREL32MSB = 0xb4,	   // word32 MSB	@dtprel(S + A)
    R_IA_64_DTPREL32LSB = 0xb5,	   // word32 LSB	@dtprel(S + A)
    R_IA_64_DTPREL64MSB = 0xb6,	   // word64 MSB	@dtprel(S + A)
    R_IA_64_DTPREL64LSB = 0xb7,	   // word64 LSB	@dtprel(S + A)
    R_IA_64_LTOFF_DTPREL22 = 0xba, // imm22	@ltoff(@dtprel(S+A))

    R_PPC_NONE = 0,		// No relocation.
    R_PPC_ADDR32 = 1,
    R_PPC_ADDR24 = 2,
    R_PPC_ADDR16 = 3,
    R_PPC_ADDR16_LO = 4,
    R_PPC_ADDR16_HI = 5,
    R_PPC_ADDR16_HA = 6,
    R_PPC_ADDR14 = 7,
    R_PPC_ADDR14_BRTAKEN = 8,
    R_PPC_ADDR14_BRNTAKEN = 9,
    R_PPC_REL24 = 10,
    R_PPC_REL14 = 11,
    R_PPC_REL14_BRTAKEN = 12,
    R_PPC_REL14_BRNTAKEN = 13,
    R_PPC_GOT16 = 14,
    R_PPC_GOT16_LO = 15,
    R_PPC_GOT16_HI = 16,
    R_PPC_GOT16_HA = 17,
    R_PPC_PLTREL24 = 18,
    R_PPC_COPY = 19,
    R_PPC_GLOB_DAT = 20,
    R_PPC_JMP_SLOT = 21,
    R_PPC_RELATIVE = 22,
    R_PPC_LOCAL24PC = 23,
    R_PPC_UADDR32 = 24,
    R_PPC_UADDR16 = 25,
    R_PPC_REL32 = 26,
    R_PPC_PLT32 = 27,
    R_PPC_PLTREL32 = 28,
    R_PPC_PLT16_LO = 29,
    R_PPC_PLT16_HI = 30,
    R_PPC_PLT16_HA = 31,
    R_PPC_SDAREL16 = 32,
    R_PPC_SECTOFF = 33,
    R_PPC_SECTOFF_LO = 34,
    R_PPC_SECTOFF_HI = 35,
    R_PPC_SECTOFF_HA = 36,

//
// TLS relocations

    R_PPC_TLS = 67,
    R_PPC_DTPMOD32 = 68,
    R_PPC_TPREL16 = 69,
    R_PPC_TPREL16_LO = 70,
    R_PPC_TPREL16_HI = 71,
    R_PPC_TPREL16_HA = 72,
    R_PPC_TPREL32 = 73,
    R_PPC_DTPREL16 = 74,
    R_PPC_DTPREL16_LO = 75,
    R_PPC_DTPREL16_HI = 76,
    R_PPC_DTPREL16_HA = 77,
    R_PPC_DTPREL32 = 78,
    R_PPC_GOT_TLSGD16 = 79,
    R_PPC_GOT_TLSGD16_LO = 80,
    R_PPC_GOT_TLSGD16_HI = 81,
    R_PPC_GOT_TLSGD16_HA = 82,
    R_PPC_GOT_TLSLD16 = 83,
    R_PPC_GOT_TLSLD16_LO = 84,
    R_PPC_GOT_TLSLD16_HI = 85,
    R_PPC_GOT_TLSLD16_HA = 86,
    R_PPC_GOT_TPREL16 = 87,
    R_PPC_GOT_TPREL16_LO = 88,
    R_PPC_GOT_TPREL16_HI = 89,
    R_PPC_GOT_TPREL16_HA = 90,

//
// The remaining relocs are from the Embedded ELF ABI, and are not in the
//  SVR4 ELF ABI.


    R_PPC_EMB_NADDR32 = 101,
    R_PPC_EMB_NADDR16 = 102,
    R_PPC_EMB_NADDR16_LO = 103,
    R_PPC_EMB_NADDR16_HI = 104,
    R_PPC_EMB_NADDR16_HA = 105,
    R_PPC_EMB_SDAI16 = 106,
    R_PPC_EMB_SDA2I16 = 107,
    R_PPC_EMB_SDA2REL = 108,
    R_PPC_EMB_SDA21 = 109,
    R_PPC_EMB_MRKREF = 110,
    R_PPC_EMB_RELSEC16 = 111,
    R_PPC_EMB_RELST_LO = 112,
    R_PPC_EMB_RELST_HI = 113,
    R_PPC_EMB_RELST_HA = 114,
    R_PPC_EMB_BIT_FLD = 115,
    R_PPC_EMB_RELSDA = 116,

    R_SPARC_NONE = 0,
    R_SPARC_8 = 1,
    R_SPARC_16 = 2,
    R_SPARC_32 = 3,
    R_SPARC_DISP8 = 4,
    R_SPARC_DISP16 = 5,
    R_SPARC_DISP32 = 6,
    R_SPARC_WDISP30 = 7,
    R_SPARC_WDISP22 = 8,
    R_SPARC_HI22 = 9,
    R_SPARC_22 = 10,
    R_SPARC_13 = 11,
    R_SPARC_LO10 = 12,
    R_SPARC_GOT10 = 13,
    R_SPARC_GOT13 = 14,
    R_SPARC_GOT22 = 15,
    R_SPARC_PC10 = 16,
    R_SPARC_PC22 = 17,
    R_SPARC_WPLT30 = 18,
    R_SPARC_COPY = 19,
    R_SPARC_GLOB_DAT = 20,
    R_SPARC_JMP_SLOT = 21,
    R_SPARC_RELATIVE = 22,
    R_SPARC_UA32 = 23,
    R_SPARC_PLT32 = 24,
    R_SPARC_HIPLT22 = 25,
    R_SPARC_LOPLT10 = 26,
    R_SPARC_PCPLT32 = 27,
    R_SPARC_PCPLT22 = 28,
    R_SPARC_PCPLT10 = 29,
    R_SPARC_10 = 30,
    R_SPARC_11 = 31,
    R_SPARC_64 = 32,
    R_SPARC_OLO10 = 33,
    R_SPARC_HH22 = 34,
    R_SPARC_HM10 = 35,
    R_SPARC_LM22 = 36,
    R_SPARC_PC_HH22 = 37,
    R_SPARC_PC_HM10 = 38,
    R_SPARC_PC_LM22 = 39,
    R_SPARC_WDISP16 = 40,
    R_SPARC_WDISP19 = 41,
    R_SPARC_GLOB_JMP = 42,
    R_SPARC_7 = 43,
    R_SPARC_5 = 44,
    R_SPARC_6 = 45,
    R_SPARC_DISP64 = 46,
    R_SPARC_PLT64 = 47,
    R_SPARC_HIX22 = 48,
    R_SPARC_LOX10 = 49,
    R_SPARC_H44 = 50,
    R_SPARC_M44 = 51,
    R_SPARC_L44 = 52,
    R_SPARC_REGISTER = 53,
    R_SPARC_UA64 = 54,
    R_SPARC_UA16 = 55,
    R_SPARC_TLS_GD_HI22 = 56,
    R_SPARC_TLS_GD_LO10 = 57,
    R_SPARC_TLS_GD_ADD = 58,
    R_SPARC_TLS_GD_CALL = 59,
    R_SPARC_TLS_LDM_HI22 = 60,
    R_SPARC_TLS_LDM_LO10 = 61,
    R_SPARC_TLS_LDM_ADD = 62,
    R_SPARC_TLS_LDM_CALL = 63,
    R_SPARC_TLS_LDO_HIX22 = 64,
    R_SPARC_TLS_LDO_LOX10 = 65,
    R_SPARC_TLS_LDO_ADD = 66,
    R_SPARC_TLS_IE_HI22 = 67,
    R_SPARC_TLS_IE_LO10 = 68,
    R_SPARC_TLS_IE_LD = 69,
    R_SPARC_TLS_IE_LDX = 70,
    R_SPARC_TLS_IE_ADD = 71,
    R_SPARC_TLS_LE_HIX22 = 72,
    R_SPARC_TLS_LE_LOX10 = 73,
    R_SPARC_TLS_DTPMOD32 = 74,
    R_SPARC_TLS_DTPMOD64 = 75,
    R_SPARC_TLS_DTPOFF32 = 76,
    R_SPARC_TLS_DTPOFF64 = 77,
    R_SPARC_TLS_TPOFF32 = 78,
    R_SPARC_TLS_TPOFF64 = 79,

    R_X86_64_NONE = 0,	     // No relocation.
    R_X86_64_64 = 1,	     // Add 64 bit symbol value.
    R_X86_64_PC32 = 2,	     // PC-relative 32 bit signed sym value.
    R_X86_64_GOT32 = 3,	     // PC-relative 32 bit GOT offset.
    R_X86_64_PLT32 = 4,	     // PC-relative 32 bit PLT offset.
    R_X86_64_COPY = 5,	     // Copy data from shared object.
    R_X86_64_GLOB_DAT = 6,   // Set GOT entry to data address.
    R_X86_64_JMP_SLOT = 7,   // Set GOT entry to code address.
    R_X86_64_RELATIVE = 8,   // Add load address of shared object.
    R_X86_64_GOTPCREL = 9,   // Add 32 bit signed pcrel offset to GOT.
    R_X86_64_32 = 10,	     // Add 32 bit zero extended symbol value
    R_X86_64_32S = 11,	     // Add 32 bit sign extended symbol value
    R_X86_64_16 = 12,	     // Add 16 bit zero extended symbol value
    R_X86_64_PC16 = 13,	// Add 16 bit signed extended pc relative symbol value
    R_X86_64_8 = 14,	// Add 8 bit zero extended symbol value
    R_X86_64_PC8 = 15, // Add 8 bit signed extended pc relative symbol value
    R_X86_64_DTPMOD64 = 16,	// ID of module containing symbol
    R_X86_64_DTPOFF64 = 17,	// Offset in TLS block
    R_X86_64_TPOFF64 = 18,	// Offset in static TLS block
    R_X86_64_TLSGD = 19,	// PC relative offset to GD GOT entry
    R_X86_64_TLSLD = 20,	// PC relative offset to LD GOT entry
    R_X86_64_DTPOFF32 = 21,	// Offset in TLS block
    R_X86_64_GOTTPOFF = 22,	// PC relative offset to IE GOT entry
    R_X86_64_TPOFF32 = 23,	// Offset in static TLS block

}

/**
 * Values for r_debug.r_state
 */
enum {
    RT_CONSISTENT,		// things are stable
    RT_ADD,			// adding a shared library
    RT_DELETE			// removing a shared library
}

import std.stdio;
import std.string;
//import std.c.unix.unix;
import sys.pread;

class Elffile: Objfile
{
    static Objfile open(string file, ulong base)
    {
	int fd = .open(toStringz(file), O_RDONLY);
	if (fd > 0) {
	    Ident ei;

	    if (pread(fd, &ei, ei.sizeof, 0) != ei.sizeof
		|| !IsElf(&ei)) {
		.close(fd);
		return null;
	    }
	    switch (ei.ei_class) {
	    case ELFCLASS32:
		debug (elf)
		    writefln("Elf32 format file %s", file);
		return new Elffile32(fd, base);
		break;
	    case ELFCLASS64:
		debug (elf)
		    writefln("Elf64 format file %s", file);
		return new Elffile64(fd, base);
		break;
	    default:
		return null;
	    }
	}
	.close(fd);
	return null;
    }

    static this()
    {
	Objfile.addFileType(&open);
    }

    override {
	ulong read(ubyte[] bytes)
	{
	    return endian_.read(bytes);
	}
	ushort read(ushort v)
	{
	    return endian_.read(v);
	}
	uint read(uint v)
	{
	    return endian_.read(v);
	}
	ulong read(ulong v)
	{
	    return endian_.read(v);
	}
	void write(ulong val, ubyte[] bytes)
	{
	    return endian_.write(val, bytes);
	}
	void write(ushort v, out ushort res)
	{
	    return endian_.write(v, res);
	}
	void write(uint v, out uint res)
	{
	    return endian_.write(v, res);
	}
	void write(ulong v, out ulong res)
	{
	    return endian_.write(v, res);
	}
    }

    short read(short v)
    {
	return endian_.read(cast(ushort) v);
    }
    int read(int v)
    {
	return endian_.read(cast(uint) v);
    }
    long read(long v)
    {
	return endian_.read(cast(ulong) v);
    }

    abstract bool is64();

    abstract Symbol* lookupSymbol(ulong addr);

    abstract Symbol* lookupSymbol(string name);

    abstract ulong offset();

    abstract uint tlsindex();

    abstract void tlsindex(uint);

    abstract bool hasSection(string name);

    abstract char[] readSection(string name);

    abstract string interpreter();

    abstract void enumerateProgramHeaders(void delegate(uint, ulong, ulong) dg);

    abstract void enumerateNotes(void delegate(uint, string, ubyte*) dg);

    abstract ubyte[] readProgram(ulong addr, size_t len);

    abstract void digestDynamic(Target target);

    abstract ulong findSharedLibraryBreakpoint(Target target);

    abstract uint sharedLibraryState(Target target);

    abstract void enumerateLinkMap(Target target,
				   void delegate(string, ulong, ulong) dg);

    abstract void enumerateNeededLibraries(Target target,
					   void delegate(string) dg);

    abstract bool inPLT(ulong pc);

private:
    Endian endian_;
}

template ElfFileBase()
{
    this(int fd, ulong base)
    {
	fd_ = fd;

	Ehdr eh;
	if (pread(fd, &eh, eh.sizeof, 0) != eh.sizeof)
	    throw new Exception("Can't read Elf header");

	if (eh.e_ident.ei_data == ELFDATA2LSB)
	    endian_ = new LittleEndian;
	else
	    endian_ = new BigEndian;
	type_ = read(eh.e_type);
	machine_ = read(eh.e_machine);

	debug (elf)
	    writefln("%d program headers", read(eh.e_phnum));
	ph_.length = read(eh.e_phnum);
	foreach (i, ref ph; ph_) {
	    if (pread(fd, &ph, eh.e_phentsize,
		      eh.e_phoff + i * eh.e_phentsize) != eh.e_phentsize)
		throw new Exception("Can't read program headers");
	}
	if (base > 0 && ph_.length > 0) {
	    foreach (ph; ph_) {
		if (read(ph.p_type) == PT_LOAD) {
		    offset_ = base - read(ph.p_vaddr);
		    break;
		}
	    }
	} else {
	    offset_ = 0;
	}

	entry_ = read(eh.e_entry) + offset_;

	debug (elf)
	    writefln("%d sections", read(eh.e_shnum));
	sections_.length = read(eh.e_shnum);
	foreach (i, ref sh; sections_) {
	    if (pread(fd, &sh, eh.e_shentsize,
		      eh.e_shoff + i * eh.e_shentsize) != eh.e_shentsize)
		throw new Exception("Can't read section headers");
	}

	if (read(eh.e_shstrndx) != SHN_UNDEF) {
	    shStrings_ = readSection(read(eh.e_shstrndx));
	}

	debug (elf)
	    foreach (i, ref sh; sections_) {
		if (read(sh.sh_type) == SHT_NULL)
		    continue;
		writefln("Section %d type %d, name %s, off %d, size %d",
			 i, read(sh.sh_type),
			 std.string.toString(&shStrings_[sh.sh_name]),
			 read(sh.sh_offset), read(sh.sh_size));
	    }

	foreach (ref sh; sections_) {
	    if (read(sh.sh_type) == SHT_NULL)
		continue;
	    if (.toString(&shStrings_[sh.sh_name]) != ".plt")
		continue;
	    pltStart_ = read(sh.sh_addr) + offset_;
	    pltEnd_ = pltStart_ + read(sh.sh_size);
	}

	Symbol[] symtab;
	Symbol[] dynsym;
	foreach (i, ref sh; sections_) {
	    if (read(sh.sh_type) == SHT_SYMTAB)
		symtab = readSymbols(i);
	    else if (read(sh.sh_type) == SHT_DYNSYM)
		dynsym = readSymbols(i);
	}

	this(symtab, dynsym);
    }

    this(Symbol[] symtab, Symbol[] dynsym)
    {
	symtab_ = symtab;
	dynsym_ = dynsym;
    }

    ~this()
    {
	if (fd_ >= 0) {
	    .close(fd_);
	    fd_ = -1;
	}
    }

    bool isExecutable()
    {
	return type_ == ET_EXEC;
    }

    MachineState getState(Target target)
    {
	switch (machine_) {
	case EM_386:
	    return new X86State(target);
	case EM_X86_64:
	    return new X86_64State(target);
	case EM_ARM:
	    return new ArmState(target);
	default:
	    throw new TargetException("Unsupported target machine type");
	}
    }

    Symbol* lookupSymbol(ulong addr)
    {
	Symbol *sp;
	sp = _lookupSymbol(addr, symtab_);
	if (sp)
	    return sp;
	sp = _lookupSymbol(addr, dynsym_);
	if (sp)
	    return sp;
	return null;
    }

    Symbol* lookupSymbol(string name)
    {
	Symbol *sp;
	sp = _lookupSymbol(name, symtab_);
	if (sp)
	    return sp;

	sp = _lookupSymbol(name, dynsym_);
	if (sp)
	    return sp;
	return null;
    }

    ulong entry()
    {
	return entry_;
    }

    ulong offset()
    {
	return offset_;
    }

    uint tlsindex()
    {
	return tlsindex_;
    }

    void tlsindex(uint i)
    {
	tlsindex_ = i;
    }

    int lookupSection(string name)
    {
	foreach (i, ref sh; sections_) {
	    if (std.string.toString(&shStrings_[sh.sh_name]) == name)
		return i;
	}
	return -1;
    }

    bool hasSection(string name)
    {
	return (lookupSection(name) >= 0);
    }

    char[] readSection(string name)
    {
	int i = lookupSection(name);
	if (i < 0)
	    throw new Exception("no such section");
	return readSection(i);
    }

    string interpreter()
    {
	foreach (ph; ph_)
	    if (ph.p_type == PT_INTERP) {
		string s;
		s.length = read(ph.p_filesz);
		if (s.length == 0)
		    return s;
		if (pread(fd_, &s[0], s.length, read(ph.p_offset))
		    != s.length)
		    throw new Exception("Can't read from file");
		return s;
	    }
	return null;
    }

    void enumerateProgramHeaders(void delegate(uint, ulong, ulong) dg)
    {
	foreach (ph; ph_)
	    dg(read(ph.p_type), read(ph.p_vaddr) + offset_,
	       read(ph.p_vaddr) + read(ph.p_memsz) + offset_);
    }

    void enumerateNotes(void delegate(uint, string, ubyte*) dg)
    {
	foreach (ph; ph_) {
	    if (read(ph.p_type) == PT_NOTE) {
		ubyte[] notes;
		notes.length = read(ph.p_filesz);
		if (pread(fd_, &notes[0], notes.length, read(ph.p_offset))
		    != notes.length)
		    throw new Exception("Can't read from file");

		size_t roundup(size_t n, size_t sz = Size.sizeof)
		{
		    return (n + sz - 1) & ~(sz - 1);
		}

		size_t i = 0;
		while (i < notes.length) {
		    Note* n = cast(Note*) &notes[i];
		    char* name = cast(char*) (n + 1);
		    ubyte* desc = cast(ubyte*)
			(name + roundup(read(n.n_namesz)));

		    dg(n.n_type, .toString(name), desc);
		    i += Note.sizeof;
		    i += roundup(read(n.n_namesz))
			+ roundup(read(n.n_descsz));
		}
	    }
	}
    }

    void enumerateDynamic(Target target, void delegate(uint, ulong) dg)
    {
	ulong s, e;
	bool found = false;

	void getDynamic(uint tag, ulong start, ulong end)
	{
	    if (tag == PT_DYNAMIC) {
		s = start;
		e = end;
		found = true;
	    }
	}
	    
	enumerateProgramHeaders(&getDynamic);
	if (!found)
	    return;

	debug (elf)
	    writefln("Found dynamic at %#x .. %#x", s, e);
	ubyte[] dyn;
	dyn = target.readMemory(s, e - s);

	if (dyn.length == 0)
	    return;

	ubyte* p = &dyn[0], end = p + dyn.length;
	while (p < end) {
	    Dyn* d = cast(Dyn*) p;
	    dg(read(d.d_tag), read(d.d_val));
	    p += Dyn.sizeof;
	}
    }

    ubyte[] readProgram(ulong addr, size_t len)
    {
	ubyte[] res;
	res.length = len;

	if (!len)
	    return res;

	memset(&res[0], 0, len);

	ulong sa = addr;
	ulong ea = addr + len;
	foreach (ph; ph_) {
	    if (read(ph.p_type) == PT_LOAD) {
		ulong psa = read(ph.p_vaddr) + offset_;
		ulong pea = psa  + read(ph.p_filesz);
		if (ea > psa && sa < pea) {
		    /*
		     * Some bytes are in this section.
		     */
		    ulong s = psa;
		    if (sa > s) s = sa;
		    ulong e = pea;
		    if (ea < e) e = ea;
		    if (pread(fd_, &res[s - sa], e - s,
			      read(ph.p_offset) + s - psa) != e - s)
			throw new Exception("Can't read from file");
		}
	    }
	}
	return res;
    }

    void digestDynamic(Target target)
    {
	void dg(uint tag, ulong val)
	{
	    if (tag == DT_DEBUG)
		r_debug_ = val + offset_;
	}

	enumerateDynamic(target, &dg);

	debug (elf)
	    if (r_debug_)
		writefln("r_debug @ %#x", r_debug_);
    }

    ulong findSharedLibraryBreakpoint(Target target)
    {
	if (!r_debug_)
	    return 0;
	ubyte[] t = target.readMemory(r_debug_, r_debug.sizeof);
	r_debug* p = cast(r_debug*) &t[0];
	return read(p.r_brk);
    }

    uint sharedLibraryState(Target target)
    {
	if (!r_debug_)
	    return RT_CONSISTENT;
	ubyte[] t = target.readMemory(r_debug_, r_debug.sizeof);
	r_debug* p = cast(r_debug*) &t[0];
	return read(p.r_state);
    }

    void enumerateLinkMap(Target target,
			  void delegate(string, ulong, ulong) dg)
    {
	if (!r_debug_)
	    return;

	string readString(Target target, ulong addr)
	{
	    string s;
	    char c;

	    do {
		ubyte[] t = target.readMemory(addr++, 1);
		c = cast(char) t[0];
		if (c)
		    s ~= c;
	    } while (c);
	    return s;
	}

	ubyte[] t = target.readMemory(r_debug_, r_debug.sizeof);
	r_debug* p = cast(r_debug*) &t[0];
	ulong lp = read(p.r_map);
	while (lp) {
	    t = target.readMemory(lp, link_map.sizeof);
	    link_map *lm = cast(link_map*) &t[0];
	    dg(readString(target, read(lm.l_name)), lp, read(lm.l_addr));
	    lp = read(lm.l_next);
	}
    }

    void enumerateNeededLibraries(Target target, void delegate(string) dg)
    {
	ulong strtabAddr, strtabSize;
	string strtab;

	void findStrtab(uint tag, ulong val)
	{
	    if (tag == DT_STRTAB)
		strtabAddr = val + offset_;
	    else if (tag == DT_STRSZ)
		strtabSize = val;
	}

	void findNeeded(uint tag, ulong val)
	{
	    if (tag == DT_NEEDED && val < strtab.length)
		dg(.toString(&strtab[val]));
	}

	enumerateDynamic(target, &findStrtab);
	strtab.length = strtabSize;
	if (strtab.length > 0)
	    strtab = cast(string) target.readMemory(strtabAddr, strtabSize);
	enumerateDynamic(target, &findNeeded);
    }

    bool inPLT(ulong pc)
    {
	return pc >= pltStart_ && pc < pltEnd_;
    }

private:
    char[] readSection(int si)
    {
	Shdr *sh = &sections_[si];
	char[] s;

	s.length = read(sh.sh_size);
	if (s.length > 0)
	    if (pread(fd_, &s[0], s.length, read(sh.sh_offset)) != s.length)
		throw new Exception("Can't read section");
	return s;
    }

    Symbol[] readSymbols(int si)
    {
	Shdr* sh = &sections_[si];
	if (read(sh.sh_entsize) != Sym.sizeof)
	    throw new Exception("Symbol section has unsupported entry size");

	Sym[] syms;
	syms.length = read(sh.sh_size) / read(sh.sh_entsize);
	if (pread(fd_, &syms[0], sh.sh_size, sh.sh_offset) != sh.sh_size)
	    throw new Exception("Can't read section");

	char[] strings = readSection(sh.sh_link);

	Symbol[] symbols;
	symbols.length = syms.length;
	foreach (i, ref sym; syms) {
	    Symbol* s = &symbols[i];
	    s.name = std.string.toString(&strings[read(sym.st_name)]);
	    s.value = read(sym.st_value) + offset_;
	    s.size = sym.st_size;
	    s.type = sym.st_type;
	    s.binding = sym.st_bind;
	    s.section = sym.st_shndx;
	}

	return symbols;
    }

    Symbol* _lookupSymbol(uintptr_t addr, Symbol[] syms)
    {
	Symbol* best = null;
	foreach (ref s; syms) {
	    if (s.type != STT_FUNC && s.type != STT_OBJECT)
		continue;
	    if (addr >= s.value && addr < s.value + s.size)
		return &s;
	    if (addr >= s.value
		&& (!best || addr - s.value < addr - best.value))
		best = &s;
	}
	return best;
    }

    Symbol* _lookupSymbol(string name, Symbol[] syms)
    {
	foreach (ref s; syms) {
	    if (s.name == name)
		return &s;
	}
	return null;
    }

    int		fd_ = -1;
    int		type_;
    uint	machine_;
    ulong	entry_;
    ulong	offset_;
    uint	tlsindex_;
    ulong	r_debug_ = 0;
    ulong	pltStart_ = 0;
    ulong	pltEnd_ = 0;
    Phdr[]	ph_;
    Shdr[]	sections_;
    char[]	shStrings_;
    Symbol[]	symtab_;
    Symbol[]	dynsym_;
}

class Elffile32: Elffile
{
    import objfile.elf32;
    mixin ElfFileBase;
    bool is64()
    {
	return false;
    }
}

class Elffile64: Elffile
{
    import objfile.elf64;
    mixin ElfFileBase;
    bool is64()
    {
	return true;
    }
}
