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
/*-
 * Copyright (c) 1996-1998 John D. Polstra.
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

module objfile.elf32;

import std.conv;
import std.stdint;
import objfile.elf: Ident;

alias uint32_t	Addr;
alias uint16_t	Half;
alias uint32_t	Off;
alias int32_t	Sword;
alias uint32_t	Word;
alias uint64_t	Lword;

alias Word Hashelt;

/* Non-standard class-dependent datatype used for abstraction. */
alias Word Size;
alias Sword Ssize;

/*
 * ELF header.
 */
struct Ehdr {
    Ident	e_ident;	// File identification.
    Half	e_type;		// File type.
    Half	e_machine;	// Machine architecture.
    Word	e_version;	// ELF format version.
    Addr	e_entry;	// Entry point.
    Off		e_phoff;	// Program header file offset.
    Off		e_shoff;	// Section header file offset.
    Word	e_flags;	// Architecture-specific flags.
    Half	e_ehsize;	// Size of ELF header in bytes.
    Half	e_phentsize;	// Size of program header entry.
    Half	e_phnum;	// Number of program header entries.
    Half	e_shentsize;	// Size of section header entry.
    Half	e_shnum;	// Number of section header entries.
    Half	e_shstrndx;	// Section name strings section.
}

/*
 * Section header.
 */
struct Shdr {
    Word	sh_name;	// Section name (index into the
				// section header string table).
    Word	sh_type;	// Section type.
    Word	sh_flags;	// Section flags.
    Addr	sh_addr;	// Address in memory image.
    Off		sh_offset;		// Offset in file.
    Word	sh_size;	// Size in bytes.
    Word	sh_link;	// Index of a related section.
    Word	sh_info;	// Depends on section type.
    Word	sh_addralign;	// Alignment in bytes.
    Word	sh_entsize;	// Size of each entry in section.
}

/*
 * Program header.
 */
struct Phdr {
    Word	p_type;		// Entry type.
    Off		p_offset;	// File offset of contents.
    Addr	p_vaddr;	// Virtual address in memory image.
    Addr	p_paddr;	// Physical address (not used).
    Word	p_filesz;	// Size of contents in file.
    Word	p_memsz;	// Size of contents in memory.
    Word	p_flags;	// Access permission flags.
    Word	p_align;	// Alignment in memory and file.
}

/*
 * Dynamic structure.  The ".dynamic" section contains an array of them.
 */
struct Dyn {
    Sword	d_tag;		// Entry type.
    union {
	Word	d_val;		// Integer value.
	Addr	d_ptr;		// Address value.
    }
}

/*
 * Relocation entries.
 */

/* Relocations that don't need an addend field. */
struct Rel {
    Addr	r_offset;	// Location to be relocated.
    Word	r_info;		// Relocation type and symbol index.
}

/* Relocations that need an addend field. */
struct Rela {
    Addr	r_offset;	// Location to be relocated.
    Word	r_info;		// Relocation type and symbol index.
    Sword	r_addend;	// Addend. */

    // Access the fields of r_info.
    int r_sym()
    {
	return r_info >> 8;
    }
    int r_type()
    {
	return r_info & 0xff;
    }

    // Constructing r_info from field values.
    void set_r_info(int sym, int type)
    {
	r_info = (sym << 8) + (type & 0xff);
    }
}

/*
 *	Move entry
 */
struct Move {
    Lword	m_value;	// symbol value
    Word 	m_info;		// size + index
    Word	m_poffset;	// symbol offset
    Half	m_repeat;	// repeat count
    Half	m_stride;	// stride info

    // Compose and decompose m_info
    int m_sym()
    {
	return m_info >> 8;
    }
    int m_size()
    {
	return m_info & 0xff;
    }
    void set_m_info(int sym, int size)
    {
	m_info = (sym << 8) + (size & 0xff);
    }
}

/*
 *	Hardware/Software capabilities entry
 */
struct Cap {
    Word	c_tag;		// how to interpret value
    union {
	Word	c_val;
	Addr	c_ptr;
    }
}

/*
 * Symbol table entries.
 */

struct Sym {
    Word	st_name;	// String table index of name.
    Addr	st_value;	// Symbol value.
    Word	st_size;	// Size of associated object.
    ubyte	st_info;	// Type and binding information.
    ubyte	st_other;	// Reserved (not used).
    Half	st_shndx;	// Section index of symbol.

    // Access the fields of st_info.
    int st_bind()
    {
	return st_info >> 4;
    }
    int st_type()
    {
	return st_info & 0xf;
    }
    void set_st_info(int bind, int type)
    {
	st_info = to!ubyte((bind << 4) + (type & 0xff));
    }

    // Access the fields of st_other
    int st_visibility()
    {
	return st_other & 0x3;
    }
}

/* Structures used by Sun & GNU symbol versioning. */
struct VerDef
{
    Half	vd_version;
    Half	vd_flags;
    Half	vd_ndx;
    Half	vd_cnt;
    Word	vd_hash;
    Word	vd_aux;
    Word	vd_next;
}

struct Verdaux
{
    Word	vda_name;
    Word	vda_next;
}

struct Verneed
{
    Half	vn_version;
    Half	vn_cnt;
    Word	vn_file;
    Word	vn_aux;
    Word	vn_next;
}

struct Vernaux
{
    Word	vna_hash;
    Half	vna_flags;
    Half	vna_other;
    Word	vna_name;
    Word	vna_next;
}

typedef Half Versym;

struct Syminfo {
    Half	si_boundto;	// direct bindings - symbol bound to
    Half	si_flags;	// per symbol flags
}

struct link_map {
    Addr	l_addr;		// Base Address of library
    Addr	l_name;		// Absolute Path to Library
    Addr	l_ld;		// Pointer to .dynamic in memory
    Addr	l_next, l_prev;	// linked list of of mapped libs
}

struct r_debug {
    Sword	r_version;	// not used
    Addr 	r_map;		// list of loaded images
    Addr	r_brk;		// pointer to break point
    Sword	r_state;	// RT_CONSISTENT, RT_ADD, RT_DELETE
}

