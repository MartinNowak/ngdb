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

module elfmodule;

import target;
import std.stdint;
import std.stdio;
import std.string;
import std.c.unix.unix;
import sys.pread;

import elf;
import dwarf;
public import elf: Symbol;

class ElfModule: TargetModule
{
    this(TargetModule mod)
    {
	mod_ = mod;

	int fd = open(toStringz(mod.filename), O_RDONLY);
	if (fd > 0) {
	    Ident ei;

	    if (pread(fd, &ei, ei.sizeof, 0) != ei.sizeof
		|| !IsElf(&ei)) {
		close(fd);
		return;
	    }
	    writefln("Elf format file %s", mod.filename);
	    switch (ei.ei_class) {
	    case ELFCLASS32:
		elf_ = new ElfFile32(fd);
		break;
	    case ELFCLASS64:
		elf_ = new ElfFile64(fd);
		break;
	    default:
		throw new Exception("Unsupported elf class");
	    }

	    if (DwarfFile.hasDebug(elf_))
		dwarf_ = new DwarfFile(elf_);
	}
    }

    Symbol* lookupSymbol(uintptr_t addr)
    {
	if (elf_) {
	    addr -= elf_.offset;
	    return elf_.lookupSymbol(addr);
	} else {
	    return null;
	}
    }
    Symbol* lookupSymbol(string name)
    {
	return elf_.lookupSymbol(name);
    }

    override {
	char[] filename()
	{
	    return mod_.filename;
	}
	uintptr_t start()
	{
	    return mod_.start;
	}
	uintptr_t end()
	{
	    return mod_.end;
	}
	TargetModule findSubModule(uintptr_t pc)
	{
	    TargetModule cu = dwarf_.findCompileUnit(pc);
	    if (cu)
		return cu;
	    return this;
	}
    }

private:
    TargetModule mod_;
    ElfFile elf_;
    DwarfFile dwarf_;
}
