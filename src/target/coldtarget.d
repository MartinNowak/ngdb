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

module target.coldtarget;

import target.target;
import objfile.objfile;
import objfile.elf;
import objfile.debuginfo;
import objfile.dwarf;
import machine.machine;
import machine.x86;

import std.stdint;
import std.stdio;
import std.string;
import std.c.stdlib;
version (DigitalMars)
import std.c.freebsd.freebsd;
else
import std.c.unix.unix;

static import std.file;

class ColdModule: TargetModule
{
    this(char[] filename, ulong addr)
    {
	void setLimits(uint tag, ulong s, ulong e)
	{
	    if (tag != PT_LOAD)
		return;
	    if (s < start_)
		start_ = s;
	    if (e > end_)
		end_ = e;
	}

	filename_ = filename;
	start_ = ~0L;
	end_ = 0;
	obj_ = cast(Elffile) Objfile.open(filename_, addr);
	if (obj_)
	    obj_.enumerateProgramHeaders(&setLimits);
	if (obj_ && DwarfFile.hasDebug(obj_))
	    dwarf_ = new DwarfFile(obj_);
    }

    override {
	char[] filename()
	{
	    return filename_;
	}

	ulong start()
	{
	    return start_;
	}

	ulong end()
	{
	    return end_;
	}

	bool contains(ulong addr)
	{
	    return addr >= start && addr < end_;
	}

	DebugInfo debugInfo()
	{
	    return dwarf_;
	}

	bool lookupSymbol(string name, out TargetSymbol ts)
	{
	    if (obj_) {
		Symbol* s = obj_.lookupSymbol(name);
		if (s) {
		    ts.name = s.name;
		    ts.value = s.value;
		    ts.size = s.size;
		    return true;
		}
	    }
	    return false;
	}	
	bool lookupSymbol(ulong addr, out TargetSymbol ts)
	{
	    if (obj_) {
		Symbol* s = obj_.lookupSymbol(addr);
		if (s) {
		    ts = TargetSymbol(s.name, s.value, s.size);
		    return true;
		}
	    }
	    return false;
	}
	bool inPLT(ulong addr)
	{
	    return false;
	}
	string[] contents(MachineState state)
	{
	    if (dwarf_)
		return dwarf_.contents(state);
	    return null;
	}
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    if (dwarf_)
		return dwarf_.lookup(name, state, val);
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

    MachineState getState(Target target)
    {
	if (obj_)
	    return obj_.getState(target);
	return null;
    }

    string interpreter()
    {
	if (obj_)
	    return obj_.interpreter;
	return null;
    }

    void enumerateNeededLibraries(Target target,
				  void delegate(string) dg)
    {
	if (obj_)
	    obj_.enumerateNeededLibraries(target, dg);
    }

    void digestDynamic(Target target)
    {
	if (obj_)
	    obj_.digestDynamic(target);
    }

    void enumerateLinkMap(Target target,
			  void delegate(string, ulong, ulong) dg)
    {
	if (obj_)
	    return obj_.enumerateLinkMap(target, dg);
	return;
    }

    int opEquals(ColdModule mod)
    {
	return filename_ == mod.filename_
	    && start_ == mod.start_
	    && end_ == mod.end_;
    }

    ubyte[] readMemory(ulong targetAddress, size_t bytes)
    {
	if (obj_)
	    return obj_.readProgram(targetAddress, bytes);
	return null;
    }

private:
    string filename_;
    ulong start_;
    ulong end_;
    Elffile obj_;
    DwarfFile dwarf_;
}

class ColdThread: TargetThread
{
    this(ColdTarget target, ubyte* p)
    {
	target_ = target;
	id_ = target.nextTid_++;
	state_ = target.modules_[0].getState(target);
	if (p)
	    state.setGRs(p);
	else if (target.modules_[0].obj_)
	    state.pc = target.modules_[0].obj_.entry;
    }

    override {
	Target target()
	{
	    return target_;
	}
	MachineState state()
	{
	    return state_;
	}
	uint id()
	{
	    return id_;
	}
    }

    ColdTarget target_;
    uint id_;
    MachineState state_;
}

struct prstatus32
{
    int32_t pr_version;		// must be 1
    uint32_t pr_statussz;
    uint32_t pr_gregsetsz;
    uint32_t pr_fpregsetsz;
    int32_t pr_osreldate;
    int32_t pr_cursig;
    int32_t pr_pid;
}

private string pathSearch(string path, string name)
{
    string execpath = "";

    execpath = name;
    if (find(execpath, "/") < 0) {
	string[] paths = split(path, ":");
	foreach (p; paths) {
	    string s = p ~ "/" ~ execpath;
	    if (std.file.exists(s) && std.file.isfile(s)) {
		execpath = s;
		break;
	    }
	}
    } else {
	if (!std.file.exists(execpath) || !std.file.isfile(execpath))
	    execpath = "";
    }
    return execpath;
}

class ColdTarget: Target
{
    this(TargetListener listener, string execname, string corename)
    {
	listener_ = listener;
	execname_ = execname;
	corename_ = corename;
	if (corename_)
	    core_ = cast(Elffile) Objfile.open(corename_, 0);

	listener.onTargetStarted(this);

	modules_ ~= new ColdModule(execname_, 0);
	listener_.onModuleAdd(this, modules_[0]);

	if (core_) {
	    void getThread(uint type, string name, ubyte* desc)
	    {
		if (type != NT_PRSTATUS)
		    return;
		prstatus32* pr = cast(prstatus32*) desc;
		auto t = new ColdThread(this, desc + prstatus32.sizeof);
		threads_ ~= t;
		listener_.onThreadCreate(this, t);
		static if (false)
		    if (pr.pr_cursig)
			listener_.onSignal(this, t, pr.pr_cursig,
					   signame(pr.pr_cursig));
	    }

	    void findCoreModules(string name, ulong lm, ulong addr)
	    {
		foreach (mod; modules_)
		    if (mod.filename == name)
			return;
		auto mod = new ColdModule(name, addr);
		modules_ ~= mod;
		listener_.onModuleAdd(this, mod);
	    }

	    modules_[0].digestDynamic(this);
	    modules_[0].enumerateLinkMap(this, &findCoreModules);

	    core_.enumerateNotes(&getThread);
	    if (threads_.length == 0) {
		threads_ ~= new ColdThread(this, null);
		listener_.onThreadCreate(this, threads_[0]);
	    }
	} else {
	    size_t i = 0;
	    ulong addr = 0x28070000;
	    string interp = modules_[0].interpreter;
	    if (interp) {
		auto mod = new ColdModule(interp, addr);
		addr = (mod.end + 0xfff) & ~0xfff; // XXX pagesize
		modules_ ~= mod;
		listener_.onModuleAdd(this, mod);
	    }
	    while (i < modules_.length) {
		void neededLib(string name)
		{
		    name = pathSearch("/lib:/usr/lib", name);
		    foreach (mod; modules_)
			if (mod.filename == name)
			    return;
		    auto mod = new ColdModule(name, addr);
		    addr = (mod.end + 0xfff) & ~0xfff; // XXX pagesize
		    modules_ ~= mod;
		    listener_.onModuleAdd(this, mod);
		}

		modules_[i].enumerateNeededLibraries(this, &neededLib);
		i++;
	    }

	    threads_ ~= new ColdThread(this, null);
	    listener_.onThreadCreate(this, threads_[0]);
	}
    }

    ~this()
    {
	modules_ = null;
	threads_ = null;
	listener_ = null;
    }

    override
    {
	TargetState state()
	{
	    return state_;
	}

	ubyte[] readMemory(ulong targetAddress, size_t bytes)
	{
	    if (core_) {
		bool readcore = false;
		void checkAddress(uint tag, ulong s, ulong e)
		{
		    if (tag != PT_LOAD)
			return;
		    if (targetAddress + bytes > s && targetAddress < e)
			readcore = true;
		}
		core_.enumerateProgramHeaders(&checkAddress);
		if (readcore)
		    return core_.readProgram(targetAddress, bytes);
	    }
	    foreach (mod; modules_) {
		if (targetAddress + bytes > mod.start
		    && targetAddress < mod.end)
		    return mod.readMemory(targetAddress, bytes);
	    }
	    throw new TargetException("Can't read memory");
	}

	void writeMemory(ulong targetAddress, ubyte[] toWrite)
	{
	    throw new TargetException("Can't write memory");
	}

	void step(TargetThread t)
	{
	}

	void cont(int)
	{
	}

	void wait()
	{
	}

	void setBreakpoint(ulong, TargetBreakpointListener)
	{
	}

	void clearBreakpoint(TargetBreakpointListener)
	{
	}
    }

private:
    TargetState state_ = TargetState.EXIT;
    uint nextTid_ = 1;
    ColdModule[] modules_;
    ColdThread[] threads_;
    TargetListener listener_;
    string execname_;
    string corename_;
    Elffile core_;
}
