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

module target.ptracetarget;

//debug = ptrace;

import target.target;
import objfile.objfile;
import objfile.elf;
import debuginfo.debuginfo;
import debuginfo.dwarf;
import debuginfo.types;
import machine.machine;
import sys.environ;

import std.algorithm;
import std.exception;
import std.stdint;
import std.stdio;
import std.string;
import std.c.stdlib;

import core.sys.posix.sys.types;
import core.sys.posix.sys.wait;
import core.sys.posix.fcntl;
import core.sys.posix.signal;
import core.sys.posix.unistd;
import core.stdc.errno;

version (FreeBSD) {
	version = use_PT_IO;
}

static import std.file;

import sys.ptrace;
import sys.wait;

extern (C)
{
    char* strerror(int);
    char* realpath(const(char)*, char*);
}

version (linux) {
    const uint __WALL = 0x40000000;
    const uint __WCLONE = 0x80000000;
    extern (C) int syscall(int, ...);
    int tkill(int tid, int sig)
    {
	const int SYS_tkill = 238;
	return syscall(238, tid, sig);
   }
}

class PtraceException: ErrnoException
{
    this(string msg = null, string file =__FILE__, uint line = __LINE__)
    {
        super(msg, file, line);
    }
}

class PtraceModule: TargetModule
{
    this(string filename, ulong start, ulong end)
    {
	filename_ = filename;
	start_ = start;
	end_ = end;
    }

    ulong entry()
    {
	if (obj_)
	    return obj_.entry;
	return 0;
    }

    void init()
    {
	if (!obj_) {
	    //writefln("Opening %s at %#x", filename_, start_);
	    obj_ = Objfile.open(filename_, start_);
	    if (obj_) {
		if (DwarfFile.hasDebug(obj_)) {
		    //writefln("Offset is %#x", obj_.offset);
		    //writefln("Reading debug info for %s", filename_);
		    dwarf_ = new DwarfFile(obj_);
		}
		auto elf = cast(Elffile) obj_;
	    }
	}
    }

    void digestDynamic(PtraceTarget target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return;
	    elf.digestDynamic(target);

	    TargetSymbol sym;
	    if (lookupSymbol("_thread_off_linkmap", sym)) {
		ubyte[] t = target.readMemory(sym.value, 4);
		target.linkmapOffset_ = elf.read(*cast(int*) &t[0]);
	    }
	    if (lookupSymbol("_thread_off_tlsindex", sym)) {
		ubyte[] t = target.readMemory(sym.value, 4);
		target.tlsindexOffset_ = elf.read(*cast(int*) &t[0]);
	    }

	    if (target.linkmapOffset_ && target.tlsindexOffset_
		&& target.modules_.length > 0
		&& this !is target.modules_[0]) {
		void findTlsindex(string name, ulong lm, ulong addr)
		{
		    if (addr == start_) {
			ulong p = lm - target.linkmapOffset_
			    + target.tlsindexOffset_;
			ubyte[] t = target.readMemory(p, 4);
			int tlsindex = elf.read(*cast(int*) &t[0]);
			//writefln("Module %s TLS index is %d", filename_, tlsindex);
			elf.tlsindex = tlsindex;
		    }
		}
		target.modules_[0].enumerateLinkMap(target, &findTlsindex);
	    } else {
		elf.tlsindex = 1;
	    }
	}
    }

    ulong findSharedLibraryBreakpoint(Target target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return 0;
	    return elf.findSharedLibraryBreakpoint(target);
	}
	return 0;
    }

    uint sharedLibraryState(Target target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return 0;
	    return elf.sharedLibraryState(target);
	}
	return 0;
    }

    void enumerateLinkMap(Target target,
			  void delegate(string, ulong, ulong) dg)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return;
	    return elf.enumerateLinkMap(target, dg);
	}
	return;
    }

    override {
	string filename() const
	{
	    return filename_;
	}

	ulong start() const
	{
	    return start_;
	}

	ulong end() const
	{
	    return end_;
	}

	bool contains(ulong addr) const
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
	bool inPLT(ulong pc) const
	{
	    if (obj_) {
		auto elf = cast(Elffile)obj_;
		if (!elf)
		    return false;
		return elf.inPLT(pc);
	    }
	    return false;
	}
	string[] contents(MachineState state)
	{
	    if (dwarf_)
		return dwarf_.contents(state);
	    return null;
	}
	DebugItem lookup(string name, MachineState state)
	{
	    return (dwarf_ is null) ? null : dwarf_.lookup(name, state);
	}
	Type lookupStruct(string name)
	{
	    return (dwarf_ is null) ? null : dwarf_.lookupStruct(name);
	}
	Type lookupUnion(string name)
	{
	    return (dwarf_ is null) ? null : dwarf_.lookupUnion(name);
	}
	Type lookupTypedef(string name)
	{
	    return (dwarf_ is null) ? null : dwarf_.lookupTypedef(name);
	}
    }

    MachineState getState(Target target)
    {
	return obj_.getState(target);
    }

    override equals_t opEquals(Object o)
    {
        if (auto mod = cast(PtraceModule)o)
            return filename_ == mod.filename_
                && start_ == mod.start_;
        else
            return false;
    }

private:
    string filename_;
    ulong start_;
    ulong end_;
    Objfile obj_;
    DwarfFile dwarf_;
}

class PtraceBreakpoint
{
    this(PtraceTarget target, ulong addr)
    {
	target_ = target;
	addr_ = addr;
    }

    void activate()
    {
	/*
	 * Write a breakpoint instruction, saving what was there
	 * before.
	 */
	save_ = target_.readMemory(addr_, target_.break_.length, false);
	target_.writeMemory(addr_, target_.break_, false);
    }

    void deactivate()
    {
	/*
	 * Disable by writing back our saved bytes.
	 */
	target_.writeMemory(addr_, save_, false);
	stoppedThreads_.length = 0;
    }

    ulong address()
    {
	return addr_;
    }

    void addListener(TargetBreakpointListener tbl)
    {
	listeners_ ~= tbl;
    }

    void removeListener(TargetBreakpointListener tbl)
    {
	TargetBreakpointListener[] newListeners;

	foreach (t; listeners_)
	    if (t !is tbl)
		newListeners ~= t;
	listeners_ = newListeners;
    }

    bool matchListener(TargetBreakpointListener tbl)
    {
	foreach (t; listeners_)
	    if (t is tbl)
		return true;
	return false;
    }

    TargetBreakpointListener[] listeners()
    {
	return listeners_;
    }

private:
    PtraceTarget target_;
    ulong addr_;
    TargetBreakpointListener[] listeners_;
    PtraceThread[] stoppedThreads_;
    ubyte[] save_;
}

class PtraceThread: TargetThread
{
    this(PtraceTarget target, lwpid_t lwpid)
    {
	target_ = target;
	id_ = target.nextTid_++;
	lwpid_ = lwpid;
	state_ = target_.modules_[0].getState(target_);
    }
    override
    {
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
        int tid()
        {
            return lwpid_;
        }
    }

private:
    void suspend()
    {
	version (FreeBSD)
	    target_.ptrace(PT_SUSPEND, lwpid_, null, 0);
	version (linux)
	    suspended_ = true;
    }
    void resume()
    {
	version (FreeBSD)
	    target_.ptrace(PT_RESUME, lwpid_, null, 0);
	version (linux)
	    suspended_ = false;
    }
    version (linux) {
	bool stop()
	{
	    tkill(lwpid_, SIGSTOP);
	    int[] pendingSigs;
	    bool stopped = false;
	    while (!stopped) {
		int status;
		auto tmp = .waitpid(lwpid_, &status, __WALL);
		assert(tmp == lwpid_);
		if (status >> 16) {
		    target_.threadEvent(lwpid_, status >> 16, true);
		    ptrace(PT_CONTINUE, lwpid_, null, 0);
		    continue;
		}
		if (!WIFSTOPPED(status))
		    return false;
		if (WSTOPSIG(status) == SIGSTOP) {
		    stopped = true;
		} else {
		    pendingSigs ~= WSTOPSIG(status);
		    ptrace(PT_CONTINUE, lwpid_, null, 0);
		}
	    }
	    foreach (sig; pendingSigs)
		tkill(lwpid_, sig);
	    return true;
	}
    }
    void readState()
    {
	try {
	    auto cmds = state_.ptraceReadCommands;
	    foreach (cmd; cmds)
		target_.ptrace(cmd.req, lwpid_, cast(char*) cmd.addr, cmd.data);
	} catch (PtraceException pte) {
	    /*
	     * We may get an error reading GSBASE if the kernel doesn't
	     * support it.
	     */
	}
    }
    void writeState()
    {
	auto cmds = state_.ptraceWriteCommands;
	foreach (cmd; cmds)
	    target_.ptrace(cmd.req, lwpid_, cast(char*) cmd.addr, cmd.data);
    }

    PtraceTarget target_;
    uint id_;
    lwpid_t lwpid_;
    MachineState state_;
    int waitStatus_;
    version (linux) {
	bool suspended_;
    }
}

string signame(int sig)
{
    static string signames[] = [
	SIGHUP: "SIGHUP",
	SIGINT: "SIGINT",
	SIGQUIT: "SIGQUIT",
	SIGILL: "SIGILL",
	SIGTRAP: "SIGTRAP",
	SIGABRT: "SIGABRT",
	//SIGIOT: "SIGIOT",
	//SIGEMT: "SIGEMT",
	SIGFPE: "SIGFPE",
	SIGKILL: "SIGKILL",
	SIGBUS: "SIGBUS",
	SIGSEGV: "SIGSEGV",
	SIGSYS: "SIGSYS",
	SIGPIPE: "SIGPIPE",
	SIGALRM: "SIGALRM",
	SIGTERM: "SIGTERM",
	SIGURG: "SIGURG",
	SIGSTOP: "SIGSTOP",
	SIGTSTP: "SIGTSTP",
	SIGCONT: "SIGCONT",
	SIGCHLD: "SIGCHLD",
	SIGTTIN: "SIGTTIN",
	SIGTTOU: "SIGTTOU",
	SIGIO: "SIGIO",
	SIGXCPU: "SIGXCPU",
	SIGXFSZ: "SIGXFSZ",
	SIGVTALRM: "SIGVTALRM",
	SIGPROF: "SIGPROF",
	SIGWINCH: "SIGWINCH",
	//SIGINFO: "SIGINFO",
	SIGUSR1: "SIGUSR1",
	SIGUSR2: "SIGUSR2",
	//SIGTHR: "SIGTHR",
	//SIGLWP: "SIGLWP",
	//SIGRTMIN: "SIGRTMIN",
	//SIGRTMAX: "SIGRTMAX"
	];

    if (sig >= 0 && sig < signames.length)
	return signames[sig];
    else
	return std.string.format("SIG%d", sig);
}

class PtraceTarget: Target, TargetBreakpointListener
{
    this(TargetListener listener, pid_t pid, string execname, int status)
    {
	pid_ = pid;
	version (linux)
	    stoppedPid_ = pid_;
	listener_ = listener;
	execname_ = execname;
	breakpointsActive_ = false;
	listener.onTargetStarted(this);
	getModules();

        // TODO: linux only, especially notice about main thread??
	version (linux) {
	    ptrace(PTRACE_SETOPTIONS, pid_, null,
		   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);
	    auto t = new PtraceThread(this, pid_);
	    break_ = t.state_.breakpoint;
	    listener_.onThreadCreate(this, t);
	    threads_[pid_] = t;
	}

	stopped(status);

	/*
	 * Continue up to the program entry point (or a user
	 * breakpoint if that happens first).
	 */
	if (modules_[0].entry) {
	    setBreakpoint(modules_[0].entry, this);
	    cont(0);
	    wait;
	}
    }

    override
    {
	TargetState state()
	{
	    return state_;
	}
	ulong entry()
	{
	    if (modules_.length > 0)
		return modules_[0].entry;
	    else
		return 0;
	}
	ubyte[] readMemory(ulong targetAddress, size_t bytes)
	{
	    return readMemory(targetAddress, bytes, true);
	}

	void writeMemory(ulong targetAddress, ubyte[] toWrite)
	{
	    return writeMemory(targetAddress, toWrite, true);
	}

	void step(TargetThread t)
	{
	    assert(state_ == TargetState.STOPPED);

	    try {
		PtraceThread pt = cast(PtraceThread) t;
		foreach (pt2; threads_)
		    if (pt2 !is pt)
			pt2.suspend;
		pt.writeState;
		ptrace(PT_STEP, pt.lwpid_, cast(char*) 1, 0);
		state_ = TargetState.RUNNING;
		wait();
		assert(focusThread is pt);
		foreach (pt2; threads_)
		    if (pt2 !is pt)
			pt2.resume;
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
	    }
	}

	void cont(int signo)
	{
	    assert(state_ == TargetState.STOPPED);

	    try {
		/*
		 * If a thread is currently sitting on a breakpoint, step
		 * over it.
		 */
		foreach (t; threads_)
		    t.writeState;
		foreach (pbp; breakpoints_) {
		    foreach (t; pbp.stoppedThreads_) {
			debug(breakpoints)
			    writefln("stepping thread %d over breakpoint at 0x%x",
				     t.id, t.state.pc);
			step(t);
			debug(breakpoints)
			    writefln("after step, thread %d pc is 0x%x",
				     t.id, t.state.pc);
		    }
		    pbp.stoppedThreads_.length = 0;
		}

		foreach (pbp; breakpoints_)
		    pbp.activate;
		breakpointsActive_ = true;
		version (FreeBSD)
		    ptrace(PT_CONTINUE, pid_, cast(char*) 1, signo);
		version (linux)
		    foreach (t; threads_)
			if (!t.suspended_)
			    ptrace(PT_CONTINUE, t.lwpid_, null, 0);
		state_ = TargetState.RUNNING;
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
	    }
	}

	void wait()
	{
	    assert(state_ == TargetState.RUNNING);

	    try {
		int status;
		do {
		    version (FreeBSD)
			waitpid(pid_, &status, 0);
		    version (linux) {
			if (threads_.length == 0) {
			    onExit;
			    return;
			}
			stoppedPid_ = waitpid(-1, &status, __WALL);
		    }
		    state_ = TargetState.STOPPED;
		} while (!stopped(status));
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
	    }
	}

	void setBreakpoint(ulong addr, TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("setting breakpoint at 0x%x for 0x%x", addr,
			 cast(ulong) cast(void*) tbl);
	    if (addr in breakpoints_) {
		breakpoints_[addr].addListener(tbl);
	    } else {
		PtraceBreakpoint pbp = new PtraceBreakpoint(this, addr);
		pbp.addListener(tbl);
		breakpoints_[addr] = pbp;
	    }
	}

        // TODO: improve
	void clearAllBreakpoints(TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("clearing breakpoints for 0x%x",
			 cast(ulong) cast(void*) tbl);
	    PtraceBreakpoint[ulong] newBreakpoints;
	    foreach (addr, pbp; breakpoints_) {
		if (pbp.matchListener(tbl)) {
		    pbp.removeListener(tbl);
		}
		if (pbp.listeners.length > 0)
		    newBreakpoints[addr] = pbp;
	    }
	    breakpoints_ = newBreakpoints;
	}

	void clearBreakpoint(ulong addr, TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("clearing breakpoint at %#x for %#x", addr, cast(void*)tbl);
            if (auto pbp = addr in breakpoints_) {
                if (pbp.matchListener(tbl))
                    pbp.removeListener(tbl);
                if (pbp.listeners.length == 0)
                    breakpoints_.remove(addr);
            }
        }

	bool onBreakpoint(Target, TargetThread, ulong addr)
	{
	    if (!sharedLibraryBreakpoint_) {
		/*
		 * We are stopped at program entry point. The dynamic
		 * linker is done now so we re-read the module lists
		 * and see if we can figure out how to monitor dlopen
		 * and dlclose.
		 */
		clearAllBreakpoints(this);
		getModules;
		/*
		 * Re-read dynamic entries - the runtime linker may have
		 * changed the value of DT_DEBUG.
		 */
		PtraceModule execMod;
		foreach (mod; modules_) {
		    mod.digestDynamic(this);
		    if (mod.obj_ && mod.obj_.isExecutable)
			execMod = mod;
		}
		if (execMod)
		    sharedLibraryBreakpoint_ =
			execMod.findSharedLibraryBreakpoint(this);
		if (sharedLibraryBreakpoint_) {
		    debug (breakpoints)
			writefln("Shared library breakpoint @ %#x",
			    sharedLibraryBreakpoint_);
		    setBreakpoint(sharedLibraryBreakpoint_, this);
		}
		return false;
	    } else {
		/*
		 * We stopped at our shared lib monitor.
		 */
		if (modules_[0].sharedLibraryState(this)
		    == RT_CONSISTENT)
		    getModules;
		return false;
	    }
	}

        int delegate(scope int delegate(ref TargetModule mod) dg) modules() {
            return &applyModules;
        }

        int delegate(scope int delegate(ref TargetThread thr) dg) threads() {
            return &applyThreads;
        }
    }

    final int applyModules(scope int delegate(ref TargetModule mod) dg) {
        foreach(TargetModule mod; modules_)
            if (auto res = dg(mod)) return res;
        return 0;
    }

    final int applyThreads(scope int delegate(ref TargetThread thr) dg) {
        foreach(pthr; threads_) {
            TargetThread tthr = pthr;
            if (auto res = dg(tthr)) return res;
        }
        return 0;
    }

    PtraceThread focusThread()
    {
	version (FreeBSD) {
	    ptrace_lwpinfo info;

	    try {
		ptrace(PT_LWPINFO, pid_, cast(char*) &info, info.sizeof);
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
		return null;
	    }
	    return threads_[info.pl_lwpid];
	}
	version (linux) {
	    assert(stoppedPid_ in threads_);
	    return threads_[stoppedPid_];
	}
    }

    ubyte[] readMemory(ulong targetAddress, size_t bytes, bool data)
    {
	debug (ptrace)
	    writefln("Reading %d bytes of %s @ %#x",
		     bytes,
		     data ? "data" : "text",
		     targetAddress);
	version (use_PT_IO) {
	    ubyte[] result;
	    ptrace_io_desc io;

	    try {
		result.length = bytes;
		io.piod_op = data ? PIOD_READ_D : PIOD_READ_I;
		io.piod_offs = cast(void*) targetAddress;
		io.piod_addr = cast(void*) result.ptr;
		io.piod_len = bytes;
		ptrace(PT_IO, pid_, cast(char*) &io, 0);
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
		throw new TargetException("Can't read target memory");
	    }

	    return result;
	} else {
	    ubyte[] result;
	    ulong start = targetAddress & ~3;
	    ulong end = (targetAddress + bytes + 3) & ~3;

	    try {
		result.length = end - start;
		int op = data ? PT_READ_D : PT_READ_I;
		for (auto i = start; i < end; i += 4) {
		    uint word = ptrace(op, pid_, cast(char*) i, 0);
		    *(cast(uint*) &result[i - start]) = word;
		}
		auto off = targetAddress - start;
		result = result[off..off + bytes];
	    } catch (PtraceException pte) {
		debug (ptrace)
		    writefln("ptrace error: %s", pte.msg);
		if (pte.errno == ESRCH)
		    onExit;
		throw new TargetException("Can't read target memory");
	    }

	    return result;
	}
    }

    void writeMemory(ulong targetAddress, ubyte[] toWrite, bool data)
    {
	version (use_PT_IO) {
	    ptrace_io_desc io;

	    try {
		io.piod_op = data ? PIOD_WRITE_D : PIOD_WRITE_I;
		io.piod_offs = cast(void*) targetAddress;
		io.piod_addr = cast(void*) toWrite.ptr;
		io.piod_len = toWrite.length;
		ptrace(PT_IO, pid_, cast(char*) &io, 0);
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
	    }
	} else {
	    auto bytes = toWrite.length;
	    ulong start = targetAddress & ~3;
	    ulong end = (targetAddress + bytes + 3) & ~3;

	    if (end - start == 4 && bytes < 4) {
		/*
		 * Special case for writing a subrange of a single
		 * word.
		 */
		auto tmp = readMemory(start, 4, data);
		auto off = targetAddress - start;
		tmp[off..off + bytes] = toWrite[];
		toWrite = tmp;
	    } else {
		if (start < targetAddress) {
		    toWrite = readMemory(start, targetAddress - start, data)
			~ toWrite;
		}
		if (end > targetAddress + bytes) {
		    toWrite = toWrite
			~ readMemory(targetAddress + bytes,
				     end - targetAddress - bytes, data);
		}
	    }

	    try {
		int op = data ? PT_WRITE_D : PT_WRITE_I;
		for (auto i = start; i < end; i += 4) {
		    uint word = *(cast(uint*) &toWrite[i - start]);
		    ptrace(op, pid_, cast(char*) i, word);
		}
	    } catch (PtraceException pte) {
		if (pte.errno == ESRCH)
		    onExit;
		throw new TargetException("Can't write target memory");
	    }
	}
    }

private:
    void onExit()
    {
	if (listener_)
	    listener_.onExit(this);
	threads_ = null;
	modules_ = null;
	breakpoints_ = null;
	listener_ = null;
    }

    version (FreeBSD) {
	void getThreads()
	{
	    lwpid_t[] newThreads;

	    PtraceThread[lwpid_t] oldThreads;
	    foreach (tid, t; threads_)
		oldThreads[tid] = t;

	    newThreads.length = ptrace(PT_GETNUMLWPS, pid_, null, 0);
	    ptrace(PT_GETLWPLIST, pid_,
		   cast(char*) newThreads.ptr,
		   std.conv.to!int(newThreads.length * lwpid_t.sizeof));

	    foreach (ntid; newThreads) {
		if (ntid in threads_) {
		    oldThreads.remove(ntid);
		    continue;
		}
		PtraceThread t = new PtraceThread(this, ntid);
		if (break_.length == 0)
		    break_ = t.state_.breakpoint;
		listener_.onThreadCreate(this, t);
		threads_[ntid] = t;
	    }
	    foreach (otid, t; oldThreads) {
		listener_.onThreadDestroy(this, t);
		threads_.remove(otid);
	    }
	}
    }

    string realpath(string filename)
    {
	char[1024] buf;
	char* p = .realpath(toStringz(filename), buf.ptr);
	if (p)
	    return std.conv.to!string(p);
	return filename;
    }

    void getModules()
    {
	string maps = readMaps();
	if (maps == lastMaps_)
	    return;
	lastMaps_ = maps;

	PtraceModule[] modules;
	PtraceModule lastMod;

	void processModule(string name, ulong start, ulong end)
	{
	    name = realpath(name);
	    if (lastMod &&
		(lastMod.filename_ == name
		 || lastMod.end_ == start)) {
		lastMod.end_ = end;
	    } else {
		PtraceModule mod =
		    new PtraceModule(name, start, end);
		modules ~= mod;
		lastMod = mod;
	    }
	}

	ulong atoi(string s) {
	    return std.c.stdlib.strtoull(toStringz(s), null, 0);
	}

	string[] lines = splitLines(maps);
	version (FreeBSD) {
	    foreach (line; lines) {
		string[] words = split(line);
		if (words[11] == "vnode") {
		    string name = words[12];
		    if (name == "-")
			name = execname_;
		    ulong start = atoi(words[0]);
		    ulong end = atoi(words[1]);

		    processModule(name, start, end);
		}
	    }
	}
	version (linux) {
	    foreach (line; lines) {
		string[] words = split(squeeze(line, " "));
		if (words.length == 6 && words[5][0] == '/') {
		    string name = words[5];
		    string[] t = split(words[0], "-");
		    ulong start = atoi("0x" ~ t[0]);
		    ulong end = atoi("0x" ~ t[1]);

		    processModule(name, start, end);
		}
	    }
	}

	PtraceModule[] newModules;
	PtraceModule[] oldModules;

	foreach (mod; modules_) {
	    bool seenit = false;
	    foreach (nmod; modules)
		if (mod == nmod)
		    seenit = true;
	    if (seenit)
		newModules ~= mod;
	    else
		oldModules ~= mod;
	}

	foreach (mod; modules) {
	    bool seenit = false;
	    foreach (omod; modules_)
		if (mod == omod)
		    seenit = true;
	    if (!seenit) {
		mod.init;
		mod.digestDynamic(this);
		listener_.onModuleAdd(this, mod);
		newModules ~= mod;
	    }
	}

	foreach (mod; oldModules)
	    listener_.onModuleDelete(this, mod);

	/*
	 * Discard any breakpoint records that don't have addresses
	 * within our new module list.
	 */
	foreach (addr; breakpoints_.keys) {
	    bool keep = false;
	    foreach (mod; newModules)
		if (mod.contains(addr))
		    keep = true;
	    if (!keep)
		breakpoints_.remove(addr);
	}

	modules_ = newModules;
    }

    version (FreeBSD) {
	string readMaps()
	{
            string mapfile = "/proc/" ~ std.conv.to!string(pid_) ~ "/map";
	    char[] result;

	    auto fd = open(toStringz(mapfile), O_RDONLY);
	    if (fd < 0) {
		writefln("can't read %s", mapfile);
		writefln("Add this line to /etc/fstab:");
		writefln("proc /proc procfs rw 0 0");
		exit(1);
	    }

	    result.length = 512;
	    for (;;) {
		/*
		 * The kernel requires that we read the whole thing in one
		 * call. We keep resizing the buffer until we read less
		 * than the buffer size.
		 */
		ssize_t nread;
		lseek(fd, 0, SEEK_SET);
		nread = read(fd, result.ptr, result.length);
		if ((nread < 0 && errno == EFBIG)
		    || nread == result.length) {
		    result.length = 2 * result.length;
		    continue;
		}
		result.length = nread;
		break;
	    }

	    return result.idup;
	}
    }
    version (linux) {
	string readMaps()
	{
	    string mapfile = "/proc/" ~ std.string.toString(pid_) ~ "/maps";
	    string result;

	    auto fd = open(toStringz(mapfile), O_RDONLY);
	    if (fd < 0) {
		writefln("can't read %s", mapfile);
		exit(1);
	    }

	    for (;;) {
		/*
		 * The kernel requires that we read the whole thing in one
		 * call. We keep resizing the buffer until we read less
		 * than the buffer size.
		 */
		char buf[512];
		ssize_t nread;
		nread = read(fd, buf.ptr, buf.length);
		if (nread <= 0)
		    break;
		result ~= buf[0..nread];
	    }

	    return result;
	}
    }

    version (linux) {
	void threadEvent(int pid, int event, bool stopping)
	{
	    int tid;
	    switch (event) {
	    case PTRACE_EVENT_CLONE:
		ptrace(PTRACE_GETEVENTMSG, pid, null, cast(uint) &tid);
		int status;
		auto tmp = .waitpid(tid, &status, __WCLONE);
		if (tmp != tid)
		    writefln("waitpid for new thread %d returned %d",
			     tid, tmp);
		auto t = new PtraceThread(this, tid);
		listener_.onThreadCreate(this, t);
		threads_[tid] = t;
		if (!stopping)
		    ptrace(PT_CONTINUE, tid, null, 0);
		return false;

	    case PTRACE_EVENT_EXIT:
		listener_.onThreadDestroy(this, threads_[pid]);
		threads_.remove(pid);
		return false;

	    default:
		assert(false);
	    }
	}
    }

    bool stopped(int waitStatus)
    {
	bool ret = true;

	version (linux)
	    getModules;
	bool checkBreakpoints = breakpointsActive_;
	version (FreeBSD) {
	    getThreads();
	    foreach (t; threads_)
		t.readState();
	}
	version (linux) {
	    if (WIFEXITED(waitStatus))
		return false;
	    int event = (waitStatus >> 16) & 0xffff;
	    if (event) {
		threadEvent(stoppedPid_, event, false);
		ptrace(PT_CONTINUE, stoppedPid_, null, 0);
		return false;
	    }
	    foreach (t; threads_.values.dup) {
		if (t.lwpid_ != stoppedPid_ && !t.suspended_) {
		    if (!t.stop)
			continue;
		}
		t.readState;
	    }
	}
	if (breakpointsActive_) {
	    foreach (pbp; breakpoints_)
		pbp.deactivate();
	    breakpointsActive_ = false;
	}

	PtraceThread pt = focusThread;
	pt.waitStatus_ = waitStatus;

	if (WIFSTOPPED(waitStatus)) {
	    if (WSTOPSIG(waitStatus) == SIGTRAP) {
		if (checkBreakpoints) {
		    /*
		     * A thread stopped at a breakpoint. Adjust its PC
		     * accordingly and find out what stopped it,
		     * informing our listener as appropriate.
		     */
		    pt.state.adjustPcAfterBreak;
		    foreach (pbp; breakpoints_.values) {
			if (pt.state.pc == pbp.address) {
			    pbp.stoppedThreads_ ~= pt;
			    ret = false;
			    foreach (tbl; pbp.listeners) {
				debug(breakpoints)
				    writefln("hit breakpoint at 0x%x for 0x%x",
					     pt.state.pc,
					     cast(ulong) cast(void*) tbl);
				if (tbl.onBreakpoint(this, pt, pbp.address))
				    ret = true;
			    }
			}
		    }
		}
	    } else {
		int sig = WSTOPSIG(waitStatus);
		listener_.onSignal(this, focusThread, sig, signame(sig));
	    }
	}
	if (!ret)
	    cont(0);
	return ret;
    }

    static int ptrace(int op, int pid, char* p, int n)
    {
	int ret = .ptrace(op, pid, p, n);
	if (op == PT_READ_I || op == PT_READ_D)
	    return ret;
	if (ret < 0)
	    throw new PtraceException;
	return ret;
    }

    static int waitpid(int pid, int* statusp, int options)
    {
	int res;
	res = .waitpid(pid, statusp, options);
	if (res < 0)
	    throw new PtraceException;
	return res;
    }

    TargetState state_ = TargetState.STOPPED;
    pid_t pid_;
    version (linux)
	pid_t stoppedPid_;
    uint nextTid_ = 1;
    PtraceThread[lwpid_t] threads_;
    PtraceModule[] modules_;
    PtraceBreakpoint[ulong] breakpoints_;
    TargetListener listener_;
    string execname_;
    bool breakpointsActive_;
    string lastMaps_;
    ulong sharedLibraryBreakpoint_;
    uint linkmapOffset_;
    uint tlsindexOffset_;
    ubyte[] break_;		// breakpoint instruction
}

class PtraceAttach: TargetFactory
{
    override
    {
	string name()
	{
	    return "attach";
	}

	Target connect(TargetListener listener, string[] args)
	{
	    int pid, status;

	    if (args.length != 1)
		throw new Exception("too many arguments to target attach");
	    pid = std.conv.to!int(args[0]);
	    PtraceTarget.ptrace(PT_ATTACH, pid, null, 0);
	    PtraceTarget.waitpid(pid, &status, 0);
	    return new PtraceTarget(listener, pid, "", status);
	}
    }
}

extern (C) int execve(const(char)*, const(char*)*, const(char*)*);

class PtraceRun: TargetFactory
{
    override
    {
	string name()
	{
	    return "run";
	}

	Target connect(TargetListener listener, string[] args)
	{
	    string[] path = split(std.conv.to!string(getenv("PATH")), ":");
	    string execpath = "";

	    debug (ptrace)
		writefln("PATH=%s", std.conv.to!string(getenv("PATH")));
	    execpath = args[0];
	    if (countUntil(execpath, "/") < 0) {
		foreach (p; path) {
		    string s = p ~ "/" ~ execpath;
		    debug (ptrace)
			    writefln("trying '%s'", s);
		    if (std.file.exists(s) && std.file.isfile(s)) {
			execpath = s;
			break;
		    }
		}
	    } else {
		if (!std.file.exists(execpath) || !std.file.isfile(execpath))
		    execpath = "";
	    }
	    if (execpath.length == 0) {
		throw new Exception("Can't find executable");
	    }

	    immutable(char)* pathz = std.string.toStringz(execpath);
	    immutable(char)*[] argv;

	    argv.length = args.length + 1;
	    foreach (i, arg; args)
		argv[i] = std.string.toStringz(arg);
	    argv[args.length] = null;

	    sigaction_t a;
	    sigaction(SIGTRAP, null, &a);

	    pid_t pid = fork();
	    if (pid) {
		/*
		 * This is the parent process. Wait for the child's
		 * first stop (which will be after the call to
		 * execve).
		 */
		int status;
		debug (ptrace)
		    writefln("waiting for execve");
		PtraceTarget.waitpid(pid, &status, 0);
		debug (ptrace)
		    writefln("done");
		return new PtraceTarget(listener, pid, execpath, status);
	    } else {
		/*
		 * This is the child process. We tell the kernel we
		 * want to be debugged and then use execve to start
		 * the required application.
		 */
		debug (ptrace)
		    writefln("child calling PT_TRACE_ME");
		if (ptrace(PT_TRACE_ME, 0, null, 0) < 0)
		    exit(1);
		debug (ptrace)
		    writefln("child execve(%s, ...)", execpath);
		setenv("LD_BIND_NOW", "yes", 1);
		execve(pathz, argv.ptr, environ);
		writefln("execve returned: %s",
			 std.conv.to!string(strerror(errno)));
		exit(1);
	    }

	    return null;
	}
    }
}
