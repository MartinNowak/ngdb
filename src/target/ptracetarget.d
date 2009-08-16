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

module target.ptracetarget;

//debug = ptrace;

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

import sys.ptrace;
import sys.wait;

extern (C)
{
    int errno;
    char* strerror(int);
    char* realpath(char*, char*);
}

class PtraceException: Exception
{
    this()
    {
	errno_ = errno;
	char[] s = std.string.toString(errno_).dup;
	super(s);
    }
    int errno_;
}

class PtraceModule: TargetModule
{
    this(char[] filename, ulong start, ulong end)
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
	bool inPLT(ulong pc)
	{
	    if (obj_) {
		auto elf = cast(Elffile) obj_;
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
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    if (dwarf_)
		return dwarf_.lookup(name, state, val);
	    return false;
	}
    }

    MachineState getState(Target target)
    {
	return obj_.getState(target);
    }

    int opEquals(PtraceModule mod)
    {
	return filename_ == mod.filename_
	    && start_ == mod.start_;
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
	save_ = target_.readMemory(addr_, break_.length, false);
	target_.writeMemory(addr_, break_, false);
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
    static ubyte[] break_ = [ 0xcc ]; // XXX i386 int3
}

class PtraceThread: TargetThread
{
    this(PtraceTarget target, lwpid_t lwpid)
    {
	target_ = target;
	id_ = target.nextTid_++;
	lwpid_ = lwpid;
	state_ = target_.modules_[0].getState(target_);
	regs_.length = state_.gregsSize;
	fpregs_.length = state_.fpregsSize;
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
    }

    void pc(ulong addr)
    {
	state_.setGR(pcRegno_, addr);
	writeState;
    }

private:
    void suspend()
    {
	target_.ptrace(PT_SUSPEND, lwpid_, null, 0);
    }
    void resume()
    {
	target_.ptrace(PT_RESUME, lwpid_, null, 0);
    }
    void readState()
    {
	target_.ptrace(PT_GETREGS, lwpid_, cast(char*) regs_.ptr, 0);
	state_.setGRs(regs_.ptr);
	grGen_ = state_.grGen;
	target_.ptrace(state_.ptraceGetFP, lwpid_, cast(char*) fpregs_.ptr, 0);
	state_.setFRs(fpregs_.ptr);
	frGen_ = state_.frGen;
	try {
	    uint32_t tp;
	    target_.ptrace(PT_GETGSBASE, lwpid_, cast(char*) &tp, 0);
	    state_.tp = tp;
	} catch (PtraceException pte) {
	    /*
	     * We may get an error reading GSBASE if the kernel doesn't 
	     * support it.
	     */
	}
    }
    void writeState()
    {
	if (grGen_ != state.grGen) {
	    state_.getGRs(regs_.ptr);
	    //writefln("write thread %d pc as %#x, eax as %#x", id, regs_.r_eip, regs_.r_eax);
	    target_.ptrace(PT_SETREGS, lwpid_, cast(char*) regs_.ptr, 0);
	    grGen_ = state.grGen;
	}
	if (frGen_ != state.frGen) {
	    state_.getFRs(fpregs_.ptr);
	    target_.ptrace(state.ptraceSetFP, lwpid_, cast(char*) fpregs_.ptr, 0);
	    frGen_ = state.frGen;
	}
    }

    static int pcRegno_ = X86Reg.EIP;

    PtraceTarget target_;
    uint id_;
    lwpid_t lwpid_;
    MachineState state_;
    ubyte[] regs_;
    uint grGen_;
    ubyte[] fpregs_;
    uint frGen_;
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
    this(TargetListener listener, pid_t pid, string execname)
    {
	pid_ = pid;
	listener_ = listener;
	execname_ = execname;
	breakpointsActive_ = false;
	listener.onTargetStarted(this);
	getModules();
	stopped();

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
		if (pte.errno_ == ESRCH)
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
		ptrace(PT_CONTINUE, pid_, cast(char*) 1, signo);
		state_ = TargetState.RUNNING;
	    } catch (PtraceException pte) {
		if (pte.errno_ == ESRCH)
		    onExit;
	    }
	}

	void wait()
	{
	    assert(state_ == TargetState.RUNNING);

	    try {
		do {
		    wait4(pid_, &waitStatus_, 0, null);
		    state_ = TargetState.STOPPED;
		} while (!stopped());
	    } catch (PtraceException pte) {
		if (pte.errno_ == ESRCH)
		    onExit;
	    }
	}

	void setBreakpoint(ulong addr, TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("setting breakpoint at 0x%x for 0x%x", addr,
		    cast(ulong) tbl);
	    if (addr in breakpoints_) {
		breakpoints_[addr].addListener(tbl);
	    } else {
		PtraceBreakpoint pbp = new PtraceBreakpoint(this, addr);
		pbp.addListener(tbl);
		breakpoints_[addr] = pbp;
	    }
	}

	void clearBreakpoint(TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("clearing breakpoints for 0x%x", cast(ulong) tbl);
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
	bool onBreakpoint(Target, TargetThread)
	{
	    if (!sharedLibraryBreakpoint_) {
		/*
		 * We are stopped at program entry point. The dynamic
		 * linker is done now so we re-read the module lists
		 * and see if we can figure out how to monitor dlopen
		 * and dlclose.
		 */
		clearBreakpoint(this);
		getModules;
		/*
		 * Re-read dynamic entries - the runtime linker may have
		 * changed the value of DT_DEBUG.
		 */
		foreach (mod; modules_)
		    mod.digestDynamic(this);
		sharedLibraryBreakpoint_ =
		    modules_[0].findSharedLibraryBreakpoint(this);
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
    }

    PtraceThread focusThread()
    {
	ptrace_lwpinfo info;

	try {
	    ptrace(PT_LWPINFO, pid_, cast(char*) &info, info.sizeof);
	} catch (PtraceException pte) {
	    if (pte.errno_ == ESRCH)
		onExit;
	    return null;
	}
	return threads_[info.pl_lwpid];
    }

    ubyte[] readMemory(ulong targetAddress, size_t bytes, bool data)
    {
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
	    if (pte.errno_ == ESRCH)
		onExit;
	    throw new TargetException("Can't read target memory");
	}

	return result;
    }

    void writeMemory(ulong targetAddress, ubyte[] toWrite, bool data)
    {
	ptrace_io_desc io;

	try {
	    io.piod_op = data ? PIOD_WRITE_D : PIOD_WRITE_I;
	    io.piod_offs = cast(void*) targetAddress;
	    io.piod_addr = cast(void*) toWrite.ptr;
	    io.piod_len = toWrite.length;
	    ptrace(PT_IO, pid_, cast(char*) &io, 0);
	} catch (PtraceException pte) {
	    if (pte.errno_ == ESRCH)
		onExit;
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

    void getThreads()
    {
	lwpid_t[] newThreads;

	PtraceThread[lwpid_t] oldThreads;
	foreach (tid, t; threads_)
	    oldThreads[tid] = t;

	newThreads.length = ptrace(PT_GETNUMLWPS, pid_, null, 0);
	ptrace(PT_GETLWPLIST, pid_,
	       cast(char*) newThreads.ptr,
	       newThreads.length * lwpid_t.sizeof);

	foreach (ntid; newThreads) {
	    if (ntid in threads_) {
		oldThreads.remove(ntid);
		continue;
	    }
	    PtraceThread t = new PtraceThread(this, ntid);
	    listener_.onThreadCreate(this, t);
	    threads_[ntid] = t;
	}
	foreach (otid, t; oldThreads) {
	    listener_.onThreadDestroy(this, t);
	    threads_.remove(otid);
	}
    }

    string realpath(string filename)
    {
	char[] buf;
	buf.length = 1024;
	char* p = .realpath(toStringz(filename), &buf[0]);
	if (p)
	    return .toString(p);
	return filename;
    }

    void getModules()
    {
	string maps = readMaps();
	if (maps == lastMaps_)
	    return;
	lastMaps_ = maps;

	string[] lines = splitlines(maps);

	PtraceModule[] modules;
	PtraceModule lastMod;
	foreach (line; lines) {
	    string[] words = split(line);
	    if (words[11] == "vnode") {
		ulong atoi(string s) {
		    return std.c.stdlib.strtoul(toStringz(s), null, 0);
		}
		string name = words[12];
		if (name == "-")
		    name = execname_;
		name = realpath(name);
		ulong start = strtoull(toStringz(words[0]), null, 0);
		ulong end = strtoull(toStringz(words[1]), null, 0);
		if (lastMod && lastMod.filename_ == name
		    && lastMod.end_ == start) {
		    lastMod.end_ = end;
		} else {
		    PtraceModule mod =
			new PtraceModule(name, start, end);
		    modules ~= mod;
		    lastMod = mod;
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

    string readMaps()
    {
	string mapfile = "/proc/" ~ std.string.toString(pid_) ~ "/map";
	string result;

	auto fd = open(toStringz(mapfile), O_RDONLY);

	result.length = 512;
	for (;;) {
	    /*
	     * The kernel requires that we read the whole thing in one
	     * call. If our buffer is too small, it returns EFBIG.
	     */
	    ssize_t nread;
	    lseek(fd, 0, SEEK_SET);
	    nread = read(fd, result.ptr, result.length);
	    const int EFBIG = 27;
	    if (nread < 0 && errno == EFBIG) {
		result.length = 2 * result.length;
		continue;
	    }
	    result.length = nread;
	    break;
	}

	return result;
    }

    bool stopped()
    {
	bool ret = true;

	bool checkBreakpoints = breakpointsActive_;
	if (breakpointsActive_) {
	    foreach (pbp; breakpoints_)
		pbp.deactivate();
	    breakpointsActive_ = false;
	}
	getThreads();
	foreach (t; threads_)
	    t.readState();

	if (WIFSTOPPED(waitStatus_)) {
	    if (WSTOPSIG(waitStatus_) == SIGTRAP) {
		if (checkBreakpoints) {
		    /*
		     * A thread stopped at a breakpoint. Adjust its PC
		     * accordingly and find out what stopped it,
		     * informing our listener as appropriate.
		     */
		    PtraceThread pt = focusThread;
		    pt.pc = pt.state.pc - 1; // XXX MachineState.adjustPcAfterBreak
		    foreach (pbp; breakpoints_.values) {
			if (pt.state.pc == pbp.address) {
			    pbp.stoppedThreads_ ~= pt;
			    ret = false;
			    foreach (tbl; pbp.listeners) {
				debug(breakpoints)
				    writefln("hit breakpoint at 0x%x for 0x%x",
					     pt.state.pc, cast(ulong) tbl);
				if (tbl.onBreakpoint(this, pt))
				    ret = true;
			    }
			}
		    }
		}
	    } else {
		int sig = WSTOPSIG(waitStatus_);
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
	if (ret < 0)
	    throw new PtraceException;
	return ret;
    }

    static void wait4(int pid, int* statusp, int options, rusage* rusage)
    {
	if (.wait4(pid, statusp, options, rusage) < 0)
	    throw new PtraceException;
    }

    TargetState state_ = TargetState.STOPPED;
    pid_t pid_;
    uint nextTid_ = 1;
    int waitStatus_;
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
	    pid = std.string.atoi(args[0]);
	    PtraceTarget.ptrace(PT_ATTACH, pid, null, 0);
	    PtraceTarget.wait4(pid, &status, 0, null);
	    return new PtraceTarget(listener, pid, "");
	}
    }
}

extern (C) int execve(char*, char**, char**);

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
	    string[] path = split(std.string.toString(getenv("PATH")), ":");
	    string execpath = "";

	    debug (ptrace)
		writefln("PATH=%s", std.string.toString(getenv("PATH")));
	    execpath = args[0];
	    if (find(execpath, "/") < 0) {
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

	    char* pathz = std.string.toStringz(execpath);
	    char*[] argv;

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
		PtraceTarget.wait4(pid, &status, 0, null);
		debug (ptrace)
		    writefln("done");
		return new PtraceTarget(listener, pid, execpath);
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
			 std.string.toString(strerror(errno)));
		exit(1);
	    }

	    return null;
	}
    }
}
