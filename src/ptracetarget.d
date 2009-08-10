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

module ptracetarget;

//debug = ptrace;

import target;
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
import sys.reg;

extern (C)
{
    int errno;
    char* strerror(int);
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
	obj_ = Objfile.open(filename_);
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
		addr -= obj_.offset;
		Symbol* s = obj_.lookupSymbol(addr);
		if (s) {
		    ts = TargetSymbol(s.name, s.value, s.size);
		    return true;
		}
	    }
	    return false;
	}
    }

    int opEquals(PtraceModule mod)
    {
	return filename_ == mod.filename_
	    && start_ == mod.start_
	    && end_ == mod.end_;
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

    void addID(void* id)
    {
	ids_ ~= id;
    }

    void removeID(void* id)
    {
	void*[] newids;

	foreach (t; ids_)
	    if (t != id)
		newids ~= t;
	ids_ = newids;
    }

    bool matchID(void* id)
    {
	foreach (t; ids_)
	    if (t == id)
		return true;
	return false;
    }

    void*[] ids()
    {
	return ids_;
    }

private:
    PtraceTarget target_;
    ulong addr_;
    void*[] ids_;
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
	state_ = new X86State(target_);
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
	regs_.r_eip = addr;
	target_.ptrace(PT_SETREGS, lwpid_, cast(char*) &regs_, 0);
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
	target_.ptrace(PT_GETREGS, lwpid_, cast(char*) &regs_, 0);
	state_.setGRs(cast(ubyte*) &regs_);
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
	state_.getGRs(cast(ubyte*) &regs_);
	//writefln("write thread %d pc as %#x, eax as %#x", id, regs_.r_eip, regs_.r_eax);
	target_.ptrace(PT_SETREGS, lwpid_, cast(char*) &regs_, 0);
    }
    void dumpState()
    {
	writefln(" fs:%08x  es:%08x  ds: %08x edi:%08x",
		 regs_.r_fs, regs_.r_es, regs_.r_ds, regs_.r_edi);
	writefln("esi:%08x ebp:%08x isp: %08x ebx:%08x",
		 regs_.r_esi, regs_.r_ebp, regs_.r_isp, regs_.r_ebx);
	writefln("edx:%08x ecx:%08x eax: %08x trapno:%08x",
		 regs_.r_edx, regs_.r_ecx, regs_.r_eax, regs_.r_trapno);
	writefln("err:%08x eip:%08x  cs: %08x eflags:%08x",
		 regs_.r_err, regs_.r_eip, regs_.r_cs, regs_.r_eflags);
	writefln("esp:%08x  ss:%08x  gs: %08x",
		 regs_.r_esp, regs_.r_ss, regs_.r_gs);
	for (int i = 0; i < 4; i++) {
	    ubyte[] s = target_.readMemory(regs_.r_esp + 4 * i, 4);
	    writef("%x ", s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24));
	}
    }

    static int pcRegno_ = X86Reg.EIP;

    PtraceTarget target_;
    uint id_;
    lwpid_t lwpid_;
    MachineState state_;
    reg regs_;
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

class PtraceTarget: Target
{
    this(TargetListener listener, pid_t pid, string execname)
    {
	pid_ = pid;
	listener_ = listener;
	execname_ = execname;
	breakpointsActive_ = false;
	listener.onTargetStarted(this);
	stopped();
	getModules();
    }

    override
    {
	TargetState state()
	{
	    return state_;
	}

	TargetThread focusThread()
	{
	    ptrace_lwpinfo info;

	    try {
		ptrace(PT_LWPINFO, pid_, cast(char*) &info, info.sizeof);
	    } catch (PtraceException pte) {
		if (pte.errno_ == ESRCH)
		    listener_.onExit(this);
		return null;
	    }
	    return threads_[info.pl_lwpid];
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
		    listener_.onExit(this);
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
		    listener_.onExit(this);
	    }
	}

	void wait()
	{
	    assert(state_ == TargetState.RUNNING);

	    try {
		wait4(pid_, &waitStatus_, 0, null);
		state_ = TargetState.STOPPED;
		stopped();
	    } catch (PtraceException pte) {
		if (pte.errno_ == ESRCH)
		    listener_.onExit(this);
	    }
	}

	void setBreakpoint(ulong addr, void* id)
	{
	    debug(breakpoints)
		writefln("setting breakpoint at 0x%x for 0x%x", addr, id);
	    if (addr in breakpoints_) {
		breakpoints_[addr].addID(id);
	    } else {
		PtraceBreakpoint pbp = new PtraceBreakpoint(this, addr);
		pbp.addID(id);
		breakpoints_[addr] = pbp;
	    }
	}

	void clearBreakpoint(void* id)
	{
	    debug(breakpoints)
		writefln("clearing breakpoints for 0x%x", id);
	    PtraceBreakpoint[ulong] newBreakpoints;
	    foreach (addr, pbp; breakpoints_) {
		if (pbp.matchID(id)) {
		    pbp.removeID(id);
		}
		if (pbp.ids.length > 0)
		    newBreakpoints[addr] = pbp;
	    }
	    breakpoints_ = newBreakpoints;
	}
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
		listener_.onExit(this);
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
		listener_.onExit(this);
	}
    }

private:
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

    void getModules()
    {
	string maps = readMaps();

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
		PtraceModule mod =
		    new PtraceModule(name, atoi(words[0]), atoi(words[1]));
		if (lastMod && lastMod.filename_ == mod.filename_
		    && lastMod.end_ == mod.start_) {
		    lastMod.end_ = mod.end_;
		} else {
		    modules ~= mod;
		    lastMod = mod;
		}
	    }
	}

	// XXX cope with modules changing and disappearing
	foreach (mod; modules) {
	    bool seenit = false;
	    foreach (omod; modules_)
		if (mod == omod)
		    seenit = true;
	    if (!seenit) {
		listener_.onModuleAdd(this, mod);
		modules_ ~= mod;
	    }
	}
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

    void stopped()
    {
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
		    PtraceThread pt = cast(PtraceThread) focusThread;
		    pt.pc = pt.state.pc - 1; // XXX MachineState.adjustPcAfterBreak
		    foreach (pbp; breakpoints_.values) {
			if (pt.state.pc == pbp.address) {
			    foreach (id; pbp.ids) {
				debug(breakpoints)
				    writefln("hit breakpoint at 0x%x for 0x%x",
					     pt.state.pc, id);
				listener_.onBreakpoint(this, pt, id);
			    }
			    pbp.stoppedThreads_ ~= pt;
			}
		    }
		}
	    } else {
		int sig = WSTOPSIG(waitStatus_);
		listener_.onSignal(this, focusThread, sig, signame(sig));
	    }
	}
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
		execve(pathz, argv.ptr, environ);
		writefln("execve returned: %s",
			 std.string.toString(strerror(errno)));
		exit(1);
	    }

	    return null;
	}
    }
}
