/*-
 * Copyright (c) 2007 Doug Rabson
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

import target;
import std.stdint;
import std.stdio;
import std.string;
import std.c.stdlib;
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
	char[] s = std.string.toString(strerror(errno)).dup;
	super(s);
    }

}

class PtraceModule: TargetModule
{
    this(char[] filename, uintptr_t start, uintptr_t end)
    {
	filename_ = filename;
	start_ = start;
	end_ = end;
    }

    override {
	char[] filename()
	{
	    return filename_;
	}

	uintptr_t start()
	{
	    return start_;
	}

	uintptr_t end()
	{
	    return end_;
	}
    }

    int opEquals(PtraceModule mod)
    {
	return filename_ == mod.filename_
	    && start_ == mod.start_
	    && end_ == mod.end_;
    }

private:
    char[] filename_;
    uintptr_t start_;
    uintptr_t end_;
}

class PtraceBreakpoint: Breakpoint
{
    this(PtraceTarget target, uintptr_t addr)
    {
	target_ = target;
	addr_ = addr;
	enabled_ = true;
    }

    uintptr_t address()
    {
	return addr_;
    }

    void setEnabled(bool enabled)
    {
	enabled_ = enabled;
    }

    void activate()
    {
	if (enabled_) {
	    /*
	     * Write a breakpoint instruction, saving what was there
	     * before.
	     */
	    save_ = target_.readMemory(addr_, break_.length, false);
	    target_.writeMemory(addr_, break_, false);
	}
    }

    void deactivate()
    {
	if (enabled_) {
	    /*
	     * Disable by writing back our saved bytes.
	     */
	    target_.writeMemory(addr_, save_, false);
	}
    }

private:
    PtraceTarget target_;
    uintptr_t addr_;
    bool enabled_;
    ubyte[] save_;
    static ubyte[] break_ = [ 0xcc ]; // XXX i386 int3
}

class PtraceThread: Thread
{
    this(PtraceTarget target, lwpid_t lwpid)
    {
	target_ = target;
	lwpid_ = lwpid;
    }
    override
    {
	Target target()
	{
	    return target_;
	}
	uintptr_t pc()
	{
	    return regs_.r_eip;
	}
    }

    void pc(uintptr_t addr)
    {
	regs_.r_eip = addr;
	target_.ptrace(PT_SETREGS, lwpid_, cast(char*) &regs_, 0);
    }

private:
    void readState()
    {
	target_.ptrace(PT_GETREGS, lwpid_, cast(char*) &regs_, 0);
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
    }

    PtraceTarget target_;
    lwpid_t lwpid_;
    reg regs_;
}

class PtraceTarget: Target
{
    this(TargetListener listener, pid_t pid, string execname)
    {
	pid_ = pid;
	listener_ = listener;
	execname_ = execname;
	breakpointsActive_ = false;
	stopped();
	getModules();
    }

    override
    {
	TargetState state()
	{
	    return state_;
	}

	Thread focusThread()
	{
	    ptrace_lwpinfo info;

	    ptrace(PT_LWPINFO, pid_, cast(char*) &info, info.sizeof);
	    return threads_[info.pl_lwpid];
	}

	Thread[] threads()
	{
	    Thread[] result;
	    size_t i;

	    result.length = threads_.length;
	    i = 0;
	    foreach (t; threads_)
		result[i++] = t;

	    return result;
	}

	TargetModule[] modules()
	{
	    TargetModule[] result;
	    size_t i;

	    result.length = modules_.length;
	    foreach (mod; modules_)
		result[i++] = mod;

	    return result;
	}

	ubyte[] readMemory(uintptr_t targetAddress, size_t bytes)
	{
	    return readMemory(targetAddress, bytes, true);
	}

	void writeMemory(uintptr_t targetAddress, ubyte[] toWrite)
	{
	    return writeMemory(targetAddress, toWrite, true);
	}

	void step()
	{
	    assert(state_ == TargetState.STOPPED);

	    ptrace(PT_STEP, pid_, cast(char*) 1, 0);
	    state_ = TargetState.RUNNING;
	    wait();
	}

	void cont()
	{
	    assert(state_ == TargetState.STOPPED);

	    /*
	     * If a thread is currently sitting on a breakpoint, step
	     * over it.
	     */
	    bool atBreakpoint = false;
	    do {
		foreach (t; threads_) 
		    foreach (pbp; breakpoints_)
			if (t.pc == pbp.address)
			    atBreakpoint = true;
		if (atBreakpoint)
		    step();
	    } while (atBreakpoint);

	    foreach (pbp; breakpoints_)
		pbp.activate;
	    breakpointsActive_ = true;
	    ptrace(PT_CONTINUE, pid_, cast(char*) 1, 0);
	    state_ = TargetState.RUNNING;
	}

	void wait()
	{
	    assert(state_ == TargetState.RUNNING);

	    wait4(pid_, &waitStatus_, 0, null);
	    if (WIFSTOPPED(waitStatus_) && WSTOPSIG(waitStatus_) != SIGTRAP)
		writefln("%d", WSTOPSIG(waitStatus_));
	    state_ = TargetState.STOPPED;
	    stopped();
	}

	Breakpoint setBreakpoint(uintptr_t addr)
	{
	    PtraceBreakpoint pbp = new PtraceBreakpoint(this, addr);
	    breakpoints_ ~= pbp;
	    return pbp;
	}

	void clearBreakpoint(Breakpoint bp)
	{
	    PtraceBreakpoint pbp = cast(PtraceBreakpoint) bp;

	    foreach (t; breakpoints_) {
		if (t is pbp) {
		    PtraceBreakpoint[] newBreakpoints;
		    newBreakpoints.length = breakpoints_.length - 1;
		    int i = 0;
		    foreach (tt; breakpoints_)
			if (tt !is pbp)
			    newBreakpoints[i++] = tt;
		    breakpoints_ = newBreakpoints;
		}
	    }
	}
    }

    ubyte[] readMemory(uintptr_t targetAddress, size_t bytes, bool data)
    {
	ubyte[] result;
	ptrace_io_desc io;

	result.length = bytes;
	io.piod_op = data ? PIOD_READ_D : PIOD_READ_I;
	io.piod_offs = cast(void*) targetAddress;
	io.piod_addr = cast(void*) result.ptr;
	io.piod_len = bytes;
	ptrace(PT_IO, pid_, cast(char*) &io, 0);

	return result;
    }

    void writeMemory(uintptr_t targetAddress, ubyte[] toWrite, bool data)
    {
	ptrace_io_desc io;

	io.piod_op = data ? PIOD_WRITE_D : PIOD_WRITE_I;
	io.piod_offs = cast(void*) targetAddress;
	io.piod_addr = cast(void*) toWrite.ptr;
	io.piod_len = toWrite.length;
	ptrace(PT_IO, pid_, cast(char*) &io, 0);
    }

private:
    TargetState state_ = TargetState.STOPPED;
    pid_t pid_;
    int waitStatus_;
    PtraceThread[lwpid_t] threads_;
    PtraceModule[] modules_;
    PtraceBreakpoint[] breakpoints_;
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
	char[] maps = readMaps();

	char[][] lines = splitlines(maps);

	PtraceModule[] modules;
	PtraceModule lastMod;
	foreach (line; lines) {
	    char[][] words = split(line);
	    if (words[11] == "vnode") {
		ulong atoi(char[] s) {
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

    char[] readMaps()
    {
	char[] mapfile = "/proc/" ~ std.string.toString(pid_) ~ "/map";
	char[] result;

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
	if (breakpointsActive_) {
	    foreach (pbp; breakpoints_)
		pbp.deactivate();
	    breakpointsActive_ = false;
	}
	getThreads();
	foreach (t; threads_)
	    t.readState();


	if (WIFSTOPPED(waitStatus_) && WSTOPSIG(waitStatus_) != SIGTRAP) {
	    foreach (t; threads_)
		t.dumpState();
	}

	/*
	 * Figure out if any threads hit a breakpoint and if so, back
	 * them up.
	 */
	foreach (t; threads_) {
	    foreach (pbp; breakpoints_) {
		if (t.pc == pbp.address + 1) {
		    t.pc = pbp.address;
		}
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
	char[] name()
	{
	    return "attach";
	}

	Target connect(TargetListener listener, char[][] args)
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
	char[] name()
	{
	    return "run";
	}

	Target connect(TargetListener listener, char[][] args)
	{
	    char[][] path = split(std.string.toString(getenv("PATH")), ":");
	    char[] execpath = "";

	    writefln("%s", std.string.toString(getenv("PATH")));
	    foreach (p; path) {
		char[] s = p ~ "/" ~ args[0];
		version (DEBUG) {
			if (debugLevel > 2)
				writefln("trying '%s'", s);
		}
		if (std.file.exists(s) && std.file.isfile(s)) {
		    execpath = s;
		    break;
		}
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
		writefln("flags=0x%x", a.sa_flags);


	    pid_t pid = fork();
	    if (pid) {
		/*
		 * This is the parent process. Wait for the child's
		 * first stop (which will be after the call to
		 * execve).
		 */
		int status;
		writefln("waiting for execve");
		PtraceTarget.wait4(pid, &status, 0, null);
		writefln("done");
		return new PtraceTarget(listener, pid, execpath);
	    } else {
		/*
		 * This is the child process. We tell the kernel we
		 * want to be debugged and then use execve to start
		 * the required application.
		 */
		writefln("child calling PT_TRACE_ME");
		if (ptrace(PT_TRACE_ME, 0, null, 0) < 0)
		    exit(1);
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
