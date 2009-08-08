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

module cli;

//debug = step;

import editline;
import target;
import ptracetarget;
import coldtarget;
import objfile.debuginfo;
import objfile.language;
import machine.machine;

version (DigitalMars)
import std.c.freebsd.freebsd;
else
import std.c.unix.unix;
import std.conv;
import std.ctype;
static import std.path;
import std.string;
import std.stdio;
import std.file;
import std.c.stdio;
import std.cstream;

extern (C) char* readline(char*);
extern (C) void add_history(char*);
extern (C) void free(void*);

/**
 * A CLI command
 */
class Command
{
    /**
     * Return the command name.
     */
    abstract string name();

    /**
     * Return the command short name, if any.
     */
    string shortName()
    {
	return null;
    }

    /**
     * Return the command description.
     */
    abstract string description();

    /**
     * Execute the command
     */
    abstract void run(Debugger db, string[] args);

    /**
     * Called when an action which sets the current source file and
     * line happens.
     */
    void onSourceLine(Debugger db, SourceFile sf, uint line)
    {
    }
}

class CommandTable
{
    void run(Debugger db, string[] args, string prefix)
    {
	string message;
	string name = args[0];
	string format = null;
	int i;

	if ((i = find(name, '/')) >= 0) {
	    format = name[i..$];
	    name = name[0..i];
	    args = format ~ args[1..$];
	} else {
	    args = args[1..$];
	}

	Command c = lookup(name, message);
	if (c)
	    c.run(db, args);
	else
	    writefln("Command %s%s is %s", prefix, name, message);
    }

    void add(Command c)
    {
	list_[c.name] = c;
	auto s = c.shortName;
	if (s)
	    shortNames_[s] = c.name;
    }

    Command lookup(string name, out string message)
    {
	if (name in shortNames_)
	    name = shortNames_[name];
	auto cp = (name in list_);
	if (cp) {
	    return *cp;
	} else {
	    /*
	     * Try to match a prefix of some command. If nothing
	     * matches or the given prefix is ambiguous, throw an
	     * exception.
	     */
	    Command[] matches;

	    foreach (c; list_) {
		string s = c.name;
		if (s.length > name.length)
		    if (s[0..name.length] == name)
			matches ~= c;
	    }
	    if (matches.length == 0) {
		message = "unrecognised";
		return null;
	    }
	    if (matches.length > 1) {
		message = "ambiguous";
		return null;
	    }
	    return matches[0];
	}
    }

    void onSourceLine(Debugger db, SourceFile sf, uint line)
    {
	foreach (c; list_)
	    c.onSourceLine(db, sf, line);
    }

    Command[string] list_;
    string[string] shortNames_;
}

private class Breakpoint
{
    this(Debugger db, uint id, SourceFile sf, uint line)
    {
	db_ = db;
	id_ = id;
	sf_ = sf;
	line_ = line;
    }

    this(Debugger db, uint id, string func)
    {
	db_ = db;
	id_ = id;
	func_ = func;
    }

    void activate(TargetModule mod)
    {
	if (mod in modules_)
	    return;
	modules_[mod] = true;

	DebugInfo di = mod.debugInfo;
	int pos;

	LineEntry[] lines;
	bool found;
	if (sf_ !is null) {
	    if (di)
		found = di.findLineByName(sf_.filename, line_, lines);
	} else {
	    if (di)
		found = di.findLineByFunction(func_, lines);
	}
	if (found) {
	    Function func = null;
	    foreach (le; lines) {
		/*
		 * In optimised code we can get several line entries for
		 * the same source line - take only the first one.
		 * XXX possibly remove this if it causes problems with
		 * inlines.
		 */
		Function f = di.findFunction(le.address);
		if (func && f == func)
		    continue;
		func = f;
		db_.target_.setBreakpoint(le.address, cast(void*) this);
		addresses_ ~= le.address;
	    }
	}
    }

    void disable()
    {
	if (enabled_) {
	    if (addresses_.length > 0)
		db_.target_.clearBreakpoint(cast(void*) this);
	    enabled_ = false;
	}
    }

    void enable()
    {
	if (!enabled_) {
	    foreach (address; addresses_)
		db_.target_.setBreakpoint(address, cast(void*) this);
	    enabled_ = true;
	}
    }

    void onExit()
    {
	addresses_.length = 0;
    }

    bool active()
    {
	return addresses_.length > 0;
    }

    uint id()
    {
	return id_;
    }

    bool enabled()
    {
	return enabled_;
    }

    ulong[] addresses()
    {
	return addresses_;
    }

    string expr()
    {
	if (sf_)
	    return format("%s:%d", sf_.filename, line_);
	else
	    return func_;
    }

    bool matches(ulong pc)
    {
	foreach (addr; addresses_)
	    if (pc == addr)
		return true;
	return false;
    }

    SourceFile sf_;
    uint line_;
    string func_;
    bool enabled_ = true;
    Debugger db_;
    uint id_;
    bool[TargetModule] modules_;
    ulong[] addresses_;
}

private class SourceFile
{
    this(string filename)
    {
	filename_ = filename;
    }

    string opIndex(uint lineno)
    {
	if (lines_.length == 0 && !error_) {
	    try {
		string file = cast(string) std.file.read(filename);
		lines_ = splitlines(file);
	    } catch {
		writefln("Can't open file %s", filename);
		error_ = true;
	    }
	}
	if (lineno < 1 || lineno > lines_.length)
	    return null;
	return lines_[lineno - 1];
    }

    string filename()
    {
	return filename_;
    }

    string filename_;
    string[] lines_;
    bool error_;
}

private class Frame
{
    this(Debugger db, uint index, Frame inner,
	 DebugInfo di, Function func, MachineState state)
    {
	db_ = db;
	index_ = index;
	inner_ = inner;
	if (inner_)
	    inner_.outer_ = this;
	di_ = di;
	func_ = func;
	state_ = state;
	Location loc;
	di.findFrameBase(state, loc);
	addr_ = loc.address(state);
	lang_ = di.findLanguage(state.pc);
    }
    string toString()
    {
	return format("#%-2d %s", index_,
		      db_.describeAddress(state_.pc, state_));
    }

    /**
     * Return the index of this frame.
     */
    uint index()
    {
	return index_;
    }

    /**
     * Return the next outer stack frame, if any
     */
    Frame outer()
    {
	if (outer_)
	    return outer_;

	auto s = di_.unwind(state_);
	if (!s)
	    return null;
	DebugInfo di;
	if (!db_.findDebugInfo(s, di))
	    return null;
	auto func = di.findFunction(s.pc);
	if (!func)
	    return null;
	return new Frame(db_, index_ + 1, this, di, func, s);
    }

    /**
     * Return the next inner stack frame, if any
     */
    Frame inner()
    {
	return inner_;
    }

    Debugger db_;
    uint index_;
    Frame inner_;
    Frame outer_;
    DebugInfo di_;
    Function func_;
    Language lang_;
    MachineState state_;
    ulong addr_;
}

class PagerQuit: Exception
{
    this()
    {
	super("Quit");
    }
}

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener, Scope
{
    this(string prog, string core)
    {
	prog_ = prog;
	core_ = core;
	prompt_ = "(ngdb)";

	HistEvent ev;
	hist_ = history_init();
	history(hist_, &ev, H_SETSIZE, 100);

	el_ = el_init(toStringz("ngdb"), stdin, stdout, stderr);
	el_set(el_, EL_EDITOR, toStringz("emacs"));
	el_set(el_, EL_SIGNAL, 1);
	el_set(el_, EL_PROMPT, &el_prompt);
	el_set(el_, EL_HIST, &history, hist_);

	tok_ = tok_init(null);

	nextBPID_ = 1;
    }

    ~this()
    {
	history_end(hist_);
	el_end(el_);
	tok_end(tok_);
    }

    static extern(C) void ignoreSig(int)
    {
    }

    void prompt(string s)
    {
	prompt_ = s;
    }

    void run()
    {
	char* buf;
	int num;
	string[] args;

	sigaction_t sa;
	sa.sa_handler = &ignoreSig;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, null);

	target_ = new ColdTarget(this, prog_, core_);
	if (core_)
	    stopped();

	staticPrompt_ = prompt_;
	while (!quit_ && (buf = el_gets(el_, &num)) != null && num != 0) {
	    int ac;
	    char** av;
	    LineInfo *li;

	    /*
	     * If we don't have a target (e.g. the active target
	     * exitted or we disconnected), switch back to a cold
	     * target.
	     */
	    if (!target_) {
		target_ = new ColdTarget(this, prog_, core_);
		if (core_)
		    stopped();
	    }

	    li = el_line(el_);

	    HistEvent ev;
	    if (continuation_ || num > 1) {
		int cont = tok_line(tok_, li, &ac, &av, null, null);
		if (cont < 0) {
		    // XXX shouldn't happen
		    continuation_ = 0;
		    continue;
		}

		history(hist_, &ev, continuation_ ? H_APPEND : H_ENTER, buf);
		continuation_ = cont;
		if (continuation_)
		    continue;

		args.length = ac;
		for (int i = 0; i < ac; i++)
		    args[i] = .toString(av[i]).dup;
		tok_reset(tok_);
	    }

	    if (args.length == 0)
		continue;

	    pageline_ = 0;
	    if (args[0] == "history") {
		for (int rv = history(hist_, &ev, H_LAST);
		     rv != -1;
		     rv = history(hist_, &ev, H_PREV))
		    writef("%d %s", ev.num, .toString(ev.str));
	    } else {
		try {
		    commands_.run(this, args, "");
		} catch (PagerQuit pq) {
		}
	    }
	}
    }

    void pagefln(...)
    {
	char[] s;

	void putc(dchar c)
	{
	    std.utf.encode(s, c);
	}

	std.format.doFormat(&putc, _arguments, _argptr);
	while (s.length) {
	    uint n = s.length;
	    if (n > 80) n = 80;
	    writefln("%s", s[0..n]);
	    s = s[n..$];
	    if (pagemaxline_) {
		pageline_++;
		if (pageline_ >= pagemaxline_) {
		    writef("--Press return to continue or type 'q' to quit--");
		    auto t = din.readLine;
		    if (t.length > 0 && (t[0] == 'q' || t[0] == 'Q'))
			throw new PagerQuit;
		    pageline_ = 0;
		}
	    }
	}
    }

    SourceFile findFile(string filename)
    {
	auto tab = &sourceFiles_;
	if (!std.path.isabs(filename))
	    tab = &sourceFilesBasename_;
	if (filename in *tab)
	    return (*tab)[filename];
	SourceFile sf = new SourceFile(filename);
	sourceFiles_[filename] = sf;
	sourceFilesBasename_[std.path.getBaseName(filename)] = sf;
	return sf;
    }

    bool parseFormat(string fmt, out uint count, out uint width, out string f)
    {
	assert(fmt[0] == '/');
	fmt = fmt[1..$];
	if (fmt.length == 0)
	    return false;
	if (isdigit(fmt[0])) {
	    count = 0;
	    while (fmt.length > 0 && isdigit(fmt[0])) {
		count = count * 10 + (fmt[0] - '0');
		fmt = fmt[1..$];
	    }
	    if (count == 0) {
		writefln("Count field in format string should be non-zero");
		return false;
	    }
	} else {
	    count = 1;
	}
	width = 4;
	f = "d";
	while (fmt.length > 0) {
	    switch (fmt[0]) {
	    case 'b':
		width = 1;
		break;
	    case 'w':
		width = 2;
		break;
	    case 'l':
		width = 4;
		break;
	    case 'q':
		width = 8;
		break;
	    case 'd':
	    case 'o':
	    case 'x':
	    case 'i':
		f = fmt[0..1];
		break;
	    default:
		writefln("Unsupported format character %s", fmt[0..1]);
		return false;
	    }
	    fmt = fmt[1..$];
	}
	return true;
    }

    bool parseSourceLine(string s, out SourceFile sf, out uint line)
    {
	auto pos = find(s, ":");
	if (pos >= 0) {
	    try {
	        line = toUint(s[pos + 1..$]);
		sf = findFile(s[0..pos]);
	    } catch (ConvError ce) {
	        return false;
	    }
	    return true;
	} else if (currentSourceFile_) {
	    try {
	        line = toUint(s);
	    } catch (ConvError ce) {
	        return false;
	    }
	    sf = currentSourceFile_;
	    return true;
	}
	return false;
    }

    void stopped()
    {
	if (!target_)
	    return;

	TargetThread t = threads_[0];	// XXX
	MachineState s = t.state;
	LineEntry[] le;
	DebugInfo di;

	if (findDebugInfo(s, di)) {
	    Location loc;
	    Function func;
	    if (di.findFrameBase(s, loc) && (func = di.findFunction(s.pc)) !is null) {
		if (!topFrame_ || topFrame_.func_ != func
		    || topFrame_.addr_ != loc.address(s)) {
		    writefln("%s", describeAddress(s.pc, s));
		    currentFrame_ = topFrame_ =
			new Frame(this, 0, null, di, func, s);
		}
	    }
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		currentSourceFile_ = stoppedSourceFile_ = sf;
		currentSourceLine_ = stoppedSourceLine_ = le[0].line;
		displaySourceLine(sf, currentSourceLine_);
		commands_.onSourceLine(this, sf, le[0].line);
		infoCommands_.onSourceLine(this, sf, le[0].line);
	    }
	} else {
	    ulong tpc = s.pc;
	    writefln("%s:\t%s", lookupAddress(s.pc),
		     s.disassemble(tpc, &lookupAddress));
	}
    }

    void displaySourceLine(MachineState s)
    {
	DebugInfo di;
	LineEntry[] le;

	if (findDebugInfo(s, di)) {
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		displaySourceLine(sf, le[0].line);
		setCurrentSourceLine(sf, le[0].line);
	    }
	}
    }

    void displaySourceLine(SourceFile sf, uint line)
    {
	string bpmark = " ";
	foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (!di)
		continue;
	    LineEntry[] lines;
	    if (di.findLineByName(sf.filename, line, lines)) {
		foreach (li; lines)
		    foreach (bp; breakpoints_)
			if (bp.matches(li.address))  {
			    bpmark = "*";
			    goto showline;
			}
	    }
	}
    showline:
	auto s = sf[line];
	if (s) {
	    string a = "  ";
	    if (sf == stoppedSourceFile_ && line == stoppedSourceLine_)
		a = "=>";
	    writefln("%s%4d%s%s", a, line, bpmark, expandtabs(s));
	}
    }

    void setCurrentSourceLine(SourceFile sf, int line)
    {
	currentSourceFile_ = sf;
	currentSourceLine_ = line;
	commands_.onSourceLine(this, sf, line);
	infoCommands_.onSourceLine(this, sf, line);
    }

    string describeAddress(ulong pc, MachineState state)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (di && di.findLineByAddress(pc, le)) {
		string s = "";

		Function func = di.findFunction(pc);
		if (func) {
		    s = func.toString(null, state) ~ ": ";
		}

		s ~= le[0].name ~ ":" ~ .toString(le[0].line);
		return s;
	    }
	}
	return lookupAddress(pc);
    }

    string lookupAddress(ulong addr)
    {
	foreach (mod; modules_) {
	    TargetSymbol sym;
	    if (mod.lookupSymbol(addr, sym)) {
		return sym.name ~ "+" ~ .toString(addr - sym.value);
	    }
	}
	return std.string.format("0x%x", addr);
    }

    void setStepBreakpoint(ulong pc)
    {
	debug (step)
	    writefln("step breakpoint at %#x", pc);
	target_.setBreakpoint(pc, cast(void*) this);
    }

    void clearStepBreakpoints()
    {
	debug (step)
	    writefln("clearing step breakpoints");
	target_.clearBreakpoint(cast(void*) this);
    }

    void stepProgram(bool stepOverCalls)
    {
	if (!target_) {
	    writefln("Program is not being debugged");
	    return;
	}

	// XXX current thread
	TargetThread t = threads_[0];
	MachineState s = t.state;
	DebugInfo di;

	if (findDebugInfo(s, di)) {
	    Location frameLoc;
	    di.findFrameBase(s, frameLoc);

	    ulong frame = frameLoc.address(s);
	    ulong startpc = s.pc;
	    ulong stoppc, flowpc;

	    LineEntry[] le;
	    if (di.findLineByAddress(s.pc, le))
		stoppc = le[1].address;
	    else {
		target_.step(t);
		stopped();
		return;
	    }
	    setStepBreakpoint(stoppc);
	    flowpc = s.findFlowControl(s.pc, stoppc);
	    if (flowpc < stoppc)
		setStepBreakpoint(flowpc);
	    else
		flowpc = 0;

	    bool resetStep = false;
	    do {
		/*
		 * Run up to the next flow control instruction or the
		 * next statement, whichever comes first. Be careful if
		 * we are sitting on a flow control instruction.
		 */
		if (s.pc != flowpc) {
		    target_.cont();
		    target_.wait();
		}
		debug (step) {
		    void stoppedAt(string msg, ulong pc)
		    {
			writefln("%s %#x (%s)", msg, pc,
				replace(s.disassemble(pc, &lookupAddress), "\t", " "));
		    }
		}
		if (s.pc == flowpc) {
		    /*
		     * Stopped at a flow control instruction - single step
		     * it and see if we change frame or go out of our step
		     * range.
		     */
		    debug (step)
			stoppedAt("stopped at flow control", s.pc);
		    target_.step(t);
		    debug (step)
			stoppedAt("single stepped to", s.pc);
		    resetStep = true;
		} else {
		    debug (step)
			stoppedAt("stopped at", s.pc);
		}
		if (!findDebugInfo(s, di)) {
		    /*
		     * If we step into something without debug info,
		     * just continue until we hit the step breakpoint.
		     */
		    debug (step)
			writefln("no debug info at %#x - continue", s.pc);
		    target_.cont();
		    target_.wait();
		    break;
		}
		di.findFrameBase(s, frameLoc);
		if (frameLoc.address(s) != frame) {
		    debug (step)
			writefln("new frame address %#x", frameLoc.address(s));
		    if (frameLoc.address(s) > frame) {
			debug (step)
			    writefln("returning to outer frame");
			break;
		    }
		    if (stepOverCalls) {
			/*
			 * We are stepping over calls - run up to the return
			 * address
			 */
			debug (step)
			    writefln("stepping over call");
			MachineState ns = di.unwind(s);
			clearStepBreakpoints();
			ulong retpc = ns.pc;
			debug (step)
			    writefln("return breakpoint at %#x", retpc);
			setStepBreakpoint(retpc);
			do {
			    target_.cont();
			    target_.wait();
			    debug (step)
				stoppedAt("stopped at", s.pc);
			    if (s.pc != retpc
				|| !di.findFrameBase(s, frameLoc))
				break;
			    debug (step)
				if (frameLoc.address(s) < frame)
				    writefln("stopped at inner frame %#x - continuing", frameLoc.address(s));
			} while (frameLoc.address(s) != frame);
			resetStep = true;
		    } else {
			clearStepBreakpoints();
			break;
		    }
		}
		if (s.pc < startpc || s.pc >= stoppc) {
		    debug (step)
			writefln("stepped outside range %#x..%#x", startpc, stoppc);
		    break;
		}
		if (resetStep) {
		    clearStepBreakpoints();
		    setStepBreakpoint(stoppc);
		    flowpc = s.findFlowControl(s.pc, stoppc);
		    if (flowpc < stoppc)
			setStepBreakpoint(flowpc);
		    else
			flowpc = 0;
		}
	    } while (s.pc < stoppc);
	    clearStepBreakpoints();
	    stopped();
	} else {
	    target_.step(t);
	    stopped();
	}
    }

    void stepInstruction(bool stepOverCalls)
    {
	if (!target_) {
	    writefln("Program is not being debugged");
	    return;
	}

	// XXX current thread
	TargetThread t = threads_[0];
	MachineState s = t.state;

	ulong frame = 0;
	DebugInfo di;

	if (findDebugInfo(s, di)) {
	    Location frameLoc;
	    di.findFrameBase(s, frameLoc);
	    frame = frameLoc.address(s);
	}

	target_.step(t);
	
	if (findDebugInfo(s, di)) {
	    Location frameLoc;
	    di.findFrameBase(s, frameLoc);
	    if (frameLoc.address(s) != frame) {
		debug (step)
		    writefln("new frame address %#x", frameLoc.address(s));
		if (frameLoc.address(s) > frame) {
		    debug (step)
			writefln("returning to outer frame");
		    stopped();
		    return;
		}
		if (stepOverCalls) {
		    /*
		     * We are stepping over calls - run up to the return
		     * address
		     */
		    debug (step)
			writefln("stepping over call");
		    MachineState ns = di.unwind(s);
		    clearStepBreakpoints();
		    ulong retpc = ns.pc;
		    debug (step)
			writefln("return breakpoint at %#x", retpc);
		    setStepBreakpoint(retpc);
		    do {
			target_.cont();
			target_.wait();
			clearStepBreakpoints();
			if (s.pc != retpc
			    || !di.findFrameBase(s, frameLoc))
			    break;
			debug (step)
			    if (frameLoc.address(s) < frame)
				writefln("stopped at inner frame %#x - continuing", frameLoc.address(s));
		    } while (frameLoc.address(s) != frame);
		}
	    }
	}
	stopped();
    }

    void setBreakpoint(string bploc)
    {
	SourceFile sf;
	string func;
	uint line;
	if (bploc) {
	    string file;
	    if (!parseSourceLine(bploc, sf, line))
		func = bploc;
	} else {
	    sf = currentSourceFile_;
	    line = currentSourceLine_;
	    if (!sf) {
		writefln("no current source file");
		return;
	    }
	}
	Breakpoint bp;
	if (sf)
	    bp = new Breakpoint(this, nextBPID_++, sf, line);
	else
	    bp = new Breakpoint(this, nextBPID_++, func);
	breakpoints_ ~= bp;
	if (target_)
	    foreach (mod; modules_)
		bp.activate(mod);
    }

    void enableBreakpoint(uint bpid)
    {
	foreach (bp; breakpoints_)
	    if (bp.id == bpid)
		bp.enable;
    }

    void disableBreakpoint(uint bpid)
    {
	foreach (bp; breakpoints_)
	    if (bp.id == bpid)
		bp.disable;
    }

    void deleteBreakpoint(uint bpid)
    {
	Breakpoint[] newBreakpoints;
	foreach (bp; breakpoints_)
	    if (bp.id == bpid)
		bp.disable;
	    else
		newBreakpoints ~= bp;
	breakpoints_ = newBreakpoints;
    }

    Frame topFrame()
    {
	return topFrame_;
    }

    Frame currentFrame()
    {
	return currentFrame_;
    }

    Frame getFrame(uint frameIndex)
    {
	Frame f;
	for (f = topFrame_; f; f = f.outer)
	    if (f.index == frameIndex)
		break;
	return f;
    }

    bool findDebugInfo(MachineState s, out DebugInfo di)
    {
	Location loc;
	foreach (mod; modules_) {
	    di = mod.debugInfo;
	    if (di && di.findFrameBase(s, loc)) {
		di = mod.debugInfo;
		return true;
	    }
	}
	return false;
    }

    static void registerCommand(Command c)
    {
	if (!commands_)
	    commands_ = new CommandTable;
	commands_.add(c);
    }

    static void registerInfoCommand(Command c)
    {
	if (!infoCommands_)
	    infoCommands_ = new CommandTable;
	infoCommands_.add(c);
    }

    override
    {
	// TargetListener
	void onTargetStarted(Target target)
	{
	    target_ = target;
	}
	void onThreadCreate(Target target, TargetThread thread)
	{
	    foreach (t; threads_)
		if (t == thread)
		    return;
	    threads_ ~= thread;
	}
	void onThreadDestroy(Target target, TargetThread thread)
	{
	    TargetThread[] newThreads;
	    foreach (t; threads_)
		if (t != thread)
		    newThreads ~= t;
	    threads_ = newThreads;
	}
	void onModuleAdd(Target, TargetModule mod)
	{
	    modules_ ~= mod;

	    auto di = mod.debugInfo;
	    if (di) {
		foreach (s; di.findSourceFiles)
		    findFile(s);
	    }
	    foreach (bp; breakpoints_)
		bp.activate(mod);
	}
	void onBreakpoint(Target, TargetThread t, void* id)
	{
	    /*
	     * We use this as id for the step breakpoints.
	     */
	    if (id == cast(void*) this) {
		return;
	    } else {
		foreach (i, bp; breakpoints_) {
		    if (id == cast(void*) bp) {
			writefln("Breakpoint %d, %s", i + 1, describeAddress(t.state.pc, t.state));
		    }
		}
	    }
	}
	void onSignal(Target, int sig, string sigName)
	{
	    writefln("Signal %d (%s)", sig, sigName);
	}
	void onExit(Target)
	{
	    if (target_ && target_.state != TargetState.EXIT)
		writefln("Target program has exited.");

	    target_ = null;
	    threads_.length = 0;
	    modules_.length = 0;
	    foreach (bp; breakpoints_)
		bp.onExit;
	}
	string[] contents()
	{
	    string[] res;
	    for (int i = 0; i < valueHistory_.length; i++)
		res ~= "$" ~ .toString(i);
	    return res;
	}
	bool lookup(string name, out DebugItem val)
	{
	    if (name.length == 0 || name[0] != '$')
		return false;
	    try {
		uint num = name.length > 1
		    ? toUint(name[1..$]) : valueHistory_.length - 1;
		if (num >= valueHistory_.length)
		    return false;
		val = valueHistory_[num];
		return true;
	    } catch (ConvError ce) {
		return false;
	    }
	}
    }

private:
    static int continuation_;
    static string staticPrompt_; // messy
    static char *el_prompt(EditLine *el)
    {
	if (continuation_)
	    return "> ";
	else
	    return toStringz(staticPrompt_ ~ " ");
    }

    static CommandTable commands_;
    static CommandTable infoCommands_;
    History* hist_;
    EditLine* el_;
    Tokenizer* tok_;
    bool quit_ = false;

    string prog_;
    string core_;
    string prompt_;
    uint pageline_;
    uint pagemaxline_ = 24;
    Target target_;
    TargetModule[] modules_;
    TargetThread[] threads_;
    Frame topFrame_;
    Frame currentFrame_;
    Breakpoint[] breakpoints_;
    SourceFile[string] sourceFiles_;
    SourceFile[string] sourceFilesBasename_;
    SourceFile stoppedSourceFile_;
    uint stoppedSourceLine_;
    SourceFile currentSourceFile_;
    uint currentSourceLine_;
    uint nextBPID_;
    Value[] valueHistory_;
}

class QuitCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new QuitCommand);
    }

    override {
	string name()
	{
	    return "quit";
	}

	string description()
	{
	    return "Exit the debugger";
	}

	void run(Debugger db, string[] args)
	{
	    db.quit_ = true;
	}
    }
}

class HelpCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new HelpCommand);
    }

    override {
	string name()
	{
	    return "help";
	}

	string description()
	{
	    return "Print this message";
	}

	void run(Debugger db, string[] args)
	{
	    foreach (c; db.commands_.list_)
		db.pagefln("%s: %s", c.name, c.description);
	}
    }
}

class InfoCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new InfoCommand);
    }

    override {
	string name()
	{
	    return "info";
	}

	string description()
	{
	    return "Print information";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length == 0) {
		db.pagefln("usage: info subcommand [args ...]");
		return;
	    }
	    db.infoCommands_.run(db, args, "info ");
	}
    }
}

class RunCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new RunCommand);
    }

    override {
	string name()
	{
	    return "run";
	}

	string description()
	{
	    return "run the program being debugged";
	}

	void run(Debugger db, string[] args)
	{
	    if (db.target_ && db.target_.state != TargetState.EXIT) {
		db.pagefln("Program is already being debugged");
		return;
	    }
	    if (db.target_)
		db.onExit(db.target_);

	    PtraceRun pt = new PtraceRun;
	    if (args.length > 1 || runArgs_.length == 0) {
		runArgs_ = db.prog_ ~ args;
	    }
	    pt.connect(db, runArgs_);
	    if (db.target_) {
		db.target_.cont();
		db.target_.wait();
		db.stopped();
	    }
	}
    }
    string[] runArgs_;
}

class KillCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new KillCommand);
    }

    override {
	string name()
	{
	    return "kill";
	}

	string description()
	{
	    return "kill the program being debugged";
	}

	void run(Debugger db, string[] args)
	{
	    if (db.target_ && db.target_.state == TargetState.EXIT) {
		db.pagefln("Program is not running");
		return;
	    }
	    
	    db.target_.cont(SIGKILL);
	    db.target_.wait;
	}
    }
    string[] runArgs_;
}

class NextCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new NextCommand);
    }

    override {
	string name()
	{
	    return "next";
	}

	string shortName()
	{
	    return "n";
	}

	string description()
	{
	    return "step the program being debugged, stepping over function calls";
	}

	void run(Debugger db, string[] args)
	{
	    db.stepProgram(true);
	}
    }
}

class StepCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new StepCommand);
    }

    override {
	string name()
	{
	    return "step";
	}

	string shortName()
	{
	    return "s";
	}

	string description()
	{
	    return "step the program being debugged, stepping into function calls";
	}

	void run(Debugger db, string[] args)
	{
	    db.stepProgram(false);
	}
    }
}

class StepICommand: Command
{
    static this()
    {
	Debugger.registerCommand(new StepICommand);
    }

    override {
	string name()
	{
	    return "stepi";
	}

	string shortName()
	{
	    return "si";
	}

	string description()
	{
	    return "Step the program one instruction, stepping into function calls";
	}

	void run(Debugger db, string[] args)
	{
	    db.stepInstruction(false);
	}
    }
}

class NextICommand: Command
{
    static this()
    {
	Debugger.registerCommand(new NextICommand);
    }

    override {
	string name()
	{
	    return "nexti";
	}

	string description()
	{
	    return "Step the program one instruction, stepping over function calls";
	}

	void run(Debugger db, string[] args)
	{
	    db.stepInstruction(true);
	}
    }
}

class ContinueCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ContinueCommand);
    }

    override {
	string name()
	{
	    return "continue";
	}

	string description()
	{
	    return "continue the program being debugged";
	}

	void run(Debugger db, string[] args)
	{
	    if (!db.target_) {
		db.pagefln("Program is not being debugged");
		return;
	    }

	    db.target_.cont();
	    db.target_.wait();
	    db.stopped();
	}
    }
}

class FinishCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new FinishCommand);
    }

    override {
	string name()
	{
	    return "finish";
	}

	string description()
	{
	    return "Continue to calling stack frame";
	}

	void run(Debugger db, string[] args)
	{
	    if (!db.topFrame.outer) {
		db.pagefln("Already in outermost stack frame");
		return;
	    }
	    auto fromFrame = db.getFrame(0);
	    auto toFrame = db.getFrame(1);

	    Type rTy = fromFrame.func_.returnType;
	    db.setStepBreakpoint(toFrame.state_.pc);
	    db.target_.cont();
	    db.target_.wait();
	    db.clearStepBreakpoints();
	    if (rTy) {
		/*
		 * XXX factor out calling convention details
		 */
		MachineState s = db.threads_[0].state;
		Location loc = new RegisterLocation(0, s.grWidth(0));
		Value val = new Value(loc, rTy);
		db.pagefln("Value returned is %s", val.toString(null, s));
	    }
	    db.stopped();
	}
    }
}

class BreakCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new BreakCommand);
    }

    override {
	string name()
	{
	    return "break";
	}

	string description()
	{
	    return "Set a breakpoint";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length > 1) {
		db.pagefln("usage: break [<function or line>]");
		return;
	    }
	    db.setBreakpoint(args.length == 1 ? args[0] : null);
	}
    }
}

class EnableCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new EnableCommand);
    }

    override {
	string name()
	{
	    return "enable";
	}

	string description()
	{
	    return "Enable a breakpoint";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length != 1) {
		db.pagefln("usage: enable <id>");
		return;
	    }
	    try {
		db.enableBreakpoint(toUint(args[0]));
	    } catch (ConvError ce) {
		db.pagefln("Can't parse breakpoint ID");
	    }
	}
    }
}

class DisableCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DisableCommand);
    }

    override {
	string name()
	{
	    return "disable";
	}

	string description()
	{
	    return "Disable a breakpoint";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length != 1) {
		db.pagefln("usage: disable <id>");
		return;
	    }
	    try {
		db.disableBreakpoint(toUint(args[0]));
	    } catch (ConvError ce) {
		db.pagefln("Can't parse breakpoint ID");
	    }
	}
    }
}

class DeleteCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DeleteCommand);
    }

    override {
	string name()
	{
	    return "delete";
	}

	string shortName()
	{
	    return "d";
	}

	string description()
	{
	    return "Delete a breakpoint";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length != 1) {
		db.pagefln("usage: delete <id>");
		return;
	    }
	    try {
		db.deleteBreakpoint(toUint(args[0]));
	    } catch (ConvError ce) {
		db.pagefln("Can't parse breakpoint ID");
	    }
	}
    }
}

class InfoBreakCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoBreakCommand);
    }

    override {
	string name()
	{
	    return "break";
	}

	string description()
	{
	    return "List breakpoints";
	}

	void run(Debugger db, string[] args)
	{
	    if (db.breakpoints_.length == 0) {
		db.pagefln("No breakpoints");
		return;
	    }
	    db.pagefln("%-3s %-3s %-18s %s",
		     "Id", "Enb", "Address", "Where");
	    foreach (b; db.breakpoints_) {
		ulong[] addrs = b.addresses;
			
		if (addrs.length > 0) {
		    bool first = true;
		    foreach (addr; addrs) {
			if (first)
			    writef("%-3d %-3s %#-18x ",
				   b.id, b.enabled ? "y" : "n", addr);
			else
			    writef("        %#-18x ", addr);
			first = false;
			db.pagefln("%s", db.describeAddress(addr, null));
		    }
		} else {
		    db.pagefln("%-3d %-3s %-18s %s",
			     b.id,  b.enabled ? "y" : "n", " ", b.expr);
		}
	    }
	}
    }
}

class InfoThreadCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoThreadCommand);
    }

    override {
	string name()
	{
	    return "thread";
	}

	string description()
	{
	    return "List threads";
	}

	void run(Debugger db, string[] args)
	{
	    foreach (i, t; db.threads_) {
		db.pagefln("%d: stopped at 0x%08x", i + 1, t.state.pc);
	    }
	}
    }
}

class InfoRegistersCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoRegistersCommand);
    }

    override {
	string name()
	{
	    return "registers";
	}

	string description()
	{
	    return "List registerss";
	}

	void run(Debugger db, string[] args)
	{
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("No current stack frame");
		return;
	    }
	    db.pagefln("%s", f.toString);
	    auto s = f.state_;
	    s.dumpState;
	    ulong pc = s.pc;
	    ulong tpc = pc;
	    db.pagefln("%s:\t%s", db.lookupAddress(pc),
		     s.disassemble(tpc, &db.lookupAddress));
	}
    }
}

class InfoVariablesCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoVariablesCommand);
    }

    override {
	string name()
	{
	    return "variables";
	}

	string description()
	{
	    return "List variables";
	}

	void run(Debugger db, string[] args)
	{
	    string fmt = null;

	    if (!db.target_) {
		db.pagefln("target is not running");
		return;
	    }

	    if (args.length > 0 && args[0][0] == '/') {
		uint count, width;
		if (!db.parseFormat(args[0], count, width, fmt))
		    return;
		if (fmt == "i") {
		    db.pagefln("Instruction format not supported");
		    return;
		}
		if (count != 1) {
		    db.pagefln("Counts greater than one not supported");
		    return;
		}
		if (width != 4) {
		    db.pagefln("Format width characters not supported");
		}
		args = args[1..$];
	    }

	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("current stack frame is invalid");
		return;
	    }
	    MachineState s = f.state_;
	    DebugInfo di;

	    if (db.findDebugInfo(s, di)) {
		Function func = di.findFunction(s.pc);
		auto vars = func.arguments;
		vars ~= func.variables;
		foreach (v; vars) {
		    if (!v.value.loc.valid(s))
			continue;
		    db.pagefln("%s = %s", v.toString, v.valueToString(fmt, s));
		}
	    }
	}
    }
}

class FrameCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new FrameCommand);
    }

    override {
	string name()
	{
	    return "frame";
	}

	string description()
	{
	    return "Manipulate stack frame";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length > 1) {
		db.pagefln("usage: frame [frame index]");
		return;
	    }
	    if (args.length == 1) {
		uint frameIndex;
		try {
		    frameIndex = toUint(args[0]);
		} catch (ConvError ce) {
		    frameIndex = ~0;
		}
		Frame f = db.getFrame(frameIndex);
		if (!f) {
		    db.pagefln("Invalid frame number %s", args[1]);
		    return;
		}
		db.currentFrame_ = f;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class UpCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new UpCommand);
    }

    override {
	string name()
	{
	    return "up";
	}

	string description()
	{
	    return "Select next outer stack frame";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length != 0) {
		db.pagefln("usage: up");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    if (f.outer)
		db.currentFrame_ = f = f.outer;
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class DownCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DownCommand);
    }

    override {
	string name()
	{
	    return "down";
	}

	string description()
	{
	    return "Select next inner stack frame";
	}

	void run(Debugger db, string[] args)
	{
	    if (args.length != 0) {
		db.pagefln("usage: down");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    if (f.inner)
		db.currentFrame_ = f = f.inner;
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class WhereCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new WhereCommand);
    }

    override {
	string name()
	{
	    return "where";
	}

	string description()
	{
	    return "Stack backtrace";
	}

	void run(Debugger db, string[] args)
	{
	    for (Frame f = db.topFrame; f; f = f.outer)
		db.pagefln("%d: %s", f.index_,
		    db.describeAddress(f.state_.pc, f.state_));
	}
    }
}

class PrintCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new PrintCommand);
    }

    override {
	string name()
	{
	    return "print";
	}

	string description()
	{
	    return "evaluate and print expressio";
	}

	void run(Debugger db, string[] args)
	{
	    MachineState s;
	    DebugInfo di;
	    string fmt = null;

	    auto f = db.currentFrame;
	    if (f)
		s = f.state_;

	    if (args.length > 0 && args[0][0] == '/') {
		uint count, width;
		if (!db.parseFormat(args[0], count, width, fmt))
		    return;
		if (fmt == "i") {
		    db.pagefln("Instruction format not supported");
		    return;
		}
		if (count != 1) {
		    db.pagefln("Counts greater than one not supported");
		    return;
		}
		if (width != 4) {
		    db.pagefln("Format width characters not supported");
		}
		args = args[1..$];
	    }

	    string expr;
	    if (args.length == 0) {
		if (!lastExpr_) {
		    db.pagefln("No previous expression to print");
		    return;
		}
		expr = lastExpr_;
	    } else {
		expr = join(args, " ");
		lastExpr_ = expr;
	    }

	    auto sc = new UnionScope;
	    Language lang;
	    if (f) {
		lang = f.lang_;

		Value thisvar;
		if (f.func_.thisArgument(thisvar)) {
		    PointerType ptrTy =
			cast (PointerType) thisvar.type.underlyingType;
		    if (ptrTy) {
			Value v = ptrTy.dereference(s, thisvar.loc);
			CompoundType cTy = cast (CompoundType) v.type;
			sc.addScope(new CompoundScope(cTy, v.loc, s));
		    }
		}
		sc.addScope(f.func_);
		sc.addScope(f.di_);
		sc.addScope(s);
	    } else {
		lang = new CLikeLanguage;
		sc.addScope(db.modules_[0].debugInfo);	// XXX
	    }
	    sc.addScope(db);

	    try {
		auto e = lang.parseExpr(expr);
		auto v = e.eval(sc, s).toValue(s);
		db.pagefln("$%s = (%s) %s", db.valueHistory_.length, v.type.toString, v.toString(fmt, s));
		db.valueHistory_ ~= v;
	    } catch (EvalException ex) {
		db.pagefln("%s", ex.msg);
	    }
	}
    }
private:
    string lastExpr_;
}

class ExamineCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ExamineCommand);
    }

    override {
	string name()
	{
	    return "examine";
	}

	string shortName()
	{
	    return "x";
	}

	string description()
	{
	    return "Examine memory";
	}

	void run(Debugger db, string[] args)
	{
	    MachineState s;
	    DebugInfo di;

	    if (!db.target_) {
		db.pagefln("Target is not running");
		return;
	    }
	    auto f = db.currentFrame;
	    if (f)
		s = f.state_;
	    else
		s = db.threads_[0].state;

	    if (args.length > 0 && args[0][0] == '/') {
		if (!db.parseFormat(args[0], count_, width_, fmt_))
		    return;
		args = args[1..$];
	    }

	    ulong addr;
	    if (args.length == 0) {
		if (!lastAddrValid_) {
		    db.pagefln("No previous address to examine");
		    return;
		}
		addr = lastAddr_;
	    } else {
		string expr = join(args, " ");
		auto sc = new UnionScope;
		Language lang;
		if (f) {
		    lang = f.lang_;

		    Value thisvar;
		    if (f.func_.thisArgument(thisvar)) {
			PointerType ptrTy =
			    cast (PointerType) thisvar.type.underlyingType;
			if (ptrTy) {
			    Value v = ptrTy.dereference(s, thisvar.loc);
			    CompoundType cTy = cast (CompoundType) v.type;
			    sc.addScope(new CompoundScope(cTy, v.loc, s));
			}
		    }
		    sc.addScope(f.func_);
		    sc.addScope(f.di_);
		    sc.addScope(s);
		} else {
		    lang = new CLikeLanguage;
		    sc.addScope(db.modules_[0].debugInfo);	// XXX
		}
		sc.addScope(db);

		try {
		    auto e = lang.parseExpr(expr);
		    auto v = e.eval(sc, s).toValue(s);
		    addr = s.readInteger(v.loc.readValue(s));
		} catch (EvalException ex) {
		    db.pagefln("%s", ex.msg);
		    return;
		}
	    }

	    uint count = count_;
	    if (fmt_ == "i") {
		while (count > 0) {
		    db.pagefln("%#-15x %s", addr, s.disassemble(addr, &db.lookupAddress));
		    count--;
		}
	    } else {
		string line = format("%#-15x ", addr);
		while (count > 0) {
		    ubyte[] mem = db.target_.readMemory(addr, width_);
		    addr += width_;
		    ulong val = s.readInteger(mem);
		    if (width_ < 8)
			val &= (1UL << width_ * 8) - 1;
		    string fmt = format("%%0%d%s ", 2*width_, fmt_);
		    string vs = format(fmt, val);
		    if (line.length + vs.length > 79) {
			db.pagefln("%s", line);
			line = format("%#-15x ", addr);
		    }
		    line ~= vs;
		    count--;
		}
		db.pagefln("%s", line);
	    }
	    lastAddrValid_ = true;
	    lastAddr_ = addr;
	}
    }
private:
    bool lastAddrValid_;
    ulong lastAddr_;
    uint count_ = 1;
    uint width_ = 4;
    string fmt_ = "x";
}

class ListCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ListCommand);
    }

    override {
	string name()
	{
	    return "list";
	}

	string description()
	{
	    return "list source file contents";
	}

	void run(Debugger db, string[] args)
	{
	    uint line = 0;
	    SourceFile sf = null;
	    if (args.length > 1) {
		db.pagefln("usage: list [- | <file:line>]");
		return;
	    }
	    if (args.length == 0) {
		sf = sourceFile_;
		line = sourceLine_;
	    } else if (args[0] == "-") {
		sf = sourceFile_;
		line = sourceLine_;
		if (line > 20)
		    line -= 20;
		else
		    line = 1;
	    } else if (args.length == 1) {
		if (!db.parseSourceLine(args[0], sf, line)) {
		    line = 0;
		    sf = db.findFile(args[1]);
		}
	    }
	    if (sf) {
		if (line == 0) {
		    if (sf == sourceFile_)
			line = sourceLine_;
		    else
			line = 1;
		}
	    } else {
		db.pagefln("no source file");
		return;
	    }
	    uint sl, el;
	    if (line > 5)
		sl = line - 5;
	    else
		sl = 1;
	    el = sl + 10;
	    for (uint ln = sl; ln < el; ln++)
		db.displaySourceLine(sf, ln);
	    db.setCurrentSourceLine(sf, line);
	    sourceFile_ = sf;
	    sourceLine_ = el + 5;
	}
	void onSourceLine(Debugger db, SourceFile sf, uint line)
	{
	    sourceFile_ = sf;
	    sourceLine_ = line;
	}
    }

    SourceFile sourceFile_;
    uint sourceLine_;
}
