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
import objfile.debuginfo;
import objfile.language;
import machine.machine;

version (DigitalMars)
import std.c.freebsd.freebsd;
else
import std.c.unix.unix;
import std.conv;
static import std.path;
import std.string;
import std.stdio;
import std.file;
import std.c.stdio;

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
     * Return the command description.
     */
    abstract string description();

    /**
     * Execute the command
     */
    abstract void run(Debugger db, string format, string[] args);

    /**
     * Called when the program stops with the current source file and line
     */
    void onStopped(Debugger db, SourceFile sf, uint line)
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
	    format = name[i+1..$];
	    switch (format) {
	    case "d":
	    case "x":
	    case "o":
		break;
	    default:
		writefln("Unsupported format string %s", format);
		return;
	    }
	    name = name[0..i];
	}

	Command c = lookup(name, message);
	if (c)
	    c.run(db, format, args);
	else
	    writefln("Command %s%s is %s", prefix, args[0], message);
    }

    void add(Command c)
    {
	list_[c.name] = c;
    }

    Command lookup(string name, out string message)
    {
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

    void onStopped(Debugger db, SourceFile sf, uint line)
    {
	foreach (c; list_)
	    c.onStopped(db, sf, line);
    }

    Command[string] list_;
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
	db_.target_.clearBreakpoint(cast(void*) this);
	enabled_ = false;
    }

    void enable()
    {
	foreach (address; addresses_)
	    db_.target_.setBreakpoint(address, cast(void*) this);
	enabled_ = true;
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

    bool matches(ulong pc)
    {
	foreach (addr; addresses_)
	    if (pc == addr)
		return true;
	return false;
    }

    string[] describe()
    {
	string[] res;
	foreach (addr; addresses_)
	    res ~= format("%#x: %s", addr, db_.describeAddress(addr, null));
	if (res.length == 0) {
	    if (sf_)
		res ~= format("%s:%d", sf_.filename, line_);
	    else
		res ~= func_;
	}
	return res;
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
    this(Debugger db, uint index,
	 DebugInfo di, Function func, MachineState state)
    {
	db_ = db;
	index_ = index;
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

    Debugger db_;
    uint index_;
    DebugInfo di_;
    Function func_;
    Language lang_;
    MachineState state_;
    ulong addr_;
}

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener
{
    this(string prog)
    {
	prog_ = prog;
	prompt_ = "(qdebug)";

	HistEvent ev;
	hist_ = history_init();
	history(hist_, &ev, H_SETSIZE, 100);

	el_ = el_init(toStringz("qdebug"), stdin, stdout, stderr);
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

	staticPrompt_ = prompt_;
	while (!quit_ && (buf = el_gets(el_, &num)) != null && num != 0) {
	    int ac;
	    char** av;
	    LineInfo *li;

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

	    if (args[0] == "history") {
		for (int rv = history(hist_, &ev, H_LAST);
		     rv != -1;
		     rv = history(hist_, &ev, H_PREV))
		    writef("%d %s", ev.num, .toString(ev.str));
	    } else {
		commands_.run(this, args, "");
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

	if (findDebugInfo(t.state, di)) {
	    Location loc;
	    Function func;
	    if (di.findFrameBase(s, loc) && (func = di.findFunction(s.pc)) !is null) {
		if (frames_.length == 0 || frames_[0].func_ != func
		    || frames_[0].addr_ != loc.address(s)) {
		    writefln("%s", describeAddress(s.pc, s));
		    frames_.length = 0;
		    MachineState fs = s;
		    DebugInfo fdi = di;
		    uint fi = 0;
		    for (;;) {
			frames_ ~= new Frame(this, fi++, fdi, func, fs);
			fs = di.unwind(fs);
			if (!fs)
			    break;
			if (!findDebugInfo(fs, fdi))
			    break;
			func = di.findFunction(fs.pc);
			if (!func)
			    break;
		    }
		    currentFrame_ = 0;
		}
	    }
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		currentSourceFile_ = stoppedSourceFile_ = sf;
		currentSourceLine_ = stoppedSourceLine_ = le[0].line;
		displaySourceLine(sf, currentSourceLine_);
		commands_.onStopped(this, sf, le[0].line);
		infoCommands_.onStopped(this, sf, le[0].line);
	    }
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

    string describeAddress(ulong pc, MachineState state)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (di && di.findLineByAddress(pc, le)) {
		string s = "";

		Function func = di.findFunction(pc);
		if (func) {
		    s = func.toString(null, di.findLanguage(pc), state);
		}

		s ~= le[0].fullname ~ ":" ~ .toString(le[0].line);
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
			debug (step)
			    stoppedAt("stopped at", s.pc);
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

    Frame currentFrame()
    {
	if (frames_.length > currentFrame_)
	    return frames_[currentFrame_];
	return null;
    }

    Frame getFrame(uint frameIndex)
    {
	if (frames_.length > frameIndex)
	    return frames_[frameIndex];
	return null;
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
	    writefln("New module %s", mod.filename);
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
	    if (target_) {
		writefln("Target program has exited.");
		target_ = null;
		threads_.length = 0;
		modules_.length = 0;
		foreach (bp; breakpoints_)
		    bp.onExit;
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
    string prompt_;
    Target target_;
    TargetModule[] modules_;
    TargetThread[] threads_;
    Frame[] frames_;
    uint currentFrame_;
    Breakpoint[] breakpoints_;
    SourceFile[string] sourceFiles_;
    SourceFile[string] sourceFilesBasename_;
    SourceFile stoppedSourceFile_;
    uint stoppedSourceLine_;
    SourceFile currentSourceFile_;
    uint currentSourceLine_;
    uint nextBPID_;
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

	void run(Debugger db, string, string[] args)
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

	void run(Debugger db, string, string[] args)
	{
	    foreach (c; db.commands_.list_)
		writefln("%s: %s", c.name, c.description);
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

	void run(Debugger db, string, string[] args)
	{
	    args = args[1..args.length];

	    if (args.length == 0) {
		writefln("usage: info subcommand [args ...]");
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

	void run(Debugger db, string, string[] args)
	{
	    if (db.target_) {
		writefln("Program is already being debugged");
		return;
	    }

	    PtraceRun pt = new PtraceRun;
	    if (args.length > 1 || runArgs_.length == 0) {
		runArgs_ = args.dup;
		runArgs_[0] = db.prog_;
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

	string description()
	{
	    return "step the program being debugged, stepping over function calls";
	}

	void run(Debugger db, string, string[] args)
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

	string description()
	{
	    return "step the program being debugged, stepping into function calls";
	}

	void run(Debugger db, string, string[] args)
	{
	    db.stepProgram(false);
	}
    }
}

class IStepCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new IStepCommand);
    }

    override {
	string name()
	{
	    return "istep";
	}

	string description()
	{
	    return "Step the program one instruction, stepping into function calls";
	}

	void run(Debugger db, string, string[] args)
	{
	    db.stepInstruction(false);
	}
    }
}

class INextCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new INextCommand);
    }

    override {
	string name()
	{
	    return "inext";
	}

	string description()
	{
	    return "Step the program one instruction, stepping over function calls";
	}

	void run(Debugger db, string, string[] args)
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

	void run(Debugger db, string, string[] args)
	{
	    if (!db.target_) {
		writefln("Program is not being debugged");
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

	void run(Debugger db, string, string[] args)
	{
	    if (db.frames_.length < 2) {
		writefln("Already in outermost stack frame");
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
		Language lang = toFrame.di_.findLanguage(s.pc);
		Location loc = new RegisterLocation(0, s.grWidth(0));
		Value val = Value(loc, rTy);
		writefln("Value returned is %s", val.toString(null, lang, s));
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

	void run(Debugger db, string, string[] args)
	{
	    if (args.length > 2) {
		writefln("usage: break [<function or line>]");
		return;
	    }
	    SourceFile sf;
	    string func;
	    uint line;
	    if (args.length == 2) {
		string file;
		if (!db.parseSourceLine(args[1], sf, line))
		    func = args[1];
	    } else {
		sf = db.currentSourceFile_;
		line = db.currentSourceLine_;
		if (!sf) {
		    writefln("no current source file");
		    return;
		}
	    }
	    Breakpoint bp;
	    if (sf)
		bp = new Breakpoint(db, db.nextBPID_++, sf, line);
	    else
		bp = new Breakpoint(db, db.nextBPID_++, func);
	    db.breakpoints_ ~= bp;
	    if (db.target_)
		foreach (mod; db.modules_)
		    bp.activate(mod);
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

	void run(Debugger db, string, string[] args)
	{
	    foreach (b; db.breakpoints_) {
		string[] desc = b.describe;
		bool first = true;
		foreach (s; desc) {
		    if (first)
			writef("%d:\t", b.id);
		    else
			writef("\n\t");
		    first = false;
		    writef("%s", s);
		}
		if (b.active)
		    writefln(" (active)");
		else
		    writefln(" (inactive)");
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

	void run(Debugger db, string, string[] args)
	{
	    foreach (i, t; db.threads_) {
		writefln("%d: stopped at 0x%08x", i + 1, t.state.pc);
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

	void run(Debugger db, string, string[] args)
	{
	    auto f = db.currentFrame;
	    writefln("%s", f.toString);
	    auto s = f.state_;
	    s.dumpState;
	    ulong pc = s.pc;
	    ulong tpc = pc;
	    writefln("%s:\t%s", db.lookupAddress(pc),
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

	void run(Debugger db, string fmt, string[] args)
	{
	    if (!db.target_) {
		writefln("target is not running");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		writefln("current stack frame is invalid");
		return;
	    }
	    MachineState s = f.state_;
	    DebugInfo di;

	    if (db.findDebugInfo(s, di)) {
		Function func = di.findFunction(s.pc);
		auto vars = func.arguments;
		vars ~= func.variables;
		Language lang = di.findLanguage(s.pc);
		foreach (v; vars) {
		    writefln("%s = %s", v.toString(lang),
			     v.valueToString(fmt, lang, s));
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

	void run(Debugger db, string, string[] args)
	{
	    if (args.length > 2) {
		writefln("usage: frame [frame index]");
		return;
	    }
	    if (args.length == 2) {
		uint frameIndex;
		try {
		    frameIndex = toUint(args[1]);
		} catch (ConvError ce) {
		    frameIndex = ~0;
		}
		if (frameIndex >= db.frames_.length) {
		    writefln("Invalid frame number %s", args[1]);
		    return;
		}
		db.currentFrame_ = frameIndex;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		writefln("stack frame information unavailable");
		return;
	    }
	    writefln("%s", f.toString);
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

	void run(Debugger db, string, string[] args)
	{
	    if (args.length != 1) {
		writefln("usage: up");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		writefln("stack frame information unavailable");
		return;
	    }
	    if (f.index_ + 1 < db.frames_.length) {
		db.currentFrame_ = f.index_ + 1;
		f = db.currentFrame;
	    }
	    writefln("%s", f.toString);
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

	void run(Debugger db, string, string[] args)
	{
	    if (args.length != 1) {
		writefln("usage: down");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		writefln("stack frame information unavailable");
		return;
	    }
	    if (f.index_ > 0) {
		db.currentFrame_ = f.index_ - 1;
		f = db.currentFrame;
	    }
	    writefln("%s", f.toString);
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

	void run(Debugger db, string, string[] args)
	{
	    foreach (f; db.frames_)
		writefln("%d: %s", f.index_,
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

	void run(Debugger db, string fmt, string[] args)
	{
	    MachineState s;
	    DebugInfo di;

	    auto f = db.currentFrame;
	    if (f)
		s = f.state_;

	    if (args.length < 2) {
		writefln("usage: print <expr>");
		return;
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
		sc.addScope(s);
	    } else {
		lang = new CLikeLanguage;
	    }

	    try {
		auto e = lang.parseExpr(join(args[1..$], " "));
		auto v = e.eval(lang, sc, s);
		writefln("%s", v.toString(fmt, lang, s));
	    } catch (Exception ex) {
		writefln("%s", ex.msg);
	    }
	}
    }
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

	void run(Debugger db, string fmt, string[] args)
	{
	    uint line = 0;
	    SourceFile sf = null;
	    if (args.length > 2) {
		writefln("usage: list [- | <file:line>]");
		return;
	    }
	    if (args.length == 1) {
		sf = sourceFile_;
		line = sourceLine_;
	    } else if (args[1] == "-") {
		sf = sourceFile_;
		line = sourceLine_;
		if (line > 20)
		    line -= 20;
		else
		    line = 1;
	    } else if (args.length == 2) {
		if (!db.parseSourceLine(args[1], sf, line)) {
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
		writefln("no source file");
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
	    sourceFile_ = sf;
	    sourceLine_ = el + 5;
	    db.currentSourceFile_ = sf;
	    db.currentSourceLine_ = line;
	}
	void onStopped(Debugger db, SourceFile sf, uint line)
	{
	    sourceFile_ = sf;
	    sourceLine_ = line;
	}
    }

    SourceFile sourceFile_;
    uint sourceLine_;
}
