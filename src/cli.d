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
interface Command
{
    /**
     * Return the command name.
     */
    string name();

    /**
     * Return the command description.
     */
    string description();

    /**
     * Execute the command
     */
    void run(Debugger db, string format, string[] args);
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

    Command[string] list_;
}

private class Breakpoint
{
    this(Debugger db, uint id, string expr)
    {
	db_ = db;
	id_ = id;
	expr_ = expr;
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
	if ((pos = expr_.find(':')) >= 0) {
	    // Assume the expr is file:line
	    uint line = toUint(expr_[pos + 1..expr_.length]);
	    string file = expr_[0..pos];
	    found = di.findLineByName(file, line, lines);
	} else {
	    // Try looking up a function
	    if (di)
		found = di.findLineByFunction(expr_, lines);
	}
	if (found) {
	    foreach (le; lines) {
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

    bool active()
    {
	return addresses_.length > 0;
    }

    uint id()
    {
	return id_;
    }

    string expr()
    {
	return expr_;
    }

    string[] describe()
    {
	string[] res;
	foreach (address; addresses_)
	    res ~= db_.describeAddress(address, null);
	if (res.length == 0)
	    res ~= expr;
	return res;
    }

    string expr_;
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
	try {
	    string file = cast(string) std.file.read(filename);
	    lines_ = splitlines(file);
	} catch {
	    writefln("Can't open file %s", filename);
	}
    }

    string[] lines_;
}

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener
{
    this(string prog)
    {
	prog_ = prog;

	HistEvent ev;
	hist_ = history_init();
	history(hist_, &ev, H_SETSIZE, 100);

	el_ = el_init(toStringz("qdebug"), stdin, stdout, stderr);
	el_set(el_, EL_EDITOR, toStringz("emacs"));
	el_set(el_, EL_SIGNAL, 1);
	el_set(el_, EL_PROMPT, &prompt);
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

    void run()
    {
	char* buf;
	int num;
	string[] args;

	sigaction_t sa;
	sa.sa_handler = &ignoreSig;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, null);

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
	try {
	    return sourceFiles_[filename];
	} catch {
	    SourceFile sf = new SourceFile(filename);
	    sourceFiles_[filename] = sf;
	    return sf;
	}
    }

    void stopped()
    {
	TargetThread t = threads_[0];	// XXX
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo d = mod.debugInfo;
	    if (d && d.findLineByAddress(t.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		if (le[0].line <= sf.lines_.length)
		    writefln("%d %s", le[0].line, sf.lines_[le[0].line - 1]);
	    }
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

    void setStepBreakpoint(TargetThread t)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo d = mod.debugInfo;
	    if (d && d.findLineByAddress(t.pc, le)) {
		target_.setBreakpoint(le[1].address, cast(void*) this);
		return;
	    }
	}
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

	    foreach (bp; breakpoints_)
		bp.activate(mod);
	}
	void onBreakpoint(Target, TargetThread t, void* id)
	{
	    /*
	     * We use this as id for the step breakpoint.
	     */
	    if (id == cast(void*) this) {
		target_.clearBreakpoint(id);
	    } else {
		foreach (i, bp; breakpoints_) {
		    if (id == cast(void*) bp) {
			writefln("Breakpoint %d, %s", i + 1, describeAddress(t.pc, t.state));
		    }
		}
	    }
	    stopped();
	}
	void onSignal(Target, int sig, string sigName)
	{
	    writefln("Signal %d (%s)", sig, sigName);
	}
    }

private:
    static int continuation_;
    static char *prompt(EditLine *el)
    {
	if (continuation_)
	    return "> ";
	else
	    return "(qdebug) ";
    }

    static CommandTable commands_;
    static CommandTable infoCommands_;
    History* hist_;
    EditLine* el_;
    Tokenizer* tok_;
    bool quit_ = false;

    string prog_;
    Target target_;
    TargetModule[] modules_;
    TargetThread[] threads_;
    Breakpoint[] breakpoints_;
    SourceFile[string] sourceFiles_;
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
	    string[] runArgs = args.dup;
	    runArgs[0] = db.prog_;
	    pt.connect(db, runArgs);
	    if (db.target_) {
		db.target_.cont();
		db.target_.wait();
	    }
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
	    return "step the program being debugged";
	}

	void run(Debugger db, string, string[] args)
	{
	    // XXX current thread
	    db.setStepBreakpoint(db.threads_[0]);
	    db.target_.cont();
	    db.target_.wait();
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
	    db.target_.cont();
	    db.target_.wait();
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
	    if (args.length != 2) {
		writefln("usage: break <function or line>");
		return;
	    }
	    Breakpoint bp = new Breakpoint(db, db.nextBPID_++, args[1]);
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
		writefln("%d: stopped at 0x%08x", i + 1, t.pc);
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
	    foreach (i, t; db.threads_) {
		writefln("%d: stopped at 0x%08x", i + 1, t.pc);
		t.state.dumpState;
		ulong pc = t.state.getGR(t.state.pcregno);
		ulong tpc = pc;
		writefln("%s:\t%s", db.lookupAddress(pc),
			 t.state.disassemble(tpc, &db.lookupAddress));
	    }
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
	    return "List variabless";
	}

	void run(Debugger db, string fmt, string[] args)
	{
	    TargetThread t = db.threads_[0];
	    MachineState s = t.state;
	    DebugInfo di;

	    if (db.findDebugInfo(s, di)) {
		Function func = di.findFunction(s.getGR(s.pcregno));
		auto vars = func.arguments;
		vars ~= func.variables;
		Language lang = di.findLanguage(s.getGR(s.pcregno));
		foreach (v; vars) {
		    writefln("%s = %s", v.toString(lang),
			     v.valueToString(fmt, lang, s));
		}
	    }
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
	    TargetThread t = db.threads_[0];
	    MachineState s = t.state, ns;
	    int i = 0;

	    while (s) {
		ulong pc = s.getGR(s.pcregno);
		writefln("%d: %s", i + 1, db.describeAddress(pc, s));
		
		DebugInfo di;
		if (db.findDebugInfo(s, di)) {
		    ns = di.unwind(s);
		} else {
		    ns = null;
		}

		s = ns;

		i++;
	    }
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
	    TargetThread t;
	    MachineState s;
	    DebugInfo di;

	    if (db.threads_.length > 0) {
		t = db.threads_[0];
		s = t.state;
	    } else {
		s = null;
	    }

	    if (args.length < 2) {
		writefln("usage: print <expr>");
		return;
	    }

	    auto sc = new UnionScope;
	    Language lang;
	    if (s && db.findDebugInfo(s, di)) {
		Function func = di.findFunction(s.getGR(s.pcregno));
		lang = di.findLanguage(s.getGR(s.pcregno));
		sc.addScope(func);
		sc.addScope(s);
	    } else {
		lang = new CLikeLanguage;
	    }

	    try {
		auto e = lang.parseExpr(join(args[1..$], " "));
		writefln("%s", e.eval(lang, sc, s).toString(fmt, lang, s));
	    } catch (Exception ex) {
		writefln("%s", ex.msg);
	    }
	}
    }
}
