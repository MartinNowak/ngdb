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
import machine.machine;

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
    void run(Debugger db, string[] args);
}

class CommandTable
{
    void run(Debugger db, string[] args, string prefix)
    {
	string message;

	Command c = lookup(args[0], message);
	if (c)
	    c.run(db, args);
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

private class CompoundBreakpoint: Breakpoint
{
    override {
	void enabled(bool b)
	{
	    enabled_ = b;
	    foreach (bp; bp_)
		bp.enabled = b;
	}
	bool enabled()
	{
	    return enabled_;
	}
	ulong address()
	{
	    return 0;
	}
    }

    void clear()
    {
	foreach (bp; bp_)
	    bp.clear();
	bp_.length = 0;
    }

    bool matches(Breakpoint tbp)
    {
	foreach (bp; bp_)
	    if (bp == tbp)
		return true;
	return false;
    }

private:
    bool enabled_ = true;
    Breakpoint[] bp_;
}

private class PendingBreakpoint: Breakpoint
{
    this(string expr)
    {
	expr_ = expr;
    }

    void activate(Target target, TargetModule mod)
    {
	if (mod in bp_) {
	    return;
	} else {
	    DebugInfo d = mod.debugInfo;
	    int pos;

	    LineEntry[] lines;
	    bool found;
	    if ((pos = expr_.find(':')) >= 0) {
		// Assume the expr is file:line
		uint line = toUint(expr_[pos + 1..expr_.length]);
		string file = expr_[0..pos];
		found = d.findLineByName(file, line, lines);

	    } else {
		// Try looking up a function
		found = d.findLineByFunction(expr_, lines);
	    }
	    if (found) {
		CompoundBreakpoint cb = new CompoundBreakpoint;
		foreach (le; lines) {
		    cb.bp_ ~= target.setBreakpoint(le.address);
		}
		bp_[mod] = cb;
	    }
	}
    }

    bool active()
    {
	return bp_.length > 0;
    }

    string expr()
    {
	return expr_;
    }

    bool matches(Breakpoint tbp)
    {
	foreach (bp; bp_)
	    if (bp.matches(tbp))
		return true;
	return false;
    }

    override {
	void enabled(bool b)
	{
	    enabled_ = b;
	    foreach (bp; bp_)
		bp.enabled = b;
	}
	bool enabled()
	{
	    return enabled_;
	}
	ulong address()
	{
	    return 0;
	}
	void clear()
	{
	    foreach (mod, bp; bp_) {
		clear();
		bp_.remove(mod);
	    }
	}
    }

    string expr_;
    bool enabled_ = true;
    CompoundBreakpoint[TargetModule] bp_;
}

private class SourceFile
{
    this(string filename)
    {
	try {
	    string file = cast(string) read(filename);
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
    }

    ~this()
    {
	history_end(hist_);
	el_end(el_);
	tok_end(tok_);
    }

    void run()
    {
	char* buf;
	int num;
	string[] args;

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

    string describeAddress(ulong pc)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo d = mod.debugInfo;
	    if (d && d.findLineByAddress(pc, le)) {
		return le[0].fullname ~ ":" ~ .toString(le[0].line);
	    }
	}
	foreach (mod; modules_) {
	    TargetSymbol sym;
	    if (mod.lookupSymbol(pc, sym)) {
		return sym.name ~ "+" ~ .toString(pc - sym.value);
	    }
	}
    }

    void setStepBreakpoint(TargetThread t)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo d = mod.debugInfo;
	    if (d && d.findLineByAddress(t.pc, le)) {
		stepBreakpoint_ = target_.setBreakpoint(le[1].address);
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
		bp.activate(target_, mod);
	}
	void onBreakpoint(Target, TargetThread t, Breakpoint tbp)
	{
	    if (tbp == stepBreakpoint_) {
		stepBreakpoint_.clear();
		stepBreakpoint_ = null;
	    } else {
		foreach (i, bp; breakpoints_) {
		    if (bp.matches(tbp)) {
			writefln("Breakpoint %d, %s", i + 1, describeAddress(t.pc));
		    }
		}
	    }
	    stopped();
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
    PendingBreakpoint[] breakpoints_;
    Breakpoint stepBreakpoint_;
    SourceFile[string] sourceFiles_;
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

	void run(Debugger db, string[] args)
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

	void run(Debugger db, string[] args)
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

	void run(Debugger db, string[] args)
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

	void run(Debugger db, string[] args)
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

	void run(Debugger db, string[] args)
	{
	    if (args.length != 2) {
		writefln("usage: break <function or line>");
		return;
	    }
	    PendingBreakpoint bp = new PendingBreakpoint(args[1]);
	    db.breakpoints_ ~= bp;
	    if (db.target_)
		foreach (mod; db.modules_)
		    bp.activate(db.target_, mod);
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
	    foreach (i, b; db.breakpoints_) {
		writef("%d: %s", i + 1, b.expr);
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

	void run(Debugger db, string[] args)
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

	void run(Debugger db, string[] args)
	{
	    foreach (i, t; db.threads_) {
		writefln("%d: stopped at 0x%08x", i + 1, t.pc);
		t.state.dumpState;
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

	void run(Debugger db, string[] args)
	{
	    TargetThread t = db.threads_[0];
	    MachineState s = t.state;
	    int i = 0;

	    while (s) {
		ulong pc = s.getGR(s.pcregno);
		writefln("%d: %s", i + 1, db.describeAddress(pc));
		Location loc;
		MachineState ns = null;
		foreach (mod; db.modules_) {
		    DebugInfo d = mod.debugInfo;
		    if (d.findFrameBase(s, loc)) {
			ns = d.unwind(s);
			break;
		    }
		}
		s = ns;

		i++;
	    }
	}
    }
}
