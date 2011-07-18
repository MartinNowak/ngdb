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

module cli;

//debug = step;

version = editline;

version (editline)
	import editline;
import target.target;
import target.ptracetarget;
import target.coldtarget;
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import machine.machine;

import core.sys.posix.signal;
import core.vararg;

import std.c.stdlib;
import std.algorithm;
import std.array;
import std.ascii;
import std.conv;
import std.datetime;
import std.exception;
static import std.path;
import std.string;
import std.stdio;
import std.traits;
import std.file;
import std.c.stdio;

extern (C) char* readline(char*);
extern (C) void add_history(char*);
extern (C) void free(void*);

private class Breakpoint: TargetBreakpointListener
{
    this(Debugger db, SourceFile sf, uint line)
    {
	db_ = db;
	sf_ = sf;
	line_ = line;
    }

    this(Debugger db, string func)
    {
	db_ = db;
	func_ = func;
    }

    bool onBreakpoint(Target, TargetThread t)
    {
	db_.currentThread = t;
	if (condition_) {
	    db_.setCurrentFrame;
	    auto f = db_.currentFrame_;
	    auto sc = f.scope_;
	    auto s = t.state;
	    try {
		auto v = expr_.eval(sc, s).toValue(s);
		if (v.type.isIntegerType)
		    if (!s.readInteger(v.loc.readValue(s)))
			return false;
	    } catch (EvalException ex) {
		db_.pagefln("Error evaluating breakpoint condition: %s", ex.msg);
		return true;
	    }
	}
	writefln("Stopped at breakpoint %d", id);
	if (command_) {
	    db_.stopped();
	    db_.executeCommand(command);
	}
	return true;
    }

    string[] condition()
    {
	return condition_;
    }

    void condition(string[] s)
    {
	if (s == null)
	    writefln("Breakpoint %d is now unconditional", id);

	/*
	 * Try to guess a source language for parsing the expression.
	 */
	Language lang;
	gotLang: foreach (address; addresses_) {
	    foreach (mod; db_.modules_) {
		auto di = mod.debugInfo;
		if (di)
		    lang = di.findLanguage(address);
		if (lang)
		    break gotLang;
	    }
	}
	if (!lang)
	    lang = CLikeLanguage.instance;
	try {
            // TODO: switch parseExpr to list
	    auto e = lang.parseExpr(join(s, " "), db_);
	    condition_ = s;
	    expr_ = e;
	} catch (EvalException ex) {
	    db_.pagefln("Error parsing breakpoint condition: %s", ex.msg);
	}
    }

    string[] command()
    {
	return command_;
    }

    void command(string[] s)
    {
	command_ = s;
    }

    void activate(TargetModule mod)
    {
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
	    if (!found) {
		TargetSymbol sym;
		if (mod.lookupSymbol(func_, sym) && sym.value) {
		    LineEntry le;
		    le.address = sym.value;
		    lines ~= le;
		    found = true;
		}
	    }
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
		if (di) {
		    Function f = di.findFunction(le.address);
		    if (func && f == func)
			continue;
		    func = f;
		}
		db_.target_.setBreakpoint(le.address, this);
		addresses_ ~= le.address;
	    }
	}
    }

    void deactivate(TargetModule mod)
    {
	ulong[] newAddresses;

	foreach (addr; addresses_)
	    if (!mod.contains(addr))
		newAddresses ~= addr;
	addresses_ = newAddresses;
    }

    void disable()
    {
	if (enabled_) {
	    if (addresses_.length > 0)
		db_.target_.clearBreakpoint(this);
	    enabled_ = false;
	}
    }

    void enable()
    {
	if (!enabled_) {
	    foreach (address; addresses_)
		db_.target_.setBreakpoint(address, this);
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

    static void printHeader()
    {
	writefln("%-7s %-14s %-4s %-3s %-18s %s",
		 "Num", "Type", "Disp", "Enb", "Address", "What");
    }

    void print()
    {
	if (addresses_.empty) {
	    writef("%-7d %-14s %-4s %-3s ", id, "breakpoint", "keep", enabled ? "y" : "n");
            writefln("%-18s %s", "<PENDING>", expr);
        } else {
            writef("%-7d %-14s %-4s %-3s ", id, "breakpoint", "keep", enabled ? "y" : "n");
            if (addresses_.length == 1) {
                auto addr = addresses_.front;
                writef("%#-18x ", addr);
                writeln(db_.describeAddress(addr, null));
            } else {
                writefln("%-18s ", "<MULTIPLE>");
                foreach(sidx, addr; addresses_) {
                    auto cid = std.string.format("%d.%d", id, sidx + 1);
                    writef("%-27s %-3s %#-18x ", cid, enabled ? "y" : "n", addr);
                    writeln(db_.describeAddress(addr, null));
                }
            }
        }
	if (condition_)
	    writefln("\tstop only if %s", join(condition_, " "));
	if (command_)
	    writefln("\t%s", join(command_, " "));
    }

    SourceFile sf_;
    uint line_;
    string func_;
    string[] condition_;
    string[] command_;
    Expr expr_;
    bool enabled_ = true;
    Debugger db_;
    uint id_;
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
                lastModifiedTime_ = timeLastModified(filename_);
		lines_ = splitLines(file);
	    } catch {
		writefln("Can't open file %s", filename);
		error_ = true;
	    }
	}
	if (lineno < 1 || lineno > lines_.length)
	    return null;
        auto ftm = timeLastModified(filename_);
	if (ftm != lastModifiedTime_) {
	    lines_ = null;
	    return opIndex(lineno);
	}
	return lines_[lineno - 1];
    }

    string filename()
    {
	return filename_;
    }

    string filename_;
    SysTime lastModifiedTime_;
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
	if (di) {
	    di.findFrameBase(state, loc);
	    addr_ = loc.address(state);
	    lang_ = di.findLanguage(state.pc);
	} else {
	    addr_ = 0;
	    lang_ = CLikeLanguage.instance;
	}

	auto sc = new UnionScope;
	Value thisvar;
	if (func_ && func_.thisArgument(thisvar)) {
	    PointerType ptrTy =
		cast (PointerType) thisvar.type.underlyingType;
	    if (ptrTy) {
		Value v = ptrTy.dereference(state_, thisvar.loc);
		CompoundType cTy = cast (CompoundType) v.type;
		sc.addScope(new CompoundScope(cTy, v.loc, state_));
	    }
	}
	if (func_)
		sc.addScope(func_);
	sc.addScope(db_);
	sc.addScope(state_);
	scope_ = sc;
    }

    override string toString()
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

	if (!di_)
	    return null;

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
    Scope scope_;
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
 * Return a copy of list with all duplicates removed.
 */
private string[] uniq(string[] list)
{
    bool[string] map;

    foreach (s; list)
	map[s] = true;
    return map.keys;
}

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener, TargetBreakpointListener, Scope
{
    this(string prog, string core, uint annotate)
    {
	prog_ = prog;
	core_ = core;
        annotate_ = annotate;
	prompt = "(ngdb)";

	version (editline) {
	    HistEvent ev;
	    hist_ = history_init();
	    history(hist_, &ev, H_SETSIZE, 100);

	    el_ = el_init(toStringz("ngdb"), std.c.stdio.stdin, std.c.stdio.stdout, std.c.stdio.stderr);
	    el_set(el_, EL_CLIENTDATA, cast(void*) this);
	    el_set(el_, EL_EDITOR, toStringz("emacs"));
	    el_set(el_, EL_SIGNAL, 1);
	    el_set(el_, EL_PROMPT, &_prompt);
	    el_set(el_, EL_HIST, &history, hist_);
	    el_set(el_, EL_ADDFN, toStringz("ed-complete"), toStringz("Complete argument"), &_complete);
	    el_set(el_, EL_BIND, toStringz("^I"), toStringz("ed-complete"), null);
	}

	nextBPID_ = 1;
    }

    ~this()
    {
	version (editline) {
	    history_end(hist_);
	    el_end(el_);
	}
    }

    static extern(C) void ignoreSig(int)
    {
    }

    bool interactive()
    {
	return interactive_;
    }

    void sourceFile(string filename)
    {
	string file = cast(string) std.file.read(filename);
	executeMacro(splitLines(file));
    }

    void executeMacro(string[] lines)
    {
	bool oldInteractive = interactive_;
	string[] oldSourceLines = sourceLines_;
	sourceLines_ = lines;
	interactive_ = false;
	while (sourceLines_.length > 0) {
	    auto cmd = split(inputline(""));
	    if (cmd.length > 0)
		executeCommand(cmd);
	}
	interactive_ = oldInteractive;
	sourceLines_ = oldSourceLines;
    }

    void prompt(string s)
    {
        if (annotate_)
            prompt_ = "\n\032\032pre-prompt\n" ~ s ~ "\n\032\032prompt\n";
        else
            prompt_ = s;
    }

    string inputline(string prompt)
    {
	if (!interactive_) {
	    if (sourceLines_.length > 0) {
		string line = sourceLines_[0];
		sourceLines_ = sourceLines_[1..$];
		return line;
	    }
	    return "";
	}

	version (editline) {
	    int num;
	    elPrompt_ = prompt;
	    auto result = to!string(el_gets(el_, &num));
	} else {
	    writef("%s ", prompt_);
	    auto result = chomp(readln());
	}
        if (annotate_)
            writeln("\n\032\032post-prompt");
        return result;
    }

    /**
     * Read the body of a compound statement (define, if, while etc.).
     * If optEnd is non-null, it can finish the statement as well as
     * "end". The value of the keyword that finishes the statement is
     * returned in endString.
     */
    string[] readStatementBody(string optEnd, out string endString)
    {
	string[] cmds;
	uint level = 1;
	for (;;) {
	    string line = strip(inputline(">"));

	    /*
	     * Only check for optEnd at the outermost level so that we
	     * don't get confused by nested if statements.
	     */
	    if (line == "end"
		|| (level == 1 && optEnd && line == optEnd)) {
		level--;
		if (level == 0) {
		    endString = line;
		    break;
		}
	    }
	    auto i = countUntil(line, ' ');
	    if (i >= 0) {
		if (line[0..i] == "if" || line[0..i] == "while")
		    level++;
	    }
	    cmds ~= line;
	}
	return cmds;
    }

    void run()
    {
	target_ = new ColdTarget(this, prog_, core_);

	try
	    sourceFile(".ngdbinit");
	catch {}

	try
	    sourceFile(to!string(getenv("HOME")) ~ "/.ngdbinit");
	catch {}

	sigaction_t sa;
	sa.sa_handler = &ignoreSig;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, null);

	if (core_)
	    stopped();

	string buf;
        string[] cmd;
	while (!quit_ && (buf = inputline(prompt_)) != null) {
	    int ac;
	    char** av;

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

            auto ncmd = split(buf);
	    if (!ncmd.empty)
                cmd = ncmd;
            if (cmd.empty)
		continue;

            if (cmd.front != "server")
            {
                version (editline) {
                    HistEvent ev;
                    if (buf.length > 1) {
                        history(hist_, &ev, H_ENTER, toStringz(buf));
                    }
                }
	    } else {
                cmd.popFront;
            }

	    pageline_ = 0;
	    try {
		executeCommand(cmd);
	    } catch (PagerQuit pq) {
	    }
	}
    }

    // not ctfe able
    // immutable string[string] cmdAbbrevs = buildAbbrevs!Cmd;
    static Cmd[string] cmdAbbrevs;
    static InfoCmd[string] infoCmdAbbrevs;
    static SetCmd[string] setCmdAbbrevs;

    static this() {
        cmdAbbrevs = buildAbbrevs!Cmd();
        infoCmdAbbrevs = buildAbbrevs!InfoCmd();
        setCmdAbbrevs = buildAbbrevs!SetCmd();
    }

    static T[string] buildAbbrevs(T)() {
        string[] list;
        foreach(e; EnumMembers!T)
            list ~= e;
        return cast(T[string])std.string.abbrev(list);
    }

    static bool tryFrontArgToUint(string[] from, out uint id) {
        if (collectException!ConvException(to!uint(from.front), id)) {
            std.stdio.stderr.writefln("Can't convert %s to an ID", from.front);
            return false;
        }
        from.popFront;
        return true;
    }

    void executeCommand(string[] args)
    {
        // ignore comments (sourced files)
	if (args.front[0] == '#')
	    return;

        if (auto cmd = args.front in cmdAbbrevs) {
            args.popFront;
            final switch (cast(string)*cmd) {
            case Cmd.Quit:
                quit_ = true;
                break;
            case Cmd.Help:
                writeln(getCmdHelp(args));
                break;

            case Cmd.History:
                version (editline) {
                    HistEvent ev;
                    for (int rv = history(hist_, &ev, H_LAST);
                         rv != -1;
                         rv = history(hist_, &ev, H_PREV))
                        writef("%d %s", ev.num, to!string(ev.str));
                }
                break;

            case Cmd.Info:
                executeInfoCommand(args);
                break;

            case Cmd.Set:
                try {
                    executeSetCommand(args);
                } catch (TargetException te) {
                    std.stdio.stderr.writeln(te.msg);
                }
                break;

            case Cmd.Run:
                // TODO: find better way for storing state
                static string[] runArgs_;
                if (target_ !is null&& target_.state != TargetState.EXIT) {
                    if (!yesOrNo("The program being debugged has been started already.\n"
                                 ~ "Start it from the beginning?"))
                        return;
                }
                if (target_ !is null) {
                    onExit(target_);
                }

                PtraceRun pt = new PtraceRun;
                if (!args.empty || runArgs_.empty)
                    runArgs_  = prog_ ~ args;
                try {
                    pt.connect(this, runArgs_);
                } catch (TargetException te) {
                    std.stdio.stderr.writeln(te.msg);
                }
                if (target_ !is null)
                    stopped();
                break;

            case Cmd.Kill:
                if (target_ !is null && target_.state == TargetState.EXIT) {
                    std.stdio.stderr.writeln("Program is not running");
                    return;
                }

                target_.cont(SIGKILL);
                target_.wait;
                break;

            case Cmd.Step:
                stepProgram(false);
                break;
            case Cmd.Next:
                stepProgram(true);
                break;
            case Cmd.Stepi:
                stepInstruction(false);
                break;
            case Cmd.Nexti:
                stepInstruction(true);
                break;

            case Cmd.Continue:
                if (target_.state == TargetState.EXIT) {
                    std.stdio.stderr.writeln("Program is not being debugged");
                    return;
                }

                started();
                try {
                    target_.cont();
                    target_.wait();
                } catch (TargetException te) {
                    std.stdio.stderr.writeln(te.msg);
                }
                stopped();
                break;

            case Cmd.Finish:
                auto f = topFrame;
                if (f is null) {
                    std.stdio.stderr.writeln("No current frame");
                    return;
                }
                if (f.outer is null) {
                    std.stdio.stderr.writeln("Already in outermost stack frame");
                    return;
                }
                auto fromFrame = f;
                auto toFrame = f.outer;

                Type rTy = fromFrame.func_.returnType;
                setStepBreakpoint(toFrame.state_.pc);
                try {
                    target_.cont();
                    target_.wait();
                } catch (TargetException te) {
                    std.stdio.stderr.writeln(te.msg);
                }
                clearStepBreakpoints();
                if (!currentThread)
                    return;
                if (rTy) {
                    MachineState s = currentThread.state;
                    Value val = s.returnValue(rTy);
                    writefln("Value returned is %s", val.toString(null, s));
                }
                stopped();
                break;

            case Cmd.Break:
                if (args.length != 1) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Break]));
                    return;
                }
                setBreakpoint(args.front);
                break;

            case Cmd.Condition:
                if (args.empty) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Condition]));
                    return;
                }
                uint bid;
                if (!tryFrontArgToUint(args, bid))
                    return;
                foreach(bp; breakpoints_)
                    if (bp.id == bid)
                        bp.condition = args;
                break;

            case Cmd.Command:
                if (args.empty) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Command]));
                    return;
                }
                uint bid;
                if (!tryFrontArgToUint(args, bid))
                    return;
                foreach(bp; breakpoints_)
                    if (bp.id == bid)
                        bp.command = args;
                break;

            case Cmd.Enable:
                if (args.empty) {
                    foreach (bp; breakpoints_)
                        bp.enable;
                } else {
                    uint bid;
                    if (!tryFrontArgToUint(args, bid))
                        return;
                    foreach (bp; breakpoints_)
                        if (bp.id == bid)
                            bp.enable;
                }
                break;

            case Cmd.Disable:
                if (args.empty) {
                    foreach (bp; breakpoints_)
                        bp.disable;
                } else {
                    uint bid;
                    if (!tryFrontArgToUint(args, bid))
                        return;
                    foreach (bp; breakpoints_)
                        if (bp.id == bid)
                            bp.disable;
                }
                break;

            case Cmd.Delete:
                if (args.empty) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Delete]));
                    return;
                } else {
                    uint bid;
                    if (!tryFrontArgToUint(args, bid))
                        return;
                    auto pred = (Breakpoint bp) { return bp.id != bid; };
                    auto drop = partition!(pred, SwapStrategy.stable)(breakpoints_);
                    breakpoints_.length -= drop.length;
                    foreach (bp; drop)
                        bp.disable;
                }
                break;

            case Cmd.Thread:
                if (args.empty) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Thread]));
                    return;
                }
                uint tid;
                if (!tryFrontArgToUint(args, tid))
                    return;
                foreach (t; threads_) {
                    if (t.id == tid) {
                        currentThread = t;
                        stopped();
                        return;
                    }
                }
                std.stdio.stderr.writefln("Invalid thread %d.", tid);
                break;

            case Cmd.Up:
                if (currentFrame_ is null) {
                    std.stdio.stderr.writeln("stack frame information unavailable");
                    return;
                }
                if (currentFrame_.outer !is null)
                    currentFrame_ = currentFrame_.outer;
                writeln(currentFrame_.toString);
                displaySourceLine(currentFrame_.state_);
                break;

            case Cmd.Down:
                if (currentFrame_ is null) {
                    std.stdio.stderr.writeln("stack frame information unavailable");
                    return;
                }
                if (currentFrame_.inner !is null)
                    currentFrame_ = currentFrame_.inner;
                writeln(currentFrame_.toString);
                displaySourceLine(currentFrame_.state_);
                break;

            case Cmd.Frame:
                Frame f;
                if (args.empty)
                    f = currentFrame_;
                else {
                    uint fidx;
                    if (!tryFrontArgToUint(args, fidx))
                        return;
                    f = getFrame(fidx);
                    if (f is null) {
                        std.stdio.stderr.writefln("Invalid frame number %d", fidx);
                        return;
                    }
                }
                if (f is null) {
                    std.stdio.stderr.writeln("stack frame information unavailable");
                    return;
                }
                currentFrame_ = f;
                writeln(f.toString);
                displaySourceLine(f.state_);
                break;

            case Cmd.Print:
                static string lastExpr_;

                string fmt;
                if (args.length > 0
                    && args.front[0] == '/') {
                    uint count, width;
                    if (!parseFormat(args.front, count, width, fmt))
                        return;
                    if (fmt == "i") {
                        std.stdio.stderr.writeln("Instruction format not supported");
                        return;
                    }
                    if (count != 1) {
                        std.stdio.stderr.writeln("Counts greater than one not supported");
                        return;
                    }
                    if (width != 4) {
                        std.stdio.stderr.writeln("Format width characters not supported");
                    }
                }

                string expr;
                if (args.empty) {
                    if (lastExpr_ is null) {
                        std.stdio.stderr.writeln("No previous expression to print");
                        return;
                    }
                    expr = lastExpr_;
                } else {
                    expr = join(args, " ");
                    lastExpr_ = expr;
                }

                MachineState s;
                auto v = evaluateExpr(expr, s);
                if (v) {
                    writefln("$%s = (%s) %s",
                            valueHistory_.length,
                            v.type.toString,
                            v.toString(fmt, s));
                    // TODO: implement output command, that doesn't record values
                    valueHistory_ ~= v;
                }
                break;

            case Cmd.List:
                // TODO: need to keep state of listing
                if (args.empty) {
                    if (currentSourceFile_ is null && sourceFiles_.length) {
                        // TODO: select a better source file, avoid ugly side effect
                        currentSourceFile_ = sourceFiles_.values.front;
                        currentSourceLine_ = 1;
                    }
                } else if (args.front == "-" && currentSourceFile_ !is null) {
                    if (currentSourceLine_ > 20)
                        currentSourceLine_ -= 20;
                    else
                        currentSourceLine_ = 1;
                } else  {
                    auto tok = split(join(args, " "), ",");
                    assert(tok.length == 1, "range list unimplemented");
                    if (!parseSourceSpec(tok.front, currentSourceFile_, currentSourceLine_)) {
                        std.stdio.stderr.writefln("Can't find %s", tok);
                        return;
                    }
                }

                if (currentSourceFile_ is null) {
                    std.stdio.stderr.writeln("No source file.");
                    return;
                }

                uint start = currentSourceLine_;
                start = (start > 5) ? start - 5 : 1;
                uint end = start + 10;
                foreach(ln; start .. end)
                    displaySourceLine(currentSourceFile_, ln);
                break;

            case Cmd.Interpreter:
                if (args.length < 2) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Interpreter]));
                    return;
                }
                switch (args.front) {
                case "mi":
                    args.popFront;
                    return executeMICommand(args);
                case "console":
                    args.popFront;
                    return executeCommand(args);
                default:
                    std.stdio.stderr.writefln("Unknown interpreter %s.", args.front);
                }
                break;
            }
        } else {
            std.stdio.stderr.writeln(getCmdHelp(args));
        }
    }

    void executeInfoCommand(string[] args) {
        if (args.empty)
            std.stdio.stderr.writeln(getInfoHelp(null));
        if (auto cmd = args.front in infoCmdAbbrevs) {
            args.popFront;
            final switch (cast(string)*cmd) {
            case InfoCmd.Source:
                if (currentSourceFile_ is null)
                    writeln("No current source file.");
                else {
                    auto sf = currentSourceFile_;
                    writefln("Current source file is %s", std.path.basename(sf.filename));
                    writefln("Compilation directory is %s", std.path.dirname(sf.filename));
                    writefln("Located in %s", sf.filename);
                    sf[0]; // force read in
                    writefln("Contains %s lines.", sf.lines_.length);
                    // TODO: need detailed information
                    writeln("Source language is c.");
                    writeln("Compiled with DWARF 2 debugging format.");
                    writeln("Does not include preprocessor macro info.");
                }
                break;

            case InfoCmd.Sources:
                writeln("Source files for which symbols have been read in:\n\n");
                writeln("\nSource files for which symbols will be read in on demand:\n");
                foreach(sf; sourceFiles_)
                    writeln(std.path.basename(sf.filename));
                break;

            case InfoCmd.Breakpoints:
                if (breakpoints_.empty) {
                    writeln("No breakpoints");
                } else {
                    Breakpoint.printHeader;
                    foreach (b; breakpoints_)
                        b.print;
                }
                break;

            case InfoCmd.Threads:
                foreach (i, t; threads_) {
                    auto mark = t is currentThread ? "*" : " ";
                    auto desc = describeAddress(t.state.pc, t.state);
                    writefln("%s %-2d: %s", mark, t.id, desc);
                }
                break;

            case InfoCmd.Locals:
                if (target_ is null) {
                    writeln("target is not running");
                    return;
                }

                string fmt;
                if (args.length > 0 && args.front[0] == '/') {
                    uint count, width;
                    if (!parseFormat(args.front, count, width, fmt))
                        return;
                    if (fmt == "i") {
                        writeln("Instruction format not supported");
                        return;
                    }
                    if (count != 1) {
                        writeln("Counts greater than one not supported");
                        return;
                    }
                    if (width != 4) {
                        writeln("Format width characters not supported");
                    }
                }

                auto f = currentFrame_;
                if (f is null) {
                    writeln("current stack frame is invalid");
                    return;
                }

                auto  s = f.state_;
                auto func = f.func_;
                if (func is null)
                    return;

                auto names = func.contents(s);
                foreach (name; names) {
                    DebugItem d;
                    if (func.lookup(name, s, d)) {
                        auto v = cast(Variable) d;
                        if (!v.value.loc.valid(s))
                            continue;
                        writefln("%s = %s",
                                v.toString, v.valueToString(fmt, s));
                    }
                }
                break;

            case InfoCmd.Modules:
                ulong pc = 0;
                if (currentThread)
                    pc = currentThread.state.pc;
                foreach (i, mod; modules_) {
                    string addrs = format("%#x .. %#x", mod.start, mod.end);
                    auto mark = (pc >= mod.start && pc < mod.end) ? "*" : " ";
                    writefln("%s%2d: %-32s %s", mark, i + 1, addrs, mod.filename);
                }
                break;

            case InfoCmd.Registers:
                auto f = currentFrame_;
                if (f is null) {
                    writeln("No current stack frame");
                    return;
                }
                writeln(f.toString);
                auto s = f.state_;
                s.dumpState;
                ulong pc = s.pc;
                ulong tpc = pc;
                writefln("%s:\t%s", lookupAddress(pc),
                         s.disassemble(tpc, &lookupAddress));
                break;

            case InfoCmd.Float:
                auto f = currentFrame_;
                if (f is null) {
                    writeln("No current stack frame");
                    return;
                }
                f.state_.dumpFloat;
                break;

            case InfoCmd.Frame:
                Frame f;
                if (args.empty)
                    f = currentFrame_;
                else
                    assert(0, "unimplemented \"info frame ADDR\"");
                if (f is null) {
                    writeln("No stack.");
                    return;
                }
                writefln("rip = %#x; saved rip %#x", f.state_.pc, null);
                // TODO: more info
                break;

            case InfoCmd.Stack:
                if (topFrame_ is null) {
                    std.stdio.stderr.writeln("No stack.");
                    return;
                }
                uint cnt = uint.max;
                if (!args.empty && !tryFrontArgToUint(args, cnt))
                    return;

                auto f = topFrame_;
                while (cnt-- && f !is null) {
                    auto pc = f.state_.pc;
                    writefln("#%-4d %#-16x %s", f.index_, pc, describeAddress(pc, f.state_));
                    f = f.outer;
                }
                break;
            }
        } else {
            std.stdio.stderr.writeln(getInfoHelp(args));
        }
    }

    void executeSetCommand(string[] args) {
        if (args.empty)
            std.stdio.stderr.writeln(getSetHelp(null));
        if (auto cmd = args.front in setCmdAbbrevs) {
            args.popFront;
            final switch (cast(string)*cmd) {
            case SetCmd.Height:
                // TODO: interpret expr
                uint height;
                if (collectException(to!uint(args.front), height))
                    std.stdio.stderr.writefln(getSetHelp([SetCmd.Height]));
                pagemaxheight_ = height;
                break;

            case SetCmd.Width:
                // TODO: noop
                break;
            }
        } else {
            std.stdio.stderr.writeln(getSetHelp(args));
        }

    }

    string getCmdHelp(string[] args) {
        if (args.empty) {
            auto result = "help [COMMAND]: Print help about command.\nCOMMAND can be of:\n";
            foreach(e; EnumMembers!Cmd) {
                result ~= (e ~ "\n");
            }
            return result;
        }

        if (auto cmd = args.front in cmdAbbrevs) {
            args.popFront;
            final switch (cast(string)*cmd) {
            case Cmd.Quit:
                return "quit: Exit the debugger";
            case Cmd.Help:
                return "help [CMD]: Print help about command.";
            case Cmd.History:
                return "history: Show recent commands.";
            case Cmd.Info:
                return getInfoHelp(args);
            case Cmd.Set:
                return getSetHelp(args);
            case Cmd.Run:
                return "run [ARGS]: Run program with arguments.";
            case Cmd.Kill:
                return "kill: Kill debugged program.";
            case Cmd.Step:
                return "step: Step.";
            case Cmd.Next:
                return "next: Step, skip function calls.";
            case Cmd.Stepi:
                return "stepi: Step instruction.";
            case Cmd.Nexti:
                return "nexti: Step instruction, skip function calls.";
            case Cmd.Continue:
                return "continue: Continue debugged program.";
            case Cmd.Finish:
                return "finish: Continue to calling stack frame.";
            case Cmd.Break:
                return "break <Line | Func | File:Line | File:Func>: Set breakpoint.";
            case Cmd.Condition:
                return "condition <id> <expr>: Break only if condition evaluates to true.";
            case Cmd.Command:
                return "command <id> <expr>: Execute command on breakpoint.";
            case Cmd.Enable:
                return "enable [id]: Enable breakpoint id or all.";
            case Cmd.Disable:
                return "disable [id]: Disable breakpoint id or all.";
            case Cmd.Delete:
                return "delete <id>: Delete breakpoint id.";
            case Cmd.Thread:
                return "thread <id>: Switch to thread id.";
            case Cmd.Up:
                return "up: Select next outer stack frame.";
            case Cmd.Down:
                return "down: Select next inner stack frame.";
            case Cmd.Frame:
                return "frame [idx]: Select frame index or topmost.";
            case Cmd.Print:
                return "print <expr>: Evaluate and print expression.";
            case Cmd.List:
                return "list [ - | Line | Func | File:Line | File:Func | *Addr ]: List source code.";
            case Cmd.Interpreter:
                return "interpreter <name> <command>: Execute a command with interpreter.";
            }
        }
        return std.string.format("Undefined command %s.", args.front);
    }

    string getInfoHelp(string[] args) {
        if (args.empty) {
            auto result = "info [SUBCOMMAND]: Print information.\nSUBCOMMAND can be of:";
            foreach(e; EnumMembers!InfoCmd) {
                result ~= ("\n" ~ e);
            }
            return result;
        }

        if (auto cmd = args.front in infoCmdAbbrevs) {
            args.popFront;
            final switch(cast(string)*cmd) {
            case InfoCmd.Source:
                return "info source: Information about current source file.";
            case InfoCmd.Sources:
                return "info sources: Information about source files of program.";
            case InfoCmd.Breakpoints:
                return "info breakpoints: Information about breakpoints.";
            case InfoCmd.Threads:
                return "info threads: Information about threads.";
            case InfoCmd.Locals:
                return "info locals: Information about local variables.";
            case InfoCmd.Modules:
                return "info modules: Information about modules.";
            case InfoCmd.Registers:
                return "info registers: Information about general purpose registers.";
            case InfoCmd.Float:
                return "info float: Information about floating point registers.";
            case InfoCmd.Frame:
                return "info frame [ADDR]: Information about current frame or frame at ADDR.";
            case InfoCmd.Stack:
                return "info stack [COUNT]: Backtrace of stack or innermost COUNT frames.";
            }
        }
        return std.string.format("Undefined command info %s.", args.front);
    }

    string getSetHelp(string[] args) {
        if (args.empty) {
            auto result = "set VAR EXPR: Evaluate expression and set VAR to result.";
            result ~= "\nVAR can be of can be of:";
            foreach(e; EnumMembers!SetCmd) {
                result ~= ("\n" ~ e);
            }
            return result;
        }

        if (auto cmd = args.front in setCmdAbbrevs) {
            args.popFront;
            final switch(cast(string)*cmd) {
            case SetCmd.Height:
                return "set height <num>: Set height of output console.";
            case SetCmd.Width:
                return "set width <num>: Set width of output console.";
            }
        }
        return std.string.format("Undefined command set %s.", args.front);
    }

    void executeMICommand(string[] cmd)
    {
        writefln("^error,msg=\"Undefined MI command: %s\"", cmd.front);
        //        assert(0, "mi commands unimplemented");
    }

    bool yesOrNo(...)
    {
	if (!interactive_)
	    return true;

	char[] prompt;

	void putc(dchar c)
	{
	    std.utf.encode(prompt, c);
	}

	std.format.doFormat(&putc, _arguments, _argptr);
	prompt ~= " (y or n)";
	string s;
	do {
	    s = std.string.toLower(strip(inputline(cast(immutable)(prompt))));
	} while (s.length == 0 || (s[0] != 'y' && s[0] != 'n'));
	if (s[0] == 'y')
	    return true;
	return false;
    }

    void pagefln(...)
    {
	char[] s;

	void putc(dchar c)
	{
	    std.utf.encode(s, c);
	}

	std.format.doFormat(&putc, _arguments, _argptr);
	s = detab(s);

        if (s.empty) {
            writeln();
            return;
        }

	while (s.length) {
	    auto n = s.length;
	    if (n > 80) n = 80;
	    writefln("%s", s[0..n]);
	    s = s[n..$];
	    if (pagemaxheight_) {
		pageline_++;
		if (pageline_ >= pagemaxheight_) {
		    writef("--Press return to continue or type 'q' to quit--");
		    auto t = readln();
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
        if (std.file.exists(filename) && std.file.isFile(filename)) {
            SourceFile sf = new SourceFile(filename);
            sourceFiles_[filename] = sf;
            sourceFilesBasename_[std.path.getBaseName(filename)] = sf;
            return sf;
        }
        return null;
    }

    bool parseFormat(ref string args,
		     out uint count, out uint width, out string f)
    {
	assert(args[0] == '/');
	auto i = countUntil(args, ' ');
	string fmt;
	if (i >= 0) {
	    fmt = args[1..i];
	    args = strip(args[i..$]);
	} else {
	    fmt = args[1..$];
	    args = "";
	}
	if (fmt.length == 0)
	    return false;
	if (isDigit(fmt[0])) {
	    count = 0;
	    while (fmt.length > 0 && isDigit(fmt[0])) {
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

    /*
     * finds source file and line from (File | File:Line | Func | File:Func)
     */
    bool parseSourceSpec(string s, ref SourceFile sf, ref uint line)
    {
        auto scoped = split(s, ":");
        SourceFile file;
        if (scoped.length == 2) {
            file = findFile(strip(scoped.front));
            scoped.popFront;
        }
        if (file is null)
            file = currentSourceFile_;

        if (scoped.length != 1 || file is null)
            return false;

        auto spec = strip(scoped.front);
        if (spec.empty)
            return false;

        if (isDigit(spec.front)) {
            uint no;
            if (collectException!ConvException(to!uint(spec), no))
                return false;
            sf = file;
            line = no;
            return true;
        } else {
            // TODO: implement function name lookup
            return false;
        }
    }

    bool setCurrentFrame()
    {
	if (!target_)
	    return false;

	TargetThread t = currentThread;
	MachineState s = t.state;
	DebugInfo di;

	if (findDebugInfo(s, di)) {
	    Location loc;
	    Function func;
	    if (di.findFrameBase(s, loc) && (func = di.findFunction(s.pc)) !is null) {
		if (!topFrame_ || topFrame_.func_ !is func
		    || topFrame_.addr_ != loc.address(s)) {
		    currentFrame_ = topFrame_ =
			new Frame(this, 0, null, di, func, s);
		    return true;
		}
	    }
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, s);
	    ulong tpc = s.pc;
	    return true;
	}
	return false;
    }

    void started()
    {
	stopped_ = false;
    }

    void stopped()
    {
	if (!target_ || stopped_)
	    return;

	stopped_ = true;

	auto t = currentThread;
	auto s = t.state;
	auto newFrame = setCurrentFrame;
	auto di = currentFrame_.di_;

	if (di) {
	    if (newFrame)
		writefln("%s", describeAddress(s.pc, s));
	    LineEntry[] le;
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		currentSourceFile_ = stoppedSourceFile_ = sf;
		currentSourceLine_ = stoppedSourceLine_ = le[0].line;
		displaySourceLine(sf, currentSourceLine_);
	    }
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, s);
	    ulong tpc = s.pc;
	    writefln("%s:\t%s", lookupAddress(s.pc),
		     s.disassemble(tpc, &lookupAddress));
	}
    }

    void displaySourceLine(MachineState s)
    {
	DebugInfo di;
	LineEntry[] le;

	if (!findDebugInfo(s, di))
            return;
        if (!di.findLineByAddress(s.pc, le))
            return;
        if (auto sf = findFile(le[0].fullname)) {
            displaySourceLine(sf, le[0].line);
            currentSourceFile_ = sf;
            currentSourceLine_ = le[0].line;
        }
    }

    void displaySourceLine(SourceFile sf, uint line)
    {
	string bpmark = " ";
	showline: foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (!di)
		continue;
	    LineEntry[] lines;
	    if (di.findLineByName(sf.filename, line, lines)) {
		foreach (li; lines)
		    foreach (bp; breakpoints_)
			if (bp.matches(li.address))  {
			    bpmark = "*";
			    break showline;
			}
	    }
	}
	auto s = sf[line];
	if (s) {
            version (none) {
                string a = "  ";
                if (sf == stoppedSourceFile_ && line == stoppedSourceLine_)
                    a = "=>";
                writefln("%s%4d%s%s", a, line, bpmark, detab(s));
            } else {
                writefln("%d\t%s", line, s);
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
		    s = func.toString(null, state) ~ ": ";
		}

		s ~= le[0].name ~ ":" ~ to!string(le[0].line);
		return s;
	    }
	}
	return lookupAddress(pc);
    }

    string lookupAddress(ulong addr)
    {
	TargetSymbol bestSym;
	bool found = false;
	foreach (mod; modules_) {
	    TargetSymbol sym;
	    if (mod.lookupSymbol(addr, sym)) {
		if (!found || addr - sym.value < addr - bestSym.value) {
		    bestSym = sym;
		    found = true;
		}
	    }
	}
	if (found) {
	    string s;
	    if (addr != bestSym.value)
		s = bestSym.name ~ "+" ~ to!string(addr - bestSym.value);
	    else
		s = bestSym.name;
	    if (s.length > 33)
		s = s[0..15] ~ "..." ~ s[$-15..$];
	    return std.string.format("%#x <%s>", addr, s);
	}
	return std.string.format("%#x", addr);
    }

    void setStepBreakpoint(ulong pc)
    {
	debug (step)
	    writefln("step breakpoint at %#x", pc);
	if (target_)
	    target_.setBreakpoint(pc, this);
    }

    void clearStepBreakpoints()
    {
	debug (step)
	    writefln("clearing step breakpoints");
	if (target_)
	    target_.clearBreakpoint(this);
    }

    void stepProgram(bool stepOverCalls)
    {
	if (!target_) {
	    writefln("Program is not being debugged");
	    return;
	}

	TargetThread t = currentThread;
	MachineState s = t.state;
	DebugInfo di;

	started();
	if (findDebugInfo(s, di)) {
	    Location frameLoc;
	    di.findFrameBase(s, frameLoc);
	    auto frameFunc = di.findFunction(s.pc);

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

		    bool inPLT(ulong pc) {
			foreach (mod; modules_)
			    if (mod.inPLT(pc))
				return true;
			return false;
		    }

		    while (inPLT(s.pc)) {
			debug (step)
			    writefln("single stepping over PLT entry");
			target_.step(t);
		    }
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
		auto func = di.findFunction(s.pc);
		if (frameLoc.address(s) != frame || func !is frameFunc) {
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
			} while (target_ && frameLoc.address(s) != frame);
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

	started();

	TargetThread t = currentThread;
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
	if (currentFrame_.func_) {
	    ulong tpc = s.pc;
	    pagefln("%s:\t%s", lookupAddress(s.pc),
		    s.disassemble(tpc, &lookupAddress));
	}
    }

    void setBreakpoint(string bploc)
    {
	SourceFile sf;
	string func;
	uint line;
	if (bploc) {
	    string file;
	    if (!parseSourceSpec(bploc, sf, line))
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
	    bp = new Breakpoint(this, sf, line);
	else
	    bp = new Breakpoint(this, func);
	if (target_)
	    foreach (mod; modules_)
		bp.activate(mod);
	if (bp.active) {
	    bp.id_ = nextBPID_++;
	    breakpoints_ ~= bp;
            // TODO: need shortPrint
	    bp.printHeader;
	    bp.print;
	} else {
	    writefln("Can't set breakpoint %s", bploc);
	}
    }

    Frame topFrame()
    {
	return topFrame_;
    }

    Frame getFrame(uint frameIndex)
    {
	Frame f;
	for (f = topFrame_; f; f = f.outer)
	    if (f.index == frameIndex)
		break;
	return f;
    }

    TargetThread currentThread()
    {
	return currentThread_;
    }

    void currentThread(TargetThread t)
    {
	if (t !is currentThread_) {
	    foreach (i, tt; threads_) {
		if (t is tt) {
		    pagefln("Switched to thread %d", i + 1);
		}
	    }
	    currentThread_ = t;
	}
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

    Language currentLanguage()
    {
	auto f = currentFrame_;
	if (f !is null)
	    return f.lang_;
	else
	    return CLikeLanguage.instance;
    }

    Value evaluateExpr(string expr, out MachineState state)
    {
	MachineState s;
	DebugInfo di;
	string fmt = null;

	auto f = currentFrame_;
	if (f !is null)
	    s = f.state_;
	else
	    s = currentThread.state;

	Scope sc;
	Language lang;
	if (f) {
	    sc = f.scope_;
	    lang = f.lang_;
	} else {
	    sc = this;
	    lang = CLikeLanguage.instance;
	}

	try {
	    auto e = lang.parseExpr(expr, sc);
	    auto v = e.eval(sc, s).toValue(s);
	    state = s;
	    return v;
	} catch (EvalException ex) {
	    pagefln("%s", ex.msg);
	    return null;
	}
    }

    Value evaluateExpr(string expr)
    {
	MachineState s;
	return evaluateExpr(expr, s);
    }

    override
    {
	// TargetListener
	void onTargetStarted(Target target)
	{
	    stopped_ = false;
	    target_ = target;
	}
	void onThreadCreate(Target target, TargetThread thread)
	{
	    foreach (t; threads_)
		if (t is thread)
		    return;
	    threads_ ~= thread;
	    if (!currentThread_)
		currentThread_ = thread;
	}
	void onThreadDestroy(Target target, TargetThread thread)
	{
	    TargetThread[] newThreads;
	    foreach (t; threads_)
		if (t !is thread)
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
	void onModuleDelete(Target, TargetModule mod)
	{
	    TargetModule[] newModules;
	    foreach (omod; modules_)
		if (omod !is mod)
		    newModules ~= omod;
	    modules_ = newModules;
	    foreach (bp; breakpoints_)
		bp.deactivate(mod);
	}
	bool onBreakpoint(Target, TargetThread t)
	{
	    /*
	     * We use this as listener for the step breakpoints.
	     */
	    currentThread = t;
	    return true;
	}
	void onSignal(Target, TargetThread t, int sig, string sigName)
	{
	    currentThread = t;
	    writefln("Thread %d received signal %d (%s)", t.id, sig, sigName);
	}
	void onExit(Target)
	{
	    if (target_ && target_.state != TargetState.EXIT)
		writefln("Target program has exited.");

	    target_ = null;
	    threads_.length = 0;
	    currentThread_ = null;
	    modules_.length = 0;
	    topFrame_ = currentFrame_ = null;
	    foreach (bp; breakpoints_)
		bp.onExit;
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (mod; modules_)
		res ~= mod.contents(state);
	    for (int i = 0; i < valueHistory_.length; i++)
		res ~= "$" ~ to!string(i);

	    return uniq(res);
	}
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    foreach (mod; modules_)
		if (mod.lookup(name, state, val))
		    return true;

	    if (name.length == 0 || name[0] != '$')
		return false;
	    name = name[1..$];
	    if (name.length == 0 || isDigit(name[0])) {
		try {
		    size_t num = name.length > 0
			? to!size_t(name) : valueHistory_.length - 1;
		    if (num >= valueHistory_.length)
			return false;
		    val = valueHistory_[num];
		    return true;
		} catch (ConvException ce) {
		    return false;
		}
	    } else if (isAlpha(name[0]) || name[0] == '_') {
		auto vp = name in userVars_;
		if (vp) {
		    val = *vp;
		    return true;
		}
		auto lang = currentLanguage;
		Value var = new Value(new UserLocation,
				      new UserType(lang));
		userVars_[name] = var;
		val = var;
		return true;
	    } else {
		return false;
	    }
	}
	bool lookupStruct(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupStruct(name, ty))
		    return true;
	    return false;
	}
	bool lookupUnion(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupTypedef(name, ty))
		    return true;
	    return false;
	}
	bool lookupTypedef(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupTypedef(name, ty))
		    return true;
	    return false;
	}
    }

private:
version (editline) {
    string elPrompt_;

    extern(C) static const(char)* _prompt(EditLine *el)
    {
	void* p;
	el_get(el, EL_CLIENTDATA, &p);
	Debugger db = cast(Debugger) p;
	assert(db);
	return toStringz(db.prompt(el));
    }
    extern(C) static char _complete(EditLine *el, int ch)
    {
	void* p;
	el_get(el, EL_CLIENTDATA, &p);
	Debugger db = cast(Debugger) p;
	assert(db);
	return db.complete(el, ch);
    }

    string prompt(EditLine *el)
    {
	return elPrompt_ ~ " ";
    }

    char complete(EditLine *el, int ch)
    {
        return CC_ERROR;
//	LineInfo* li = el_line(el);
//
//	size_t n = li.cursor - li.buffer;
//	string args = chomp(li.buffer[0..n].idup);
//	string[] matches = commands_.complete(this, args);
//
//	if (matches.length == 1) {
//	    string s = matches[0] ~ " ";
//	    if (el_insertstr(el, toStringz(s)) == -1)
//		return CC_ERROR;
//	    return CC_REFRESH;
//	} else {
//	    /*
//	     * Find the longest common prefix of all the matches
//	     * and try to insert from that. If we can't insert any
//	     * more, display the match list.
//	     */
//	    if (matches.length == 0)
//		return CC_ERROR;
//	    int i;
//	    string m0 = matches[0];
//	    gotPrefix: for (i = 0; i < m0.length; i++) {
//		foreach (m; matches[1..$]) {
//		    if (i >= m.length || m[i] != m0[i])
//			break gotPrefix;
//		}
//	    }
//	    if (i > 0) {
//		string s = m0[0..i];
//		if (el_insertstr(el, toStringz(s)) == -1)
//		    return CC_ERROR;
//		return CC_REFRESH;
//	    }
//	    return CC_ERROR;
//	}
    }
    History* hist_;
    EditLine* el_;
}

    bool interactive_ = true;
    bool quit_ = false;
    uint annotate_;
    string[] sourceLines_;
    string prog_;
    string core_;
    string prompt_;
    uint pageline_;
    uint pagemaxheight_ = 23;
    Target target_;
    TargetModule[] modules_;
    TargetThread[] threads_;
    TargetThread currentThread_;
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
    Value[string] userVars_;
    bool stopped_;
}

enum Cmd : string {
    Quit = "quit",
    Help = "help",
    History = "history",
    Info = "info",
    Set = "set",
    Run = "run",
    Kill = "kill",
    Step = "step",
    Next = "next",
    Stepi = "stepi",
    Nexti = "nexti",
    Continue = "continue",
    Finish = "finish",
    Break = "break",
    Condition = "condition",
    Command = "command",
    Enable = "enable",
    Disable = "disable",
    Delete = "delete",
    Thread = "thread",
    Up = "up",
    Down = "down",
    Frame = "frame",
    Print = "print",
    List = "list",
    Interpreter = "interpreter",
}

enum InfoCmd : string {
    Source = "source",
    Sources = "sources",
    Breakpoints = "breakpoints",
    Threads = "threads",
    Locals = "locals",
    Modules = "modules",
    Registers = "registers",
    Float = "float",
    Frame = "frame",
    Stack = "stack",
}

enum SetCmd : string {
    Height = "height",
    Width = "width",
}

class ExamineCommand
{
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
        auto f = db.currentFrame_;
        if (f)
            s = f.state_;
        else if (db.currentThread)
            s = db.currentThread.state;

        if (args.length > 0 && args.front[0] == '/') {
            if (!db.parseFormat(args.front, count_, width_, fmt_))
                return;
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
            Scope sc;
            Language lang;
            if (f) {
                sc = f.scope_;
                lang = f.lang_;
            } else {
                sc = db;
                lang = CLikeLanguage.instance;
            }

            try {
                auto e = lang.parseExpr(expr, sc);
                auto v = e.eval(sc, s).toValue(s);
                auto pTy = cast(PointerType) v.type;
                auto fTy = cast(FunctionType) v.type;
                if (pTy || v.type.isIntegerType)
                    addr = s.readInteger(v.loc.readValue(s));
                else if (fTy)
                    addr = v.loc.address(s);
                else
                    throw new EvalException("Not an address");
            } catch (EvalException ex) {
                db.pagefln("%s", ex.msg);
                return;
            }
        }

        uint count = count_;
        if (fmt_ == "i") {
            while (count > 0) {
                string addrString = db.lookupAddress(addr);
                db.pagefln("%-31s %s", addrString,
                           s.disassemble(addr, &db.lookupAddress));
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

private:
    bool lastAddrValid_;
    ulong lastAddr_;
    uint count_ = 1;
    uint width_ = 4;
    string fmt_ = "x";
}

class DefineCommand
{
    string name()
    {
        return "define";
    }

    string description()
    {
        return "define a macro";
    }

    void run(Debugger db, string[] args)
    {
        if (args.length != 1) {
            db.pagefln("usage: define name");
            return;
        }

//        Command c = db.lookupCommand(args.front);
//        if (c) {
//            if (c.builtin) {
//                db.pagefln("Can't redefine built-in command \"%s\"",
//                           args.front);
//                return;
//            }
//            if (!db.yesOrNo("Redefine command \"%s\"?", args.front))
//                return;
//        }

        if (db.interactive)
            db.pagefln("Enter commands for \"%s\", finish with \"end\"",
                       args.front);
        string line, junk;
        string[] cmds = db.readStatementBody(null, junk);
        //        Debugger.registerCommand(new MacroCommand(args.front, cmds));
    }
}

class MacroCommand
{
    this(string name, string[] cmds)
    {
	name_ = name;
	cmds_ = cmds;
    }

    string name()
    {
        return name_;
    }

    string description()
    {
        return name_;
    }

    void run(Debugger db, string[] args)
    {
        if (depth_ > 1000) {
            db.pagefln("Recursion too deep");
            depth_ = 0;
            throw new PagerQuit;
        }
        string[] cmds;
        foreach (cmd; cmds_) {
            foreach (i, arg; args)
                cmd = replace(cmd, "$arg" ~ to!string(i), arg);
            cmds ~= cmd;
        }
        depth_++;
        db.executeMacro(cmds);
        depth_--;
    }

    bool builtin()
    {
        return false;
    }

private:
    string name_;
    string[] cmds_;
    static uint depth_ = 0;
}

class SourceCommand
{
    string name()
    {
        return "source";
    }

    string description()
    {
        return "Read commands from a file";
    }

    void run(Debugger db, string[] args)
    {
        if (args.length != 1) {
            db.pagefln("usage: source filename");
            return;
        }

        try
            db.sourceFile(args.front);
        catch {
            writefln("Can't open file %s", args);
        }
    }
}

class IfCommand
{
    string name()
    {
        return "if";
    }

    string description()
    {
        return "Conditionally execute commands";
    }

    void run(Debugger db, string[] args)
    {
        if (args.length != 1) {
            db.pagefln("usage: if expr");
            return;
        }

        bool cond = false;
        MachineState s;
        auto v = db.evaluateExpr(args.front, s);
        if (v.type.isIntegerType)
            cond = s.readInteger(v.loc.readValue(s)) != 0;

        string endString;
        string[] ifCmds = db.readStatementBody("else", endString);
        string[] elseCmds;
        if (endString == "else")
            elseCmds = db.readStatementBody("", endString);

        if (cond)
            db.executeMacro(ifCmds);
        else
            db.executeMacro(elseCmds);
    }
}

class WhileCommand
{
    string name()
    {
        return "while";
    }

    string description()
    {
        return "Conditionally execute commands";
    }

    void run(Debugger db, string[] args)
    {
        if (args.length != 1) {
            db.pagefln("usage: while expr");
            return;
        }

        string endString;
        string[] cmds = db.readStatementBody("", endString);

        for (;;) {
            bool cond = false;
            MachineState s;
            auto v = db.evaluateExpr(args.front, s);
            if (v.type.isIntegerType)
                cond = s.readInteger(v.loc.readValue(s)) != 0;
            if (!cond)
                break;
            db.executeMacro(cmds);
        }
    }
}

class InterpreterCommand
{
    string name()
    {
        return "interpreter";
    }

    string description()
    {
        return "choose interpreter";
    }

    void run(Debugger db, string[] args)
    {
        if (args.empty) {
            db.pagefln("usage: interpreter <name> cmd");
            return;
        }

        switch (args.front) {
        case "console":
            db.executeCommand(args[1 .. $]);
            break;
        case "mi":
            db.executeMICommand(args[1 .. $]);
            break;
        default:
            assert(0, "unknown interpreter " ~ args.front);
        }
    }
}

