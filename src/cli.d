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

private class Breakpoint
{
    this(SourceLocSpec spec)
    {
	spec_ = spec;
    }

    string condition()
    {
	return condition_;
    }

    string[] command()
    {
	return command_;
    }

    void command(string[] s)
    {
	command_ = s;
    }

    // returns newly added addresses
    ulong[] addAddresses(TargetModule mod)
    {
	DebugInfo di = mod.debugInfo;
	int pos;

	LineEntry[] lines;
	bool found;
	if (spec_.func is null) {
            assert(spec_.line != 0 && spec_.file !is null);
	    if (di)
		found = di.findLineByName(spec_.file, spec_.line_, lines);
	} else {
	    if (di)
		found = di.findLineByFunction(spec_.func, lines);
	    if (!found) {
		TargetSymbol sym;
		if (mod.lookupSymbol(spec_.func, sym) && sym.value) {
		    LineEntry le;
		    le.address = sym.value;
		    lines ~= le;
		    found = true;
		}
	    }
	}
	if (found) {
            auto oldlen = addresses_.length;
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
		addresses_ ~= le.address;
	    }
            if (oldlen != addresses_.length)
                return addresses_[oldlen .. $];
	}
        return null;
    }

    bool active()
    {
	return addresses_.length > 0;
    }

    string expr()
    {
        return spec_.toString();
    }

    bool matches(ulong pc)
    {
        return canFind(addresses_, pc);
    }

    static void printHeader()
    {
	writefln("%-7s %-14s %-4s %-3s %-18s %s",
		 "Num", "Type", "Disp", "Enb", "Address", "What");
    }

    void print(Debugger db)
    {
	if (addresses_.empty) {
	    writef("%-7d %-14s %-4s %-3s ", id_, "breakpoint", "keep", enabled_ ? "y" : "n");
            writefln("%-18s %s", "<PENDING>", expr);
        } else {
            writef("%-7d %-14s %-4s %-3s ", id_, "breakpoint", "keep", enabled_ ? "y" : "n");
            if (addresses_.length == 1) {
                auto addr = addresses_.front;
                writef("%#-18x ", addr);
                writeln(db.describeAddress(addr, null));
            } else {
                writefln("%-18s ", "<MULTIPLE>");
                foreach(sidx, addr; addresses_) {
                    auto cid = std.string.format("%d.%d", id_, sidx + 1);
                    writef("%-27s %-3s %#-18x ", cid, enabled_ ? "y" : "n", addr);
                    writeln(db.describeAddress(addr, null));
                }
            }
        }
	if (condition_ !is null)
	    writefln("\tstop only if %s", condition_);
	if (command_)
	    writefln("\t%s", join(command_, " "));
    }

    SourceLocSpec spec_;
    ulong[] addresses_;
    string condition_;
    string[] command_;
    // TODO: synthesize condition text from Expr ???
    Expr expr_;
    bool enabled_ = true;
    uint id_;
}


private struct SourceLocSpec {
    this(string func, string file=null) {
        func_ = func;
        file_ = file;
    }

    this(uint line, string file=null) {
        line_ = line;
        file_ = file;
    }

    @property string file() const {
        return file_;
    }

    @property void file(string f) {
        file_ = f;
    }

    @property string func() const {
        return func_.ptr is null ? null : func_;
    }

    @property uint line() const {
        return func_.ptr is null ? line_ : 0;
    }

    @property string toString() const {
        auto postcol = (func is null) ? to!string(line) : func;
        return (file is null) ? postcol : std.string.format("%s:%s", file, postcol);
    }

private:
    // can be discriminated by func_.ptr being null
    union {
        string func_;
        uint line_;
    }
    string file_;
}

unittest {
    auto pb = SourceLocSpec("_Dmain");
    assert(pb.file is null);
    assert(pb.func == "_Dmain");
    assert(pb.line == 0);

    pb = SourceLocSpec("_Dmain", "foo.d");
    assert(pb.file == "foo.d");
    assert(pb.func == "_Dmain");
    assert(pb.line == 0);

    pb = SourceLocSpec(12);
    assert(pb.file is null);
    assert(pb.func is null);
    assert(pb.line == 12);

    pb = SourceLocSpec(12, "foo.d");
    assert(pb.file == "foo.d");
    assert(pb.func is null);
    assert(pb.line == 12);
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

	if (auto s = di_.unwind(state_))
            if (auto di = db_.findDebugInfo(s))
                if (auto func = di.findFunction(s.pc))
                    return new Frame(db_, index_ + 1, this, di, func, s);
        return null;
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

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener, TargetBreakpointListener, Scope
{
    /**
     * Bitmask to communicate available/wanted target information.
     */
    private enum Info {
        None = 0,
        Thread = (1 << 0),
        MState = (1 << 1),
        Debug = (1 << 2),
        FrameLoc = (1 << 3),
        Func = (1 << 4),
        Frame = (1 << 5),
        FrameEx = (1 << 6),
        Stack = (1 << 7),
        SourceLocation = (1 << 8),
        SymbolName = (1 << 9),
        LineEntry = (1 << 10),
    }

    this(string prog, string core, string prompt, uint annotate)
    {
	prog_ = prog;
	core_ = core;
        annotate_ = annotate;
	prompt_ = prompt;
    }

    static extern(C) void ignoreSig(int)
    {
    }

    bool sourceFile(string filename)
    {
        if (!std.file.exists(filename) || !std.file.isFile(filename))
            return false;
        auto f = File(filename, "r");
        executeLines(f.byLine());
        return true;
    }

    void executeLines(Lines)(Lines lines)
    {
	interactive_ = false;
        foreach(line; lines) {
            if (!line.empty)
                executeCommand(split(line.idup));
        }
	interactive_ = true;
    }

    string inputline(string prompt, string annotation)
    in {
        assert(prompt.endsWith(" "));
        assert(!annotation.empty);
    } body {
        if (annotate_)
            writefln("\n\032\032pre-%s", annotation);
        write(prompt);
        if (annotate_)
            writefln("\n\032\032%s", annotation);
        auto result = readln();
        if (annotate_)
            writefln("\n\032\032post-%s", annotation);
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
	    string line = strip(inputline("> ", "commands"));

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
        sourceFile(".ngdbinit");
        sourceFile(to!string(getenv("HOME")) ~ "/.ngdbinit");

	sigaction_t sa;
	sa.sa_handler = &ignoreSig;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, null);

        {
            auto tgt = target; // TODO: needed to eagerly load ColdTarget
        }

        string[] cmd;
	while (!quit_) {
            auto buf = inputline(prompt_, "prompt");

            auto ncmd = split(buf);
	    if (!ncmd.empty) {
                cmd = ncmd;
                // TODO: store command in history
                if (cmd.front == "server")
                    cmd.popFront;
            }
            if (cmd.empty)
		continue;

            executeCommand(cmd);
	}
    }

    // not ctfe able
    // immutable string[string] cmdAbbrevs = buildAbbrevs!Cmd;
    static Cmd[string] cmdAbbrevs;
    static InfoCmd[string] infoCmdAbbrevs;
    static SetCmd[string] setCmdAbbrevs;

    static this() {
        cmdAbbrevs = buildAbbrevs!Cmd();
        // resolve commonly used but possibly ambiguous abbreviations
        cmdAbbrevs["s" ] = Cmd.Step;
        cmdAbbrevs["si"] = Cmd.Stepi;
        cmdAbbrevs["n" ] = Cmd.Next;
        cmdAbbrevs["ni"] = Cmd.Nexti;
        cmdAbbrevs["c" ] = Cmd.Continue;
        cmdAbbrevs["r" ] = Cmd.Run;
        cmdAbbrevs["q" ] = Cmd.Quit;
        cmdAbbrevs["p" ] = Cmd.Print;

        infoCmdAbbrevs = buildAbbrevs!InfoCmd();
        setCmdAbbrevs = buildAbbrevs!SetCmd();
    }

    static T[string] buildAbbrevs(T)() if(is(OriginalType!T == string)) {
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

        TargetInfos infos;
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
                // TODO: print history
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
                if (activeTarget) {
                    auto info = "The program being debugged has been started already.";
                    auto question = "Start it from the beginning?";
                    if (!query(info, question))
                        return;
                }

                PtraceRun pt = new PtraceRun;
                if (!args.empty || runArgs_.empty)
                    runArgs_  = prog_ ~ args;
                try {
                    pt.connect(this, runArgs_);
                } catch (TargetException te) {
                    std.stdio.stderr.writeln(te.msg);
                }
                break;

            case Cmd.Kill:
                if (auto tgt = activeTarget) {
                    target.cont(SIGKILL);
                    target.wait;
                } else
                    std.stdio.stderr.writeln("Program is not running.");
                break;

            case Cmd.Step:
                programStep();
                break;
            case Cmd.Next:
                programStepOver();
                break;
            case Cmd.Stepi:
                stepInstruction(false);
                break;
            case Cmd.Nexti:
                stepInstruction(true);
                break;

            case Cmd.Continue:
                if (auto tgt = activeTarget) {
                    started();
                    try {
                        target.cont();
                        target.wait();
                    } catch (TargetException te) {
                        std.stdio.stderr.writeln(te.msg);
                    }
                } else
                    std.stdio.stderr.writeln("Program is not running.");
                break;

            case Cmd.Finish:
                if (auto missing = wantInfos(Info.Frame, infos)) {
                    std.stdio.stderr.writeln("No current frame");
                return;
                }
                if (auto toFrame = infos.frame.outer) {
                    setStepBreakpoint(toFrame.state_.pc);
                    started();
                    try {
                        target.cont();
                        target.wait();
                    } catch (TargetException te) {
                        std.stdio.stderr.writeln(te.msg);
                    }
                    stopped();
                    clearStepBreakpoints();
                    if (auto rTy = infos.frame.func_.returnType) {
                        if (wantInfos(Info.MState, infos))
                            return;
                        MachineState s = currentThread.state;
                        Value val = infos.mstate.returnValue(rTy);
                        writefln("Value returned is %s", val.toString(null, infos.mstate));
                    }
                    stopped();
                } else
                    std.stdio.stderr.writeln("Can't retrieve outer frame.");
                break;

            case Cmd.Break:
                addBreakpoint(args.empty ? null : args.front);
                break;

            case Cmd.Condition:
                if (args.empty) {
                    std.stdio.stderr.writeln(getCmdHelp([Cmd.Condition]));
                    return;
                }
                uint bid;
                if (!tryFrontArgToUint(args, bid))
                    return;

                if (args.empty) {
                    foreach(bp; breakpoints_) {
                        if (bp.id_ != bid)
                            continue;
                        writefln("Breakpoint %d is now unconditional", bid);
                        bp.condition_ = null;
                        bp.expr_ = null;
                    }
                    return;
                }

                auto exprstr = join(args, " ");

                foreach(bp; breakpoints_) {
                    if (bp.id_ != bid)
                        continue;

                    // Try to guess a source language for parsing the expression.
                    Language lang;
                gotLang: foreach(addr; bp.addresses_)
                        foreach(mod; target.modules)
                            if (auto di = mod.debugInfo)
                                if ((lang = di.findLanguage(addr)) !is null)
                                    break gotLang;

                    if (lang is null)
                        lang = (currentFrame_ !is null && currentFrame_.lang_ !is null)
                            ? currentFrame_.lang_
                            : CLikeLanguage.instance;
                    try {
                        auto e = lang.parseExpr(exprstr, this);
                        bp.condition_ = exprstr;
                        bp.expr_ = e;
                    } catch (EvalException ex) {
                        std.stdio.stderr.writefln("Error parsing breakpoint condition: %s", ex.msg);
                    }
                }
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
                    if (bp.id_ == bid)
                        bp.command = args;
                break;

            case Cmd.Enable:
                if (args.empty) {
                    foreach (bp; breakpoints_) {
                        if (bp.enabled_)
                            continue;
                        foreach (addr; bp.addresses_) {
                            breakpointMap_[addr] = bp;
                            target.setBreakpoint(addr, this);
                        }
                        bp.enabled_ = true;
                    }
                } else {
                    uint bid;
                    if (!tryFrontArgToUint(args, bid))
                        return;
                    foreach (bp; breakpoints_) {
                        if (bp.id_ != bid || bp.enabled_)
                            continue;
                        foreach (addr; bp.addresses_) {
                            breakpointMap_[addr] = bp;
                            target.setBreakpoint(addr, this);
                        }
                        bp.enabled_ = true;
                    }
                }
                break;

            case Cmd.Disable:
                if (args.empty) {
                    foreach (bp; breakpoints_) {
                        if (!bp.enabled_)
                            continue;
                        foreach (addr; bp.addresses_) {
                            target.clearBreakpoint(addr, this);
                            breakpointMap_.remove(addr);
                        }
                        bp.enabled_ = false;
                    }
                } else {
                    uint bid;
                    if (!tryFrontArgToUint(args, bid))
                        return;
                    foreach (bp; breakpoints_) {
                        if (bp.id_ != bid || !bp.enabled_)
                            continue;
                        foreach (addr; bp.addresses_) {
                            target.clearBreakpoint(addr, this);
                            breakpointMap_.remove(addr);
                        }
                        bp.enabled_ = false;
                    }
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
                    auto pred = (Breakpoint bp) { return bp.id_ != bid; };
                    auto drop = partition!(pred, SwapStrategy.stable)(breakpoints_);
                    breakpoints_.length -= drop.length;
                    foreach (bp; drop) {
                        foreach(addr; bp.addresses_) {
                            breakpointMap_.remove(addr);
                            if (bp.enabled_)
                                target.clearBreakpoint(addr, this);
                        }
                        bp.enabled_ = false;
                    }
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
                foreach (t; target.threads) {
                    if (t.id == tid) {
                        currentThread = t;
                        stopped();
                        return;
                    }
                }
                std.stdio.stderr.writefln("Invalid thread %d.", tid);
                break;

            case Cmd.Up:
                if (auto missing = wantInfos(Info.Frame | Info.MState, infos)) {
                    // TODO: reportUnavailableInfos(missing);
                    std.stdio.stderr.writeln("Stack frame information unavailable.");
                    return;
                }
                if (auto upf = infos.frame.outer) {
                    currentFrame_ = upf;
                    writeln(currentFrame_.toString);
                    displaySourceLine(currentFrame_.state_);
                } else {
                    std.stdio.stderr.writeln("Can't retrieve outer frame.");
                }
                break;

            case Cmd.Down:
                if (auto missing = wantInfos(Info.Frame | Info.MState, infos)) {
                    std.stdio.stderr.writeln("Stack frame information unavailable.");
                    return;
                }
                if (auto dof = infos.frame.inner) {
                    currentFrame_ = dof;
                    writeln(currentFrame_.toString);
                    displaySourceLine(currentFrame_.state_);
                } else {
                    std.stdio.stderr.writeln("Can't retrieve inner frame.");
                }
                break;

            case Cmd.Frame:
                if (args.empty)
                    printStackFrames(1, currentFrame_);
                else {
                    uint fidx;
                    if (!tryFrontArgToUint(args, fidx))
                        return;
                    if (auto f = getFrame(fidx))
                        currentFrame_ = f;
                    if (interactive_)
                        printStackFrames(1, currentFrame_);
                }
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
                    SourceLocSpec spec;
                    if (!parseSourceLocSpec(tok.front, spec)) {
                        std.stdio.stderr.writefln("Failed to parse source location %s.", tok.front);
                        return;
                    }
                    if (auto func = spec.func) {
                        bool found;
                        foreach(mod; target.modules) {
                            if (mod.debugInfo is null)
                                continue;
                            LineEntry[] lines;
                            // TODO: check pubnames scanning, seems to be unreliable
                            if (!mod.debugInfo.findLineByFunction(func, lines))
                                continue;
                            // TODO: ambiguity possible???
                            assert(lines.length == 1);
                            if (auto sf = findFile(lines.front.fullname)) {
                                currentSourceFile_ = sf;
                                currentSourceLine_ = lines.front.line;
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            std.stdio.stderr.writefln("Can't find location %s.", spec);
                            return;
                        }
                    } else if (auto sf = findFile(spec.file)) {
                        assert(spec.line);
                        currentSourceFile_ = sf;
                        currentSourceLine_ = spec.line;
                    } else {
                        std.stdio.stderr.writefln("Can't find location %s.", spec);
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
                        b.print(this);
                }
                break;

            case InfoCmd.Threads:
                foreach (t; target.threads) {
                    auto mark = t is currentThread ? "*" : " ";
                    auto desc = describeAddress(t.state.pc, t.state);
                    // TODO: need thread entry point instead of pc
                    writefln("%s %d Thread %x (LWP 100351) %s", mark, t.id, t.state.pc, desc);
                }
                break;

            case InfoCmd.Locals:
                if (!activeTarget) {
                    std.stdio.stderr.writeln("Program is not running.");
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
                    if (auto d = func.lookup(name, s)) {
                        auto v = cast(Variable)d;
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
                size_t idx;
                foreach (mod; target.modules) {
                    ++idx;
                    string addrs = format("%#x .. %#x", mod.start, mod.end);
                    auto mark = (pc >= mod.start && pc < mod.end) ? "*" : " ";
                    writefln("%s%2d: %-32s %s", mark, idx, addrs, mod.filename);
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
                else {
                    uint idx;
                    if (tryFrontArgToUint(args, idx))
                        f = getFrame(idx);
                }
                if (f is null) {
                    std.stdio.stderr.writeln("No frame.");
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
                printStackFrames(cnt);
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
                // TODO: set pager height
                break;

            case SetCmd.Width:
                // TODO: set pager width
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
                return "info frame [INDEX]: Information about current frame or frame at INDEX.";
            case InfoCmd.Stack:
                return "info stack [COUNT]: Backtrace of stack up to COUNT frames.";
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

    bool query(string info, string question)
    in {
        assert(!info.empty && !question.empty);
    } body {
	if (!interactive_)
	    return true;

	auto prompt = std.string.format("%s\n%s (y or n) ", info, question);
        string resp;
	do {
            resp = strip(inputline(prompt, "query"));
	} while (resp.empty || (resp.front != 'y' && resp.front != 'n'));
        return resp.front == 'y';
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
            sourceFilesBasename_[std.path.basename(filename)] = sf;
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
    bool parseSourceLocSpec(string s, out SourceLocSpec spec)
    {
        auto scoped = split(s, ":");
        string file;
        if (scoped.length == 2) {
            file = strip(scoped.front);
            scoped.popFront;
        }

        if (scoped.length != 1)
            return false;

        auto loc = strip(scoped.front);
        if (loc.empty)
            return false;

        if (isDigit(loc.front)) {
            uint lineno;
            if (collectException!ConvException(to!uint(loc), lineno))
                return false;
            spec = SourceLocSpec(lineno, file);
            return true;
        } else {
            // assume loc is a func
            spec = SourceLocSpec(loc, file);
            return true;
        }
    }

    bool setCurrentFrame()
    {
	TargetThread t = currentThread;
	MachineState s = t.state;

	if (auto di = findDebugInfo(s)) {
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
            return false;
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, s);
	    return true;
	}
    }

    void started()
    {
	stopped_ = false;
        if (annotate_)
            writeln("\n\032\032starting");
    }

    void stopped()
    {
	if (stopped_ || !activeTarget)
	    return;

	stopped_ = true;

	auto t = currentThread;
	auto s = t.state;
	auto newFrame = setCurrentFrame;
	auto di = currentFrame_.di_;

	if (di) {
            if (newFrame)
                printStackFrames(1);
	    LineEntry[] le;
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		currentSourceFile_ = stoppedSourceFile_ = sf;
		currentSourceLine_ = stoppedSourceLine_ = le[0].line;
                // TODO: character is absolute file index, middle ???
                auto character = le[0].column;
                if (annotate_)
                    writefln("\n\032\032source %s:%d:%d:%s:%#x",
                             currentSourceFile_.filename, currentSourceLine_,
                             character, false ? "middle" : "beg", s.pc);
                else
                    // TODO: there should actually be no else to annotate_ but
                    // having no source in cli is as bad as having source in mi.
                    displaySourceLine(sf, currentSourceLine_);
	    }
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, s);
	    ulong tpc = s.pc;
	    writefln("%s:\t%s", lookupAddress(s.pc),
		     s.disassemble(tpc, &lookupAddress));
	}
        if (annotate_)
            writeln("\n\032\032stopped");
    }

    void displaySourceLine(MachineState s)
    {
	LineEntry[] le;

	if (auto di = findDebugInfo(s))
            if (di.findLineByAddress(s.pc, le))
                if (auto sf = findFile(le[0].fullname)) {
                    displaySourceLine(sf, le[0].line);
                    currentSourceFile_ = sf;
                    currentSourceLine_ = le[0].line;
                }
    }

    void displaySourceLine(SourceFile sf, uint line)
    {
	string bpmark = " ";
	showline: foreach (mod; target.modules) {
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

    /**
     * Prints a backtrace of at most depth frames from frame or topFrame_.
     */
    void printStackFrames(uint depth, Frame frame=null) {
        if (frame is null)
            frame = topFrame_;
        while (depth-- && frame !is null) {
            const pc = frame.state_.pc;
            const idx = frame.index_;
            if (annotate_)
                writefln("\n\032\032frame-begin %d %#x", idx, pc);
            writefln("#%d %s", idx, describeAddress(pc, frame.state_));
            frame = frame.outer;
        }
    }

    /**
     * Return a string describing the location of pc. At best through function
     * name and source location, at worst through addr and module.
     */
    string describeAddress(ulong pc, MachineState state)
    {
	LineEntry[] le;
	foreach (mod; target.modules) {
	    DebugInfo di = mod.debugInfo;
	    if (di && di.findLineByAddress(pc, le)) {
		if (auto func = di.findFunction(pc)) {
		    return std.string.format("%s at %s:%d",
                                             func.toString(null, state), le[0].name, le[0].line);
		} else if (mod.contains(pc)) {
		    return std.string.format("%#-16x in ?? () at %s:%d", pc, le[0].name, le[0].line);
                }
	    }
	}
	return lookupAddress(pc);
    }

    string lookupAddress(ulong addr)
    {
	TargetSymbol bestSym;
	string modname;
	foreach (mod; target.modules) {
	    TargetSymbol sym;
	    if (mod.lookupSymbol(addr, sym)) {
                // TODO: underflow subtract ???
		if (modname.empty || addr - sym.value < addr - bestSym.value) {
		    bestSym = sym;
		    modname = mod.filename;
		}
	    }
	}
        // TODO: don't write modname if it's the main module (program)
	if (!modname.empty) {
            return std.string.format("%#-16x in %s+%d () from %s",
                                     addr, bestSym.name, addr - bestSym.value, modname);
	}
	return std.string.format("%#-16x in ?? () from %s", addr, modname);
    }

    void setStepBreakpoint(ulong pc)
    {
	debug (step)
	    writefln("step breakpoint at %#x", pc);
	if (auto tgt = activeTarget) {
            steppcs_[pc] = true;
	    tgt.setBreakpoint(pc, this);
        }
    }

    void clearStepBreakpoints()
    {
	debug (step)
	    writefln("clearing step breakpoints");
	if (auto tgt = activeTarget) {
            foreach(pc; steppcs_.values) {
                tgt.clearBreakpoint(pc, this);
                steppcs_.remove(pc);
            }
            // @@ BUG 5683 have to delete one after another @@
            // steppcs_.clear;
        }
    }

    void programStepOver()
    {
	if (activeTarget is null) {
	    std.stdio.stderr.writeln("Program is not running.");
	    return;
	}

	started();

        TargetInfos infos;
        enum needed = Info.Thread | Info.MState | Info.LineEntry;

	if (auto missing = wantInfos(needed, infos)) {
            if (missing & Info.Thread)
                std.stdio.stderr.writeln("Can't get active thread.");
            else {
                target.step(infos.thr);
                stopped();
            }
            return;
        }

        auto startpc = infos.mstate.pc;
        auto stoppc = infos.lineEntry[1].address;

        // if no flow control findFlowControl returns stoppc
        while (infos.mstate.pc < stoppc) {
            auto flowOrstop = infos.mstate.findFlowControl(infos.mstate.pc + 1, stoppc);
            setStepBreakpoint(flowOrstop);
            // need to loop in case an unrelated breakpoint is hit
            do {
                target.cont();
                target.wait();
            } while (infos.mstate.pc < flowOrstop);
            clearStepBreakpoints();
        }
        stopped();
        assert(infos.mstate.pc == stoppc,
               std.string.format("pc:%#x stoppc:%#x", infos.mstate.pc, stoppc));
    }

    void programStep()
    {
	if (!activeTarget) {
	    std.stdio.stderr.writeln("Program is not running.");
	    return;
	}

	started();

        TargetInfos infos;
        enum needed = Info.Thread | Info.MState | Info.Debug
            | Info.Func | Info.FrameLoc | Info.LineEntry;

	if (auto missing = wantInfos(needed, infos)) {
            if (missing & Info.Thread)
                std.stdio.stderr.writeln("Can't get active thread.");
            else {
                target.step(infos.thr);
                // stopped(); still needed ??
            }
            return;
        }

        scope (exit) { clearStepBreakpoints(); stopped(); }

        ulong framepc = infos.frameLoc.address(infos.mstate);
        auto oldFrameFunc = infos.func;

        ulong startpc = infos.mstate.pc;
        ulong stoppc = infos.lineEntry[1].address;
        ulong flowpc;

        void rearmStepBreakPoints() {
            clearStepBreakpoints();
            setStepBreakpoint(stoppc);
            flowpc = infos.mstate.findFlowControl(infos.mstate.pc, stoppc);
            if (flowpc < stoppc)
                setStepBreakpoint(flowpc);
            else
                flowpc = 0;
        }

        rearmStepBreakPoints();
        do {
            /*
             * Run up to the next flow control instruction or the
             * next statement, whichever comes first. Be careful if
             * we are sitting on a flow control instruction.
             */
            if (infos.mstate.pc != flowpc) {
                target.cont();
                target.wait();
            } else {
                /*
                 * Stopped at a flow control instruction - single step
                 * it and see if we change frame or go out of our step
                 * range.
                 */
                target.step(infos.thr);

                bool inPLT(ulong pc) {
                    foreach (mod; target.modules)
                        if (mod.inPLT(pc))
                            return true;
                    return false;
                }

                while (inPLT(infos.mstate.pc)) {
                    debug (step)
                        writefln("single stepping over PLT entry");
                    target.step(infos.thr);
                }
            }

            enum neededInner = Info.Thread | Info.MState | Info.Debug
                | Info.Func | Info.FrameLoc;
            auto missingInner = wantInfos(neededInner, infos);
            if (missingInner & (Info.Debug | Info.MState)) {
                /*
                 * If we step into something without debug info,
                 * just continue until we hit the step breakpoint.
                 */
                target.cont();
                target.wait();
                return;
            } else if (missingInner == 0 &&
                       (infos.frameLoc.address(infos.mstate) != framepc
                        || infos.func !is oldFrameFunc)) {
                // left frame in either direction
                return;
            }
            if (infos.mstate.pc < startpc || infos.mstate.pc >= stoppc) {
                return;
            }
        } while (infos.mstate.pc < stoppc);
    }

    void stepInstruction(bool stepOverCalls)
    {
	if (!activeTarget) {
	    std.stdio.stderr.writeln("Program is not running.");
	    return;
	}

	started();

	TargetThread t = currentThread;
	MachineState s = t.state;

	ulong frame = 0;

        Location frameLoc;
	if (auto di = findDebugInfo(s, frameLoc)) {
	    di.findFrameBase(s, frameLoc);
	    frame = frameLoc.address(s);
	}

	target.step(t);

	if (auto di = findDebugInfo(s, frameLoc)) {
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
			target.cont();
			target.wait();
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
	    writefln("%s:\t%s", lookupAddress(s.pc),
                     s.disassemble(tpc, &lookupAddress));
	}
    }

    void addBreakpoint(string bploc)
    {
        SourceLocSpec spec;
        if (bploc.empty) {
            if (currentSourceFile_ is null) {
                std.stdio.stderr.writeln("No current source file.");
                return;
            } else {
                spec = SourceLocSpec(currentSourceLine_, currentSourceFile_.filename);
            }
        } else {
	    if (!parseSourceLocSpec(bploc, spec)) {
                std.stdio.stderr.writefln("Failed to parse source location %s.", bploc);
                return;
            }
            // Bind line only specs to the current source file but
            // leave func specs alone.
            if (spec.file is null && spec.func is null)
                spec.file = currentSourceFile_.filename;
        }
        auto bp = new Breakpoint(spec);
        if (!activateBreakpoint(bp)) {
            auto info = std.string.format("Can't set breakpoint at %s.",
                                          (bploc.empty) ? "current location" : bploc);
            enum question = "Make breakpoint pending on future shared library load?";
            if (query(info, question)) {
                bp.id_ = nextBPID_++;
                breakpoints_ ~= bp;
            }
            return;
        }
    }

    bool activateBreakpoint(Breakpoint bp) {
        foreach (mod; target.modules) {
            foreach(addr; bp.addAddresses(mod)) {
                breakpointMap_[addr] = bp;
                if (bp.enabled_)
                    target.setBreakpoint(addr, this);
            }
        }
        if (!bp.active)
            return false;
        bp.id_ = nextBPID_++;
        breakpoints_ ~= bp;
        // TODO: need shortPrint
        bp.printHeader;
        bp.print(this);
        return true;
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
	if (t is currentThread_)
            return;
        if (currentThread_ is null && activeTarget)
            writefln("[New LWP %d]", t.tid);
        currentThread_ = t;
        if (t is null)
            return;
        assert(t.target is target_); // unless capable of handling multiple targets
        if (activeTarget) {
            if (annotate_)
                writeln("\n\032\032thread-changed");
            // TODO: need stack base
            writefln("[Switching to Thread %x (LWP %d)]", t.target.entry, t.tid);
        }
    }

    private Target activeTarget() {
        return (target_ !is null && target_.state != TargetState.EXIT) ? target_ : null;
    }

    private Target target() {
        if (target_ is null)
            target_ = new ColdTarget(this, prog_, core_);
        return target_;
    }

    private void target(Target tgt) {
        if (target_ is tgt)
            return;
        if (activeTarget)
            writeln("Target program has exited.");
        target_ = tgt;
        if (activeTarget) {
            if (annotate_)
                writeln("\n\032\032starting");
        }
    }

    DebugInfo findDebugInfo(MachineState s, out Location loc)
    {
	foreach (mod; target.modules)
	    if (auto di = mod.debugInfo)
                if (di.findFrameBase(s, loc))
                    return di;
	return null;
    }

    DebugInfo findDebugInfo(MachineState s)
    {
	Location loc;
        return findDebugInfo(s, loc);
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
	    std.stdio.stderr.writeln(ex.msg);
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
	void onTargetStarted(Target tgt)
	{
	    stopped_ = false;
	    target = tgt;
	}

	void onThreadCreate(Target tgt, TargetThread thread)
        in {
            foreach (t; target.threads)
                assert(t !is thread);
            assert(tgt is target_);
        } body {
            if (activeTarget) {
                if (annotate_)
                    writeln("\n\032\032new-thread");
                // TODO: need stack top of thread instead of entry
                writefln("[New Thread %x (LWP %d)]", tgt.entry, thread.tid);
            }
	    if (currentThread is null)
		currentThread = thread;
	}

	void onThreadDestroy(Target target, TargetThread thread)
	{
	}

	void onModuleAdd(Target, TargetModule mod)
	{
	    auto di = mod.debugInfo;
	    if (di) {
		foreach (s; di.findSourceFiles)
		    findFile(s);
	    }
	    foreach (bp; breakpoints_) {
                foreach(addr; bp.addAddresses(mod)) {
                    breakpointMap_[addr] = bp;
                    if (bp.enabled_)
                        target.setBreakpoint(addr, this);
                }
            }
	}
	void onModuleDelete(Target, TargetModule mod)
	{
            auto pred = (ulong addr) { return !mod.contains(addr); };
	    foreach (bp; breakpoints_) {
                auto drop = partition!(pred, SwapStrategy.stable)(bp.addresses_);
                bp.addresses_.length -= drop.length;
                foreach (addr; drop) {
                    if (bp.enabled_)
                        target.clearBreakpoint(addr, this);
                    breakpointMap_.remove(addr);
                }
            }
	}
	bool onBreakpoint(Target, TargetThread t, ulong addr)
	{
            if (addr in steppcs_) // ignore step breakpoints
                return true;

            currentThread = t;
            stopped();
            Breakpoint bp;
            if (auto p = addr in breakpointMap_)
                bp = *p;
            else
                assert(0);

            if (bp.condition_) {
                setCurrentFrame;
                auto f = currentFrame_;
                auto sc = f.scope_;
                auto s = t.state;
                try {
                    auto v = bp.expr_.eval(sc, s).toValue(s);
                    if (v.type.isIntegerType)
                        if (!s.readInteger(v.loc.readValue(s)))
                            return false;
                } catch (EvalException ex) {
                    std.stdio.stderr.writeln("Error evaluating breakpoint condition: %s", ex.msg);
                    return true;
                }
            }
            if (annotate_) {
                writefln("\n\032\032breakpoint %d", bp.id_);
                setCurrentFrame;
                auto f = currentFrame_;
                stopped();
            }
            writefln("Stopped at breakpoint %d %s", bp.id_, describeAddress(t.state.pc, null));
            if (bp.command) {
                stopped();
                executeCommand(bp.command);
            }
            return true;
        }

	void onSignal(Target, TargetThread t, int sig, string sigName)
	{
	    currentThread = t;
            stopped();
	    writefln("Thread %d received signal %d (%s)", t.id, sig, sigName);
	}
	void onExit(Target)
	{
	    target = null;
	    currentThread = null;
	    topFrame_ = currentFrame_ = null;
	    foreach (bp; breakpoints_) {
                foreach(addr; bp.addresses_)
                    breakpointMap_.remove(addr);
		bp.addresses_ = null;
            }
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (mod; target.modules)
		res ~= mod.contents(state);
	    for (int i = 0; i < valueHistory_.length; i++)
		res ~= "$" ~ to!string(i);

	    return array(uniq(sort(res)));
	}
	DebugItem lookup(string name, MachineState state)
	{
	    foreach (mod; target.modules)
		if (auto val = mod.lookup(name, state))
		    return val;

	    if (name.length == 0 || name[0] != '$')
		return null;
	    name = name[1..$];
	    if (name.length == 0 || isDigit(name[0])) {
		try {
		    size_t num = name.length > 0
			? to!size_t(name) : valueHistory_.length - 1;
		    return (num < valueHistory_.length) ? valueHistory_[num] : null;
		} catch (ConvException ce) {
		    return null;
		}
	    } else if (isAlpha(name[0]) || name[0] == '_') {
		if (auto vp = name in userVars_)
		    return *vp;
		auto lang = currentLanguage;
		Value var = new Value(new UserLocation,
				      new UserType(lang));
		userVars_[name] = var;
		return var;
	    } else {
		return null;
	    }
	}
	Type lookupStruct(string name)
	{
	    foreach (mod; target.modules)
		if (auto ty = mod.lookupStruct(name))
		    return ty;
	    return null;
	}
	Type lookupUnion(string name)
	{
	    foreach (mod; target.modules)
		if (auto ty = mod.lookupUnion(name))
		    return ty;
	    return null;
	}
	Type lookupTypedef(string name)
	{
	    foreach (mod; target.modules)
		if (auto ty = mod.lookupTypedef(name))
		    return ty;
	    return null;
	}
    }

    /**
     * Tries to make the wanted information available and returns a bitmask of
     * missing infos.
     */
    private final Info wantInfos(Info wantMask, out TargetInfos infos)
    in {
        assert(wantMask != Info.None);
        assert(target_ is null || target_.state != TargetState.RUNNING);
    } body {

        Info resolved;
        // bare minimum
        {
            auto thr = currentThread;
            if (thr is null)
                return resolved;
            infos.thr = thr;
            resolved |= Info.Thread;
            // If have no state from frame use thread state or fail. This is so to
            // allow switching frames.
            auto st = (currentFrame_ is null) ? null : currentFrame_.state_;
            if (st is null && (st = infos.thr.state) is null)
                return resolved;

            infos.mstate = st;
            resolved |= Info.MState;
        }


        enum needDebug = Info.Debug | Info.FrameLoc | Info.Func
            | Info.Frame | Info.FrameEx | Info.LineEntry;
        if (wantMask & needDebug) {
            Location loc;
            if (auto di = findDebugInfo(infos.mstate, loc)) {
                infos.dbg = di;
                infos.frameLoc = loc;
                resolved |= Info.Debug | Info.FrameLoc;
            }
        }

        if (wantMask & (Info.Func | Info.Frame | Info.FrameEx)) {
            if (resolved & Info.Debug) {
                if (auto func = infos.dbg.findFunction(infos.mstate.pc)) {
                    infos.func = func;
                    resolved |= Info.Func;
                }
            }
        }

        if (wantMask & (Info.Frame | Info.FrameEx)) {
            if (resolved & Info.Func) {
                if (currentFrame_ is null
                    || currentFrame_.func_ != infos.func
                    || currentFrame_.addr_ != infos.frameLoc.address(infos.mstate)
                )
                    currentFrame_ = new Frame(this, 0, null, infos.dbg, infos.func, infos.mstate);
                infos.frame = currentFrame_;
                resolved |= Info.Frame;
            } else {
                // TODO: possibly create a bare frame from state
            }
        }

        if (wantMask & Info.LineEntry) {
            LineEntry[] le;
            if (infos.dbg.findLineByAddress(infos.mstate.pc, le)) {
                infos.lineEntry = le;
                resolved |= Info.LineEntry;
            }
        }

        infos.mask = resolved;
        return ~resolved & wantMask;
    }

private:

    static struct TargetInfos {
        Info mask;

        TargetThread thr;
        MachineState mstate;

        DebugInfo dbg;
        Location frameLoc;
        Function func;

        Frame frame;

        LineEntry[] lineEntry;
    }

    immutable string prog_;
    immutable string core_;
    immutable string prompt_;
    immutable uint annotate_;
    bool interactive_ = true;
    bool quit_ = false;
    bool stopped_;
    string[] runArgs_;
    Target target_;
    TargetThread currentThread_;
    Frame topFrame_;
    Frame currentFrame_;

    Breakpoint[ulong] breakpointMap_;
    // TODO: consider synthesizing this member from breakpointMap_
    Breakpoint[] breakpoints_;
    bool[ulong] steppcs_;

    SourceFile[string] sourceFiles_;
    SourceFile[string] sourceFilesBasename_;
    SourceFile stoppedSourceFile_;
    uint stoppedSourceLine_;
    SourceFile currentSourceFile_;
    uint currentSourceLine_;
    uint nextBPID_ = 1;
    Value[] valueHistory_;
    Value[string] userVars_;
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

        if (!db.activeTarget) {
            std.stdio.stderr.writeln("Target is not running");
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
                std.stdio.stderr.writeln("No previous address to examine");
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
                std.stdio.stderr.writeln(ex.msg);
                return;
            }
        }

        uint count = count_;
        if (fmt_ == "i") {
            while (count > 0) {
                string addrString = db.lookupAddress(addr);
                std.stdio.stdout.writefln("%-31s %s", addrString,
                           s.disassemble(addr, &db.lookupAddress));
                count--;
            }
        } else {
            string line = format("%#-15x ", addr);
            while (count > 0) {
                ubyte[] mem = db.target.readMemory(addr, width_);
                addr += width_;
                ulong val = s.readInteger(mem);
                if (width_ < 8)
                    val &= (1UL << width_ * 8) - 1;
                string fmt = format("%%0%d%s ", 2*width_, fmt_);
                string vs = format(fmt, val);
                if (line.length + vs.length > 79) {
                    std.stdio.stdout.writeln(line);
                    line = format("%#-15x ", addr);
                }
                line ~= vs;
                count--;
            }
            std.stdio.stdout.writeln(line);
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
            std.stdio.stderr.writeln("usage: define name");
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

        if (db.interactive_)
            std.stdio.stdout.writefln("Enter commands for \"%s\", finish with \"end\"",
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
            std.stdio.stderr.writeln("Recursion too deep");
            depth_ = 0;
            return;
        }
        string[] cmds;
        foreach (cmd; cmds_) {
            foreach (i, arg; args)
                cmd = replace(cmd, "$arg" ~ to!string(i), arg);
            cmds ~= cmd;
        }
        depth_++;
        db.executeLines(cmds);
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
            std.stdio.stderr.writeln("usage: source filename");
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
            std.stdio.stderr.writeln("usage: if expr");
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
            db.executeLines(ifCmds);
        else
            db.executeLines(elseCmds);
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
            std.stdio.stderr.writeln("usage: while expr");
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
            db.executeLines(cmds);
        }
    }
}
