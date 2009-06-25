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

import std.stdio;

import ptracetarget;
import target;
import objfile.dwarf;
import elfmodule;
import cli;

int
main(char[][] args)
{
    version (ATTACH) {
	if (args.length != 2) {
	    writef("Usage: fdb <pid>\n");
	    return 1;
	}
    }

    version (GUI)
	    Gtk.init(args);

    try {
	version (GUI)
	{
	    Gtk.main();
	} else {
	    if (args.length != 2) {
		writefln("usage: %s <program>", args[0]);
		return 1;
	    }

	    cli.Debugger cli = new cli.Debugger(args[1]);
	    cli.run();

	    static if (false) {
		version (ATTACH)
		{
		    PtraceAttach pt = new PtraceAttach;
		    string[] attachArgs = args[1..2];
		} else {
		    PtraceRun pt = new PtraceRun;
		    string[] attachArgs = [ "hello" ];
		}
		Target target = pt.connect(dbg, attachArgs);
		TargetModule[] tmodules = target.modules();
		//DwarfModule[] modules;
		ElfModule[] modules;

		modules.length = tmodules.length;
		foreach (i, tmod; tmodules)
		    modules[i] = new ElfModule(tmod);

		// Put a breakpoint on main and continue up to that point
		Breakpoint bpMain;
		foreach (mod; modules) {
		    Symbol* s = mod.lookupSymbol("main");
		    if (s) {
			bpMain = target.setBreakpoint(s.value);
		    }
		}
		target.cont();
		target.wait();

		for (;;) {
		    Thread t = target.focusThread;
		    ulong pc = t.pc;

		    if (modules.length > 0) {
			foreach (mod; modules) {
			    if (pc >= mod.start && pc < mod.end) {
				writef("%s: ", mod.filename);
				mod.findSubModule(pc);
				Symbol* s = mod.lookupSymbol(pc);
				if (s)
				    writefln("0x%08x (%s+%d)", pc, s.name, pc - s.value);
				else
				    writefln("0x%08x", pc);
			    }
			}
		    } else {
			writefln("0x%08x", pc);
		    }
		    target.step();
		}
	    }
	}
    } catch (Exception e) {
	writefln("error: %s", e.msg);
    }

    return 0;
}
