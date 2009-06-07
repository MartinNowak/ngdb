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
import std.stdint;

import gtk.GtkD;
import gtk.MainWindow;

import ptracetarget;
import target;
import dwarf;
import elfmodule;

version (DEBUG)
{
	int debugLevel = 0;
}

version (GUI)
{
    class Debugger: MainWindow, TargetListener
    {
	import gtk.AccelGroup;
	import gtk.HBox;
	import gtk.HPaned;
	import gtk.Menu;
	import gtk.MenuBar;
	import gtk.MenuItem;
	import gtk.TextView;
	import gtk.Toolbar;
	import gtk.TreeView;
	import gtk.VBox;
	import gtk.VPaned;
	import gtk.Widget;
	import gtkc.gtktypes;

	this()
	{
	    super("Debugger");
	    version (GUI)
	    {
		createInterface();
		showAll();
	    }
	}

	void createInterface()
	{
	    setDefaultSize(1024, 768);

	    VBox vbox = new VBox(false, 0);
	    add(vbox);
	    vbox.packStart(createMenus(), false, false, 0);
	    vbox.packStart(createToolbar(), false, false, 0);

	    HPaned hpaned = new HPaned();
	    hpaned.setPosition(300);
	    vbox.packStart(hpaned, true, true, 0);

	    VPaned vpaned = new VPaned();
	    vpaned.setPosition(350);
	    hpaned.pack1(vpaned, false, false);
	    hpaned.pack2(createSourceView(), true, true);
	    vpaned.add(new TreeView, new TreeView);
	}

	Widget createMenus()
	{
	    AccelGroup accel = new AccelGroup;
	    MenuBar menubar = new MenuBar;

	    Menu fileMenu = menubar.append("_FILE");
	    fileMenu.append(new MenuItem(&onMenuActivate, "_New", "file.new",
					 true, accel, 'n'));
	    fileMenu.append(new MenuItem(&onMenuActivate, "_Open", "file.open",
					 true, accel, 'n'));
	    fileMenu.append(new MenuItem(&onMenuActivate, "_Close", "file.close",
					 true, accel, 'n'));

	    return menubar;
	}

	Widget createToolbar()
	{
	    Toolbar toolbar = new Toolbar;

	    toolbar.insertStock(StockID.GO_FORWARD, "fruit", "fruit", 0);

	    return toolbar;
	}

	Widget createSourceView()
	{
	    TextView text = new TextView;

	    text.appendText("Source view");

	    return text;
	}

	// GTK callbacks
	void onMenuActivate(MenuItem item)
	{
	}

	override
	{
	    // TargetListener
	    void onThreadCreate(Target target, Thread thread)
	    {
	    }
	    void onThreadDestroy(Target target, Thread thread)
	    {
	    }
	    void onModuleAdd(Target, TargetModule)
	    {
	    }
	}
    }
} else {
    class Debugger: TargetListener
    {
	this()
	{
	}

	override
	{
	    // TargetListener
	    void onThreadCreate(Target target, Thread thread)
	    {
	    }
	    void onThreadDestroy(Target target, Thread thread)
	    {
	    }
	    void onModuleAdd(Target, TargetModule)
	    {
	    }
	}
    }
}

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
	Debugger dbg = new Debugger;

	version (GUI)
	{
	    Gtk.main();
	} else {
	    version (ATTACH)
	    {
		PtraceAttach pt = new PtraceAttach;
		char[][] attachArgs = args[1..2];
	    } else {
		PtraceRun pt = new PtraceRun;
		char[][] attachArgs = [ "hello" ];
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
		uintptr_t pc = t.pc;

		if (modules.length > 0) {
		    foreach (mod; modules) {
			if (pc >= mod.start && pc < mod.end) {
			    writef("%s: ", mod.filename);
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
    } catch (Exception e) {
	writefln("error: %s", e.msg);
    }

    return 0;
}
