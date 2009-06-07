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

module target;
import std.stdint;

/**
 * This interface is used to manipulate a single thread (program counter and
 * register set) within a target.
 */
interface Thread
{
    /**
     * Return the target that contains this thread.
     */
    Target target();

    /**
     * Return the thread's current program counter.
     */
    uintptr_t pc();
}

/**
 * Describe a mapping of part of the target address space to a file
 */
interface TargetModule
{
    /**
     * Return the filename of the module that occupies this address
     * range.
     */
    char[] filename();

    /**
     * Return the start address in the target address space for this
     * module.
     */
    uintptr_t start();

    /**
     * Return the end address for this module
     */
    uintptr_t end();
}

/**
 * Target state
 */
enum TargetState {
    STOPPED,
    RUNNING,
}

/**
 * This interface is used to allow a target to notify a user of
 * changes in the target state.
 */
interface TargetListener
{
    /**
     * Called when a new thread is created in the target.
     */
    void onThreadCreate(Target, Thread);

    /**
     * Called when a thread is destroyed.
     */
    void onThreadDestroy(Target, Thread);

    /**
     * Called when a new module is mapped in the target.
     */
    void onModuleAdd(Target, TargetModule);
}

/**
 * A breakpoint in a target
 */
interface Breakpoint
{
    /**
     * Set enabled/disabled state
     */
    void setEnabled(bool);
}


/**
 * This interface represents a debugging target.
 */
interface Target
{
    /**
     * Return the current target state.
     */
    TargetState state();

    /**
     * Return the thread which caused the target to stop.
     */
    Thread focusThread();

    /**
     * Return a set of all the threads in the target.
     */
    Thread[] threads();

    /**
     * Return a set of all the modules in the target.
     */
    TargetModule[] modules();

    /**
     * Read from the target's memory.
     */
    ubyte[] readMemory(uintptr_t targetAddress, size_t bytes);

    /**
     * Write to the target's memory.
     */
    void writeMemory(uintptr_t targetAddress, ubyte[] toWrite);

    /**
     * Step the target by one instruction. After this method returns,
     * the target will be stopped again.
     */
    void step();

    /**
     * Allow a target in state STOPPED to continue. The target's state
     * changes to RUNNING. Call wait() to pause until the target stops
     * again (e.g. at a breakpoint).
     */
    void cont();

    /**
     * Wait for the target to receive an event which causes it to stop.
     */
    void wait();

    /**
     * Set a breakpoint at the given address. Return an object that
     * represents the breakpoint and which can be used to cancel it.
     */
    Breakpoint setBreakpoint(uintptr_t addr);

    /**
     * Remove a breakpoint
     */
    void clearBreakpoint(Breakpoint bp);
}

/**
 * This interface provides an abstraction to allow creating
 * targets or attaching to existing targets.
 */
interface TargetFactory
{
    /**
     * Return the name of the target factory (e.g. "process", "core" etc.).
     */
    char[]			name();

    /**
     * Create a new target instance with the given arguments.
     */
    Target			connect(TargetListener listener, char[][] args);
}
