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

module machine.machine;
import target.target;
import debuginfo.debuginfo;
import debuginfo.types;
version(tangobos) import std.compat;

/**
 * A structure used to decribe how to use ptrace(2) to update the
 * machine state.
 */
struct PtraceCommand
{
    uint	req;
    ubyte*	addr;
    uint	data;
}

/**
 * A representation of the target machine. Registers are indexed by
 * dwarf register number.
 */
interface MachineState: Scope
{
    void dumpState();

    /**
     * Return the machine's program counter register.
     */
    ulong pc();

    /**
     * Set the program counter register.
     */
    void pc(ulong);

    /**
     * Return the thread pointer register.
     */
    ulong tp();

    /**
     * Return the address of the TLS object at the given module index
     * and offset.
     */
    ulong tls_get_addr(uint index, ulong offset);

    /**
     * Return a set of ptrace commands to read the machine state from
     * a process or thread.
     */
    PtraceCommand[] ptraceReadCommands();

    /**
     * Return a set of ptrace commands to write the machine state back
     * to a process or thread.
     */
    PtraceCommand[] ptraceWriteCommands();

    /**
     * Set the values of all the general registers.
     */
    void setGRs(ubyte* regs);

    /**
     * Get the values of all the general registers.
     */
    void getGRs(ubyte* regs);

    /**
     * Set a general register by register number.
     */
    void setGR(uint gregno, ulong val);

    /**
     * Get a general register by register number.
     */
    ulong getGR(uint gregno);

    /**
     * Return the width in bytes of a general register
     */
    size_t grWidth(int greg);

    /**
     * Return the stack pointer register index.
     */
    uint spregno();

    /**
     * Return the number of general registers
     */
    size_t grCount();

    /**
     * Print a representation of the floating point state.
     */
    void dumpFloat();

    /**
     * Set the values of all the floating point registers.
     */
    void setFRs(ubyte* regs);

    /**
     * Get the values of all the floating point registers.
     */
    void getFRs(ubyte* regs);

    /**
     * Read raw register bytes in target byte order. Register index
     * corresponds to dwarf register number.
     */
    ubyte[] readRegister(uint regno, size_t bytes);

    /**
     * Write raw register bytes in target byte order. Register index
     * corresponds to dwarf register number.
     */
    void writeRegister(uint regno, ubyte[]);

    /**
     * Return a byte array containing a breakpoint instruction for
     * this architecture.
     */
    ubyte[] breakpoint();

    /**
     * Called after a thread hits a breakpoint to make any adjustments
     * to the machine state so that the PC is at the breakpoint
     * address.
     */
    void adjustPcAfterBreak();

    /**
     * Return the width of a pointer in bytes
     */
    uint pointerWidth();

    /**
     * Convert an integer in machine-native format to host format.
     */
    ulong readInteger(ubyte[] bytes);

    /**
     * Convert an integer in host format to machine-native format.
     */
    void writeInteger(ulong val, ubyte[] bytes);

    /**
     * Convert a floating point value in machine-native format to host format.
     */
    real readFloat(ubyte[] bytes);

    /**
     * Convert a floating point value in host format to machine-native format.
     */
    void writeFloat(real val, ubyte[] bytes);

    /**
     * Read from the machine's memory.
     */
    ubyte[] readMemory(ulong address, size_t bytes);

    /**
     * Write to the machine's memory.
     */
    void writeMemory(ulong address, ubyte[] toWrite);

    /**
     * Call a function in the target.
     */
    Value call(ulong address, Type returnType, Value[] args);

    /**
     * Scan the interval [start..end) and return the address of
     * any flow control instructions in the range. If there are none,
     * return end.
     */
    ulong findFlowControl(ulong start, ulong end);

    /**
     * Scan the interval [start..end) and return the target address of
     * the first unconditional jump in the range or end if there are none.
     */
    ulong findJump(ulong start, ulong end);

    /**
     * Disassemble the instruction at 'address' advancing the value of
     * 'address' to point at the next instruction in sequence. The
     * delegate 'lookupAddress' is used to translate machine addresses
     * to a symbolic equivalent.
     */
    string disassemble(ref ulong address,
		       string delegate(ulong) lookupAddress);

    /**
     * Make a copy of the machine state
     */
    MachineState dup();
}
