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
import objfile.debuginfo;
version(tangobos) import std.compat;

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
     * Return the thread pointer register.
     */
    ulong tp();

    /**
     * Set the thread pointer register.
     */
    void tp(ulong);

    /**
     * Return the address of the TLS object at the given module index
     * and offset.
     */
    ulong tls_get_addr(uint index, ulong offset);

    /**
     * Return the size of a structure which contains all the general
     * registers. Typically used with ptrace(PT_GETREGS);
     */
    size_t gregsSize();

    /**
     * Return a value which increments each time the general register
     * set changes.
     */
    uint grGen();

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
     * Read raw register bytes in target byte order
     */
    ubyte[] readGR(uint gregno);

    /**
     * Write raw register bytes in target byte order
     */
    void writeGR(uint gregno, ubyte[]);

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
     * Return the size of a structure which contains all the floating
     * point registers. Typically used with ptrace(PT_GETFPREGS);
     */
    size_t fpregsSize();

    /**
     * Ptrace command to get the floating point state
     */
    int ptraceGetFP();

    /**
     * Ptrace command to set the floating point state
     */
    int ptraceSetFP();

    /**
     * Return a value which increments each time the general register
     * set changes.
     */
    uint frGen();

    /**
     * Set the values of all the general registers.
     */
    void setFRs(ubyte* regs);

    /**
     * Get the values of all the general registers.
     */
    void getFRs(ubyte* regs);

    /**
     * Set a floating point register by register number.
     */
    void setFR(uint fpregno, real val);

    /**
     * Get a general register by register number.
     */
    real getFR(uint fpregno);

    /**
     * Read raw register bytes in target byte order
     */
    ubyte[] readFR(uint fpregno);

    /**
     * Write raw register bytes in target byte order
     */
    void writeFR(uint fpregno, ubyte[]);

    /**
     * Return the width in bytes of a general register
     */
    size_t frWidth(int fpregno);

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
     * Scan the interval [start..end) and return the address of
     * any flow control instructions in the range. If there are none,
     * return end.
     */
    ulong findFlowControl(ulong start, ulong end);

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
