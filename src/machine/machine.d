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
import target;
version(tangobos) import std.compat;

/**
 * A representation of the target machine. Registers are indexed by
 * dwarf register number.
 */
interface MachineState
{
    void dumpState();

    /**
     * Set a general register by register number.
     */
    void setGR(uint gregno, ulong val);

    /**
     * Set a general register by register name.
     */
    void setGR(string gregname, ulong val);

    /**
     * Get a general register by register number.
     */
    ulong getGR(uint gregno);

    /**
     * Get a general register by register name.
     */
    ulong getGR(string gregname);

    /**
     * Read raw register bytes in target byte order
     */
    ubyte[] readGR(uint gregno);

    /**
     * Write raw register bytes in target byte order
     */
    void writeGR(uint gregno, ubyte[]);

    /**
     * Return the width in bits of a general register
     */
    size_t grWidth(int greg);

    /**
     * Return the number of general registers
     */
    size_t grCount();

    /**
     * Return the register number for the program counter
     */
    int pcregno();

    /**
     * Read from the machine's memory.
     */
    ubyte[] readMemory(ulong address, size_t bytes);

    /**
     * Write to the machine's memory.
     */
    void writeMemory(ulong address, ubyte[] toWrite);

    /**
     * Make a copy of the machine state
     */
    MachineState dup();
}
