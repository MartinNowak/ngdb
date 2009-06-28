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

module objfile.debuginfo;
version(tangobos) import std.compat;

import machine.machine;

/**
 * This structure is used to represent line number information
 * extracted from the debug info.
 */
struct LineEntry
{
    ulong address;
    string name;		// leaf name
    string fullname;		// name including directory
    uint line;
    uint column;
    bool isStatement;
    bool basicBlock;
    bool endSequence;
    bool prologueEnd;
    bool epilogueBegin;
    int isa;
}

struct Location
{
    enum Type {
	Value,
	Address,
	Register
    }
    Type type;
    size_t length;
    union {
	/*
	 * A constant value or something made up as a composite of
	 * value pieces.
	 */
	ubyte[] value;

	/*
	 * A value located in target memory.
	 */
	ulong address;

	/*
	 * A value located in a target register
	 */
	uint register;
    }
}

/**
 * We use this interface to work with debug info for a particular
 * module.
 */
interface DebugInfo
{

    /**
     * Search for a source line by address. If found, two line entries
     * are returned, one before the address and the second after
     * it. Return true if any line enty matched.
     */
    bool findLineByAddress(ulong address, out LineEntry[] res);

    /**
     * Search for an address by source line. All entries which match
     * are returnbed in res (there could be many in the case of
     * templates or inline functions). Return true if any line entry
     * matched.
     */
    bool findLineByName(string file, int line, out LineEntry[] res);

    /**
     * Find the line entry that represents the first line of the given
     * function. All entries which match are returnbed in res (there
     * could be many in the case of templates or inline
     * functions). Return true if any line entry matched.
     */
    bool findLineByFunction(string func, out LineEntry[] res);

    /**
     * Find the stack frame base associated with the given machine state.
     */
    bool findFrameBase(MachineState state, out Location loc);
}
