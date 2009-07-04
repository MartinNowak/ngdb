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
import std.string;
import std.ctype;

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

interface Type
{
    string toString();
    string valueToString(MachineState, Location);
    bool isCharType();
    bool isStringType();
}

ulong
readInteger(ubyte[] bytes)
{
    // XXX endian
    uint bit = 0;
    ulong value = 0;

    foreach (b; bytes) {
	value |= b << bit;
	bit += 8;
    }
    return value;
}

class IntegerType: Type
{
    this(string name, bool isSigned, uint byteWidth)
    {
	name_ = name;
	isSigned_ = isSigned;
	byteWidth_ = byteWidth;
    }

    bool isSigned()
    {
	return isSigned_;
    }

    uint bitWidth()
    {
	return byteWidth_;
    }

    override
    {
	string toString()
	{
	    return name_;
	}

	string valueToString(MachineState state, Location loc)
	{
	    ubyte[] val = loc.readValue(state);
	    return .toString(readInteger(val));
	}
	bool isCharType()
	{
	    return byteWidth_ == 1;
	}
	bool isStringType()
	{
	    return false;
	}
    }

private:
    string name_;
    bool isSigned_;
    int byteWidth_;
}

class PointerType: Type
{
    this(string name, Type baseType)
    {
	name_ = name;
	baseType_ = baseType;
    }

    override
    {
	string toString()
	{
	    if (baseType_)
		return baseType_.toString ~ "*";
	    else
		return "void*";
	}
	string valueToString(MachineState state, Location loc)
	{
	    string v;
	    ulong p = readInteger(loc.readValue(state));
	    v = std.string.format("0x%x", p);
	    if (isStringType) {
		ubyte[] b;
		char c;
		v ~= " \"";
		do {
		    b = state.readMemory(p++, 1);
		    c = cast(char) b[0];
		    if (c) {
			if (isprint(c)) {
			    v ~= c;
			} else {
			    string specials[char] = [
				'\a': "\\a",
				'\b': "\\b",
				'\f': "\\f",
				'\n': "\\n",
				'\r': "\\r",
				'\t': "\\t",
				'\v': "\\v"];
			    if (c in specials)
				v ~= specials[c];
			    else
				v ~= std.string.format("%02x", c);
			}
		    }
		} while (c);
		v ~= "\"";
	    }
	    return v;
	}
	bool isCharType()
	{
	    return false;
	}
	bool isStringType()
	{
	    return baseType_.isCharType;
	}
    }

private:
    string name_;
    Type baseType_;
}

class ModifierType: Type
{
    this(string name, string modifier, Type baseType)
    {
	name_ = name;
	modifier_ = modifier;
	baseType_ = baseType;
    }

    override
    {
	string toString()
	{
	    return modifier_ ~ " " ~ baseType_.toString;
	}
	string valueToString(MachineState state, Location loc)
	{
	    return baseType_.valueToString(state, loc);
	}
	bool isCharType()
	{
	    return baseType_.isCharType;
	}
	bool isStringType()
	{
	    return baseType_.isStringType;
	}
    }

private:
    string name_;
    string modifier_;
    Type baseType_;
}

class VoidType: Type
{
    override
    {
	string toString()
	{
	    return "void";
	}
	string valueToString(MachineState, Location)
	{
	    return "void";
	}
	bool isCharType()
	{
	    return false;
	}
	bool isStringType()
	{
	    return false;
	}
    }
}

interface Location
{
    size_t length();
    ubyte[] readValue(MachineState);
    void writeValue(MachineState, ubyte[]);
    ulong address();
}

struct Value
{
    Location loc;
    Type type;

    string toString(MachineState state)
    {
	return type.valueToString(state, loc);
    }
}

struct Variable
{
    string name;
    Value value;

    string toString()
    {
	return value.type.toString ~ " " ~ name;
    }
    string valueToString(MachineState state)
    {
	return value.toString(state);
    }
}

class Function
{
    this(string name, Type returnType)
    {
	name_ = name;
	returnType_ = returnType;
    }

    void addArgument(Variable var)
    {
	arguments_ ~= var;
    }

    void addVariable(Variable var)
    {
	variables_ ~= var;
    }

    string name()
    {
	return name_;
    }

    Type returnType()
    {
	return returnType_;
    }

    Variable[] arguments()
    {
	return arguments_;
    }

    Variable[] variables()
    {
	return variables_;
    }

    string name_;
    Type returnType_;
    Variable[] arguments_;
    Variable[] variables_;
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

    /**
     * Return a list of arguments to the function matching the given
     * machine state.
     */
    Variable[] findArguments(MachineState state);

    /**
     * Return a list of variables accessible the the scope matching
     * the given machine state.
     */
    Variable[] findVariables(MachineState state);

    /**
     * Return an object describing the function matching the given
     * machine state.
     */
    Function findFunction(MachineState state);

    /**
     * Unwind the stack frame associated with a given machine state
     * and return the state for the calling frame or null if there is
     * no calling state.
     */
    MachineState unwind(MachineState state);
}
