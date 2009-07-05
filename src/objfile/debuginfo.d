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
    size_t byteWidth();
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

	uint byteWidth()
	{
	    return byteWidth_;
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
    uint byteWidth_;
}

class PointerType: Type
{
    this(string name, Type baseType, uint byteWidth)
    {
	name_ = name;
	baseType_ = baseType;
	byteWidth_ = byteWidth;
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
		string sv;
		try {
		    ubyte[] b;
		    char c;
		    sv = " \"";
		    do {
			b = state.readMemory(p++, 1);
			c = cast(char) b[0];
			if (c) {
			    if (isprint(c)) {
				sv ~= c;
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
				    sv ~= specials[c];
				else
				    sv ~= std.string.format("%02x", c);
			    }
			}
		    } while (c);
		    sv ~= "\"";
		} catch (Exception e) {
		    sv = "";
		}
		v ~= sv;
	    }
	    return v;
	}

	size_t byteWidth()
	{
	    return byteWidth_;
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
    uint byteWidth_;
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
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
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

class TypedefType: Type
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
	    return name_;
	}
	string valueToString(MachineState state, Location loc)
	{
	    return baseType_.valueToString(state, loc);
	}
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
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
    Type baseType_;
}

class CompoundType: Type
{
    this(string kind, string name, uint byteWidth)
    {
	kind_ = kind;
	name_ = name;
	byteWidth_ = byteWidth;
    }

    void addField(string name, Type type, Location loc)
    {
	fields_ ~= field(name, type, loc);
    }

    override
    {
	string toString()
	{
	    return kind_ ~ " " ~ name_;
	}
	string valueToString(MachineState state, Location loc)
	{
	    string v = "{ ";
	    bool first = true;

	    foreach (f; fields_) {
		if (!first) {
		    v ~= std.string.format(", ");
		}
		first = false;
		v ~= f.name ~ " = ";
		v ~= f.type.valueToString(state,
					  loc.fieldLocation(f.loc));
	    }
	    v ~= " }";
	    return v;
	}
	size_t byteWidth()
	{
	    return byteWidth_;
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

private:
    struct field {
	string name;
	Type type;
	Location loc;
    }

    string kind_;
    string name_;
    uint byteWidth_;
    field[] fields_;
}

class ArrayType: Type
{
    this(Type baseType)
    {
	baseType_ = baseType;
    }

    void addDim(size_t indexBase, size_t count)
    {
	dims_ ~= dim(indexBase, count);
    }

    override
    {
	string toString()
	{
	    string v = baseType_.toString;
	    foreach (d; dims_) {
		if (d.indexBase > 0)
		    v ~= std.string.format("[%d..%d]", d.indexBase,
					   d.indexBase + d.count - 1);
		else
		    v ~= std.string.format("[%d]", d.count);
	    }
	    return v;
	}
	string valueToString(MachineState state, Location loc)
	{
	    return toString;
	}
	size_t byteWidth()
	{
	    size_t n = 1;
	    foreach (d; dims_)
		n *= d.count;

	    return baseType_.byteWidth * n;
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

private:
    struct dim {
	size_t indexBase;
	size_t count;
    }

    Type baseType_;
    dim[] dims_;
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
	size_t byteWidth()
	{
	    return 1;
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
    ulong address(MachineState);
    Location fieldLocation(Location fieldLoc);
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

    string toString(MachineState state)
    {
	if (state)
	    return toString ~ " = " ~ valueToString(state);
	else
	    return toString;
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
     * Return an object describing the function matching the given
     * address.
     */
    Function findFunction(ulong pc);

    /**
     * Unwind the stack frame associated with a given machine state
     * and return the state for the calling frame or null if there is
     * no calling state.
     */
    MachineState unwind(MachineState state);
}
