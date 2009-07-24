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
import std.stdio;

import objfile.language;
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

interface DebugItem
{
}

interface Type: DebugItem
{
    string toString(Language);
    string valueToString(string, Language, MachineState, Location);
    size_t byteWidth();
    bool isCharType();
    bool isIntegerType();
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
	string toString(Language)
	{
	    return name_;
	}

	string valueToString(string fmt, Language,
			     MachineState state, Location loc)
	{
	    ulong val = readInteger(loc.readValue(state));

	    if (fmt)
		fmt = "%#" ~ fmt;
	    else
		fmt = "%d";
	    return format(fmt, val);
	}

	uint byteWidth()
	{
	    return byteWidth_;
	}

	bool isCharType()
	{
	    return byteWidth_ == 1;
	}

	bool isIntegerType()
	{
	    return true;
	}
    }

private:
    string name_;
    bool isSigned_;
    uint byteWidth_;
}

class BooleanType: Type
{
    this(string name, uint byteWidth)
    {
	name_ = name;
	byteWidth_ = byteWidth;
    }

    override
    {
	string toString(Language)
	{
	    return name_;
	}

	string valueToString(string, Language, MachineState state, Location loc)
	{
	    ubyte[] val = loc.readValue(state);
	    return readInteger(val) ? "true" : "false";
	}

	uint byteWidth()
	{
	    return byteWidth_;
	}

	bool isCharType()
	{
	    return false;
	}

	bool isIntegerType()
	{
	    return true;
	}
    }

private:
    string name_;
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
	string toString(Language lang)
	{
	    if (baseType_)
		return lang.pointerType(baseType_.toString(lang));
	    else
		return lang.pointerType("void");
	}

	string valueToString(string, Language lang, MachineState state, Location loc)
	{
	    string v;
	    ulong p = readInteger(loc.readValue(state));
	    v = std.string.format("0x%x", p);
	    if (lang.isStringType(this))
		v ~= " " ~ lang.stringConstant(state, this, loc);
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

	bool isIntegerType()
	{
	    return false;
	}
    }

    Type baseType()
    {
	return baseType_;
    }

private:
    string name_;
    Type baseType_;
    uint byteWidth_;
}

class ReferenceType: Type
{
    this(string name, Type baseType, uint byteWidth)
    {
	name_ = name;
	baseType_ = baseType;
	byteWidth_ = byteWidth;
    }

    override
    {
	string toString(Language lang)
	{
	    if (baseType_)
		return lang.referenceType(baseType_.toString(lang));
	    else
		return lang.referenceType("void");
	}

	string valueToString(string, Language, MachineState state, Location loc)
	{
	    string v;
	    ulong p = readInteger(loc.readValue(state));
	    v = std.string.format("0x%x", p);
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

	bool isIntegerType()
	{
	    return false;
	}
    }

    Type baseType()
    {
	return baseType_;
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
	string toString(Language lang)
	{
	    return modifier_ ~ " " ~ baseType_.toString(lang);
	}
	string valueToString(string fmt, Language lang, MachineState state, Location loc)
	{
	    return baseType_.valueToString(fmt, lang, state, loc);
	}
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
	}
	bool isCharType()
	{
	    return baseType_.isCharType;
	}
	bool isIntegerType()
	{
	    return baseType_.isIntegerType;
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
	string toString(Language)
	{
	    return name_;
	}
	string valueToString(string fmt, Language lang, MachineState state, Location loc)
	{
	    return baseType_.valueToString(fmt, lang, state, loc);
	}
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
	}
	bool isCharType()
	{
	    return baseType_.isCharType;
	}
	bool isIntegerType()
	{
	    return baseType_.isIntegerType;
	}
    }

private:
    string name_;
    Type baseType_;
}

class CompoundType: Type
{
    struct field {
	string name;
	Type type;
	Location loc;
    }

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
	string toString(Language lang)
	{
	    return lang.structureType(name_);
	}
	string valueToString(string fmt, Language lang, MachineState state, Location loc)
	{
	    if (lang.isStringType(this))
		return lang.stringConstant(state, this, loc);

	    string v = "{ ";
	    bool first = true;

	    foreach (f; fields_) {
		if (!first) {
		    v ~= std.string.format(", ");
		}
		first = false;
		v ~= f.name ~ " = ";
		v ~= f.type.valueToString(fmt, lang, state,
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
	bool isIntegerType()
	{
	    return false;
	}
    }

    size_t length()
    {
	return fields_.length;
    }

    field opIndex(size_t i)
    {
	return fields_[i];
    }

private:
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
	string toString(Language lang)
	{
	    string v = baseType_.toString(lang);
	    foreach (d; dims_) {
		if (d.indexBase > 0)
		    v ~= std.string.format("[%d..%d]", d.indexBase,
					   d.indexBase + d.count - 1);
		else
		    v ~= std.string.format("[%d]", d.count);
	    }
	    return v;
	}
	string valueToString(string, Language lang, MachineState state, Location loc)
	{
	    return toString(lang);
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
	bool isIntegerType()
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
	string toString(Language)
	{
	    return "void";
	}
	string valueToString(string, Language, MachineState, Location)
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
	bool isIntegerType()
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

class RegisterLocation: Location
{
    this(uint regno, size_t length)
    {
	regno_ = regno;
	length_ = length;
    }

    override {
	size_t length()
	{
	    return length_;
	}

	ubyte[] readValue(MachineState state)
	{
	    return state.readGR(regno_);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    return state.writeGR(regno_, value);
	}

	ulong address(MachineState)
	{
	    assert(false);
	    return 0;
	}

	Location fieldLocation(Location fieldLoc)
	{
	    return null;
	}
    }

    uint regno_;
    size_t length_;
}

class MemoryLocation: Location
{
    this(ulong address, size_t length)
    {
	address_ = address;
	length_ = length;
    }

    override {
	size_t length()
	{
	    return length_;
	}

	ubyte[] readValue(MachineState state)
	{
	    return state.readMemory(address_, length_);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(value.length == length_);
	    return state.writeMemory(address_, value);
	}

	ulong address(MachineState)
	{
	    return address_;
	}

	Location fieldLocation(Location fieldLoc)
	{
	    return null;
	}
    }

    ulong address_;
    size_t length_;
}

struct Value
{
    Location loc;
    Type type;

    string toString(string fmt, Language lang, MachineState state)
    {
	return type.valueToString(fmt, lang, state, loc);
    }
}

struct Variable
{
    string name;
    Value value;

    string toString(Language lang)
    {
	return value.type.toString(lang) ~ " " ~ name;
    }

    string toString(string fmt, Language lang, MachineState state)
    {
	if (state)
	    return toString(lang) ~ " = " ~ valueToString(fmt, lang, state);
	else
	    return toString(lang);
    }

    string valueToString(string fmt, Language lang, MachineState state)
    {
	return value.toString(fmt, lang, state);
    }
}

interface Scope
{
    string[] contents();
    bool lookup(string, out Variable);
}

class Function: DebugItem, Scope
{
    this(string name)
    {
	name_ = name;
	returnType_ = new VoidType;
	containingType_ = null;
    }

    string toString(string fmt, Language lang, MachineState state)
    {
	string s;

	s = returnType_.toString(lang) ~ " ";
	if (containingType_)
	    s ~= containingType_.toString(lang) ~ lang.namespaceSeparator;
	s ~= std.string.format("%s(", name_);
	bool first = true;
	foreach (a; arguments_) {
	    if (!first) {
		s ~= std.string.format(", ");
	    }
	    first = false;
	    s ~= std.string.format("%s", a.toString(fmt, lang, state));
	}
	s ~= "): ";
	return s;
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

    void returnType(Type rt)
    {
	returnType_ = rt;
    }

    Type returnType()
    {
	return returnType_;
    }

    void containingType(Type ct)
    {
	containingType_ = ct;
    }

    Type containingType()
    {
	return containingType_;
    }

    Variable[] arguments()
    {
	return arguments_;
    }

    Variable[] variables()
    {
	return variables_;
    }

    override {
	string[] contents()
	{
	    string[] res;
	    foreach (v; arguments_ ~ variables_)
		res ~= v.name;
	    return res;
	}
	bool lookup(string name, out Variable var)
	{
	    foreach (v; arguments_ ~ variables_) {
		if (name == v.name) {
		    var = v;
		    return true;
		}
	    }
	    return false;
	}
    }

    string name_;
    Type returnType_;
    Type containingType_;
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
     * Return a Language object that matches the compilation unit
     * containing the given address.
     */
    Language findLanguage(ulong address);

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
