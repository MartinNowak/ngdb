/*-
 * Copyright (c) 2009-2010 Doug Rabson
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

module debuginfo.debuginfo;

import std.string;
import std.c.stdlib;
import std.range;

import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import machine.machine;
import target.target;

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
    string toString();
    string toString(string, MachineState);
    Value toValue(MachineState);
}

interface Scope
{
    string[] contents(MachineState);
    DebugItem lookup(string, MachineState);
    Type lookupStruct(string );
    Type lookupUnion(string);
    Type lookupTypedef(string);
}

class UnionScope: Scope
{
    void addScope(Scope sc)
    {
	subScopes_ ~= sc;
    }

    override {
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (sc; subScopes_)
		res ~= sc.contents(state);
	    return res;
	}
	DebugItem lookup(string name, MachineState state)
	{
	    foreach (sc; subScopes_)
		if (auto item = sc.lookup(name, state))
                    return item;
	    return null;
	}
	Type lookupStruct(string name)
	{
	    foreach (sc; subScopes_)
		if (auto ty = sc.lookupStruct(name))
                    return ty;
	    return null;
	}
	Type lookupUnion(string name)
	{
	    foreach (sc; subScopes_)
		if (auto ty = sc.lookupUnion(name))
		    return ty;
	    return null;
	}
	Type lookupTypedef(string name)
	{
	    foreach (sc; subScopes_)
		if (auto ty = sc.lookupTypedef(name))
		    return ty;
	    return null;
	}
    }

private:
    Scope[] subScopes_;
}

interface Location
{
    /**
     * Return true if the location is valid for this machine state (e.g.
     * for dwarf loclists, the pc is within one of the ranged location
     * records).
     */
    bool valid(MachineState);

    /**
     * Size in bytes of the object
     */
    size_t length();

    /**
     * Resize an object
     */
    void length(size_t len);

    /**
     * Read the object value
     */
    ubyte[] readValue(MachineState);

    /**
     * Write the object value
     */
    void writeValue(MachineState, ubyte[]);

    /**
     * Return true if the object has a memory address
     */
    bool hasAddress(MachineState);

    /**
     * Return the memory address of the object
     */
    ulong address(MachineState);

    /**
     * Return true if the object is an l-value (i.e. implements writeValue).
     */
    bool isLval(MachineState);

    /**
     * Assuming this location represents the address of a field within
     * a compound type, return a location that can access that field
     * of the compound object located at base.
     */
    Location fieldLocation(Location base, MachineState state);

    /**
     * Return a location object which represents a subrange of this
     * location.
     */
    Location subrange(size_t start, size_t length, MachineState state);

    /**
     * Return a copy of this location.
     */
    Location dup();
}

class RegisterLocation: Location
{
    this(size_t regno, size_t length)
    {
	regno_ = regno;
	length_ = length;
    }

    override {
	bool valid(MachineState)
	{
	    return true;
	}

	size_t length()
	{
	    return length_;
	}

	void length(size_t length)
	{
	    length_ = length;
	}

	ubyte[] readValue(MachineState state)
	{
	    return state.readRegister(regno_, length);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    return state.writeRegister(regno_, value);
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return new SubrangeLocation(this, start, length);
	}

	Location dup()
	{
	    return new RegisterLocation(regno_, length_);
	}
    }

    size_t regno_;
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
	bool valid(MachineState)
	{
	    return true;
	}

	size_t length()
	{
	    return length_;
	}

	void length(size_t length)
	{
	    length_ = length;
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

	bool hasAddress(MachineState)
	{
	    return true;
	}

	ulong address(MachineState)
	{
	    return address_;
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    assert(length_ == 0 || start + length <= length_);
	    return new MemoryLocation(address_ + start, length);
	}

	Location dup()
	{
	    return new MemoryLocation(address_, length_);
	}
    }

    ulong address_;
    size_t length_;
}

class TLSLocation: Location
{
    this(uint index, ulong offset, size_t length)
    {
	index_ = index;
	offset = offset;
	length_ = length;
    }

    override {
	bool valid(MachineState state)
	{
	    return state.tls_get_addr(index_, 0) != 0;
	}

	size_t length()
	{
	    return length_;
	}

	void length(size_t length)
	{
	    length_ = length;
	}

	ubyte[] readValue(MachineState state)
	{
	    try {
		return state.readMemory(address(state), length_);
	    } catch (TargetException te) {
		return null;
	    }
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(value.length == length_);
	    try {
		return state.writeMemory(address(state), value);
	    } catch (TargetException te) {
	    }
	}

	bool hasAddress(MachineState)
	{
	    return true;
	}

	ulong address(MachineState state)
	{
	    return state.tls_get_addr(index_, offset_);
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    assert(start + length < length_);
	    return new TLSLocation(index_, offset_ + start, length);
	}

	Location dup()
	{
	    return new TLSLocation(index_, offset_, length_);
	}
    }

    uint index_;
    ulong offset_;
    size_t length_;
}

class CompositeLocation: Location
{
    void addPiece(Location loc, size_t len)
    {
	pieces_ ~= piece(loc, len);
    }

    override {
	bool valid(MachineState state)
	{
	    foreach (p; pieces_)
		if (!p.loc.valid(state))
		    return false;
	    return true;
	}

	size_t length()
	{
	    size_t len = 0;
	    foreach (p; pieces_)
		len += p.len;
	    return len;
	}

	void length(size_t length)
	{
	    assert(false);
	}

	ubyte[] readValue(MachineState state)
	{
	    ubyte[] v;
	    foreach (p; pieces_)
		v ~= p.loc.readValue(state)[0..p.len];
	    return v;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    size_t off = 0;
	    foreach (p; pieces_) {
		p.loc.writeValue(state, value[off..off+p.len]);
		off += p.len;
	    }
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return new SubrangeLocation(this, start, length);
	}

	Location dup()
	{
	    auto res = new CompositeLocation;
	    foreach (p; pieces_)
		res.addPiece(p.loc, p.len);
	    return res;
	}
    }
private:
    struct piece
    {
	Location loc;
	size_t len;
    }
    piece[] pieces_;
}

class NoLocation: Location
{
    override {
	bool valid(MachineState)
	{
	    return false;
	}

	size_t length()
	{
	    return 0;
	}

	void length(size_t length)
	{
	    assert(false);
	}

	ubyte[] readValue(MachineState state)
	{
	    return null;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(false);
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return null;
	}

	Location dup()
	{
	    return this;
	}
    }
}

/**
 * A field location that describes a field at the exact start of a compound.
 * Typically used for union field locations.
 */
class FirstFieldLocation: Location
{
    this(size_t length)
    {
	length_ = length;
    }

    override {
	bool valid(MachineState)
	{
	    return false;
	}

	size_t length()
	{
	    return length_;
	}

	void length(size_t length)
	{
	    assert(false);
	}

	ubyte[] readValue(MachineState state)
	{
	    assert(false);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(false);
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    if (baseLoc.length == length_) {
		return baseLoc;
	    } else {
		auto res = baseLoc.dup;
		res.length = length_;
		return res;
	    }
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return null;
	}

	Location dup()
	{
	    return this;
	}
    }

    size_t length_;
}

class ConstantLocation: Location
{
    this(ubyte[] value)
    {
	value_.length = value.length;
	value_[] = value[];
    }

    override {
	bool valid(MachineState)
	{
	    return true;
	}

	size_t length()
	{
	    return value_.length;
	}

	void length(size_t length)
	{
	    assert(false);
	}

	ubyte[] readValue(MachineState state)
	{
	    return value_;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(value.length == value_.length);
	    value_[] = value[];
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return new SubrangeLocation(this, start, length);
	}

	Location dup()
	{
	    return this;
	}
    }

    ubyte[] value_;
}

class SubrangeLocation: Location
{
    this(Location base, size_t start, size_t length)
    {
	base_ = base;
	start_ = start;
	length_ = length;
    }

    override {
	bool valid(MachineState state)
	{
	    return base_.valid(state);
	}

	size_t length()
	{
	    return length;
	}

	void length(size_t length)
	{
	    assert(false);
	}

	ubyte[] readValue(MachineState state)
	{
	    ubyte v[] = base_.readValue(state);
	    return v[start_..start_ + length_];
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    ubyte v[] = base_.readValue(state);
	    v[start_..start_ + length_] = value[];
	    base_.writeValue(state, v);
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return new SubrangeLocation(base_, start_ + start, length);
	}

	Location dup()
	{
	    return new SubrangeLocation(base_, start_, length_);
	}
    }

    Location base_;
    size_t start_;
    size_t length_;
}

class UserLocation: Location
{
    this()
    {
    }

    override {
	bool valid(MachineState)
	{
	    return true;
	}

	size_t length()
	{
	    return value_.length;
	}

	void length(size_t length)
	{
	    value_.length = length;
	}

	ubyte[] readValue(MachineState state)
	{
	    return value_;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    value_.length = value.length;
	    value_[] = value[];
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    return new SubrangeLocation(this, start, length);
	}

	Location dup()
	{
	    return this;
	}
    }

    ubyte[] value_;
}

class Value: DebugItem
{
    this(Location loc, Type type)
    {
	loc_ = loc;
	type_ = type;
    }

    Location loc()
    {
	return loc_;
    }

    Type type()
    {
	return type_;
    }

    Value dup(MachineState state)
    {
	ubyte[] v = loc_.readValue(state);
	return new Value(new ConstantLocation(v), type_);
    }

    override {
	string toString()
	{
	    return toString(null, null);
	}
	string toString(string fmt, MachineState state)
	{
	    if (!loc.valid(state))
		return "<invalid>";
	    try {
		return type.valueToString(fmt, state, loc);
	    } catch (TargetException te) {
		return "<invalid>";
	    }
	}
	Value toValue(MachineState)
	{
	    return this;
	}
    }

private:
    Location loc_;
    Type type_;
}

class Variable: DebugItem
{
    this(string name, Value value)
    {
	name_ = name;
	value_ = value;
    }

    string name()
    {
	return name_;
    }

    Value value()
    {
	return value_;
    }


    override {
	string toString()
	{
	    return value.type.toString ~ " " ~ name;
	}

	string toString(string fmt, MachineState state)
	{
	    if (state)
		return toString ~ " = " ~ valueToString(fmt, state);
	    else
		return toString;
	}

	Value toValue(MachineState)
	{
	    return value_;
	}
    }

    string valueToString(string fmt, MachineState state)
    {
	return value_.toString(fmt, state);
    }
private:
    string name_;
    Value value_;
}

struct AddressRange
{
    bool contains(ulong pc)
    {
	return pc >= start && pc < end;
    }

    ulong start;
    ulong end;
}

class LexicalScope: DebugItem, Scope
{
    this(Language lang, AddressRange[] addresses)
    {
	lang_ = lang;
	addresses_ = addresses;
    }

    override {
	string toString()
	{
	    return "";
	}
	string toString(string fmt, MachineState state)
	{
	    return "";
	}
	Value toValue(MachineState state)
	{
	    throw new EvalException("not a value");
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    res ~= sc.contents(state);
	    foreach (v; variables_)
		res ~= v.name;
	    return res;
	}
	DebugItem lookup(string name, MachineState state)
	{
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    if (auto val = sc.lookup(name, state))
			return val;
	    foreach (v; variables_) {
		if (name == v.name) {
		    return v;
		}
	    }
	    return null;
	}
	Type lookupStruct(string name) { return null; }
	Type lookupUnion(string name) { return null; }
	Type lookupTypedef(string name) { return null; }
    }

    void addVariable(Variable var)
    {
	variables_ ~= var;
    }

    void addScope(LexicalScope sc)
    {
	scopes_ ~= sc;
    }

    Variable[] variables()
    {
	return variables_;
    }

    bool contains(ulong pc)
    {
	foreach (a; addresses_)
	    if (a.contains(pc))
		return true;
	return false;
    }

    Language lang_;
    AddressRange[] addresses_;
    Variable[] variables_;
    LexicalScope[] scopes_;
}

class Function: DebugItem, Scope
{
    this(string name, Language lang, size_t byteWidth)
    {
	name_ = name;
	returnType_ = lang.voidType;
	containingType_ = null;
	lang_ = lang;
	address_ = 0;
	byteWidth_ = byteWidth;
    }

    override {
	string toString()
	{
	    return toString(null, null);
	}
	string toString(string fmt, MachineState state)
	{
	    string s;

	    if (containingType_)
		s ~= containingType_.toString ~ lang_.renderNamespaceSeparator;
	    s ~= std.string.format("%s (", name_);
	    bool first = true;
	    foreach (a; arguments_) {
		if (!first) {
		    s ~= std.string.format(", ");
		}
		first = false;
		if (state)
		    s ~= std.string.format("%s=%s",
					   a.name,
					   a.value.toString(fmt, state));
		else
		    s ~= std.string.format("%s", a.toString(fmt, state));
	    }
	    if (varargs_) {
		if (arguments_.length > 0)
		    s ~= ", ";
		s ~= "...";
	    }
	    s ~= ")";
	    return s;
	}
	Value toValue(MachineState state)
	{
	    FunctionType ft = new FunctionType(lang_);
	    ft.returnType(returnType_);
	    foreach (a; arguments_)
		ft.addArgumentType(a.value.type);
	    ft.varargs(varargs_);
	    return new Value(new MemoryLocation(address_, 0), ft);
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    res ~= sc.contents(state);
	    foreach (v; arguments_ ~ variables_)
		res ~= v.name;
	    if (compilationUnit_)
		res ~= compilationUnit_.contents(state);
	    return res;
	}
	DebugItem lookup(string name, MachineState state)
	{
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    if (auto val = sc.lookup(name, state))
			return val;
	    foreach (val; chain(arguments_, variables_))
		if (name == val.name)
		    return val;
	    if (compilationUnit_ !is null)
		return compilationUnit_.lookup(name, state);
	    return null;
	}
	Type lookupStruct(string name)
	{
	    return (compilationUnit_ is null) ? null : compilationUnit_.lookupStruct(name);
	}
	Type lookupUnion(string name)
	{
	    return (compilationUnit_ is null) ? null : compilationUnit_.lookupUnion(name);
	}
	Type lookupTypedef(string name)
	{
	    return (compilationUnit_ is null) ? null : compilationUnit_.lookupTypedef(name);
	}
    }

    void varargs(bool v)
    {
	varargs_ = v;
    }

    bool varargs()
    {
	return varargs_;
    }

    void isInline(bool v)
    {
	inline_ = v;
    }

    bool isInline()
    {
	return inline_;
    }

    void addArgument(Variable var)
    {
	arguments_ ~= var;
    }

    void addVariable(Variable var)
    {
	variables_ ~= var;
    }

    void addScope(LexicalScope sc)
    {
	scopes_ ~= sc;
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

    bool thisArgument(out Value val)
    {
	if (arguments_.length > 0 && arguments_[0].name == "this") {
	    val = arguments_[0].value;
	    return true;
	}
	return false;
    }

    Variable[] arguments()
    {
	return arguments_;
    }

    Variable[] variables()
    {
	return variables_;
    }

    ulong address()
    {
	return address_;
    }

    void address(ulong address)
    {
	address_ = address;
    }

    Scope compilationUnit()
    {
	return compilationUnit_;
    }

    void compilationUnit(Scope cu)
    {
	compilationUnit_ = cu;
    }

private:
    string name_;
    Language lang_;
    bool varargs_;
    bool inline_;
    Type returnType_;
    Type containingType_;
    Variable[] arguments_;
    Variable[] variables_;
    LexicalScope[] scopes_;
    Scope compilationUnit_;
    ulong address_;
    size_t byteWidth_;
}

/**
 * We use this interface to work with debug info for a particular
 * module.
 */
interface DebugInfo: Scope
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
     * Returh a list of all the source files referenced by this debug info.
     */
    string[] findSourceFiles();

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
