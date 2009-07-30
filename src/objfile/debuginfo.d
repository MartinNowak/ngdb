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
import std.conv;
import std.ctype;
import std.stdio;
import std.string;

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
    string toString();
    string toString(string, MachineState);
    Value toValue();
}

interface Type: DebugItem
{
    Language language();
    string toString();
    string valueToString(string, MachineState, Location);
    size_t byteWidth();
    Type underlyingType();
    Type pointerType(uint);
    bool isCharType();
    bool isIntegerType();
}

class TypeBase: Type
{
    this(Language lang)
    {
	lang_ = lang;
    }
    Language language()
    {
	return lang_;
    }
    string toString(string, MachineState)
    {
	return toString;
    }
    Value toValue()
    {
	throw new Exception(format("%s is not a value", toString));
    }
    abstract string toString();
    abstract string valueToString(string, MachineState, Location);
    abstract size_t byteWidth();
    Type underlyingType()
    {
	return this;
    }
    Type pointerType(uint width)
    {
	if (width in ptrTypes_)
	    return ptrTypes_[width];
	return (ptrTypes_[width] = new PointerType(lang_, this, width));
    }
    abstract bool isCharType();
    abstract bool isIntegerType();

private:
    Language lang_;
    Type[uint] ptrTypes_;
}

interface Scope
{
    string[] contents();
    bool lookup(string, out DebugItem);
}

class UnionScope: Scope
{
    void addScope(Scope sc)
    {
	subScopes_ ~= sc;
    }

    override {
	string[] contents()
	{
	    string[] res;
	    foreach (sc; subScopes_)
		res ~= sc.contents;
	    return res;
	}
	bool lookup(string name, out DebugItem val)
	{
	    foreach (sc; subScopes_) {
		if (sc.lookup(name, val))
		    return true;
	    }
	    return false;
	}
    }

private:
    Scope[] subScopes_;
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

void
writeInteger(ulong val, ubyte[] bytes)
{
    // XXX endian

    for (int i = 0; i < bytes.length; i++) {
	bytes[i] = val & 0xff;
	val >>= 8;
    }
}

class IntegerType: TypeBase
{
    this(Language lang, string name, bool isSigned, uint byteWidth)
    {
	super(lang);
	name_ = name;
	isSigned_ = isSigned;
	byteWidth_ = byteWidth;
    }

    bool isSigned()
    {
	return isSigned_;
    }

    override
    {
	string toString()
	{
	    return name_;
	}

	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (fmt)
		fmt = "%#" ~ fmt;
	    else
		fmt = "%d";

	    if (isSigned) {
		long val = readInteger(loc.readValue(state));
		switch (byteWidth_) {
		case 1:
		    return format(fmt, cast(byte) val);
		case 2:
		    return format(fmt, cast(short) val);
		case 4:
		    return format(fmt, cast(int) val);
		default:
		    return format(fmt, val);
		}
	    } else {
		ulong val = readInteger(loc.readValue(state));
		switch (byteWidth_) {
		case 1:
		    return format(fmt, cast(ubyte) val);
		case 2:
		    return format(fmt, cast(ushort) val);
		case 4:
		    return format(fmt, cast(uint) val);
		default:
		    return format(fmt, val);
		}
		return format(fmt, val);
	    }
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
    bool isSigned_;
    uint byteWidth_;
}

class CharType: IntegerType
{
    this(Language lang, string name, bool isSigned, uint byteWidth)
    {
	super(lang, name, isSigned, byteWidth);
    }

    override
    {
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (fmt)
		return super.valueToString(fmt, state, loc);

	    if (isSigned) {
		long val = readInteger(loc.readValue(state));
		return super.valueToString(fmt, state, loc)
		    ~ lang_.charConstant(val);
	    } else {
		ulong val = readInteger(loc.readValue(state));
		return super.valueToString(fmt, state, loc)
		    ~ lang_.charConstant(val);
	    }		
	}

	bool isCharType()
	{
	    return true;
	}
    }

private:
    string name_;
    bool isSigned_;
    uint byteWidth_;
}

class BooleanType: TypeBase
{
    this(Language lang, string name, uint byteWidth)
    {
	super(lang);
	name_ = name;
	byteWidth_ = byteWidth;
    }

    override
    {
	string toString()
	{
	    return name_;
	}

	string valueToString(string, MachineState state, Location loc)
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

class PointerType: TypeBase
{
    this(Language lang, Type baseType, uint byteWidth)
    {
	super(lang);
	baseType_ = baseType;
	byteWidth_ = byteWidth;
    }

    override
    {
	string toString()
	{
	    if (baseType_)
		return lang_.pointerType(baseType_.toString);
	    else
		return lang_.pointerType("void");
	}

	string valueToString(string, MachineState state, Location loc)
	{
	    string v;
	    ulong p = readInteger(loc.readValue(state));
	    v = std.string.format("0x%x", p);
	    if (lang_.isStringType(this) && p)
		v ~= " " ~ lang_.stringConstant(state, this, loc);
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

    Value dereference(MachineState state, Location loc)
    {
	return new Value(new MemoryLocation(
			 readInteger(loc.readValue(state)),
			 baseType.byteWidth),
		     baseType);
    }

private:
    Type baseType_;
    uint byteWidth_;
}

class ReferenceType: TypeBase
{
    this(Language lang, string name, Type baseType, uint byteWidth)
    {
	super(lang);
	name_ = name;
	baseType_ = baseType;
	byteWidth_ = byteWidth;
    }

    override
    {
	string toString()
	{
	    if (baseType_)
		return lang_.referenceType(baseType_.toString);
	    else
		return lang_.referenceType("void");
	}

	string valueToString(string, MachineState state, Location loc)
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

class ModifierType: TypeBase
{
    this(Language lang, string name, string modifier, Type baseType)
    {
	super(lang);
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
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    return baseType_.valueToString(fmt, state, loc);
	}
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
	}
	Type underlyingType()
	{
	    return baseType_.underlyingType;
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

class TypedefType: TypeBase
{
    this(Language lang, string name, Type baseType)
    {
	super(lang);
	name_ = name;
	baseType_ = baseType;
    }

    override
    {
	string toString()
	{
	    return name_;
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    return baseType_.valueToString(fmt, state, loc);
	}
	size_t byteWidth()
	{
	    return baseType_.byteWidth;
	}
	Type underlyingType()
	{
	    return baseType_.underlyingType;
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

class CompoundType: TypeBase
{
    struct field {
	string name;
	Type type;
	Location loc;
    }

    this(Language lang, string kind, string name, uint byteWidth)
    {
	super(lang);
	kind_ = kind;
	name_ = name;
	byteWidth_ = byteWidth;
    }

    void addField(Variable field)
    {
	if (field) fields_ ~= field;
    }

    void addFunction(Function func)
    {
	if (func) functions_ ~= func;
    }

    override
    {
	string toString()
	{
	    if (kind_ == "struct")
		return lang_.structureType(name_);
	    else
		return lang_.unionType(name_);
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    bool first = true;
	    string s;

	    foreach (f; fields_) {
		auto v = f.value;
		if (!first) {
		    s ~= std.string.format(", ");
		}
		first = false;
		s ~= f.name ~ " = ";
		s ~= v.type.valueToString(fmt, state,
					  v.loc.fieldLocation(loc, state));
	    }
	    return lang_.structConstant(s);
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

    Variable opIndex(size_t i)
    {
	return fields_[i];
    }

    Value fieldValue(string fieldName, Location loc, MachineState state)
    {
	foreach (f; fields_) {
	    if (f.name == fieldName) {
		auto v = f.value;
		return new Value(v.loc.fieldLocation(loc, state), v.type);
	    }
	}
	throw new Exception(format("Field %s not found", fieldName));
    }

private:
    string kind_;
    string name_;
    uint byteWidth_;
    Variable[] fields_;
    Function[] functions_;
}

class CompoundScope: Scope
{
    this(CompoundType type, Location base, MachineState state)
    {
	type_ = type;
	base_ = base;
	state_ = state;
    }
    string[] contents()
    {
	string[] res;
	foreach (f; type_.fields_)
	    res ~= f.name;
	return res;
    }
    bool lookup(string name, out DebugItem val)
    {
	foreach (f; type_.fields_) {
	    if (f.name == name) {
		Value v = f.value;
		val = new Value(v.loc.fieldLocation(base_, state_), v.type);
		return true;
	    }
	}
	return false;
    }
private:
    CompoundType type_;
    Location base_;
    MachineState state_;
}

class ArrayType: TypeBase
{
    this(Language lang, Type baseType)
    {
	super(lang);
	baseType_ = baseType;
    }

    Type baseType()
    {
	return baseType_;
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
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (!loc.hasAddress(state))
		return lang_.arrayConstant("");
	    ulong addr = loc.address(state);
	    return valueToString(fmt, state, addr, 0);
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
    string valueToString(string fmt, MachineState state, ref ulong addr,
			 size_t di)
    {
	string v;
	for (size_t i = 0; i < dims_[di].count; i++) {
	    if (i > 0 && i <= 3)
		v ~= ", ";
	    if (i == 3)
		v ~= "...";
	    string elem;
	    if (di == dims_.length - 1) {
		elem = baseType_.valueToString(fmt, state,
			new MemoryLocation(addr, baseType_.byteWidth));
		addr += baseType_.byteWidth;
	    } else {
		elem = valueToString(fmt, state, addr, di + 1);
	    }
	    if (i < 3)
		v ~= elem;
	}
	return lang_.arrayConstant(v);
    }
    struct dim {
	size_t indexBase;
	size_t count;
    }

    Type baseType_;
    dim[] dims_;
}

class DArrayType: TypeBase
{
    this(Language lang, Type baseType, size_t byteWidth)
    {
	super(lang);
	baseType_ = baseType;
	byteWidth_ = byteWidth;
    }

    Type baseType()
    {
	return baseType_;
    }

    override
    {
	string toString()
	{
	    return baseType_.toString ~ "[]";
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (lang_.isStringType(this))
		return lang_.stringConstant(state, this, loc);

	    ubyte[] val = loc.readValue(state);
	    ulong len = readInteger(val[0..state.pointerWidth]);
	    ulong addr = readInteger(val[state.pointerWidth..$]);
	    string v;
	    for (auto i = 0; i < len; i++) {
		if (i > 0)
		    v ~= ", ";
		v ~= baseType_.valueToString(fmt, state,
			new MemoryLocation(addr, baseType_.byteWidth));
		addr += baseType_.byteWidth;
	    }
	    return lang_.arrayConstant(v);
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

private:
    Type baseType_;
    size_t byteWidth_;
}

class FunctionType: TypeBase
{
    this(Language lang)
    {
	super(lang);
    }

    Type returnType()
    {
	return returnType_;
    }

    void returnType(Type returnType)
    {
	returnType_ = returnType;
    }

    void addArgumentType(Type at)
    {
	argumentTypes_ ~= at;
    }

    void varargs(bool v)
    {
	varargs_ = v;
    }

    bool varargs()
    {
	return varargs_;
    }

    override
    {
	string toString()
	{
	    string s;

	    if (returnType_)
		s = returnType_.toString;
	    else
		s = "void";
	    s ~= " (";
	    foreach (i, at; argumentTypes_) {
		if (i > 0)
		    s ~= ", ";
		s ~= at.toString;
	    }
	    if (varargs_) {
		if (argumentTypes_.length > 0)
		    s ~= ", ";
		s ~= "...";
	    }
	    s ~= ")";

	    return s;
	}
	string valueToString(string, MachineState, Location)
	{
	    return "{}";
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
private:
    Type returnType_;
    Type[] argumentTypes_;
    bool varargs_;
}

class VoidType: TypeBase
{
    this(Language lang)
    {
	super(lang);
    }
    override
    {
	string toString()
	{
	    return "void";
	}
	string valueToString(string, MachineState, Location)
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
     * Assuming this location represents the address of a field within
     * a compound type, return a location that can access that field
     * of the compound object located at base.
     */
    Location fieldLocation(Location base, MachineState state);
}

class RegisterLocation: Location
{
    this(uint regno, size_t length)
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

	ubyte[] readValue(MachineState state)
	{
	    return state.readGR(regno_);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    return state.writeGR(regno_, value);
	}

	bool hasAddress(MachineState)
	{
	    return false;
	}

	ulong address(MachineState)
	{
	    assert(false);
	    return 0;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
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
	bool valid(MachineState)
	{
	    return true;
	}

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

	bool hasAddress(MachineState)
	{
	    return true;
	}

	ulong address(MachineState)
	{
	    return address_;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}
    }

    ulong address_;
    size_t length_;
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

	ubyte[] readValue(MachineState state)
	{
	    assert(false);
	    return null;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(false);
	}

	bool hasAddress(MachineState)
	{
	    return true;
	}

	ulong address(MachineState)
	{
	    assert(false);
	    return 0;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
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

	ubyte[] readValue(MachineState state)
	{
	    assert(false);
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
	    return 0;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return baseLoc;
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
	    return 0;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}
    }

    ubyte[] value_;
}

interface Expr
{
    Language language();
    string toString();
    DebugItem eval(Scope sc, MachineState state);
}

class ExprBase: Expr
{
    this(Language lang)
    {
	lang_ = lang;
    }
    Language language()
    {
	return lang_;
    }
    abstract string toString();
    abstract DebugItem eval(Scope sc, MachineState state);
    Language lang_;
}

class VariableExpr: ExprBase
{
    this(Language lang, string name)
    {
	super(lang);
	name_ = name;
    }

    override {
	string toString()
	{
	    return name_;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    DebugItem val;
	    if (sc.lookup(name_, val))
		return val;
	    throw new Exception(format("Variable %s not found", name_));
	}
    }
private:
    string name_;
}

class NumericExpr: ExprBase
{
    this(Language lang, string num)
    {
	super(lang);
	if (num[$-1] == 'U' || num[$-1] == 'u') {
	    unum_ = toUlong(num[0..$-1]);
	    isSigned_ = false;
	} else {
	    num_ = toLong(num);
	    isSigned_ = true;
	}
    }
    override {
	string toString()
	{
	    return std.string.toString(num_);
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    ubyte val[4];
	    long n = num_;
	    
	    Type ty;
	    if (isSigned_) {
		writeInteger(num_, val);
		ty = new IntegerType(lang_, "int", true, 4);
	    } else {
		writeInteger(unum_, val);
		ty = new IntegerType(lang_, "uint", false, 4);
	    }
	    return new Value(new ConstantLocation(val), ty);
	}
    }
private:
    bool isSigned_;
    union {
	ulong unum_;
	long num_;
    }
}

class UnaryExpr: ExprBase
{
    this(Language lang, Expr e)
    {
	super(lang);
	expr_ = e;
    }
    abstract string toString();
    abstract DebugItem eval(Scope sc, MachineState state);
private:
    Expr expr_;
}

class AddressOfExpr: UnaryExpr
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }

    override {
	string toString()
	{
	    return "&" ~ expr_.toString();
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue;
	    if (expr.loc.hasAddress(state)) {
		ulong addr = expr.loc.address(state);
		ubyte[] val;
		val.length = state.pointerWidth;
		writeInteger(addr, val);
		return new Value(new ConstantLocation(val),
			     expr.type.pointerType(state.pointerWidth));
	    } else {
		throw new Exception("Can't take the address of a value which is not in memory");
	    }
	}
    }
}

class DereferenceExpr: UnaryExpr
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }

    override {
	string toString()
	{
	    return "*" ~ expr_.toString();
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue;
	    PointerType ptrTy = cast(PointerType) expr.type.underlyingType;
	    if (!ptrTy)
		throw new Exception("Attempting to dereference a non-pointer");
	    return ptrTy.dereference(state, expr.loc);
	}
    }
}

template IntegerUnaryExpr(string op, string name)
{
    class IntegerUnaryExpr: UnaryExpr
    {
	this(Language lang, Expr e)
	{
	    super(lang, e);
	}

	override {
	    string toString()
	    {
		return op ~ expr_.toString;
	    }
	    DebugItem eval(Scope sc, MachineState state)
	    {
		Value expr = expr_.eval(sc, state).toValue;
		if (!expr.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       expr.type.toString));
		ubyte[] v = expr.loc.readValue(state);
		ulong val = readInteger(v);
		mixin("val = " ~ op ~ "val;");
		writeInteger(val, v);
		return new Value(new ConstantLocation(v), expr.type);
	    }
	}
    }
}

class NegateExpr: IntegerUnaryExpr!("-", "negate")
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }
}

class LogicalNegateExpr: IntegerUnaryExpr!("!", "logically negate")
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }
    override {
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue;
	    PointerType ptrTy = cast(PointerType) expr.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);
	    ulong ptr = readInteger(expr.loc.readValue(state));
	    Type ty = new IntegerType(lang_, "int", true, 4);
	    ubyte v[4];
	    writeInteger(ptr ? 0 : 1, v);
	    return new Value(new ConstantLocation(v), ty);
	}
    }
}

class ComplementExpr: IntegerUnaryExpr!("~", "complement")
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }
}

class PreIncrementExpr: UnaryExpr
{
    this(Language lang, string op, Expr e)
    {
	super(lang, e);
	op_ = op;
    }
    override {
	string toString()
	{
	    return op_ ~ expr_.toString;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    return new Value(null, new VoidType(lang_));
	}
    }
    string op_;
}

class PostIncrementExpr: UnaryExpr
{
    this(Language lang, string op, Expr e)
    {
	super(lang, e);
	op_ = op;
    }
    override {
	string toString()
	{
	    return expr_.toString() ~ op_;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    return new Value(null, new VoidType(lang_));
	}
    }
    string op_;
}

class BinopExpr: ExprBase
{
    this(Language lang, string op, Expr l, Expr r)
    {
	super(lang);
	op_ = op;
	left_ = l;
	right_ = r;
    }
    override {
	string toString()
	{
	    return left_.toString ~ " " ~ op_ ~ " " ~ right_.toString;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    return new Value(null, new VoidType(lang_)); // XXX
	}
    }
private:
    string op_;
    Expr left_;
    Expr right_;
}

class AssignExpr: BinopExpr
{
    this(Language lang, string op, Expr l, Expr r)
    {
	super(lang, op, l, r);
    }
}

class BinaryExpr: ExprBase
{
    this(Language lang, Expr l, Expr r)
    {
	super(lang);
	left_ = l;
	right_ = r;
    }
    abstract string toString();
    abstract DebugItem eval(Scope sc, MachineState state);
private:
    Expr left_;
    Expr right_;
}

template IntegerBinaryExpr(string op, string name)
{
    class IntegerBinaryExpr: BinaryExpr
    {
	this(Language lang, Expr l, Expr r)
	{
	    super(lang, l, r);
	}

	override {
	    string toString()
	    {
		return left_.toString ~ " " ~ op ~ " " ~ right_.toString;
	    }
	    DebugItem eval(Scope sc, MachineState state)
	    {
		Value left = left_.eval(sc, state).toValue;
		if (!left.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       left.type.toString));
		ulong lval = readInteger(left.loc.readValue(state));

		Value right = right_.eval(sc, state).toValue;
		if (!right.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       right.type.toString));
		ulong rval = readInteger(right.loc.readValue(state));
		
		static if (op == "/" || op == "%") {
		    if (!rval)
			throw new Exception("Divide or remainder with zero");
		}
		
		mixin("lval = lval " ~ op ~ "rval;");
		ubyte[] v;
		v.length = left.loc.length;
		writeInteger(lval, v);
		return new Value(new ConstantLocation(v), left.type);
	    }
	}
    }
}

class CommaExpr: BinaryExpr
{
    this(Language lang, Expr l, Expr r)
    {
	super(lang, l, r);
    }
    override {
	string toString()
	{
	    return left_.toString ~ ", " ~ right_.toString;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value left = left_.eval(sc, state).toValue;
	    Value right = right_.eval(sc, state).toValue;
	    return right;
	}
    }
}

class AddExpr: IntegerBinaryExpr!("+", "add")
{
    this(Language lang, Expr l, Expr r)
    {
	super(lang, l, r);
    }
    override {
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value left = left_.eval(sc, state).toValue;
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);

	    Value right = right_.eval(sc, state).toValue;
	    if (!right.type.isIntegerType)
		throw new Exception("Pointer arithmetic with non-integer");

	    ulong ptr = readInteger(left.loc.readValue(state));
	    ulong off = readInteger(right.loc.readValue(state));
	    ptr += off * ptrTy.baseType.byteWidth;
	    ubyte[] val;
	    val.length = ptrTy.byteWidth;
	    writeInteger(ptr, val);
	    return new Value(new ConstantLocation(val), ptrTy);
	}
    }
}

class SubtractExpr: IntegerBinaryExpr!("-", "add")
{
    this(Language lang, Expr l, Expr r)
    {
	super(lang, l, r);
    }
    override {
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value left = left_.eval(sc, state).toValue;
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);

	    Value right = right_.eval(sc, state).toValue;
	    PointerType rptrTy = cast(PointerType) right.type.underlyingType;
	    if (!rptrTy && !right.type.isIntegerType)
		throw new Exception("Pointer arithmetic with non-integer or non-pointer");
	    if (rptrTy && rptrTy != ptrTy)
		throw new Exception("Pointer arithmetic with differing pointer types");

	    ulong lval = readInteger(left.loc.readValue(state));
	    ulong rval  = readInteger(right.loc.readValue(state));
	    if (rptrTy) {
		ulong diff = (lval - rval) / ptrTy.baseType.byteWidth;
		ubyte[] val;
		val.length = ptrTy.byteWidth;
		writeInteger(diff, val);
		return new Value(new ConstantLocation(val),
			     new IntegerType(lang_, "int", true, ptrTy.byteWidth));
	    } else {
		ulong ptr = lval - rval * ptrTy.baseType.byteWidth;
		ubyte[] val;
		val.length = ptrTy.byteWidth;
		writeInteger(ptr, val);
		return new Value(new ConstantLocation(val), ptrTy);
	    }
	}
    }
}

class IndexExpr: ExprBase
{
    this(Language lang, Expr base, Expr index)
    {
	super(lang);
	base_ = base;
	index_ = index;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "[" ~ index_.toString ~ "]";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value base = base_.eval(sc, state).toValue;

	    ArrayType aTy = cast(ArrayType) base.type.underlyingType;
	    DArrayType daTy = cast(DArrayType) base.type.underlyingType;
	    PointerType ptrTy = cast(PointerType) base.type.underlyingType;
	    Type elementType;
	    Location baseLoc;
	    ulong minIndex, maxIndex;
	    if (aTy) {
		baseLoc = base.loc;
		minIndex = aTy.dims_[0].indexBase;
		maxIndex = minIndex + aTy.dims_[0].count;
		if (aTy.dims_.length == 1) {
		    elementType = aTy.baseType;
		} else {
		    ArrayType subTy = new ArrayType(lang_, aTy.baseType);
		    subTy.dims_ = aTy.dims_[1..$];
		    elementType = subTy;
		}
	    } else if (daTy) {
		/*
		 * The memory representation of dynamic arrays is two
		 * pointer sized values, the first being the array length
		 * and the second the base pointer.
		 */
		elementType = daTy.baseType;
		ubyte[] val = base.loc.readValue(state);
		minIndex = 0;
		maxIndex = readInteger(val[0..state.pointerWidth]);
		ulong addr = readInteger(val[state.pointerWidth..$]);
		baseLoc = new MemoryLocation(addr, 0);
	    } else if (ptrTy) {
		elementType = ptrTy.baseType;
		/*
		 * Dereference the pointer to get the array base
		 */
		ulong addr = readInteger(base.loc.readValue(state));
		minIndex = 0;
		maxIndex = ~0;
		baseLoc = new MemoryLocation(addr, 0);
	    } else {
		throw new Exception("Expected array or pointer for index expression");
	    }

	    Value index = index_.eval(sc, state).toValue;
	    IntegerType intTy = cast(IntegerType) index.type.underlyingType;
	    if (!index.type.isIntegerType) {
		throw new Exception("Expected integer for index expression");
	    }
	    long i = readInteger(index.loc.readValue(state));
	    if (i < minIndex || i >= maxIndex)
		throw new Exception(format("Index %d out of array bounds", i));
	    i -= minIndex;

	    auto elementLoc = new MemoryLocation(
		baseLoc.address(state)
		+ i * elementType.byteWidth, 
		elementType.byteWidth);

	    return new Value(elementLoc, elementType);
	}
    }
private:
    Expr base_;
    Expr index_;
}

class MemberExpr: ExprBase
{
    this(Language lang, Expr base, string member)
    {
	super(lang);
	base_ = base;
	member_ = member;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "." ~ member_;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value base = base_.eval(sc, state).toValue;
	    CompoundType cTy = cast(CompoundType) base.type.underlyingType;
	    if (!cTy)
		throw new Exception("Not a compound type");
	    return cTy.fieldValue(member_, base.loc, state);
	}
    }
private:
    Language lang_;
    Expr base_;
    string member_;
}

class PointsToExpr: ExprBase
{
    this(Language lang, Expr base, string member)
    {
	super(lang);
	base_ = base;
	member_ = member;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "->" ~ member_;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value base = base_.eval(sc, state).toValue;
	    PointerType ptrTy = cast(PointerType) base.type.underlyingType;
	    if (!ptrTy)
		throw new Exception("Not a pointer");

	    CompoundType cTy = cast(CompoundType) ptrTy.baseType.underlyingType;
	    if (!cTy)
		throw new Exception("Not a pointer to a compound type");
	    ulong ptr = readInteger(base.loc.readValue(state));
	    return cTy.fieldValue(member_,
				  new MemoryLocation(ptr, cTy.byteWidth),
				  state);
	}
    }
private:
    Expr base_;
    string member_;
}

class IfElseExpr: ExprBase
{
    this(Language lang, Expr cond, Expr trueExp, Expr falseExp)
    {
	super(lang);
	cond_ = cond;
	trueExp_ = trueExp;
	falseExp_ = falseExp;
    }
    override {
	string toString()
	{
	    return cond_.toString ~ " ? " ~ trueExp_.toString
		~ " : " ~ falseExp_.toString;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value cond = cond_.eval(sc, state).toValue;
	    if (!cond.type.isIntegerType)
		throw new Exception("Condition value is not an integer");
	    if (readInteger(cond.loc.readValue(state)))
		return trueExp_.eval(sc, state);
	    else
		return falseExp_.eval(sc, state);
	}
    }
private:
    Expr cond_;
    Expr trueExp_;
    Expr falseExp_;
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

    override {
	string toString()
	{
	    return toString(null, null);
	}
	string toString(string fmt, MachineState state)
	{
	    if (!loc.valid(state))
		return "<invalid>";
	    return type.valueToString(fmt, state, loc);
	}
	Value toValue()
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

	Value toValue()
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

class Function: DebugItem, Scope
{
    this(string name, Language lang)
    {
	name_ = name;
	returnType_ = new VoidType(lang);
	containingType_ = null;
	lang_ = lang;
	address_ = 0;
    }

    override {
	string toString()
	{
	    return toString(null, null);
	}
	string toString(string fmt, MachineState state)
	{
	    string s;

	    s = returnType_.toString ~ " ";
	    if (containingType_)
		s ~= containingType_.toString ~ lang_.namespaceSeparator;
	    s ~= std.string.format("%s(", name_);
	    bool first = true;
	    foreach (a; arguments_) {
		if (!first) {
		    s ~= std.string.format(", ");
		}
		first = false;
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
	Value toValue()
	{
	    FunctionType ft = new FunctionType(lang_);
	    ft.returnType(returnType_);
	    foreach (a; arguments_)
		ft.addArgumentType(a.value.type);
	    ft.varargs(varargs_);
	    Type pt = ft.pointerType(4);

	    ubyte[4] ptrVal;	// XXX pointerWidth
	    writeInteger(address_, ptrVal);
	    return new Value(new ConstantLocation(ptrVal), pt);
	}
	string[] contents()
	{
	    string[] res;
	    foreach (v; arguments_ ~ variables_)
		res ~= v.name;
	    return res;
	}
	bool lookup(string name, out DebugItem val)
	{
	    foreach (v; arguments_ ~ variables_) {
		if (name == v.name) {
		    val = v.value;
		    return true;
		}
	    }
	    return false;
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

    string name_;
    Language lang_;
    bool varargs_;
    Type returnType_;
    Type containingType_;
    Variable[] arguments_;
    Variable[] variables_;
    ulong address_;
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
