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
}

interface Type: DebugItem
{
    string toString(Language);
    string valueToString(string, Language, MachineState, Location);
    size_t byteWidth();
    Type underlyingType();
    Type pointerType(uint);
    bool isCharType();
    bool isIntegerType();
}

class TypeBase: Type
{
    abstract string toString(Language);
    abstract string valueToString(string, Language, MachineState, Location);
    abstract size_t byteWidth();
    Type underlyingType()
    {
	return this;
    }
    Type pointerType(uint width)
    {
	if (width in ptrTypes_)
	    return ptrTypes_[width];
	return (ptrTypes_[width] = new PointerType(this, width));
    }
    abstract bool isCharType();
    abstract bool isIntegerType();

private:
    Type[uint] ptrTypes_;
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

    override
    {
	string toString(Language)
	{
	    return name_;
	}

	string valueToString(string fmt, Language,
			     MachineState state, Location loc)
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
    this(string name, bool isSigned, uint byteWidth)
    {
	super(name, isSigned, byteWidth);
    }

    override
    {
	string valueToString(string fmt, Language lang,
			     MachineState state, Location loc)
	{
	    if (fmt)
		return super.valueToString(fmt, lang, state, loc);

	    if (isSigned) {
		long val = readInteger(loc.readValue(state));
		return super.valueToString(fmt, lang, state, loc)
		    ~ lang.charConstant(val);
	    } else {
		ulong val = readInteger(loc.readValue(state));
		return super.valueToString(fmt, lang, state, loc)
		    ~ lang.charConstant(val);
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

class PointerType: TypeBase
{
    this(Type baseType, uint byteWidth)
    {
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

    Value dereference(MachineState state, Location loc)
    {
	return Value(new MemoryLocation(
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

class ModifierType: TypeBase
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
	    if (kind_ == "struct")
		return lang.structureType(name_);
	    else
		return lang.unionType(name_);
	}
	string valueToString(string fmt, Language lang, MachineState state, Location loc)
	{
	    bool first = true;
	    string v;

	    foreach (f; fields_) {
		if (!first) {
		    v ~= std.string.format(", ");
		}
		first = false;
		v ~= f.name ~ " = ";
		v ~= f.type.valueToString(fmt, lang, state,
					  f.loc.fieldLocation(loc, state));
	    }
	    return lang.structConstant(v);
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

    Value fieldValue(string fieldName, Location loc, MachineState state)
    {
	foreach (f; fields_) {
	    if (f.name == fieldName)
		return Value(f.loc.fieldLocation(loc, state), f.type);
	}
	throw new Exception(format("Field %s not found", fieldName));
    }

private:
    string kind_;
    string name_;
    uint byteWidth_;
    field[] fields_;
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
    bool lookup(string name, out Variable var)
    {
	foreach (f; type_.fields_) {
	    if (f.name == name) {
		var.name = name;
		var.value = Value(f.loc.fieldLocation(base_, state_), f.type);
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
    this(Type baseType)
    {
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
	string valueToString(string fmt, Language lang,
			     MachineState state, Location loc)
	{
	    if (!loc.hasAddress(state))
		return lang.arrayConstant("");
	    ulong addr = loc.address(state);
	    return valueToString(fmt, lang, state, addr, 0);
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
    string valueToString(string fmt, Language lang,
			 MachineState state, ref ulong addr, size_t di)
    {
	string v;
	for (size_t i = 0; i < dims_[di].count; i++) {
	    if (i > 0 && i <= 3)
		v ~= ", ";
	    if (i == 3)
		v ~= "...";
	    string elem;
	    if (di == dims_.length - 1) {
		elem = baseType_.valueToString(fmt, lang, state,
			new MemoryLocation(addr, baseType_.byteWidth));
		addr += baseType_.byteWidth;
	    } else {
		elem = valueToString(fmt, lang, state, addr, di + 1);
	    }
	    if (i < 3)
		v ~= elem;
	}
	return lang.arrayConstant(v);
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
    this(Type baseType, size_t byteWidth)
    {
	baseType_ = baseType;
	byteWidth_ = byteWidth;
    }

    Type baseType()
    {
	return baseType_;
    }

    override
    {
	string toString(Language lang)
	{
	    return baseType_.toString(lang) ~ "[]";
	}
	string valueToString(string fmt, Language lang,
			     MachineState state, Location loc)
	{
	    if (lang.isStringType(this))
		return lang.stringConstant(state, this, loc);

	    ubyte[] val = loc.readValue(state);
	    ulong len = readInteger(val[0..state.pointerWidth]);
	    ulong addr = readInteger(val[state.pointerWidth..$]);
	    string v;
	    for (auto i = 0; i < len; i++) {
		if (i > 0)
		    v ~= ", ";
		v ~= baseType_.valueToString(fmt, lang, state,
			new MemoryLocation(addr, baseType_.byteWidth));
		addr += baseType_.byteWidth;
	    }
	    return lang.arrayConstant(v);
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

class VoidType: TypeBase
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
    string toString();
    Value eval(Language lang, Scope sc, MachineState state);
}

class VariableExpr: Expr
{
    this(string name)
    {
	name_ = name;
    }
    override {
	string toString()
	{
	    return name_;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Variable var;
	    if (sc.lookup(name_, var))
		return var.value;
	    throw new Exception(format("Variable %s not found", name_));
	}
    }
private:
    string name_;
}

class NumericExpr: Expr
{
    this(string num)
    {
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
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    ubyte val[4];
	    long n = num_;

	    
	    Type ty;
	    if (isSigned_) {
		writeInteger(num_, val);
		ty = new IntegerType("int", true, 4);
	    } else {
		writeInteger(unum_, val);
		ty = new IntegerType("uint", false, 4);
	    }
	    return Value(new ConstantLocation(val), ty);
	}
    }
private:
    bool isSigned_;
    union {
	ulong unum_;
	long num_;
    }
}

class UnaryExpr: Expr
{
    this(Expr e)
    {
	expr_ = e;
    }
    abstract string toString();
    abstract Value eval(Language lang, Scope sc, MachineState state);
private:
    Expr expr_;
}

class AddressOfExpr: UnaryExpr
{
    this(Expr e)
    {
	super(e);
    }

    override {
	string toString()
	{
	    return "&" ~ expr_.toString();
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(lang, sc, state);
	    if (expr.loc.hasAddress(state)) {
		ulong addr = expr.loc.address(state);
		ubyte[] val;
		val.length = state.pointerWidth;
		writeInteger(addr, val);
		return Value(new ConstantLocation(val),
			     expr.type.pointerType(state.pointerWidth));
	    } else {
		throw new Exception("Can't take the address of a value which is not in memory");
	    }
	}
    }
}

class DereferenceExpr: UnaryExpr
{
    this(Expr e)
    {
	super(e);
    }

    override {
	string toString()
	{
	    return "*" ~ expr_.toString();
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(lang, sc, state);
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
	this(Expr e)
	{
	    super(e);
	}

	override {
	    string toString()
	    {
		return op ~ expr_.toString();
	    }
	    Value eval(Language lang, Scope sc, MachineState state)
	    {
		Value expr = expr_.eval(lang, sc, state);
		if (!expr.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       expr.type.toString(lang)));
		ubyte[] v = expr.loc.readValue(state);
		ulong val = readInteger(v);
		mixin("val = " ~ op ~ "val;");
		writeInteger(val, v);
		return Value(new ConstantLocation(v), expr.type);
	    }
	}
    }
}

class NegateExpr: IntegerUnaryExpr!("-", "negate")
{
    this(Expr e)
    {
	super(e);
    }
}

class LogicalNegateExpr: IntegerUnaryExpr!("!", "logically negate")
{
    this(Expr e)
    {
	super(e);
    }
    override {
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(lang, sc, state);
	    PointerType ptrTy = cast(PointerType) expr.type.underlyingType;
	    if (!ptrTy)
		return super.eval(lang, sc, state);
	    ulong ptr = readInteger(expr.loc.readValue(state));
	    Type ty = new IntegerType("int", true, 4);
	    ubyte v[4];
	    writeInteger(ptr ? 0 : 1, v);
	    return Value(new ConstantLocation(v), ty);
	}
    }
}

class ComplementExpr: IntegerUnaryExpr!("~", "complement")
{
    this(Expr e)
    {
	super(e);
    }
}

class PreIncrementExpr: UnaryExpr
{
    this(string op, Expr e)
    {
	super(e);
	op_ = op;
    }
    override {
	string toString()
	{
	    return op_ ~ expr_.toString;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    return Value(null, new VoidType);
	}
    }
    string op_;
}

class PostIncrementExpr: UnaryExpr
{
    this(string op, Expr e)
    {
	super(e);
	op_ = op;
    }
    override {
	string toString()
	{
	    return expr_.toString() ~ op_;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    return Value(null, new VoidType);
	}
    }
    string op_;
}

class BinopExpr: Expr
{
    this(string op, Expr l, Expr r)
    {
	op_ = op;
	left_ = l;
	right_ = r;
    }
    override {
	string toString()
	{
	    return left_.toString ~ " " ~ op_ ~ " " ~ right_.toString;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    return Value(null, null); // XXX
	}
    }
private:
    string op_;
    Expr left_;
    Expr right_;
}

class AssignExpr: BinopExpr
{
    this(string op, Expr l, Expr r)
    {
	super(op, l, r);
    }
}

class BinaryExpr: Expr
{
    this(Expr l, Expr r)
    {
	left_ = l;
	right_ = r;
    }
    abstract string toString();
    abstract Value eval(Language lang, Scope sc, MachineState state);
private:
    Expr left_;
    Expr right_;
}

template IntegerBinaryExpr(string op, string name)
{
    class IntegerBinaryExpr: BinaryExpr
    {
	this(Expr l, Expr r)
	{
	    super(l, r);
	}

	override {
	    string toString()
	    {
		return left_.toString() ~ " " ~ op ~ " " ~ right_.toString();
	    }
	    Value eval(Language lang, Scope sc, MachineState state)
	    {
		Value left = left_.eval(lang, sc, state);
		if (!left.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       left.type.toString(lang)));
		ulong lval = readInteger(left.loc.readValue(state));

		Value right = right_.eval(lang, sc, state);
		if (!right.type.isIntegerType)
		    throw new Exception(
			format("Attempting to %s a value of type %s",
			       name,
			       right.type.toString(lang)));
		ulong rval = readInteger(right.loc.readValue(state));
		
		static if (op == "/" || op == "%") {
		    if (!rval)
			throw new Exception("Divide or remainder with zero");
		}
		
		mixin("lval = lval " ~ op ~ "rval;");
		ubyte[] v;
		v.length = left.loc.length;
		writeInteger(lval, v);
		return Value(new ConstantLocation(v), left.type);
	    }
	}
    }
}

class CommaExpr: BinaryExpr
{
    this(Expr l, Expr r)
    {
	super(l, r);
    }
    override {
	string toString()
	{
	    return left_.toString() ~ ", " ~ right_.toString();
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value left = left_.eval(lang, sc, state);
	    Value right = right_.eval(lang, sc, state);
	    return right;
	}
    }
}

class AddExpr: IntegerBinaryExpr!("+", "add")
{
    this(Expr l, Expr r)
    {
	super(l, r);
    }
    override {
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value left = left_.eval(lang, sc, state);
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(lang, sc, state);

	    Value right = right_.eval(lang, sc, state);
	    if (!right.type.isIntegerType)
		throw new Exception("Pointer arithmetic with non-integer");

	    ulong ptr = readInteger(left.loc.readValue(state));
	    ulong off = readInteger(right.loc.readValue(state));
	    ptr += off * ptrTy.baseType.byteWidth;
	    ubyte[] val;
	    val.length = ptrTy.byteWidth;
	    writeInteger(ptr, val);
	    return Value(new ConstantLocation(val), ptrTy);
	}
    }
}

class SubtractExpr: IntegerBinaryExpr!("-", "add")
{
    this(Expr l, Expr r)
    {
	super(l, r);
    }
    override {
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value left = left_.eval(lang, sc, state);
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(lang, sc, state);

	    Value right = right_.eval(lang, sc, state);
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
		return Value(new ConstantLocation(val),
			     new IntegerType("int", true, ptrTy.byteWidth));
	    } else {
		ulong ptr = lval - rval * ptrTy.baseType.byteWidth;
		ubyte[] val;
		val.length = ptrTy.byteWidth;
		writeInteger(ptr, val);
		return Value(new ConstantLocation(val), ptrTy);
	    }
	}
    }
}

class IndexExpr: Expr
{
    this(Expr base, Expr index)
    {
	base_ = base;
	index_ = index;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "[" ~ index_.toString ~ "]";
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value base = base_.eval(lang, sc, state);

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
		    ArrayType subTy = new ArrayType(aTy.baseType);
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

	    Value index = index_.eval(lang, sc, state);
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

	    return Value(elementLoc, elementType);
	}
    }
private:
    Expr base_;
    Expr index_;
}

class MemberExpr: Expr
{
    this(Expr base, string member)
    {
	base_ = base;
	member_ = member;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "." ~ member_;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value base = base_.eval(lang, sc, state);
	    CompoundType cTy = cast(CompoundType) base.type.underlyingType;
	    if (!cTy)
		throw new Exception("Not a compound type");
	    return cTy.fieldValue(member_, base.loc, state);
	}
    }
private:
    Expr base_;
    string member_;
}

class PointsToExpr: Expr
{
    this(Expr base, string member)
    {
	base_ = base;
	member_ = member;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "->" ~ member_;
	}
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value base = base_.eval(lang, sc, state);
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

class IfElseExpr: Expr
{
    this(Expr cond, Expr trueExp, Expr falseExp)
    {
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
	Value eval(Language lang, Scope sc, MachineState state)
	{
	    Value cond = cond_.eval(lang, sc, state);
	    if (!cond.type.isIntegerType)
		throw new Exception("Condition value is not an integer");
	    if (readInteger(cond.loc.readValue(state)))
		return trueExp_.eval(lang, sc, state);
	    else
		return falseExp_.eval(lang, sc, state);
	}
    }
private:
    Expr cond_;
    Expr trueExp_;
    Expr falseExp_;
}

struct Value
{
    Location loc;
    Type type;

    string toString(string fmt, Language lang, MachineState state)
    {
	if (!loc.valid(state))
	    return "<invalid>";
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
	bool lookup(string name, out Variable var)
	{
	    foreach (sc; subScopes_) {
		if (sc.lookup(name, var))
		    return true;
	    }
	    return false;
	}
    }

private:
    Scope[] subScopes_;
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
