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
import std.ctype;
import std.stdio;
import std.string;
import std.c.stdlib;

import language.language;
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
    Value toValue(MachineState);
}

interface Type: DebugItem
{
    Language language();
    string toString();
    bool coerce(MachineState, ref Value);
    string valueToString(string, MachineState, Location);
    size_t byteWidth();
    Type underlyingType();
    Type pointerType(uint);
    Type referenceType(uint);
    Type modifierType(string modifier);
    bool isCharType();
    bool isIntegerType();
    bool isNumericType();
}

class EvalException: Exception
{
    this(string s)
    {
	super(s);
    }
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
    Value toValue(MachineState)
    {
	throw new EvalException(format("%s is not a value", toString));
    }
    abstract string toString();
    bool coerce(MachineState, ref Value val)
    {
	return false;
    }
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
    Type referenceType(uint width)
    {
	if (width in refTypes_)
	    return refTypes_[width];
	return (refTypes_[width] = new ReferenceType(lang_, this, width));
    }
    Type modifierType(string modifier)
    {
	if (modifier in modifierTypes_)
	    return modifierTypes_[modifier];
	return (modifierTypes_[modifier] =
		new ModifierType(lang_, modifier, this));
    }
    bool isCharType()
    {
	return false;
    }
    bool isIntegerType()
    {
	return false;
    }
    bool isNumericType()
    {
	return false;
    }

private:
    Language lang_;
    Type[uint] ptrTypes_;
    Type[uint] refTypes_;
    Type[string] modifierTypes_;
}

interface Scope
{
    string[] contents(MachineState);
    bool lookup(string, MachineState, out DebugItem);
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
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    foreach (sc; subScopes_) {
		if (sc.lookup(name, state, val))
		    return true;
	    }
	    return false;
	}
    }

private:
    Scope[] subScopes_;
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
	hash_t toHash()
	{
	    return typeid(string).getHash(cast(void*) &name_)
		+ cast(int) isSigned_ * 17
		+ byteWidth_ * 31;
	}

	int opEquals(Object o)
	{
	    IntegerType ty = cast(IntegerType) o;
	    if (!ty)
		return 0;
	    return name_ == ty.name_
		&& isSigned_ == ty.isSigned_
		&& byteWidth_ == ty.byteWidth_;
	}

	int opCmp(Object o)
	{
	    IntegerType ty = cast(IntegerType) o;
	    if (!ty)
		return 1;
	    if (name_ < ty.name_)
		return -1;
	    if (name_ > ty.name_)
		return 1;
	    if (isSigned_ < ty.isSigned_)
		return -1;
	    if (isSigned_ > ty.isSigned_)
		return 1;
	    if (byteWidth_ < ty.byteWidth_)
		return -1;
	    if (byteWidth_ > ty.byteWidth_)
		return 1;
	    return 0;
	}

	string toString()
	{
	    return name_;
	}

	bool coerce(MachineState state, ref Value val)
	{
	    if (!val.type.isIntegerType)
		return false;

	    ulong i = state.readInteger(val.loc.readValue(state));
	    ubyte[] v;
	    v.length = byteWidth_;
	    state.writeInteger(i, v);
	    val = new Value(new ConstantLocation(v), this);
	    return true;
	}

	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (fmt)
		fmt = "%#" ~ fmt;
	    else
		fmt = "%d";

	    if (isSigned) {
		long val = state.readInteger(loc.readValue(state));
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
		ulong val = state.readInteger(loc.readValue(state));
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

	bool isNumericType()
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
		long val = state.readInteger(loc.readValue(state));
		return super.valueToString(fmt, state, loc)
		    ~ lang_.renderCharConstant(val);
	    } else {
		ulong val = state.readInteger(loc.readValue(state));
		return super.valueToString(fmt, state, loc)
		    ~ lang_.renderCharConstant(val);
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
	hash_t toHash()
	{
	    return typeid(string).getHash(cast(void*) &name_)
		+ byteWidth_ * 31;
	}

	int opEquals(Object o)
	{
	    BooleanType ty = cast(BooleanType) o;
	    if (!ty)
		return 0;
	    return name_ == ty.name_
		&& byteWidth_ == ty.byteWidth_;
	}

	int opCmp(Object o)
	{
	    BooleanType ty = cast(BooleanType) o;
	    if (!ty)
		return 1;
	    if (name_ < ty.name_)
		return -1;
	    if (name_ > ty.name_)
		return 1;
	    if (byteWidth_ < ty.byteWidth_)
		return -1;
	    if (byteWidth_ > ty.byteWidth_)
		return 1;
	    return 0;
	}

	string toString()
	{
	    return name_;
	}

	string valueToString(string, MachineState state, Location loc)
	{
	    ubyte[] val = loc.readValue(state);
	    return state.readInteger(val) ? "true" : "false";
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

class FloatType: TypeBase
{
    this(Language lang, string name, uint byteWidth)
    {
	super(lang);
	name_ = name;
	byteWidth_ = byteWidth;
    }

    override
    {
	hash_t toHash()
	{
	    return typeid(string).getHash(cast(void*) &name_)
		+ byteWidth_ * 31;
	}

	int opEquals(Object o)
	{
	    FloatType ty = cast(FloatType) o;
	    if (!ty)
		return 0;
	    return name_ == ty.name_
		&& byteWidth_ == ty.byteWidth_;
	}

	int opCmp(Object o)
	{
	    FloatType ty = cast(FloatType) o;
	    if (!ty)
		return 1;
	    if (name_ < ty.name_)
		return -1;
	    if (name_ > ty.name_)
		return 1;
	    if (byteWidth_ < ty.byteWidth_)
		return -1;
	    if (byteWidth_ > ty.byteWidth_)
		return 1;
	    return 0;
	}

	string toString()
	{
	    return name_;
	}

	bool coerce(MachineState state, ref Value val)
	{
	    if (!val.type.isNumericType)
		return false;

	    if (val.type.isIntegerType) {
		ulong i = state.readInteger(val.loc.readValue(state));
		ubyte[] v;
		v.length = byteWidth_;
		state.writeFloat(cast(real) i, v);
		val = new Value(new ConstantLocation(v), this);
	    } else {
		real f = state.readFloat(val.loc.readValue(state));
		ubyte[] v;
		v.length = byteWidth_;
		state.writeFloat(f, v);
		val = new Value(new ConstantLocation(v), this);
	    }
	    return true;
	}

	string valueToString(string fmt, MachineState state, Location loc)
	{
	    real val = state.readFloat(loc.readValue(state));
	    return format("%g", val);
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
	    return false;
	}

	bool isNumericType()
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
    private this(Language lang, Type baseType, uint byteWidth)
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
		return lang_.renderPointerType(baseType_.toString);
	    else
		return lang_.renderPointerType("void");
	}

	string valueToString(string, MachineState state, Location loc)
	{
	    string v;
	    ulong p = state.readInteger(loc.readValue(state));
	    v = std.string.format("0x%x", p);
	    if (lang_.isStringType(this) && p)
		v ~= " " ~ lang_.renderStringConstant(state, this, loc);
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
			 state.readInteger(loc.readValue(state)),
			 baseType.byteWidth),
		     baseType);
    }

private:
    Type baseType_;
    uint byteWidth_;
}

class ReferenceType: TypeBase
{
    private this(Language lang, Type baseType, uint byteWidth)
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
		return lang_.renderReferenceType(baseType_.toString);
	    else
		return lang_.renderReferenceType("void");
	}

	string valueToString(string, MachineState state, Location loc)
	{
	    string v;
	    ulong p = state.readInteger(loc.readValue(state));
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
    Type baseType_;
    uint byteWidth_;
}

class ModifierType: TypeBase
{
    private this(Language lang, string modifier, Type baseType)
    {
	super(lang);
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
		return lang_.renderStructureType(name_);
	    else
		return lang_.renderUnionType(name_);
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
	    return lang_.renderStructConstant(s);
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
	throw new EvalException(format("Field %s not found", fieldName));
    }

private:
    string kind_;
    string name_;
    uint byteWidth_;
    Variable[] fields_;
    Function[] functions_;
}

class EnumType: IntegerType
{
    struct tag {
	string name;
	ulong value;
    }

    this(Language lang, string name, uint byteWidth)
    {
	super(lang, name, false, byteWidth);
    }

    void addTag(string name, ulong value)
    {
	tags_ ~= tag(name, value);
    }

    override
    {
	string toString()
	{
	    return lang_.renderEnumType(name_);
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    string s;

	    if (fmt)
		return super.valueToString(fmt, state, loc);

	    ulong val = state.readInteger(loc.readValue(state));
	    foreach (t; tags_) {
		if (t.value == val)
		    return t.name;
	    }
	    return super.valueToString(fmt, state, loc);
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
    tag[] tags_;
}

class CompoundScope: Scope
{
    this(CompoundType type, Location base, MachineState state)
    {
	type_ = type;
	base_ = base;
	state_ = state;
    }
    string[] contents(MachineState)
    {
	string[] res;
	foreach (f; type_.fields_)
	    res ~= f.name;
	return res;
    }
    bool lookup(string name, MachineState, out DebugItem val)
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
		return lang_.renderArrayConstant("");
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
	return lang_.renderArrayConstant(v);
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
		return lang_.renderStringConstant(state, this, loc);

	    ubyte[] val = loc.readValue(state);
	    ulong len = state.readInteger(val[0..state.pointerWidth]);
	    ulong addr = state.readInteger(val[state.pointerWidth..$]);
	    string v;
	    for (auto i = 0; i < len; i++) {
		if (i > 0)
		    v ~= ", ";
		if (i == 3) {
		    v ~= "...";
		    break;
		}
		v ~= baseType_.valueToString(fmt, state,
			new MemoryLocation(addr, baseType_.byteWidth));
		addr += baseType_.byteWidth;
	    }
	    return lang_.renderArrayConstant(v);
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
     * Return a copy of this location.
     */
    Location dup();
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
	    return 0;
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location dup()
	{
	    return new RegisterLocation(regno_, length_);
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
	    return state.readMemory(address(state), length_);
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    assert(value.length == length_);
	    return state.writeMemory(address(state), value);
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
	    return 0;
	}

	bool isLval(MachineState)
	{
	    return true;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
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

	bool isLval(MachineState)
	{
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
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
	    return 0;
	}

	bool isLval(MachineState)
	{
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    return null;
	}

	Location dup()
	{
	    return this;
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
	    if (sc.lookup(name_, state, val))
		return val;
	    throw new EvalException(format("Variable %s not found", name_));
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
	    unum_ = strtoull(toStringz(num), null, 0);
	    isSigned_ = false;
	} else {
	    num_ = strtoll(toStringz(num), null, 0);
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
		state.writeInteger(num_, val);
		ty = lang_.integerType("int", true, 4);
	    } else {
		state.writeInteger(unum_, val);
		ty = lang_.integerType("uint", false, 4);
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

class LengthExpr: UnaryExpr
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }

    override {
	string toString()
	{
	    return expr_.toString() ~ ".length";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue(state);
	    ArrayType aTy = cast(ArrayType) expr.type.underlyingType;
	    DArrayType daTy = cast(DArrayType) expr.type.underlyingType;
	    ulong minIndex, maxIndex;
	    if (aTy) {
		minIndex = aTy.dims_[0].indexBase;
		maxIndex = minIndex + aTy.dims_[0].count;
	    } else if (daTy) {
		/*
		 * The memory representation of dynamic arrays is two
		 * pointer sized values, the first being the array length
		 * and the second the base pointer.
		 */
		ubyte[] val = expr.loc.readValue(state);
		minIndex = 0;
		maxIndex = state.readInteger(val[0..state.pointerWidth]);
	    } else {
		throw new EvalException("Expected array for length expression");
	    }
	    ubyte[4] val;
	    state.writeInteger(maxIndex - minIndex, val);
	    auto ty = lang_.integerType("size_t", false, 4);
	    return new Value(new ConstantLocation(val), ty);
	}
    }
}

class SizeofExpr: UnaryExpr
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }

    override {
	string toString()
	{
	    return expr_.toString() ~ ".length";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue(state);
	    ubyte[4] val;
	    state.writeInteger(expr.type.byteWidth, val);
	    auto ty = lang_.integerType("size_t", false, 4);
	    return new Value(new ConstantLocation(val), ty);
	}
    }
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
	    Value expr = expr_.eval(sc, state).toValue(state);
	    if (expr.loc.hasAddress(state)) {
		ulong addr = expr.loc.address(state);
		ubyte[] val;
		val.length = state.pointerWidth;
		state.writeInteger(addr, val);
		return new Value(new ConstantLocation(val),
			     expr.type.pointerType(state.pointerWidth));
	    } else {
		throw new EvalException("Can't take the address of a value which is not in memory");
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
	    Value expr = expr_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) expr.type.underlyingType;
	    if (!ptrTy)
		throw new EvalException("Attempting to dereference a non-pointer");
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
		Value expr = expr_.eval(sc, state).toValue(state);
		if (!expr.type.isIntegerType)
		    throw new EvalException(
			format("Attempting to %s a value of type %s",
			       name,
			       expr.type.toString));
		ubyte[] v = expr.loc.readValue(state);
		ulong val = state.readInteger(v);
		mixin("val = " ~ op ~ "val;");
		state.writeInteger(val, v);
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
	    Value expr = expr_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) expr.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);
	    ulong ptr = state.readInteger(expr.loc.readValue(state));
	    Type ty = lang_.integerType("int", true, 4);
	    ubyte v[4];
	    state.writeInteger(ptr ? 0 : 1, v);
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
	    /**
	     * Our expr is either 'a + 1' or 'a - 1'. We read the
	     * initial value of a before overwriting with the new
	     * value.
	     */
	    BinaryExpr b = cast(BinaryExpr) expr_;
	    assert(b);
	    Value left = b.left_.eval(sc, state).toValue(state);
	    if (!left.loc.isLval(state))
		throw new EvalException("Not an l-value in post-increment");
	    Value res = left.dup(state);
	    Value newval = b.eval(sc, state).toValue(state);
	    ubyte[] v = newval.loc.readValue(state);
	    left.loc.writeValue(state, v);
	    return res;
	}
    }
    string op_;
}

class AssignExpr: ExprBase
{
    this(Language lang, Expr l, Expr r)
    {
	super(lang);
	left_ = l;
	right_ = r;
    }

    override {
	string toString()
	{
	    return "(" ~ left_.toString ~ " = " ~ right_.toString ~ ")";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value left = left_.eval(sc, state).toValue(state);
	    if (!left.loc.isLval(state))
		throw new EvalException("Not an l-value in assignment");
	    Value right = right_.eval(sc, state).toValue(state);
	    if (left.type != right.type) {
		if (!left.type.coerce(state, right))
		    throw new EvalException("Incompatible types in assignment");
	    }
		
	    ubyte[] v = right.loc.readValue(state);
	    left.loc.writeValue(state, v);
	    return left;
	}
    }

    Expr left_;
    Expr right_;
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
		return "(" ~ left_.toString ~ " " ~ op ~ " " ~ right_.toString ~ ")";
	    }
	    DebugItem eval(Scope sc, MachineState state)
	    {
		Value left = left_.eval(sc, state).toValue(state);
		if (!left.type.isIntegerType)
		    throw new EvalException(
			format("Attempting to %s a value of type %s",
			       name,
			       left.type.toString));
		ulong lval = state.readInteger(left.loc.readValue(state));

		Value right = right_.eval(sc, state).toValue(state);
		if (!right.type.isIntegerType)
		    throw new EvalException(
			format("Attempting to %s a value of type %s",
			       name,
			       right.type.toString));
		ulong rval = state.readInteger(right.loc.readValue(state));
		
		static if (op == "/" || op == "%") {
		    if (!rval)
			throw new EvalException("Divide or remainder with zero");
		}
		
		mixin("lval = lval " ~ op ~ "rval;");
		ubyte[] v;
		v.length = left.loc.length;
		state.writeInteger(lval, v);
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
	    Value left = left_.eval(sc, state).toValue(state);
	    Value right = right_.eval(sc, state).toValue(state);
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
	    Value left = left_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);

	    Value right = right_.eval(sc, state).toValue(state);
	    if (!right.type.isIntegerType)
		throw new EvalException("Pointer arithmetic with non-integer");

	    ulong ptr = state.readInteger(left.loc.readValue(state));
	    ulong off = state.readInteger(right.loc.readValue(state));
	    ptr += off * ptrTy.baseType.byteWidth;
	    ubyte[] val;
	    val.length = ptrTy.byteWidth;
	    state.writeInteger(ptr, val);
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
	    Value left = left_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) left.type.underlyingType;
	    if (!ptrTy)
		return super.eval(sc, state);

	    Value right = right_.eval(sc, state).toValue(state);
	    PointerType rptrTy = cast(PointerType) right.type.underlyingType;
	    if (!rptrTy && !right.type.isIntegerType)
		throw new EvalException("Pointer arithmetic with non-integer or non-pointer");
	    if (rptrTy && rptrTy != ptrTy)
		throw new EvalException("Pointer arithmetic with differing pointer types");

	    ulong lval = state.readInteger(left.loc.readValue(state));
	    ulong rval  = state.readInteger(right.loc.readValue(state));
	    if (rptrTy) {
		ulong diff = (lval - rval) / ptrTy.baseType.byteWidth;
		ubyte[] val;
		val.length = ptrTy.byteWidth;
		state.writeInteger(diff, val);
		return new Value(new ConstantLocation(val),
			     lang_.integerType("int", true, ptrTy.byteWidth));
	    } else {
		ulong ptr = lval - rval * ptrTy.baseType.byteWidth;
		ubyte[] val;
		val.length = ptrTy.byteWidth;
		state.writeInteger(ptr, val);
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
	    Value base = base_.eval(sc, state).toValue(state);

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
		maxIndex = state.readInteger(val[0..state.pointerWidth]);
		ulong addr = state.readInteger(val[state.pointerWidth..$]);
		baseLoc = new MemoryLocation(addr, 0);
	    } else if (ptrTy) {
		elementType = ptrTy.baseType;
		/*
		 * Dereference the pointer to get the array base
		 */
		ulong addr = state.readInteger(base.loc.readValue(state));
		minIndex = 0;
		maxIndex = ~0;
		baseLoc = new MemoryLocation(addr, 0);
	    } else {
		throw new EvalException("Expected array or pointer for index expression");
	    }

	    Value index = index_.eval(sc, state).toValue(state);
	    IntegerType intTy = cast(IntegerType) index.type.underlyingType;
	    if (!index.type.isIntegerType) {
		throw new EvalException("Expected integer for index expression");
	    }
	    long i = state.readInteger(index.loc.readValue(state));
	    if (i < minIndex || i >= maxIndex)
		throw new EvalException(format("Index %d out of array bounds", i));
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
	    Value base = base_.eval(sc, state).toValue(state);
	    CompoundType cTy = cast(CompoundType) base.type.underlyingType;
	    if (!cTy)
		throw new EvalException("Not a compound type");
	    return cTy.fieldValue(member_, base.loc, state);
	}
    }
private:
    Language lang_;
    Expr base_;
    string member_;
}

class DMemberExpr: ExprBase
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
	    Value base = base_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) base.type.underlyingType;
	    if (ptrTy) {
		CompoundType cTy = cast(CompoundType) ptrTy.baseType.underlyingType;
		if (!cTy)
		    throw new EvalException("Not a pointer to a compound type");
		ulong ptr = state.readInteger(base.loc.readValue(state));
		return cTy.fieldValue(member_,
				      new MemoryLocation(ptr, cTy.byteWidth),
				      state);
	    }
	    CompoundType cTy = cast(CompoundType) base.type.underlyingType;
	    if (cTy) {
		return cTy.fieldValue(member_, base.loc, state);
	    }
	    throw new EvalException("Not a compound or pointer to compound");
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
	    Value base = base_.eval(sc, state).toValue(state);
	    PointerType ptrTy = cast(PointerType) base.type.underlyingType;
	    if (!ptrTy)
		throw new EvalException("Not a pointer");

	    CompoundType cTy = cast(CompoundType) ptrTy.baseType.underlyingType;
	    if (!cTy)
		throw new EvalException("Not a pointer to a compound type");
	    ulong ptr = state.readInteger(base.loc.readValue(state));
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
	    Value cond = cond_.eval(sc, state).toValue(state);
	    if (!cond.type.isIntegerType)
		throw new EvalException("Condition value is not an integer");
	    if (state.readInteger(cond.loc.readValue(state)))
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
	    return type.valueToString(fmt, state, loc);
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
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    if (sc.lookup(name, state, val))
			return true;
	    foreach (v; variables_) {
		if (name == v.name) {
		    val = v;
		    return true;
		}
	    }
	    return false;
	}
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

	    s = returnType_.toString ~ " ";
	    if (containingType_)
		s ~= containingType_.toString ~ lang_.renderNamespaceSeparator;
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
	Value toValue(MachineState state)
	{
	    FunctionType ft = new FunctionType(lang_);
	    ft.returnType(returnType_);
	    foreach (a; arguments_)
		ft.addArgumentType(a.value.type);
	    ft.varargs(varargs_);
	    Type pt = ft.pointerType(byteWidth_);

	    ubyte[] ptrVal;
	    ptrVal.length = byteWidth_;
	    state.writeInteger(address_, ptrVal);
	    return new Value(new ConstantLocation(ptrVal), pt);
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    res ~= sc.contents(state);
	    foreach (v; arguments_ ~ variables_)
		res ~= v.name;
	    return res;
	}
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    foreach (sc; scopes_)
		if (sc.contains(state.pc))
		    if (sc.lookup(name, state, val))
			return true;
	    foreach (v; arguments_ ~ variables_) {
		if (name == v.name) {
		    val = v;
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

    string name_;
    Language lang_;
    bool varargs_;
    Type returnType_;
    Type containingType_;
    Variable[] arguments_;
    Variable[] variables_;
    LexicalScope[] scopes_;
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
