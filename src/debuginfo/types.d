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

module debuginfo.types;

version(tangobos) import std.compat;
import std.conv;
import std.string;

import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import machine.machine;

interface Type: DebugItem
{
    Language language();
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
    abstract override string toString();
    override bool coerce(MachineState, ref Value val)
    {
	return false;
    }
    abstract string valueToString(string, MachineState, Location);
    abstract size_t byteWidth();
    override {
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
    }

private:
    Language lang_;
    Type[uint] ptrTypes_;
    Type[uint] refTypes_;
    Type[string] modifierTypes_;
}

class IntegerType: TypeBase
{
    this(Language lang, string name, bool isSigned, size_t byteWidth)
    {
	super(lang);
	name_ = name;
	isSigned_ = isSigned;
	byteWidth_ = to!uint(byteWidth);
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

	bool opEquals(Object o)
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
	    if (!val.type.isIntegerType
		&& !cast(PointerType) val.type)
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
    this(Language lang, string name, bool isSigned, size_t byteWidth)
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
		    ~ lang_.renderCharConstant(to!dchar(val));
	    } else {
		ulong val = state.readInteger(loc.readValue(state));
		return super.valueToString(fmt, state, loc)
		    ~ lang_.renderCharConstant(to!dchar(val));
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
    this(Language lang, string name, size_t byteWidth)
    {
	super(lang);
	name_ = name;
	byteWidth_ = to!uint(byteWidth);
    }

    override
    {
	hash_t toHash()
	{
	    return typeid(string).getHash(cast(void*) &name_)
		+ byteWidth_ * 31;
	}

	bool opEquals(Object o)
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
	    return true;
	}
    }

private:
    string name_;
    uint byteWidth_;
}

class FloatType: TypeBase
{
    this(Language lang, string name, size_t byteWidth)
    {
	super(lang);
	name_ = name;
	byteWidth_ = to!uint(byteWidth);
    }

    override
    {
	hash_t toHash()
	{
	    return typeid(string).getHash(cast(void*) &name_)
		+ byteWidth_ * 31;
	}

	bool opEquals(Object o)
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
	    if (baseType_) {
		auto aTy = cast(ArrayType) baseType_;
		if (aTy)
		    return lang_.renderPointerToArray(
			aTy.baseType.toString, aTy.renderDims);
		auto fTy = cast(FunctionType) baseType_;
		if (fTy)
		    return lang_.renderPointerToFunction(
			fTy.returnType.toString, fTy.renderArgs);
		return lang_.renderPointerType(baseType_.toString);
	    } else
		return lang_.renderPointerType("void");
	}

	bool coerce(MachineState state, ref Value val)
	{
	    if (val.type.isIntegerType) {
		ulong i = state.readInteger(val.loc.readValue(state));
		ubyte[] v;
		v.length = byteWidth_;
		state.writeInteger(i, v);
		val = new Value(new ConstantLocation(v), this);
		return true;
	    }
	    auto pTy = cast(PointerType) val.type;
	    if (pTy) {
		val = new Value(val.loc, this);
		return true;
	    }
	    return false;
	}

	string valueToString(string, MachineState state, Location loc)
	{
	    string v;
	    ulong p = state.readInteger(loc.readValue(state));
	    if (p) {
		v = std.string.format("0x%x", p);
		if (lang_.isStringType(this) && p)
		    v ~= " " ~ lang_.renderStringConstant(state, this, loc);
	    } else {
		v = lang_.renderNullPointer;
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

    string modifier()
    {
	return modifier_;
    }

    Type baseType()
    {
	return baseType_;
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
	bool coerce(MachineState state, ref Value val)
	{
	    if (baseType_.coerce(state, val)) {
		val = new Value(val.loc, this);
		return true;
	    }
	    return false;
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
	    else if (kind_ == "union")
		return lang_.renderUnionType(name_);
	    else
		return lang_.renderClassType(name_);
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

    this(Language lang, string name, size_t byteWidth)
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
    bool lookupStruct(string name, out Type)
    {
	return false;
    }
    bool lookupUnion(string name, out Type)
    {
	return false;
    }
    bool lookupTypedef(string name, out Type)
    {
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

    size_t dims()
    {
	return dims_.length;
    }

    size_t indexBase(uint dim)
    {
	return dims_[dim].indexBase;
    }

    size_t count(uint dim)
    {
	return dims_[dim].count;
    }

    /**
     * Return a type which represents a single top-level element of
     * the array.
     */
    Type elementType()
    {
	if (dims_.length == 1)
	    return baseType_;
	else {
	    ArrayType subTy = new ArrayType(lang_, baseType_);
	    subTy.dims_ = dims_[1..$];
	    return subTy;
	}
    }

    override
    {
	string toString()
	{
	    return baseType_.toString ~ renderDims;
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    if (lang_.isStringType(this))
		return lang_.renderStringConstant(state, this, loc);
	    size_t off = 0;
	    return valueToString(fmt, state, loc, off, 0);
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

    string renderDims()
	{
	    string v;
	    foreach (d; dims_) {
		if (d.indexBase > 0)
		    v ~= std.string.format("[%d..%d]", d.indexBase,
					   d.indexBase + d.count - 1);
		else
		    v ~= std.string.format("[%d]", d.count);
	    }
	    return v;
	}

private:
    string valueToString(string fmt, MachineState state,
			 Location loc, ref size_t off,
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
			loc.subrange(off, baseType_.byteWidth, state));
		off += baseType_.byteWidth;
	    } else {
		elem = valueToString(fmt, state, loc, off, di + 1);
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

class AArrayType: TypeBase
{
    this(Language lang, Type baseType, Type keyType, size_t byteWidth)
    {
	super(lang);
	baseType_ = baseType;
	keyType_ = keyType;
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
	    return baseType_.toString ~ "[" ~ keyType_.toString ~"]";
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    struct keyval {
		Location k;
		Location v;
	    }
	    keyval[] kvs;

	    void addKv(Location k, Location v)
	    {
		kvs ~= keyval(k, v);
	    }

	    iterateElements(state, loc, &addKv);
	    string res;

	    foreach (i, kv; kvs) {
		if (i > 0)
		    res ~= ", ";
		if (i == 3) {
		    res ~= "...";
		    break;
		}
		res ~= keyType_.valueToString(fmt, state, kv.k);
		res ~= ":";
		res ~= baseType_.valueToString(fmt, state, kv.v);
	    }

	    return lang_.renderArrayConstant(res);
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
    void iterateElements(MachineState state, Location loc,
			 void delegate(Location, Location) dg)
    {
// 	struct aaA
// 	{
// 	    aaA *left;
// 	    aaA *right;
// 	    hash_t hash;
// 	    /* key   */
// 	    /* value */
// 	}

// 	struct BB
// 	{
// 	    aaA*[] b;
// 	    size_t nodes;       // total number of aaA nodes
// 	    TypeInfo keyti;
// 	}

	/*
	 * First get the pointer to the BB structure and make a
	 * location which describes the aaA*[] array.
	 */
	auto pw = state.pointerWidth;
	auto p = state.readInteger(loc.readValue(state));
	if (!p)
	    return;
	loc = new MemoryLocation(p, 2*pw);
	auto val = loc.readValue(state);
	auto aaAlen = state.readInteger(val[0..pw]);
	auto aaAptr = state.readInteger(val[pw..$]);

	for (auto i = 0; i < aaAlen; i++) {
	    loc = new MemoryLocation(aaAptr + i * pw,
				     pw);
	    auto aaAp = state.readInteger(loc.readValue(state));

	    void visitNode(ulong p)
	    {
		if (!p)
		    return;

		loc = new MemoryLocation(p, 3*pw);
		auto keyLoc = new MemoryLocation(p + 3*pw,
						 keyType_.byteWidth);
		auto valLoc = new MemoryLocation(p + 3*pw
						 + keyType_.byteWidth,
						 baseType_.byteWidth);
		auto rec = loc.readValue(state);
		visitNode(state.readInteger(rec[0..pw]));
		dg(keyLoc, valLoc);
		visitNode(state.readInteger(rec[pw..2*pw]));
	    }

	    visitNode(aaAp);
	}
    }

    Type baseType_;
    Type keyType_;
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
	    s ~= renderArgs;
	    s ~= ")";

	    return s;
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    assert(loc.hasAddress(state));
	    return format("%#x", loc.address(state));
	}
	size_t byteWidth()
	{
	    return 0;
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

    Type[] argumentTypes()
    {
	return argumentTypes_;
    }

    string renderArgs()
    {
	string s;
	foreach (i, at; argumentTypes_) {
	    if (i > 0)
		s ~= ", ";
	    s ~= at.toString;
	}
	if (varargs_)
	    s = lang_.renderVarargs(s);
	return s;
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

class UserType: TypeBase
{
    this(Language lang)
    {
	super(lang);
	type_ = lang.voidType;
    }

    override {
	string toString()
	{
	    return type_.toString;
	}
	Language language()
	{
	    return type_.language;
	}
	bool coerce(MachineState, ref Value val)
	{
	    type_ = val.type;
	    return true;
	}
	string valueToString(string fmt, MachineState state, Location loc)
	{
	    return type_.valueToString(fmt, state, loc);
	}
	size_t byteWidth()
	{
	    return type_.byteWidth;
	}
	Type pointerType(uint width)
	{
	    return type_.pointerType(width);
	}
	Type referenceType(uint width)
	{
	    return type_.referenceType(width);
	}
	Type modifierType(string modifier)
	{
	    return type_.modifierType(modifier);
	}
	bool isCharType()
	{
	    return type_.isCharType;
	}
	bool isIntegerType()
	{
	    return type_.isIntegerType;
	}
	bool isNumericType()
	{
	    return type_.isNumericType;
	}
    }

private:
    Type type_;
}
