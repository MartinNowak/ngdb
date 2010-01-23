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

module debuginfo.expr;

version(tangobos) import std.compat;
import std.string;
import std.c.stdlib;

import debuginfo.debuginfo;
import debuginfo.language;
import debuginfo.types;
import machine.machine;

class EvalException: Exception
{
    this(string s)
    {
	super(s);
    }
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

class CastExpr: ExprBase
{
    this(Language lang, Type type, Expr expr)
    {
	super(lang);
	type_ = type;
	expr_ = expr;
    }

    override {
	string toString()
	{
	    return "(" ~ type_.toString ~ ") " ~ expr_.toString;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue(state);
	    if (!type_.coerce(state, expr))
		throw new EvalException("Incompatible types for cast");
	    return expr;
	}
    }
private:
    Type type_;
    Expr expr_;
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

class IntegerConstantExpr: ExprBase
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

class FloatConstantExpr: ExprBase
{
    this(Language lang, string num)
    {
	super(lang);
	num_ = strtold(toStringz(num), null);
	if (num[$-1] == 'f' || num[$-1] == 'F')
	    ty_ = lang_.floatType("float", 4);
	else if (num[$-1] == 'L')
	    ty_ = lang_.floatType("real", 12);
	else
	    ty_ = lang_.floatType("double", 8);
    }
    override {
	string toString()
	{
	    return std.string.toString(num_);
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Type ty;
	    ubyte[] val;
	    val.length = ty_.byteWidth;
	    state.writeFloat(num_, val);
	    return new Value(new ConstantLocation(val), ty_);
	}
    }
private:
    Type ty_;
    real num_;
}

class CharConstantExpr: ExprBase
{
    this(Language lang, uint ch, Type ty)
    {
	super(lang);
	ch_ = ch;
	ty_ = ty;
    }
    override {
	string toString()
	{
	    return std.string.toString(ch_);
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    ubyte[] val;
	    val.length = ty_.byteWidth;
	    state.writeInteger(ch_, val);
	    return new Value(new ConstantLocation(val), ty_);
	}
    }
private:
    uint ch_;
    Type ty_;
}

class StringConstantExpr: ExprBase
{
    this(Language lang, string s, Type ty)
    {
	super(lang);
	s_ = s;
	ty_ = ty;
    }
    override {
	string toString()
	{
	    return "\"" ~ s_ ~ "\"";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    assert(s_.length == ty_.byteWidth);
	    auto val = cast(ubyte[]) s_;
	    return new Value(new ConstantLocation(val), ty_);
	}
    }
private:
    string s_;
    Type ty_;
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
		minIndex = aTy.indexBase(0);
		maxIndex = minIndex + aTy.count(0);
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

class PtrExpr: UnaryExpr
{
    this(Language lang, Expr e)
    {
	super(lang, e);
    }

    override {
	string toString()
	{
	    return expr_.toString() ~ ".ptr";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value expr = expr_.eval(sc, state).toValue(state);
	    ArrayType aTy = cast(ArrayType) expr.type.underlyingType;
	    DArrayType daTy = cast(DArrayType) expr.type.underlyingType;
	    ulong minIndex, maxIndex;
	    auto pw = state.pointerWidth;
	    if (aTy) {
		if (!expr.loc.hasAddress(state))
		    throw new EvalException(
			"Can't take the address of a value "
			"which is not in memory");
		ulong addr = expr.loc.address(state);
		ubyte[] val;
		val.length = state.pointerWidth;
		state.writeInteger(addr, val);
		return new Value(new ConstantLocation(val),
				 aTy.baseType.pointerType(pw));
	    } else if (daTy) {
		/*
		 * The memory representation of dynamic arrays is two
		 * pointer sized values, the first being the array length
		 * and the second the base pointer.
		 */
		ubyte[] val = expr.loc.readValue(state);
		return new Value(new ConstantLocation(val[pw..$]),
				 daTy.baseType.pointerType(pw));
	    } else {
		throw new EvalException("Expected array for ptr expression");
	    }
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
	    return expr_.toString() ~ ".sizeof";
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

class SizeofTypeExpr: ExprBase
{
    this(Language lang, Type ty)
    {
	super(lang);
	ty_ = ty;
    }

    override {
	string toString()
	{
	    return ty_.toString ~ ".sizeof";
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    ubyte[4] val;
	    state.writeInteger(ty_.byteWidth, val);
	    auto ty = lang_.integerType("size_t", false, 4);
	    return new Value(new ConstantLocation(val), ty);
	}
    }
private:
    Type ty_;
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
		Type ty;
		if (left.type.byteWidth > right.type.byteWidth)
		    ty = left.type;
		else
		    ty = right.type;
		v.length = ty.byteWidth;
		state.writeInteger(lval, v);
		return new Value(new ConstantLocation(v), ty);
	    }
	}
    }
}

template NumericBinaryExpr(string op, string name)
{
    class NumericBinaryExpr: BinaryExpr
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
		if (!left.type.isNumericType)
		    throw new EvalException(
			format("Attempting to %s a value of type %s",
			       name,
			       left.type.toString));
		Value right = right_.eval(sc, state).toValue(state);
		if (!right.type.isNumericType)
		    throw new EvalException(
			format("Attempting to %s a value of type %s",
			       name,
			       right.type.toString));

		if (!left.type.isIntegerType ||
		    !right.type.isIntegerType) {
		    /*
		     * Cast everything to real and do the operation in
		     * floating point.
		     */
		    real lval, rval;
		    auto v = left.loc.readValue(state);
		    if (left.type.isIntegerType)
			lval = cast(real) state.readInteger(v);
		    else
			lval = state.readFloat(v);
		    v = right.loc.readValue(state);
		    if (right.type.isIntegerType)
			rval = cast(real) state.readInteger(v);
		    else
			rval = state.readFloat(v);
		    static if (op == "/" || op == "%") {
			if (!rval)
			    throw new EvalException(
				"Divide or remainder with zero");
		    }
		    mixin("lval = lval " ~ op ~ "rval;");

		    /*
		     * Pick the widest float type for the result.
		     */
		    Type ty;
		    if (!left.type.isIntegerType
			&& !right.type.isIntegerType)
			if (left.type.byteWidth > right.type.byteWidth)
			    ty = left.type;
			else
			    ty = right.type;
		    else if (!left.type.isIntegerType)
			ty = left.type;
		    else
			ty = right.type;
		    v.length = ty.byteWidth;
		    state.writeFloat(lval, v);
		    return new Value(new ConstantLocation(v), ty);
		} else {
		    ulong lval = state.readInteger(left.loc.readValue(state));
		    ulong rval = state.readInteger(right.loc.readValue(state));
		
		    static if (op == "/" || op == "%") {
			if (!rval)
			    throw new EvalException(
				"Divide or remainder with zero");
		    }
		
		    mixin("lval = lval " ~ op ~ "rval;");
		    ubyte[] v;
		    Type ty;
		    if (left.type.byteWidth > right.type.byteWidth)
			ty = left.type;
		    else
			ty = right.type;
		    v.length = ty.byteWidth;
		    state.writeInteger(lval, v);
		    return new Value(new ConstantLocation(v), ty);
		}
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

class AddExpr: NumericBinaryExpr!("+", "add")
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

class SubtractExpr: NumericBinaryExpr!("-", "add")
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
		minIndex = aTy.indexBase(0);
		maxIndex = minIndex + aTy.count(0);
		elementType = aTy.elementType;
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

	    auto elementLoc = baseLoc.subrange(i * elementType.byteWidth,
					       elementType.byteWidth,
					       state);

	    return new Value(elementLoc, elementType);
	}
    }
private:
    Expr base_;
    Expr index_;
}

class SliceExpr: ExprBase
{
    this(Language lang, Expr base, Expr start, Expr end)
    {
	super(lang);
	base_ = base;
	start_ = start;
	end_ = end;
    }
    override {
	string toString()
	{
	    return base_.toString ~ "["
		~ start_.toString ~ ".."
		~ end_.toString ~ "]";
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
		minIndex = aTy.indexBase(0);
		maxIndex = minIndex + aTy.count(0);
		elementType = aTy.elementType;
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

	    Value start = start_.eval(sc, state).toValue(state);
	    if (!start.type.isIntegerType)
		throw new EvalException(
		    "Expected integer for slice expression");
	    long si = state.readInteger(start.loc.readValue(state));
	    if (si < minIndex || si >= maxIndex)
		throw new EvalException(
		    format("Index %d out of array bounds", si));

	    Value end = end_.eval(sc, state).toValue(state);
	    if (!end.type.isIntegerType)
		throw new EvalException(
		    "Expected integer for slice expression");
	    long ei = state.readInteger(end.loc.readValue(state));
	    if (ei < minIndex || ei > maxIndex)
		throw new EvalException(
		    format("Index %d out of array bounds", ei));

	    if (ei < si)
		throw new EvalException(
		    format("End index %d less than start index %d",
			   ei, si));

	    si -= minIndex;
	    ei -= minIndex;

	    if (!baseLoc.hasAddress(state))
		throw new EvalException(
		    "Can't create a slice of something not in memory");

	    auto addr = baseLoc.address(state) + si * elementType.byteWidth;
	    auto len = ei - si;

	    ubyte[] val;
	    val.length = 2 * state.pointerWidth;
	    state.writeInteger(len, val[0..state.pointerWidth]);
	    state.writeInteger(addr, val[state.pointerWidth..$]);

	    return new Value(new ConstantLocation(val),
			     new DArrayType(lang_, elementType,
					    2 * state.pointerWidth));
	}
    }
private:
    Expr base_;
    Expr start_;
    Expr end_;
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

class CallExpr: ExprBase
{
    this(Language lang, Expr func, Expr[] args)
    {
	super(lang);
	func_ = func;
	args_ = args;
    }
    override {
	string toString()
	{
	    string s;
	    s = func_.toString ~ "(";
	    foreach (i, arg; args_) {
		if (i > 0)
		    s ~= ", ";
		s ~= arg.toString;
	    }
	    s ~= ")";
	    return s;
	}
	DebugItem eval(Scope sc, MachineState state)
	{
	    Value func = func_.eval(sc, state).toValue(state);
	    auto fTy = cast(FunctionType) func.type;
	    if (!fTy) {
		auto pTy = cast(PointerType) func.type;
		if (!pTy)
		    throw new EvalException("Can't call a non-function");
		fTy = cast(FunctionType) pTy.baseType;
		if (!fTy)
		    throw new EvalException("Can't call a non-function");
	    }

	    Type[] argTypes = fTy.argumentTypes;
	    
	    if (argTypes.length != args_.length)
		throw new EvalException(
		    format("%d arguments expected for function call",
			   argTypes.length));

	    Value[] args;
	    args.length = args_.length;
	    foreach (i, arg; args_) {
		auto argVal = arg.eval(sc, state).toValue(state);
		if (argTypes[i].coerce(state, argVal))
		    args[i] = argVal;
		else
		    throw new EvalException("Can't convert argument values");
	    }
		
	    return state.call(func.loc.address(state), fTy.returnType, args);
	}
    }
private:
    Expr func_;
    Expr[] args_;
}
