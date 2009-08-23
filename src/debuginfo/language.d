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

module debuginfo.language;

version(tangobos) import std.compat;
import std.string;
import std.ctype;
import std.stdio;
import std.c.stdlib;

import debuginfo.debuginfo;
import machine.machine;
import target.target;

class Language
{
    private this()
    {
	voidType_ = new VoidType(this);
    }

    Type voidType()
    {
	return voidType_;
    }
    Type integerType(string name, bool isSigned, uint byteWidth)
    {
	scope IntegerType t = new IntegerType(this, name, isSigned, byteWidth);
	auto p = t in integerTypes_;
	if (p)
	    return *p;
	auto ty = new IntegerType(this, name, isSigned, byteWidth);
	integerTypes_[ty] = ty;
	return ty;
    }
    Type charType(string name, bool isSigned, uint byteWidth)
    {
	scope CharType t = new CharType(this, name, isSigned, byteWidth);
	auto p = t in charTypes_;
	if (p)
	    return *p;
	auto ty = new CharType(this, name, isSigned, byteWidth);
	charTypes_[ty] = ty;
	return ty;
    }
    Type booleanType(string name, uint byteWidth)
    {
	scope BooleanType t = new BooleanType(this, name, byteWidth);
	auto p = t in booleanTypes_;
	if (p)
	    return *p;
	auto ty = new BooleanType(this, name, byteWidth);
	booleanTypes_[ty] = ty;
	return ty;
    }
    Type floatType(string name, uint byteWidth)
    {
	scope FloatType t = new FloatType(this, name, byteWidth);
	auto p = t in floatTypes_;
	if (p)
	    return *p;
	auto ty = new FloatType(this, name, byteWidth);
	floatTypes_[ty] = ty;
	return ty;
    }
    abstract bool isStringType(Type type);

    abstract string renderEnumType(string baseType);
    abstract string renderStructureType(string baseType);
    abstract string renderUnionType(string baseType);
    abstract string renderPointerType(string baseType);
    abstract string renderPointerToArray(string baseType, string dims);
    abstract string renderPointerToFunction(string baseType, string args);
    abstract string renderVarargs(string args);
    abstract string renderReferenceType(string baseType);
    abstract string renderStringConstant(MachineState state, Type type, Location loc);
    abstract string renderNamespaceSeparator();
    abstract string renderCharConstant(int ch);
    abstract string renderStructConstant(string);
    abstract string renderArrayConstant(string);
    abstract string renderNullPointer();

    abstract Expr parseExpr(string s, Scope sc);

private:
    Type voidType_;
    Type integerTypes_[Type];
    Type charTypes_[Type];
    Type booleanTypes_[Type];
    Type floatTypes_[Type];
}

class CLikeLanguage: Language
{
    static CLikeLanguage instance;
    private this()
    {
    }
    static this()
    {
	instance = new CLikeLanguage;
    }
    override {
	bool isStringType(Type type)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt)
		return pt.baseType.isCharType;

	    ArrayType at = cast(ArrayType) type;
	    if (at)
		return at.baseType.isCharType;

	    return false;
	}

	string renderEnumType(string baseType)
	{
	    return "enum " ~ baseType;
	}
	string renderStructureType(string baseType)
	{
	    return "struct " ~ baseType;
	}
	string renderUnionType(string baseType)
	{
	    return "union " ~ baseType;
	}
	string renderPointerType(string baseType)
	{
	    return baseType ~ "*";
	}
	string renderPointerToArray(string baseType, string dims)
	{
	    return baseType ~ "(*)" ~ dims;
	}
	string renderPointerToFunction(string baseType, string args)
	{
	    return baseType ~ "(*)(" ~ args ~ ")";
	}
	string renderVarargs(string args)
	{
	    if (args.length)
		return args ~ ", ...";
	    return "...";
	}
	string renderReferenceType(string baseType)
	{
	    return baseType ~ "&";
	}
	string renderStringConstant(MachineState state, Type type, Location loc)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt) {
		ulong p = state.readInteger(loc.readValue(state));
		loc = new MemoryLocation(p, ~0);
		return _stringConstant(state, loc, 0, true);
	    }
	    ArrayType at = cast(ArrayType) type;
	    if (at)
		return _stringConstant(state, loc, at.byteWidth, false);
	    return "";
	}
        string renderNamespaceSeparator()
	{
	    return "::";
	}
	string renderCharConstant(int ch)
	{
	    string specials[char] = [
		'\0': "\\0",
		'\a': "\\a",
		'\b': "\\b",
		'\f': "\\f",
		'\n': "\\n",
		'\r': "\\r",
		'\t': "\\t",
		'\v': "\\v"];
	    if (ch in specials || isprint(ch)) {
		string res = " '";
		if (ch in specials)
		    res ~= specials[ch];
		else
		    res ~= cast(char) ch;
		res ~= "'";
		return res;
	    }
	    return "";
	}
	string renderStructConstant(string s)
	{
	    return format("{%s}", s);
	}
	string renderArrayConstant(string s)
	{
	    return format("{%s}", s);
	}
	string renderNullPointer()
	{
	    return "NULL";
	}

	Expr parseExpr(string s, Scope sc)
	{
	    auto lex = new CLikeLexer(s, sc);
	    auto e = expr(lex);
	    auto tok = lex.nextToken;
	    if (tok.id != "EOF")
		throw unexpected(tok);
	    return e;
	}
    }

    string _stringConstant(MachineState state, Location loc, size_t len,
			   bool zt)
    {
	string sv;
	uint off = 0;
	bool more;
	string specials[char] = [
	    '\0': "\\0",
	    '\a': "\\a",
	    '\b': "\\b",
	    '\f': "\\f",
	    '\n': "\\n",
	    '\r': "\\r",
	    '\t': "\\t",
	    '\v': "\\v"];

	try {
	    ubyte[] b;
	    char c;
	    sv = "\"";
	    more = zt ? true : len > 0;
	    while (more) {
		auto bloc = loc.subrange(off++, 1, state);
		c = cast(char) state.readInteger(bloc.readValue(state));
		if (c || !zt) {
		    if (isprint(c)) {
			sv ~= c;
		    } else {
			if (c in specials)
			    sv ~= specials[c];
			else
			    sv ~= std.string.format("\\x%02x", c);
		    }
		}
		more = zt ? c != 0 : --len > 0;
	    }
	    sv ~= "\"";
	} catch (TargetException e) {
	    sv = "";
	}
	return sv;
    }

    Exception error(Token tok, string message)
    {
	writefln("%s", tok.parent_.source);
	for (uint i = 0; i < tok.start; i++)
	    writef(" ");
	if (tok.end > tok.start)
	    for (uint i = tok.start; i < tok.end; i++)
		writef("^");
	else
	    writef("^");
	writefln("");
	return new EvalException(message);
    }
    Exception unexpected(Token tok)
    {
	if (cast(EOFToken) tok)
	    return error(tok, "Unexpected end of expression");
	else
	    return error(tok, format("Unexpected token '%s'", tok.value));
    }
    Expr expr(Lexer lex)
    {
	/*
	 * Expression:
	 *	AssignExpression
	 *	AssignExpression , Expression
	 */
	auto e = assignExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	if (tok.id == "EOF")
	    return e;
	if (tok.id == ",") {
	    lex.consume;
	    auto e2 = expr(lex);
	    if (!e2)
		return null;
	    return new CommaExpr(this, e, e2);
	}
	return e;
    }
    Expr assignExpr(Lexer lex)
    {
	/*
	 * AssignExpression:
	 *	ConditionalExpression
	 *	ConditionalExpression = AssignExpression
	 *	ConditionalExpression += AssignExpression
	 *	ConditionalExpression -= AssignExpression
	 *	ConditionalExpression *= AssignExpression
	 *	ConditionalExpression /= AssignExpression
	 *	ConditionalExpression %= AssignExpression
	 *	ConditionalExpression &= AssignExpression
	 *	ConditionalExpression |= AssignExpression
	 *	ConditionalExpression ^= AssignExpression
	 *	ConditionalExpression <<= AssignExpression
	 *	ConditionalExpression >>= AssignExpression
	 */
	auto e = conditionalExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	if (isAssignToken(tok.id)) {
	    lex.consume;
	    auto e2 = assignExpr(lex);
	    if (!e2)
		return null;
	    switch (tok.id) {
	    case "=":
		return new AssignExpr(this, e, e2);
	    case "+=":
		e2 = new AddExpr(this, e, e2);
		break;
	    case "-=":
		e2 = new SubtractExpr(this, e, e2);
		break;
	    case "*=":
		e2 = new NumericBinaryExpr!("*", "multiply")(this, e, e2);
		break;
	    case "/=":
		e2 = new NumericBinaryExpr!("/", "divide")(this, e, e2);
		break;
	    case "%=":
		e2 = new NumericBinaryExpr!("%", "modulus")(this, e, e2);
		break;
	    case "&=":
		e2 = new IntegerBinaryExpr!("&", "bitwise and")(this, e, e2);
		break;
	    case "|=":
		e2 = new IntegerBinaryExpr!("|", "bitwise or")(this, e, e2);
		break;
	    case "^=":
		e2 = new IntegerBinaryExpr!("^", "bitwise exclusive or")(this, e, e2);
		break;
	    case "<<=":
		e2 = new IntegerBinaryExpr!("<<", "left shift")(this, e, e2);
		break;
	    case ">>=":
		e2 = new IntegerBinaryExpr!(">>", "right shift")(this, e, e2);
		break;
	    default:
		throw unexpected(tok);
	    }
	    return new AssignExpr(this, e, e2);
	}
	return e;
    }
    Expr conditionalExpr(Lexer lex)
    {
	/*
	 * ConditionalExpression:
	 *	OrOrExpression
	 *	OrOrExpression ? Expression : ConditionalExpression
	 */
	auto e = ororExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	if (tok.id == "?") {
	    lex.consume;
	    auto e2 = expr(lex);
	    if (!e2)
		return null;
	    tok = lex.nextToken;
	    if (tok.id != ":")
		throw unexpected(tok);
	    lex.consume;
	    auto e3 = conditionalExpr(lex);
	    return new IfElseExpr(this, e, e2, e3);
	}
	return e;
    }
    Expr ororExpr(Lexer lex)
    {
	/*
	 * OrOrExpression:
	 *	AndAndExpression
	 *	OrOrExpression || AndAndExpression
	 *
	 * eliminating left recursion:
	 *
	 * OrOrExpression:
	 *	AndAndExpression OrOrExpression2
	 * OrOrExpression2:
	 *	|| AndAndExpression OrOrExpression2
	 *	empty
	 */
	auto e = andandExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "||") {
	    lex.consume;
	    auto e2 = andandExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("||", "logical or")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr andandExpr(Lexer lex)
    {
	/*
	 * AndAndExpression:
	 *	OrExpression
	 *	AndAndExpression && OrExpression
	 *
	 * eliminating left recursion:
	 *
	 * AndAndExpression:
	 *	OrExpression AndAndExpression2
	 * AndAndExpression2:
	 *	&& OrExpression AndAndExpression2
	 *	empty
	 */
	auto e = orExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "&&") {
	    lex.consume;
	    auto e2 = orExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("&&", "logical and")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr orExpr(Lexer lex)
    {
	/*
	 * OrExpression:
	 *	XorExpression
	 *	OrExpression | XorExpression
	 *
	 * eliminating left recursion:
	 *
	 * OrExpression:
	 *	XorExpression OrExpression2
	 * OrExpression2:
	 *	| XorExpression OrExpression2
	 *	empty
	 */
	auto e = xorExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "|") {
	    lex.consume;
	    auto e2 = xorExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("|", "bitwise or")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr xorExpr(Lexer lex)
    {
	/*
	 * XorExpression:
	 *	AndExpression
	 *	XorExpression ^ AndExpression
	 *
	 * eliminating left recursion:
	 *
	 * XorExpression:
	 *	AndExpression XorExpression2
	 * XorExpression2:
	 *	^ AndExpression XorExpression2
	 *	empty
	 */
	auto e = andExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "^") {
	    lex.consume;
	    auto e2 = andExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("^", "bitwise exclusive or")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr andExpr(Lexer lex)
    {
	/*
	 * AndExpression:
	 *	CmpExpression
	 *	AndExpression & CmpExpression
	 *
	 * eliminating left recursion:
	 *
	 * AndExpression:
	 *	CmpExpression AndExpression2
	 * AndExpression2:
	 *	& CmpExpression AndExpression2
	 *	empty
	 */
	auto e = cmpExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "&") {
	    lex.consume;
	    auto e2 = andExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("&", "bitwise and")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr cmpExpr(Lexer lex)
    {
	/*
	 * CmpExpression:
	 *	EqualExpression
	 *	RelExpression
	 *
	 * EqualExpression:
	 *	ShiftExpression
	 *	ShiftExpression == ShiftExpression
	 *	ShiftExpression != ShiftExpression

	 * RelExpression:
	 *	ShiftExpression
	 *	ShiftExpression < ShiftExpression
	 *	ShiftExpression <= ShiftExpression
	 *	ShiftExpression > ShiftExpression
	 *	ShiftExpression >= ShiftExpression
	 */
	auto e = shiftExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	if (tok.id == "==" || tok.id == "!="
	    || tok.id == "<" || tok.id == "<="
	    || tok.id == ">" || tok.id == ">=") {
	    lex.consume;
	    auto e2 = shiftExpr(lex);
	    if (!e2)
		return null;
	    switch (tok.id) {
	    case "==":
		e = new IntegerBinaryExpr!("==", "equals")(this, e, e2);
		break;
	    case "!=":
		e = new IntegerBinaryExpr!("!=", "not equals")(this, e, e2);
		break;
	    case "<":
		e = new IntegerBinaryExpr!("<", "less than")(this, e, e2);
		break;
	    case "<=":
		e = new IntegerBinaryExpr!("<=", "less than or equals")(this, e, e2);
		break;
	    case ">":
		e = new IntegerBinaryExpr!(">", "greater than")(this, e, e2);
		break;
	    case ">=":
		e = new IntegerBinaryExpr!(">=", "greater than or equals")(this, e, e2);
		break;
	    default:
		assert(false);
	    }
	}
	return e;
    }
    Expr shiftExpr(Lexer lex)
    {
	/*
	 * ShiftExpression:
	 *	AddExpression
	 *	ShiftExpression << AddExpression
	 *	ShiftExpression >> AddExpression
	 *
	 * eliminating left recursion:
	 *
	 * ShiftExpression:
	 *	AddExpression ShiftExpression2
	 * ShiftExpression2:
	 *	<< AddExpression ShiftExpression2
	 *	>> AddExpression ShiftExpression2
	 *	empty
	 */
	auto e = addExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "<<" || tok.id == ">>") {
	    lex.consume;
	    auto e2 = addExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "<<")
		e = new IntegerBinaryExpr!("<<", "left shift")(this, e, e2);
	    else
		e = new IntegerBinaryExpr!(">>", "right shift")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr addExpr(Lexer lex)
    {
	/*
	 * AddExpression:
	 *	MulExpression
	 *	AddExpression + MulExpression
	 *	AddExpression + MulExpression
	 *
	 * eliminating left recursion:
	 *
	 * AddExpression:
	 *	MulExpression AddExpression2
	 * AddExpression2:
	 *	+ MulExpression AddExpression2
	 *	- MulExpression AddExpression2
	 *	empty
	 */
	auto e = mulExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "+" || tok.id == "-") {
	    lex.consume;
	    auto e2 = mulExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "+")
		e = new AddExpr(this, e, e2);
	    else
		e = new SubtractExpr(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr mulExpr(Lexer lex)
    {
	/*
	 * MulExpression:
	 *	CastExpression
	 *	MulExpression * CastExpression
	 *	MulExpression / CastExpression
	 *	MulExpression % CastExpression
	 *
	 * eliminating left recursion:
	 *
	 * MulExpression:
	 *	CastExpression MulExpression2
	 * MulExpression2:
	 *	* CastExpression MulExpression2
	 *	/ CastExpression MulExpression2
	 *	% CastExpression MulExpression2
	 *	empty
	 */
	auto e = castExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "*" || tok.id == "/" || tok.id == "%") {
	    lex.consume;
	    auto e2 = castExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "*")
		e = new NumericBinaryExpr!("*", "multiply")(this, e, e2);
	    else if (tok.id == "/")
		e = new NumericBinaryExpr!("/", "divide")(this, e, e2);
	    else
		e = new NumericBinaryExpr!("%", "remainder")(this, e, e2);
	    tok = lex.nextToken;
	}
	return e;
    }
    Expr castExpr(Lexer lex)
    {
	/*
	 * CastExpresion:
	 *	UnaryExpression
	 *	( TypeName ) CastExpression
	 */
	auto tok = lex.nextToken;
	if (tok.id == "(") {
	    lex.consume;
	    auto ty = typeName(lex);
	    if (!ty) {
		lex.pushBack(tok);
		return unaryExpr(lex);
	    }
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    auto e = castExpr(lex);
	    return new CastExpr(this, ty, e);
	} else {
	    return unaryExpr(lex);
	}
    }
    Expr unaryExpr(Lexer lex)
    {
	/*
	 * UnaryExpression:
	 *	PostfixExpression
	 *	& UnaryExpression
	 *	++ UnaryExpression
	 *	-- UnaryExpression
	 *	* UnaryExpression
	 *	- UnaryExpression
	 *	+ UnaryExpression
	 *	! UnaryExpression
	 *	~ UnaryExpression
	 *	sizeof UnaryExpression
	 *	sizeof ( TypeName )
	 */
	auto tok = lex.nextToken;
	if (tok.id == "++" || tok.id == "--") {
	    lex.consume;
	    auto e = unaryExpr(lex);
	    auto one = new IntegerConstantExpr(this, "1");
	    Expr e2;
	    if (tok.id == "++")
		e2 = new AddExpr(this, e, one);
	    else
		e2 = new SubtractExpr(this, e, one);
	    return new AssignExpr(this, e, e2);
	}
	if (tok.id == "&"
	    || tok.id == "*" || tok.id == "-" || tok.id == "+"
	    || tok.id == "!" || tok.id == "~") {
	    lex.consume;
	    auto e = unaryExpr(lex);
	    if (tok.id == "&")
		return new AddressOfExpr(this, e);
	    if (tok.id == "*")
		return new DereferenceExpr(this, e);
	    if (tok.id == "-")
		return new NegateExpr(this, e);
	    if (tok.id == "+")
		return e;
	    if (tok.id == "!")
		return new LogicalNegateExpr(this, e);
	    if (tok.id == "~")
		return new ComplementExpr(this, e);
	    assert(false);
	}
	if (tok.id == "sizeof") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id == "(") {
		lex.consume;
		auto ty = typeName(lex);
		if (ty) {
		    tok = lex.nextToken;
		    if (tok.id != ")")
			throw unexpected(tok);
		    lex.consume;
		    return new SizeofTypeExpr(this, ty);
		} else {
		    lex.pushBack(tok);
		}
	    }
	    auto e = unaryExpr(lex);
	    return new SizeofExpr(this, e);
	}
	return postfixExpr(lex);
    }
    Expr postfixExpr(Lexer lex)
    {
	/*
	 * PostfixExpression:
	 *	PrimaryExpression
	 *	PostfixExpression . Identifier
	 *	PostfixExpression -> Identifier
	 *	PostfixExpression ++
	 *	PostfixExpression --
	 *	PostfixExpression ( )
	 *	PostfixExpression ( ArgumentList )
	 *	PostfixExpression [ AssignExpression ]
	 *
	 *
	 * eliminating left recursion
	 *
	 * PostfixExpression:
	 *	PrimaryExpression PostfixExpression2
	 *
	 * PostfixExpression2:
	 *	. Identifier PostfixExpression2
	 *	-> Identifier PostfixExpression2
	 *	++ PostfixExpression2
	 *	-- PostfixExpression2
	 *	( ) PostfixExpression2
	 *	( ArgumentList ) PostfixExpression2
	 *	[ AssignExpression ] PostfixExpression2
	 *	empty
	 */
	auto e = primaryExpr(lex);
	for (auto tok = lex.nextToken; ; tok = lex.nextToken) {
	    if (tok.id == ".") {
		lex.consume;
		tok = lex.nextToken;
		if (tok.id != "identifier")
		    throw unexpected(tok);
		lex.consume;
		e = new MemberExpr(this, e, (cast(IdentifierToken) tok).value);
	    } else if (tok.id == "->") {
		lex.consume;
		tok = lex.nextToken;
		if (tok.id != "identifier")
		    throw unexpected(tok);
		lex.consume;
		e = new PointsToExpr(this, e, (cast(IdentifierToken) tok).value);
	    } else if (tok.id == "++" || tok.id == "--") {
		lex.consume;
		auto one = new IntegerConstantExpr(this, "1");
		if (tok.id == "++")
		    e = new AddExpr(this, e, one);
		else
		    e = new SubtractExpr(this, e, one);
		e = new PostIncrementExpr(this, tok.id, e);
	    } else if (tok.id == "[") {
		lex.consume;
		auto e2 = assignExpr(lex);
		tok = lex.nextToken;
		if (tok.id != "]")
		    throw unexpected(tok);
		lex.consume;
		e = new IndexExpr(this, e, e2);
	    } else {
		return e;
	    }
	    /*
	     * XXX Handle function call
	     */
	}
    }
    Expr primaryExpr(Lexer lex)
    {
	/*
	 * PrimaryExpression:
	 *	Identifier
	 *	Number
	 *	( Expression )
	 */
	auto tok = lex.nextToken;
	if (tok.id == "identifier") {
	    lex.consume;
	    return new VariableExpr(this, tok.value);
	}
	if (tok.id == "int literal") {
	    lex.consume;
	    return new IntegerConstantExpr(this, tok.value);
	}
	if (tok.id == "float literal") {
	    lex.consume;
	    return new FloatConstantExpr(this, tok.value);
	}
	if (tok.id == "char literal") {
	    lex.consume;
	    return new CharConstantExpr(this,
					(cast(CharToken) tok).ch,
					charType("char", true, 1));
	}
	if (tok.id == "string literal") {
	    lex.consume;
	    auto cTy = charType("char", true, 1);
	    auto aTy = new ArrayType(this, cTy);
	    auto s = tok.value ~ "\0";
	    aTy.addDim(0, s.length);
	    return new StringConstantExpr(this, s, aTy);
	}
	if (tok.id == "(") {
	    lex.consume;
	    Expr e = expr(lex);
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    return e;
	}
	throw unexpected(tok);
    }
    Type typeName(Lexer lex)
    {
	/*
	 * TypeName:
	 *	SpecifierQualifierList
	 *	SpecifierQualifierList AbstractDeclarator
	 */
	auto ty = specifierQualifierList(lex);
	if (ty) {
	    auto tr = new nullTransform(ty);
	    auto ntr = abstractDeclarator(tr, lex);
	    ty = ntr.transform;
	}
	return ty;
    }
    Type specifierQualifierList(Lexer lex)
    {
	/*
	 * SpecifierQualifierList:
	 *	TypeSpecifier SpecifierQualifierListOpt
	 *	TypeQualifier SpecifierQualifierListOpt
	 *
	 * TypeQualifier:
	 *	const
	 *	restrict
	 *	volatile
	 *
	 * TypeSpecifier:
	 *	void
	 *	char
	 *	short
	 *	int
	 *	long
	 *	float
	 *	double
	 *	signed
	 *	unsigned
	 *	StructOrUnionSpecifier
	 *	EnumSpecifier
	 *	TypedefName
	 *
	 * TypedefName:
	 *	identifier
	 */
	string[] quals;
	string[] specs;
	Type ty;

	void twoTypes(Token tok)
	{
	    error(tok, "two or more date types in type declaration");
	}

	Token lastTok;
    sqlist: for (;;) {
	    auto tok = lex.nextToken;
	    lastTok = tok;
	    switch (tok.id) {
	    case "const":
	    case "restrict":
	    case "volatile":
		lex.consume;
		bool seenQual = false;
		foreach (q; quals)
		    if (q == tok.id)
			seenQual = true;
		if (!seenQual)
		    quals ~= tok.id;
		break;

	    case "void":
	    case "char":
	    case "short":
	    case "int":
	    case "long":
	    case "float":
	    case "double":
	    case "signed":
	    case "unsigned":
		lex.consume;
		if (ty)
		    twoTypes(lastTok);
		specs ~= tok.id;
		break;

	    case "struct":
	    case "union":
		if (ty || specs.length > 0)
		    twoTypes(lastTok);
		ty = structOrUnionSpecifier(lex);
		break;

	    case "enum":
		if (ty)
		    twoTypes(lastTok);
		ty = enumSpecifier(lex);
		break;

	    case "identifier":
		if (ty)
		    twoTypes(lastTok);
		lex.consume;
		if (lex.sc.lookupTypedef(tok.value, ty))
		    break;
		throw new EvalException(format("Can't find typedef %s", tok.value));
	    default:
		break sqlist;
	    }
	}
	if (!ty && specs.length == 0 && quals.length == 0)
	    return null;
	if (!ty) {
	    /*
	     * Try to make sense of the specifier list
	     */
	    specs = specs.sort;
	    if (specs == ["void"])
		ty = voidType;
	    else if (specs == ["char"]
		     || specs == ["char", "signed"])
		ty = charType("char", true, 1);
	    else if (specs == ["char", "unsigned"])
		ty = charType("unsigned char", false, 1);
	    else if (specs == ["short"]
		     || specs == ["short", "signed"]
		     || specs == ["int", "short"]
		     || specs == ["int", "short", "signed"])
		ty = integerType("short", true, 2);
	    else if (specs == ["short", "unsigned"]
		     || specs == ["int", "short", "unsigned"])
		ty = integerType("unsigned short", false, 2);
	    else if (specs == ["int"]
		     || specs == ["signed"]
		     || specs == ["int", "signed"])
		ty = integerType("int", true, 4);
	    else if (specs == ["unsigned"]
		     || specs == ["int", "unsigned"])
		ty = integerType("unsigned int", false, 4);
	    else if (specs == ["long"]
		     || specs == ["long", "signed"]
		     || specs == ["int", "long"]
		     || specs == ["int", "long", "signed"])
		ty = integerType("long", true, 4); // XXX 64bit
	    else if (specs == ["long", "unsigned"]
		     || specs == ["int", "long", "unsigned"])
		ty = integerType("unsigned long", false, 4); // XXX 64bit
	    else if (specs == ["long", "long"]
		     || specs == ["long", "long", "signed"]
		     || specs == ["int", "long", "long"]
		     || specs == ["int", "long", "long", "signed"])
		ty = integerType("long long", true, 8);
	    else if (specs == ["long", "long", "unsigned"]
		     || specs == ["int", "long", "long", "unsigned"])
		ty = integerType("unsigned long long", false, 8);
	    else if (specs == ["float"])
		ty = floatType("float", 4);
	    else if (specs == ["double"])
		ty = floatType("double", 8);
	    else if (specs == ["double", "long"])
		ty = floatType("long double", 12);
	    else
		error(lastTok, "unrecognised type specifiers");
	} else {
	    /*
	     * Remove any qualifiers from our list that are already present
	     * in the type we parsed (e.g. if we parsed a typedef to a type
	     * with qualifiers).
	     */
	    for (auto modTy = cast(ModifierType) ty; modTy;
		 modTy = cast(ModifierType) modTy.baseType) {
		string[] newQuals;
		foreach (q; quals)
		    if (q != modTy.modifier)
			newQuals ~= q;
		quals = newQuals;
	    }
	}
	foreach (q; quals)
	    ty = ty.modifierType(q);
	return ty;
    }
    Type structOrUnionSpecifier(Lexer lex)
    {
	/*
	 * StructOrUnionSpecifier:
	 *	StructOrUnion identifier
	 *
	 * StructOrUnion:
	 *	struct
	 *	union
	 */
	auto tok = lex.nextToken;
	if (tok.id == "struct") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != "identifier")
		throw unexpected(tok);
	    lex.consume;
	    Type ty;
	    if (lex.sc.lookupStruct(tok.value, ty))
		return ty;
	    throw new EvalException(format("Can't find struct %s", tok.value));
	} else if (tok.id == "union") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != "identifier")
		throw unexpected(tok);
	    lex.consume;
	    Type ty;
	    if (lex.sc.lookupUnion(tok.value, ty))
		return ty;
	    throw new EvalException(format("Can't find union %s", tok.value));
	} else {
	    throw unexpected(tok);
	}
	return null;
    }
    Type enumSpecifier(Lexer lex)
    {
	/*
	 * EnumSpecifier:
	 *	enum identifier
	 */
	return null;
    }
    typeTransform abstractDeclarator(typeTransform tr, Lexer lex)
    {
	/*
	 * AbstractDeclarator:
	 *	Pointer
	 *	PointerOpt DirectAbstractDeclarator
	 *
	 * Pointer:
	 *	* TypeQualifierListOpt
	 *	* TypeQualifierListOpt Pointer
	 */
	auto tok = lex.nextToken;
	while (tok.id == "*") {
	    lex.consume;
	    tr = new pointerTransform(tr, typeQualifierList(lex));
	    tok = lex.nextToken;
	}
	auto ntr = directAbstractDeclarator(tr, lex);
	if (ntr)
	    return ntr;
	return tr;
    }
    typeTransform directAbstractDeclarator(typeTransform tr, Lexer lex)
    {
	/*
	 * DirectAbstractDeclarator:
	 *	( AbstractDeclarator )
	 *	DirectAbstractDeclaratorOpt [ TypeQualifierListOpt
	 *		AssignmentExpression ]
	 *	DirectAbstractDeclaratorOpt [ * ] // not supported
	 *	DirectAbstractDeclaratorOpt ( ParameterTypeListOpt )
	 *
	 * left factoring
	 *
	 * DirectAbstractDeclarator:
	 *	( AbstractDeclarator ) DirectAbstractDeclaratorTail
	 *	DirectAbstractDeclaractor2 DirectAbstractDeclaratorTail
	 *
	 * DirectAbstractDeclarator2:
	 *	( ParameterTypeListOpt )
	 *	[ TypeQualifierListOpt AssignmentExpression ]

	 * DirectAbstractDeclaratorTail:
	 *	epsilon
	 *	DirectAbstractDeclaractor2 DirectAbstractDeclaratorTail
	 *
	 * ParameterTypeList:
	 *	ParameterList
	 *	ParameterList , ...
	 *
	 * ParameterList:
	 *	ParameterDeclaration
	 *	ParameterList , ParameterDeclaration
	 *
	 * ParameterDeclaration:
	 *	DeclarationSpecifiers Declarator
	 *	DeclarationSpecifiers AbstractDeclaratorOpt
	 *
	 * DeclarationSpecifiers:
	 *	StorageClassSpecifier DeclarationSpecifiersOpt
	 *	TypeSpecifier DeclarationSpecifiersOpt
	 *	TypeQualifier DeclarationSpecifiersOpt
	 *	FunctionSpecifier DeclarationSpecifiersOpt
	 *
	 * StorageClassSpecifier:
	 *	typedef
	 *	extern
	 *	static
	 *	auto
	 *	register
	 *
	 * FunctionSpecifier:
	 *	inline
	 *
	 * Declarator:
	 *	DirectDeclarator
	 *	Pointer DirectDeclarator
	 */
	auto tok = lex.nextToken;
	auto ptr = new pendingTransform(tr);
	typeTransform ntr = ptr;
	if (tok.id == "(") {
	    lex.consume;
	    tok = lex.nextToken;
	    /*
	     * See if this token can start an abstractDeclarator
	     */
	    switch (tok.id) {
	    case "*":
	    case "[":
	    case "(":
		ntr = abstractDeclarator(ptr, lex);
		if (!ntr)
		    return tr;
		break;
	    default:
		ptr.pend_ = functionParameters(ptr.pend_, lex);
	    }
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    tok = lex.nextToken;
	}

	/*
	 * At this point, we have parsed any ( AbstractDeclarator ) prefix
	 * and we have zero or more array/function suffixes.
	 * XXX just arrays to start with.
	 */
	while (tok.id == "[" || tok.id == "(") {
	    if (tok.id == "[") {
		/*
		 * We ought to parse a full assignment expression here.
		 */
		lex.consume;
		tok = lex.nextToken;
		if (tok.id != "int literal")
		    throw unexpected(tok);
		lex.consume;
		ptr.pend_ = new arrayTransform(this, ptr.pend_,
					       strtoul(toStringz(tok.value),
						       null, 0));
		tok = lex.nextToken;
		if (tok.id != "]")
		    throw unexpected(tok);
		lex.consume;
		tok = lex.nextToken;
	    } else if (tok.id == "(") {
		lex.consume;
		ptr.pend_ = functionParameters(ptr.pend_, lex);
		tok = lex.nextToken;
		if (tok.id != ")")
		    throw unexpected(tok);
		lex.consume;
		tok = lex.nextToken;
	    }
	}
	return ntr;
    }
    typeTransform functionParameters(typeTransform tr, Lexer lex)
    {
	/*
	 * ParameterTypeList:
	 *	ParameterList
	 *	ParameterList , ...
	 *
	 * ParameterList:
	 *	Parameter
	 *	Parameter , ParameterList
	 *
	 * Parameter:
	 *	Type
	 */
	auto tok = lex.nextToken;
	Type[] argTypes;
	bool isVarargs;

	tok = lex.nextToken;
	while (tok.id != ")") {
	    if (tok.id == "...") {
		lex.consume;
		isVarargs = true;
		break;
	    }
	    argTypes ~= typeName(lex);
	    tok = lex.nextToken;
	    if (tok.id == ",") {
		lex.consume;
		tok = lex.nextToken;
		if (tok.id == ")")
		    throw unexpected(tok);
		continue;
	    } else if (tok.id != ")") {
		throw unexpected(tok);
	    }
	}
	return new functionTransform(this, tr, isVarargs, argTypes);
    }
    string[] typeQualifierList(Lexer lex)
    {
	/*
	 * TypeQualifierList:
	 *	TypeQualifier
	 *	TypeQualifierList TypeQualifier
	 */
	auto tok = lex.nextToken;
	string[] quals;
	for (;;) {
	    switch (tok.id) {
	    case "const":
	    case "restrict":
	    case "volatile":
		lex.consume;
		bool seenQual = false;
		foreach (q; quals)
		    if (q == tok.id)
			seenQual = true;
		if (!seenQual)
		    quals ~= tok.id;
		break;
	    default:
		return quals;
	    }
	}
    }
    bool isAssignToken(string s)
    {
	switch (s) {
	case "=":
	case "+=":
	case "-=":
	case "*=":
	case "/=":
	case "%=":
	case "&=":
	case "|=":
	case "^=":
	case "<<=":
	case ">>=":
	    return true;
	default:
	    return false;
	}
    }

    interface typeTransform
    {
	Type transform();
    }
    static class nullTransform: typeTransform
    {
	this(Type ty)
	{
	    ty_ = ty;
	}
	Type transform()
	{
	    return ty_;
	}
	Type ty_;
    }
    static class pendingTransform: typeTransform
    {
	this(typeTransform tr)
	{
	    pend_ = tr;
	}
	Type transform()
	{
	    return pend_.transform;
	}
	typeTransform pend_;
    }
    static class pointerTransform: typeTransform
    {
	this(typeTransform base, string[] quals)
	{
	    base_ = base;
	    quals_ = quals;
	}
	Type transform()
	{
	    auto ty = base_.transform;
	    ty = ty.pointerType(4);	// XXX 64bit
	    foreach (q; quals_)
		ty = ty.modifierType(q);
	    return ty;
	}
	typeTransform base_;
	string[] quals_;
    }
    static class arrayTransform: typeTransform
    {
	this(Language lang, typeTransform base, uint dim)
	{
	    lang_ = lang;
	    base_ = base;
	    dim_ = dim;
	}
	Type transform()
	{
	    auto ty = new ArrayType(lang_, base_.transform);
	    ty.addDim(0, dim_);
	    return ty;
	}
	Language lang_;
	typeTransform base_;
	uint dim_;
    }
    static class functionTransform: typeTransform
    {
	this(Language lang, typeTransform base, bool isVarargs,
	     Type[] argTypes)
	{
	    lang_ = lang;
	    base_ = base;
	    isVarargs_ = isVarargs;
	    argTypes_ = argTypes;
	}
	Type transform()
	{
	    auto ty = new FunctionType(lang_);
	    ty.returnType = base_.transform;
	    ty.varargs = isVarargs_;
	    foreach (arg; argTypes_)
		ty.addArgumentType(arg);
	    return ty;
	}
	Language lang_;
	typeTransform base_;
	bool isVarargs_;
	Type[] argTypes_;
    }
}

class CPlusPlusLanguage: CLikeLanguage
{
    static CPlusPlusLanguage instance;
    private this()
    {
    }
    static this()
    {
	instance = new CPlusPlusLanguage;
    }
    override {
	string renderStructureType(string baseType)
	{
	    return baseType;
	}
    }
}

class DLanguage: CLikeLanguage
{
    static DLanguage instance;
    private this()
    {
    }
    static this()
    {
	instance = new DLanguage;
    }
    override {
	bool isStringType(Type type)
	{
	    if (super.isStringType(type))
		return true;

	    DArrayType at = cast(DArrayType) type;
	    if (!at)
		return false;
	    return at.baseType.isCharType;
	}

	string renderStructureType(string baseType)
	{
	    return baseType;
	}
	string renderReferenceType(string baseType)
	{
	    return "ref " ~ baseType;
	}
	string renderPointerToArray(string baseType, string dims)
	{
	    return baseType ~ dims ~ "*";
	}
	string renderPointerToFunction(string baseType, string args)
	{
	    return baseType ~ " function(" ~ args ~ ")";
	}
	string renderVarargs(string args)
	{
	    if (args.length)
		return args ~ " ...";
	    return "...";
	}
	string renderStringConstant(MachineState state, Type type, Location loc)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt)
		return super.renderStringConstant(state, type, loc);

	    ArrayType at = cast(ArrayType) type;
	    if (at)
		return super.renderStringConstant(state, type, loc);

	    /*
	     * Assume the representation is two pointer-sized
	     * quantities - the length followed by the base pointer.
	     */
	    ubyte[] val = loc.readValue(state);
	    ulong ptr = state.readInteger(val[state.pointerWidth..$]);
	    ulong len = state.readInteger(val[0..state.pointerWidth]);
	    if (len > 256) len = 256;	// XXX
	    loc = new MemoryLocation(ptr, len);
	    return _stringConstant(state, loc, len, false);
	}
        string renderNamespaceSeparator()
	{
	    return ".";
	}
	string renderArrayConstant(string s)
	{
	    return format("[%s]", s);
	}
	string renderNullPointer()
	{
	    return "null";
	}

	Expr parseExpr(string s, Scope sc)
	{
	    auto lex = new DLexer(s, sc);
	    auto e = expr(lex);
	    auto tok = lex.nextToken;
	    if (tok.id != "EOF")
		throw unexpected(tok);
	    return e;
	}
    }
    Expr castExpr(Lexer lex)
    {
	/*
	 * CastExpresion:
	 *	UnaryExpression
	 *	cast ( TypeName ) CastExpression
	 */
	auto tok = lex.nextToken;
	if (tok.id == "cast") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != "(")
		throw unexpected(tok);
	    lex.consume;
	    auto ty = typeName(lex);
	    if (!ty)
		return unaryExpr(lex);
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    auto e = castExpr(lex);
	    return new CastExpr(this, ty, e);
	} else {
	    return unaryExpr(lex);
	}
    }
    Expr unaryExpr(Lexer lex)
    {
	/*
	 * UnaryExpression:
	 *	PostfixExpression
	 *	& UnaryExpression
	 *	++ UnaryExpression
	 *	-- UnaryExpression
	 *	* UnaryExpression
	 *	- UnaryExpression
	 *	+ UnaryExpression
	 *	! UnaryExpression
	 *	~ UnaryExpression
	 */
	auto tok = lex.nextToken;
	if (tok.id == "++" || tok.id == "--") {
	    lex.consume;
	    auto e = unaryExpr(lex);
	    auto one = new IntegerConstantExpr(this, "1");
	    Expr e2;
	    if (tok.id == "++")
		e2 = new AddExpr(this, e, one);
	    else
		e2 = new SubtractExpr(this, e, one);
	    return new AssignExpr(this, e, e2);
	}
	if (tok.id == "&"
	    || tok.id == "*" || tok.id == "-" || tok.id == "+"
	    || tok.id == "!" || tok.id == "~") {
	    lex.consume;
	    auto e = unaryExpr(lex);
	    if (tok.id == "&")
		return new AddressOfExpr(this, e);
	    if (tok.id == "*")
		return new DereferenceExpr(this, e);
	    if (tok.id == "-")
		return new NegateExpr(this, e);
	    if (tok.id == "+")
		return e;
	    if (tok.id == "!")
		return new LogicalNegateExpr(this, e);
	    if (tok.id == "~")
		return new ComplementExpr(this, e);
	    assert(false);
	}
	return postfixExpr(lex);
    }
    Expr postfixExpr(Lexer lex)
    {
	/*
	 * PostfixExpression:
	 *	PrimaryExpression
	 *	PostfixExpression . Identifier
	 *	PostfixExpression ++
	 *	PostfixExpression --
	 *	PostfixExpression ( )
	 *	PostfixExpression ( ArgumentList )
	 *	PostfixExpression [ AssignExpression ]
	 *	PostfixExpression [ AssignExpression .. AssignExpression ]
	 *
	 * eliminating left recursion
	 *
	 * PostfixExpression:
	 *	PrimaryExpression PostfixExpression2
	 *
	 * PostfixExpression2:
	 *	. Identifier PostfixExpression2
	 *	-> Identifier PostfixExpression2
	 *	++ PostfixExpression2
	 *	-- PostfixExpression2
	 *	( ) PostfixExpression2
	 *	( ArgumentList ) PostfixExpression2
	 *	[ AssignExpression ] PostfixExpression2
	 *	empty
	 */
	auto e = primaryExpr(lex);
	for (auto tok = lex.nextToken; ; tok = lex.nextToken) {
	    if (tok.id == ".") {
		lex.consume;
		tok = lex.nextToken;
		if (tok.id != "identifier")
		    throw unexpected(tok);
		lex.consume;
		auto idtok = cast(IdentifierToken) tok;
		switch (idtok.value) {
		case "ptr":
		    e = new PtrExpr(this, e);
		    break;
		case "length":
		    e = new LengthExpr(this, e);
		    break;
		case "sizeof":
		    e = new SizeofExpr(this, e);
		    break;
		default:
		    e = new DMemberExpr(this, e, idtok.value);
		}
	    } else if (tok.id == "++" || tok.id == "--") {
		lex.consume;
		auto one = new IntegerConstantExpr(this, "1");
		if (tok.id == "++")
		    e = new AddExpr(this, e, one);
		else
		    e = new SubtractExpr(this, e, one);
		e = new PostIncrementExpr(this, tok.id, e);
	    } else if (tok.id == "[") {
		lex.consume;
		auto e2 = assignExpr(lex);
		tok = lex.nextToken;
		if (tok.id == "..") {
		    lex.consume;
		    auto e3 = assignExpr(lex);
		    e = new SliceExpr(this, e, e2, e3);
		} else {
		    e = new IndexExpr(this, e, e2);
		}
		tok = lex.nextToken;
		if (tok.id != "]")
		    throw unexpected(tok);
		lex.consume;
	    } else {
		return e;
	    }
	    /*
	     * XXX Handle function call
	     */
	}
    }
    Expr primaryExpr(Lexer lex)
    {
	/*
	 * PrimaryExpression:
	 *	Identifier
	 *	Number
	 *	( Expression )
	 */
	auto tok = lex.nextToken;
	if (tok.id == "identifier") {
	    lex.consume;
	    return new VariableExpr(this, tok.value);
	}
	if (tok.id == "this") {
	    lex.consume;
	    return new VariableExpr(this, "this");
	}
	if (tok.id == "int literal") {
	    lex.consume;
	    return new IntegerConstantExpr(this, tok.value);
	}
	if (tok.id == "float literal") {
	    lex.consume;
	    return new FloatConstantExpr(this, tok.value);
	}
	if (tok.id == "char literal") {
	    lex.consume;
	    return new CharConstantExpr(this,
					(cast(CharToken) tok).ch,
					charType("char", false, 1));
	}
	if (tok.id == "string literal") {
	    lex.consume;
	    auto cTy = charType("char", false, 1);
	    auto aTy = new ArrayType(this, cTy);
	    auto s = tok.value;
	    aTy.addDim(0, s.length);
	    return new StringConstantExpr(this, s, aTy);
	}
	auto ty = typeName(lex);
	if (ty) {
	    tok = lex.nextToken;
	    if (tok.id != ".")
		throw unexpected(tok);
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != "identifier")
		throw unexpected(tok);
	    lex.consume;
	    if (tok.value != "sizeof")
		throw unexpected(tok);
	    return new SizeofTypeExpr(this, ty);
	}
	if (tok.id == "(") {
	    lex.consume;
	    Expr e = expr(lex);
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    return e;
	}
	throw unexpected(tok);
    }
    Type typeName(Lexer lex)
    {
	/*
	 * Type:
	 *	BasicType
	 *	BasicType Declarator2
	 *
	 * Declarator2:
	 *	BasicType2 Declarator2
	 *	( Declarator2 )
	 *	( Declarator2 ) DeclaratorSuffixes
	 *
	 * BasicType2:
	 *	*
	 *	[ ]
	 *	[ Expression ]
	 *	[ Expression .. Expression ]
	 *	[ Type ]
	 *	delegate Parameters
	 *	function Parameters
	 *
	 * DeclaratorSuffixes:
	 *	DeclaratorSuffix
	 *	DeclaratorSuffix DeclaratorSuffixes
	 *
	 * DeclaratorSuffix
	 *	[ ]
	 *	[ Expression ]
	 *	[ Type ]
	 *	TemplateParameterList_opt Parameters
	 */
	Type ty = basicType(lex);
	if (ty) {
	    auto tok = lex.nextToken;
	    switch (tok.id) {
	    case "*":
	    case "[":
	    case "delegate":
	    case "function":
	    case "(":
		auto tr = new nullTransform(ty);
		ty = declarator2(tr, lex).transform;
		break;
	    default:
	    }
	}
	return ty;
    }
    Type basicType(Lexer lex)
    {
	/*
	 * BasicType:
	 *	bool
	 *	byte
	 *	ubyte
	 *	short
	 *	ushort
	 *	int
	 *	uint
	 *	long
	 *	ulong
	 *	char
	 *	wchar
	 *	dchar
	 *	float
	 *	double
	 *	real
	 *	ifloat
	 *	idouble
	 *	ireal
	 *	cfloat
	 *	cdouble
	 *	creal
	 *	void
	 *	.IdentifierList
	 *	IdentifierList
	 *	Typeof
	 *	Typeof . IdentifierList
	 *
	 * Typeof:
	 *	typeof ( Expression )
	 *	typeof ( return )
	 */
	auto tok = lex.nextToken;
	switch (tok.id) {
	case "bool":
	    lex.consume;
	    return booleanType(tok.id, 1);
	case "byte":
	    lex.consume;
	    return integerType(tok.id, true, 1);
	case "ubyte":
	    lex.consume;
	    return integerType(tok.id, false, 1);
	case "short":
	    lex.consume;
	    return integerType(tok.id, true, 2);
	case "ushort":
	    lex.consume;
	    return integerType(tok.id, false, 2);
	case "int":
	    lex.consume;
	    return integerType(tok.id, true, 4);
	case "uint":
	    lex.consume;
	    return integerType(tok.id, false, 4);
	case "long":
	    lex.consume;
	    return integerType(tok.id, true, 8);
	case "ulong":
	    lex.consume;
	    return integerType(tok.id, false, 8);
	case "char":
	    lex.consume;
	    return charType(tok.id, false, 1);
	case "wchar":
	    lex.consume;
	    return charType(tok.id, false, 2);
	case "dchar":
	    lex.consume;
	    return charType(tok.id, false, 4);
	case "float":
	    lex.consume;
	    return floatType(tok.id, 4);
	case "double":
	    lex.consume;
	    return floatType(tok.id, 8);
	case "real":
	    lex.consume;
	    return floatType(tok.id, 12);
	case "ifloat":
	case "idouble":
	case "ireal":
	case "cfloat":
	case "cdouble":
	case "creal":
	    lex.consume;
	    throw new EvalException("complex types not supported");
	case "void":
	    lex.consume;
	    return voidType;
	case ".":
	    lex.consume;
	    // fall through
	case "identifier":
	    auto ids = join(identifierList(lex), ".");
	    Type ty;
	    if (lex.sc.lookupStruct(ids, ty))
		return ty;
	    if (lex.sc.lookupUnion(ids, ty))
		return ty;
	    if (lex.sc.lookupTypedef(ids, ty))
		return ty;
	    throw new EvalException(format("Can't find type %s", ids));

	case "typeof":
	    throw new EvalException("typeof not supported");

	default:
	    return null;
	}
    }
    typeTransform declarator2(typeTransform tr, Lexer lex)
    {
	/*
	 * Declarator2:
	 *	BasicType2 Declarator2
	 *	( Declarator2 )
	 *	( Declarator2 ) DeclaratorSuffixes
	 */
	auto tok = lex.nextToken;
	if (tok.id == "(") {
	    /*
	     * Try for a C-Style declaraction, e.g.:
	     *
	     *		int (*)[3];
	     */
	    lex.consume;
	    auto ptr = new pendingTransform(tr);
	    tr = declarator2(ptr, lex);
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id == "[")
		ptr.pend_ = declaratorSuffixes(ptr.pend_, lex);
	} else {
	    tr = basicType2(tr, lex);
	    tok = lex.nextToken;
	    switch (tok.id) {
	    case "*":
	    case "[":
	    case "delegate":
	    case "function":
		tr = declarator2(tr, lex);
		break;
	    default:
	    }
	}
	return tr;
    }
    typeTransform declaratorSuffixes(typeTransform tr, Lexer lex)
    {
	/*
	 * DeclaratorSuffixes:
	 *	DeclaratorSuffix
	 *	DeclaratorSuffix DeclaratorSuffixes
	 */
	tr = declaratorSuffix(tr, lex);
	auto tok = lex.nextToken;
	while (tok.id == "[") {
	    tr = declaratorSuffix(tr, lex);
	    tok = lex.nextToken;
	}
	return tr;
    }
    typeTransform declaratorSuffix(typeTransform tr, Lexer lex)
    {
	/*
	 * DeclaratorSuffix
	 *	[ ]
	 *	[ Expression ]
	 *	[ Type ]
	 *	TemplateParameterList_opt Parameters
	 */
	auto tok = lex.nextToken;
	if (tok.id != "[")
	    throw unexpected(tok);
	/*
	 * For now, just support [ ] and [ number ].
	 */
	lex.consume;
	tok = lex.nextToken;
	if (tok.id == "]") {
	    lex.consume;
	    return new darrayTransform(this, tr);
	}
	if (tok.id != "int literal")
	    throw unexpected(tok);
	lex.consume;
	tr = new arrayTransform(this, tr,
				strtoul(toStringz(tok.value), null, 0));
	tok = lex.nextToken;
	if (tok.id != "]")
	    throw unexpected(tok);
	lex.consume;
	return tr;
    }
    typeTransform basicType2(typeTransform tr, Lexer lex)
    {
	/*
	 * BasicType2:
	 *	*
	 *	[ ]
	 *	[ Expression ]
	 *	[ Expression .. Expression ]
	 *	[ Type ]
	 *	delegate Parameters
	 *	function Parameters
	 */
	auto tok = lex.nextToken;
	switch (tok.id) {
	case "*":
	    lex.consume;
	    return new pointerTransform(tr, null);
	case "[":
	    /*
	     * For now, just support [ ] and [ number ].
	     */
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id == "]") {
		lex.consume;
		return new darrayTransform(this, tr);
	    }
	    if (tok.id != "int literal")
		throw unexpected(tok);
	    lex.consume;
	    tr = new arrayTransform(this, tr,
				    strtoul(toStringz(tok.value), null, 0));
	    tok = lex.nextToken;
	    if (tok.id != "]")
		throw unexpected(tok);
	    lex.consume;
	    return tr;
	case "delegate":
	    throw new EvalException("delegate not supported yet");
	case "function":
	    lex.consume;
	    tr = functionParameters(tr, lex);
	    return new pointerTransform(tr, null);
	}
    }
    typeTransform functionParameters(typeTransform tr, Lexer lex)
    {
	/*
	 * Parameters:
	 *	( ParameterList )
	 *	( )
	 *
	 * ParameterList:
	 *	Parameter
	 *	Parameter , ParameterList
	 *	Parameter ...
	 *	...
	 *
	 * Parameter:
	 *	Type
	 *	InOut Type
	 */
	auto tok = lex.nextToken;
	Type[] argTypes;
	bool isVarargs;

	if (tok.id != "(")
	    throw unexpected(tok);
	lex.consume;
	tok = lex.nextToken;
	if (tok.id == "...") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != ")")
		throw unexpected(tok);
	    lex.consume;
	    return new functionTransform(this, tr, true, null);
	}
	while (tok.id != ")") {
	    if (tok.id == "in"
		|| tok.id == "out"
		|| tok.id == "ref"
		|| tok.id == "lazy") {
		lex.consume;
	    }
	    argTypes ~= typeName(lex);
	    tok = lex.nextToken;
	    if (tok.id == "...") {
		lex.consume;
		isVarargs = true;
		tok = lex.nextToken;
	    }
	    if (tok.id == ",") {
		lex.consume;
		tok = lex.nextToken;
		if (tok.id == ")")
		    throw unexpected(tok);
		continue;
	    } else if (tok.id != ")") {
		throw unexpected(tok);
	    }
	}
	tok = lex.nextToken;
	if (tok.id != ")")
	    throw unexpected(tok);
	lex.consume;
	return new functionTransform(this, tr, isVarargs, argTypes);
    }
    string[] identifierList(Lexer lex)
    {
	string[] ids;
	auto tok = lex.nextToken;
	if (tok.id != "identifier")
	    throw unexpected(tok);
	lex.consume;
	ids ~= tok.value;
	tok = lex.nextToken;
	while (tok.id == ".") {
	    lex.consume;
	    tok = lex.nextToken;
	    if (tok.id != "identifier")
		throw unexpected(tok);
	    ids ~= tok.value;
	    tok = lex.nextToken;
	}
	return ids;
    }
    static class darrayTransform: typeTransform
    {
	this(Language lang, typeTransform base)
	{
	    lang_ = lang;
	    base_ = base;
	}
	Type transform()
	{
	    auto ty = new DArrayType(lang_, base_.transform, 8); // XXX 64bit
	    return ty;
	}
	Language lang_;
	typeTransform base_;
    }
}

private:

class Token
{
    this(Lexer parent, uint start, uint end)
    {
	parent_ = parent;
	start_ = start;
	end_ = end;
    }

    string id()
    {
	return value;
    }
    string value()
    {
	return parent_.source_[start_..end_];
    }
    uint start()
    {
	return start_;
    }
    uint end()
    {
	return end_;
    }

    Lexer parent_;
    uint start_;
    uint end_;
}

class EOFToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "EOF";
    }
}

class ErrorToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "error";
    }
}

class IdentifierToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "identifier";
    }
}

class IntegerToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "int literal";
    }
}

class FloatToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "float literal";
    }
}

class CharToken: Token
{
    this(Lexer parent, uint start, uint end, char ch)
    {
	super(parent, start, end);
	ch_ = ch;
    }
    string id()
    {
	return "char literal";
    }
    char ch()
    {
	return ch_;
    }
    char ch_;
}

class StringToken: Token
{
    this(Lexer parent, uint start, uint end, string s)
    {
	super(parent, start, end);
	s_ = s;
    }
    string id()
    {
	return "string literal";
    }
    string value()
    {
	return s_;
    }
    string s_;
}

class Lexer
{
    this(string s, Scope sc)
    {
	source_ = s;
	next_ = 0;
	sc_ = sc;
	tok_ = _nextToken;
    }

    string source()
    {
	return source_;
    }

    Scope sc()
    {
	return sc_;
    }

    Token nextToken()
    {
	return tok_;
    }

    void consume()
    {
	tok_ = _nextToken;
    }

    Token _nextToken()
    {
	uint tokStart = next_;
	char c;
	uint n;

	do {
	    if (next_ == source_.length)
		return new EOFToken(this, next_, next_);

	    if (isspace(c))
		tokStart++;

	    c = nextChar;
	} while (isspace(c));
	    
	if (isalpha(c) || c == '_' || c == '$') {
	    for (;;) {
		if (next_ == source_.length)
		    break;
		c = nextChar;
		if (!isalnum(c) && c != '_') {
		    next_--;
		    break;
		}
	    }

	    foreach (k; keywords) {
		if (source_[tokStart..next_] == k) {
		    return new Token(this, tokStart, next_);
		}
	    }

	    return new IdentifierToken(this, tokStart, next_);
	}

	if (isdigit(c)) {
	    /*
	     * numeric:
	     *		<integer> <integersuffix>?
	     *		<float> <floatsuffix>?
	     *
	     * integer:
	     *		0
	     *		0 x <hexdigit>+
	     *		0 <octaldigit>+
	     *		<decimaldigit>+
	     *
	     * integersuffix:
	     *		L
	     *		u
	     *		U
	     *		Lu
	     *		LU
	     *		uL
	     *		UL
	     *
	     * float:
	     *		<decimaldigit>+ .
	     *		<decimaldigit>+ . <decimaldigit>+
	     *		<decimaldigit>+ . <decimaldigit>+ <exponent>
	     *		<decimaldigit>+ <exponent>
	     *
	     * <exponent>
	     *		e <decimaldigit>+
	     *		E <decimaldigit>+
	     *		e + <decimaldigit>+
	     *		E + <decimaldigit>+
	     *		e - <decimaldigit>+
	     *		E - <decimaldigit>+
	     *
	     * floatsuffix:
	     *		f
	     *		F
	     */
	    if (c == '0') {
		if (atEOF)
		    return new IntegerToken(this, tokStart, next_);
		c = nextChar;
		if (c == 'x' || c == 'X') {
		    if (atEOF)
			return new ErrorToken(this, tokStart, next_);
		    c = nextChar;
		    if (!isxdigit(c))
			return new ErrorToken(this, tokStart, next_);
		    for (;;) {
			if (atEOF)
			    break;
			c = nextChar;
			if (!isxdigit(c)) {
			    next_--;
			    break;
			}
		    }
		} else if (isoctal(c)) {
		    for (;;) {
			if (atEOF)
			    break;
			c = nextChar;
			if (!isoctal(c)) {
			    next_--;
			    break;
			}
		    }
		    return new IntegerToken(this, tokStart, next_);
		} else {
		    next_--;
		}
	    } else {
		for (;;) {
		    if (atEOF)
			break;
		    c = nextChar;
		    if (!isdigit(c)) {
			next_--;
			break;
		    }
		}
		/*
		 * Check for floating point.
		 */
		if (!atEOF) {
		    c = nextChar;
		    if (c == '.' || c == 'e' || c == 'E') {
			if (c == '.' && !atEOF) {
			    c = nextChar;
			    if (c == '.') {
				/*
				 * This is not the decimal point we
				 * are looking for.
				 */
				next_ -= 2;
				goto parseIntSuffix;
			    }
			    for (;;) {
				if (atEOF)
				    break;
				c = nextChar;
				if (!isdigit(c)) {
				    next_--;
				    break;
				}
			    }
			} else {
			    next_--;
			}
			if (!atEOF) {
			    c = nextChar;
			    if (c == 'e' || c == 'E') {
				if (atEOF)
				    return new ErrorToken(
					this, tokStart, next_);
				c = nextChar;
				if (c == '+' || c == '-') {
				    if (atEOF)
					return new ErrorToken(
					    this, tokStart, next_);
				    c = nextChar;
				}
				if (!isdigit(c))
				    return new ErrorToken(
					this, tokStart, next_);
				for (;;) {
				    if (atEOF)
					break;
				    c = nextChar;
				    if (!isdigit(c)) {
					next_--;
					break;
				    }
				}				
			    }
			}
			if (!atEOF) {
			    c = nextChar;
			    if (c != 'f' && c != 'F' && c != 'L')
				next_--;
			}
			return new FloatToken(this, tokStart, next_);
		    } else {
			next_--;
		    }
		}
	    }
	    /*
	     * Parse integer suffix, if any.
	     */
	parseIntSuffix:
	    if (!atEOF) {
		auto t = next_;
		c = nextChar;
		if (c == 'L' || c == 'u' || c == 'U') {
		    if (!atEOF) {
			c = nextChar;
			if (c != 'L' && c != 'u' && c != 'U')
			    next_--;
		    }
		    auto suffix = source_[t..next_];
		    switch (suffix) {
		    case "L":
		    case "u":
		    case "U":
		    case "Lu":
		    case "LU":
		    case "uL":
		    case "UL":
			break;
		    default:
			next_ = t;
		    }
		} else {
		    next_--;
		}
	    }
	    return new IntegerToken(this, tokStart, next_);
	}

	bool parseEscape(out char res)
	{
	    if (atEOF)
		return false;
	    auto c = nextChar;
	    switch (c) {
	    case '?':
		c = '\?';
		break;
	    case 'a':
		c = '\a';
		break;
	    case 'b':
		c = '\b';
		break;
	    case 'f':
		c = '\f';
		break;
	    case 'n':
		c = '\n';
		break;
	    case 'r':
		c = '\r';
		break;
	    case 't':
		c = '\t';
		break;
	    case 'v':
		c = '\v';
		break;
	    case 'x':
		if (atEOF)
		    return false;
		c = nextChar;
		if (!isxdigit(c))
		    return false;
		n = fromhex(c);
		if (atEOF)
		    return false;
		c = nextChar;
		if (!isxdigit(c))
		    return false;
		n = n * 16 + fromhex(c);
		c = cast(char) n;
		break;
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
		n = c - '0';
		if (!atEOF) {
		    c = nextChar;
		    if (isoctal(c)) {
			n = 8 * n + (c - '0');
			if (!atEOF) {
			    c = nextChar;
			    if (isoctal(c))
				n = 8 * n + (c - '0');
			    else
				next_--;
			}
		    } else {
			next_--;
		    }
		}
		c = cast(char) n;
		break;
	    default:
		/*
		 * Allow \<any> to represent <any>
		 */
		break;
	    }
	    res = c;
	    return true;
	}

	if (c == '\'') {
	    /*
	     * Only allow single character constants.
	     *
	     * character:
	     *		' <quotedcharacter> '
	     *
	     * quotedcharacter:
	     *		<character>
	     *		<escape-sequence>
	     *
	     * escape-sequence:
	     *		\'
	     *		\"
	     *		\?
	     *		\\
	     *		\a
	     *		\b
	     *		\f
	     *		\n
	     *		\r
	     *		\t
	     *		\v
	     *		\x <hexdigit> <hexdigit>
	     *		\ <octaldigit>
	     *		\ <octaldigit> <octaldigit>
	     *		\ <octaldigit> <octaldigit> <octaldigit>
	     */
	    if (atEOF)
		return new ErrorToken(this, tokStart, next_);
	    c = nextChar;
	    if (c == '\'')
		return new ErrorToken(this, tokStart, next_);
	    if (c == '\\') {
		if (!parseEscape(c))
		    return new ErrorToken(this, tokStart, next_);
	    }
	    if (atEOF)
		return new ErrorToken(this, tokStart, next_);
	    if (nextChar != '\'')
		return new ErrorToken(this, tokStart, next_);
	    return new CharToken(this, tokStart, next_, c);
	}

	if (c == '"') {
	    /*
	     * string:
	     *		" <quotedcharacter>* "
	     */
	    string s;
	    if (atEOF)
		return new ErrorToken(this, tokStart, next_);
	    c = nextChar;
	    while (c != '"') {
		if (c == '\\')
		    if (!parseEscape(c))
			return new ErrorToken(this, tokStart, next_);
		s ~= c;
		if (atEOF)
		    return new ErrorToken(this, tokStart, next_);
		c = nextChar;
	    }
	    return new StringToken(this, tokStart, next_, s);
	}

	string[] toks = tokens;
	uint opindex = 0;

	for (;;) {
	    string[] matchingToks;
	    foreach (t; toks) {
		/*
		 * Keep any operator which matches this character.
		 */
		if (opindex < t.length && t[opindex] == c)
		    matchingToks ~= t;
	    }

	    /*
	     * If nothing matches and we have already matched at least
	     * one character, the previous set should have exactly one
	     * member with length equal to opindex - thats our match.
	     */
	    if (opindex > 0 && matchingToks.length == 0) {
		foreach (t; toks) {
		    if (opindex == t.length)
			matchingToks ~= t;
		}
		assert(matchingToks.length == 1);
		/*
		 * Don't consume the character which terminated the
		 * match.
		 */
		next_--;
		return new Token(this, tokStart, next_);
	    }

	    toks = matchingToks;
	    if (toks.length == 0) {
		next_ = tokStart + 1;
		return new ErrorToken(this, tokStart, next_);
	    }

	    if (toks.length == 1 && opindex == toks[0].length - 1)
		return new Token(this, tokStart, next_);

	    if (next_ == source_.length)
		return new ErrorToken(this, tokStart, next_);

	    c = nextChar;

	    opindex++;
	}
    }

    void pushBack(Token tok)
    {
	next_ = tok.start_;
	tok_ = _nextToken;
    }

    bool atEOF()
    {
	return next_ == source_.length;
    }

    char nextChar()
    {
	if (next_ < source_.length)
	    return source_[next_++];
	else
	    return 0;
    }

    bool isoctal(char c)
    {
	return c >= '0' && c <= '7';
    }

    int fromhex(char c)
    {
	if (c >= '0' && c <= '9')
	    return c - '0';
	else if (c >= 'A' && c <= 'F')
	    return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
	    return c - 'a' + 10;
	else
	    assert(false);
    }

    abstract string[] tokens();
    abstract string[] keywords();

    string source_;
    Scope sc_;
    uint next_;
    Token tok_;
}

class CLikeLexer: Lexer
{
    this(string s, Scope sc)
    {
	super(s, sc);
    }

    static this()
    {
	tokens_ = [
	    "/",
	    "/=",
	    ".",
	    "...",
	    "&",
	    "&=",
	    "&&",
	    "&&=",
	    "|",
	    "|=",
	    "||",
	    "||=",
	    "-",
	    "-=",
	    "--",
	    "->",
	    "+",
	    "+=",
	    "++",
	    "<",
	    "<=",
	    "<<",
	    "<<=",
	    ">",
	    ">=",
	    ">>",
	    ">>=",
	    "!",
	    "!=",
	    "(",
	    ")",
	    "[",
	    "]",
	    "{",
	    "}",
	    "?",
	    ",",
	    ":",
	    "=", 
	    "==",
	    "*",
	    "*=",
	    "%",
	    "%=",
	    "^",
	    "^=",
	    "~",
	    "~="
	    ];
	keywords_ = [
	    "auto",
	    "break",
	    "case",
	    "char",
	    "const",
	    "continue",
	    "default",
	    "do",
	    "double",
	    "else",
	    "enum",
	    "extern",
	    "float",
	    "for",
	    "goto",
	    "if",
	    "inline",
	    "int",
	    "long",
	    "register",
	    "restrict",
	    "return",
	    "short",
	    "signed",
	    "sizeof",
	    "static",
	    "struct",
	    "switch",
	    "typedef",
	    "union",
	    "unsigned",
	    "void",
	    "volatile",
	    "while",
	    "_Bool",
	    "_Complex",
	    "_Imaginary"
	    ];
    }

    override {
	string[] tokens()
	{
	    return tokens_;
	}
	string[] keywords()
	{
	    return keywords_;
	}
    }

    static string[] tokens_;
    static string[] keywords_;
}

class DLexer: Lexer
{
    this(string s, Scope sc)
    {
	super(s, sc);
    }

    static this()
    {
	tokens_ = [
	    "/",
	    "/=",
	    ".",
	    "..",
	    "...",
	    "&",
	    "&=",
	    "&&",
	    "&&=",
	    "|",
	    "|=",
	    "||",
	    "||=",
	    "-",
	    "-=",
	    "--",
	    "->",
	    "+",
	    "+=",
	    "++",
	    "<",
	    "<=",
	    "<<",
	    "<<=",
	    "<>",
	    "<>=",
	    ">",
	    ">=",
	    ">>=",
	    ">>>=",
	    ">>",
	    ">>>",
	    "!",
	    "!=",
	    "!<>",
	    "!<>=",
	    "!<",
	    "!<=",
	    "!>",
	    "!>=",
	    "(",
	    ")",
	    "[",
	    "]",
	    "{",
	    "}",
	    "?",
	    ",",
	    ":",
	    "$",
	    "=", 
	    "==",
	    "*",
	    "*=",
	    "%",
	    "%=",
	    "^",
	    "^=",
	    "~",
	    "~="
	    ];
	keywords_ = [
	    "abstract",
	    "alias",
	    "align",
	    "asm",
	    "assert",
	    "auto",

	    "body",
	    "bool",
	    "break",
	    "byte",

	    "case",
	    "cast",
	    "catch",
	    "cdouble",
	    "cent",
	    "cfloat",
	    "char",
	    "class",
	    "const",
	    "continue",
	    "creal",

	    "dchar",
	    "debug",
	    "default",
	    "delegate",
	    "delete",
	    "deprecated",
	    "do",
	    "double",

	    "else",
	    "enum",
	    "export",
	    "extern",

	    "false",
	    "final",
	    "finally",
	    "float",
	    "for",
	    "foreach",
	    "foreach_reverse",
	    "function",

	    "goto",

	    "idouble",
	    "if",
	    "ifloat",
	    "import",
	    "in",
	    "inout",
	    "int",
	    "interface",
	    "invariant",
	    "ireal",
	    "is",

	    "lazy",
	    "long",

	    "macro",
	    "mixin",
	    "module",

	    "new",
	    "null",

	    "out",
	    "override",

	    "package",
	    "pragma",
	    "private",
	    "protected",
	    "public",

	    "real",
	    "ref",
	    "return",

	    "scope",
	    "short",
	    "static",
	    "struct",
	    "super",
	    "switch",
	    "synchronized",

	    "template",
	    "this",
	    "throw",
	    "true",
	    "try",
	    "typedef",
	    "typeid",
	    "typeof",

	    "ubyte",
	    "ucent",
	    "uint",
	    "ulong",
	    "union",
	    "unittest",
	    "ushort",

	    "version",
	    "void",
	    "volatile",

	    "wchar",
	    "while",
	    "with"];
    }

    override {
	string[] tokens()
	{
	    return tokens_;
	}
	string[] keywords()
	{
	    return keywords_;
	}
    }

    static string[] tokens_;
    static string[] keywords_;
}
