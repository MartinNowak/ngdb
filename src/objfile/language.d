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

module objfile.language;

version(tangobos) import std.compat;
import std.string;
import std.ctype;
import std.stdio;

import objfile.debuginfo;
import machine.machine;

interface Language
{
    string enumType(string baseType);
    string structureType(string baseType);
    string unionType(string baseType);
    string pointerType(string baseType);
    string referenceType(string baseType);
    bool isStringType(Type type);
    string stringConstant(MachineState state, Type type, Location loc);
    string namespaceSeparator();
    string charConstant(int ch);
    string structConstant(string);
    string arrayConstant(string);
    Expr parseExpr(string s);
}

class CLikeLanguage: Language
{
    override {
	string enumType(string baseType)
	{
	    return "enum " ~ baseType;
	}
	string structureType(string baseType)
	{
	    return "struct " ~ baseType;
	}
	string unionType(string baseType)
	{
	    return "union " ~ baseType;
	}
	string pointerType(string baseType)
	{
	    return baseType ~ "*";
	}
	string referenceType(string baseType)
	{
	    return baseType ~ "&";
	}
	bool isStringType(Type type)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt) {
		return pt.baseType.isCharType;
	    }
	    return false;
	}
	string stringConstant(MachineState state, Type type, Location loc)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt) {
		ulong p = state.readInteger(loc.readValue(state));
		return _stringConstant(state, p, 0);
	    }
	    return "";
	}
        string namespaceSeparator()
	{
	    return "::";
	}
	string charConstant(int ch)
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
	string structConstant(string s)
	{
	    return format("{%s}", s);
	}
	string arrayConstant(string s)
	{
	    return format("{%s}", s);
	}
	Expr parseExpr(string s)
	{
	    auto lex = new CLikeLexer(s);
	    auto e = expr(lex);
	    auto tok = lex.nextToken;
	    if (tok.id != "EOF")
		return unexpected(tok);
	    return e;
	}
    }

    string _stringConstant(MachineState state, ulong p, size_t len)
    {
	string sv;
	bool zt = (len == 0);
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
		b = state.readMemory(p++, 1);
		c = cast(char) b[0];
		if (c) {
		    if (isprint(c)) {
			sv ~= c;
		    } else {
			if (c in specials)
			    sv ~= specials[c];
			else
			    sv ~= std.string.format("%02x", c);
		    }
		}
		more = zt ? c != 0 : --len > 0;
	    }
	    sv ~= "\"";
	} catch (Exception e) {
	    sv = "";
	}
	return sv;
    }

    Expr unexpected(Token tok)
    {
	writefln("%s", tok.parent_.source);
	for (uint i = 0; i < tok.start; i++)
	    writef(" ");
	for (uint i = tok.start; i < tok.end; i++)
	    writef("^");
	writefln("");
	throw new EvalException(format("Unexpected token '%s'", tok.value));
	return null;
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
	    auto e2 = expr(lex);
	    if (!e2)
		return null;
	    return new CommaExpr(this, e, e2);
	}
	lex.pushBack(tok);
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
		e2 = new IntegerBinaryExpr!("*", "multiply")(this, e, e2);
		break;
	    case "/=":
		e2 = new IntegerBinaryExpr!("/", "divide")(this, e, e2);
		break;
	    case "%=":
		e2 = new IntegerBinaryExpr!("%", "modulus")(this, e, e2);
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
		return unexpected(tok);
	    }
	    return new AssignExpr(this, e, e2);
	}
	lex.pushBack(tok);
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
	    auto e2 = expr(lex);
	    if (!e2)
		return null;
	    tok = lex.nextToken;
	    if (tok.id != ":")
		return unexpected(tok);
	    auto e3 = conditionalExpr(lex);
	    return new IfElseExpr(this, e, e2, e3);
	}
	lex.pushBack(tok);
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
	    auto e2 = andandExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("||", "logical or")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
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
	    auto e2 = orExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("&&", "logical and")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
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
	    auto e2 = xorExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("|", "bitwise or")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
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
	    auto e2 = andExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("^", "bitwise exclusive or")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
	return e;
    }
    Expr andExpr(Lexer lex)
    {
	/*
	 * AndExpression:
	 *	CmpExpression
	 *	AndExpression ^ CmpExpression
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
	    auto e2 = andExpr(lex);
	    if (!e2)
		return null;
	    e = new IntegerBinaryExpr!("&", "bitwise and")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
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
	lex.pushBack(tok);
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
	    auto e2 = addExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "<<")
		e = new IntegerBinaryExpr!("<<", "left shift")(this, e, e2);
	    else
		e = new IntegerBinaryExpr!(">>", "right shift")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
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
	    auto e2 = mulExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "+")
		e = new AddExpr(this, e, e2);
	    else
		e = new SubtractExpr(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
	return e;
    }
    Expr mulExpr(Lexer lex)
    {
	/*
	 * MulExpression:
	 *	UnaryExpression
	 *	MulExpression * UnaryExpression
	 *	MulExpression / UnaryExpression
	 *	MulExpression % UnaryExpression
	 *
	 * eliminating left recursion:
	 *
	 * MulExpression:
	 *	UnaryExpression MulExpression2
	 * MulExpression2:
	 *	* UnaryExpression MulExpression2
	 *	/ UnaryExpression MulExpression2
	 *	% UnaryExpression MulExpression2
	 *	empty
	 */
	auto e = unaryExpr(lex);
	if (!e)
	    return null;
	auto tok = lex.nextToken;
	while (tok.id == "*" || tok.id == "/" || tok.id == "%") {
	    auto e2 = unaryExpr(lex);
	    if (!e2)
		return null;
	    if (tok.id == "*")
		e = new IntegerBinaryExpr!("*", "multiply")(this, e, e2);
	    else if (tok.id == "/")
		e = new IntegerBinaryExpr!("/", "divide")(this, e, e2);
	    else
		e = new IntegerBinaryExpr!("%", "remainder")(this, e, e2);
	    tok = lex.nextToken;
	}
	lex.pushBack(tok);
	return e;
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
	    auto e = unaryExpr(lex);
	    auto one = new NumericExpr(this, "1");
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
	lex.pushBack(tok);
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
		tok = lex.nextToken;
		if (tok.id != "identifier")
		    unexpected(tok);
		e = new MemberExpr(this, e, (cast(IdentifierToken) tok).value);
	    } else if (tok.id == "->") {
		tok = lex.nextToken;
		if (tok.id != "identifier")
		    unexpected(tok);
		e = new PointsToExpr(this, e, (cast(IdentifierToken) tok).value);
	    } else if (tok.id == "++" || tok.id == "--") {
		auto one = new NumericExpr(this, "1");
		if (tok.id == "++")
		    e = new AddExpr(this, e, one);
		else
		    e = new SubtractExpr(this, e, one);
		e = new PostIncrementExpr(this, tok.id, e);
	    } else if (tok.id == "[") {
		auto e2 = assignExpr(lex);
		tok = lex.nextToken;
		if (tok.id != "]")
		    return unexpected(tok);
		e = new IndexExpr(this, e, e2);
	    } else {
		lex.pushBack(tok);
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
	if (tok.id == "identifier")
	    return new VariableExpr(this, tok.value);
	if (tok.id == "number")
	    return new NumericExpr(this, tok.value);
	if (tok.id == "(") {
	    Expr e = expr(lex);
	    tok = lex.nextToken;
	    if (tok.id != ")")
		return unexpected(tok);
	    return e;
	}
	return unexpected(tok);
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
}

class CPlusPlusLanguage: CLikeLanguage
{
    override {
	string structureType(string baseType)
	{
	    return baseType;
	}
    }
}

class DLanguage: CLikeLanguage
{
    override {
	string structureType(string baseType)
	{
	    return baseType;
	}
	string referenceType(string baseType)
	{
	    return "ref " ~ baseType;
	}
	bool isStringType(Type type)
	{
	    if (super.isStringType(type))
		return true;

	    DArrayType at = cast(DArrayType) type;
	    if (!at)
		return false;
	    return at.baseType.isCharType;
	}
	string stringConstant(MachineState state, Type type, Location loc)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt)
		return super.stringConstant(state, type, loc);

	    /*
	     * Assume the representation is two pointer-sized
	     * quantities - the length followed by the base pointer.
	     */
	    ubyte[] val = loc.readValue(state);
	    return _stringConstant(
		state,
		state.readInteger(val[state.pointerWidth..$]),
		state.readInteger(val[0..state.pointerWidth]));
	}
        string namespaceSeparator()
	{
	    return ".";
	}
	string arrayConstant(string s)
	{
	    return format("[%s]", s);
	}
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

class NumberToken: Token
{
    this(Lexer parent, uint start, uint end)
    {
	super(parent, start, end);
    }
    string id()
    {
	return "number";
    }
}

class Lexer
{
    this(string s)
    {
	source_ = s;
	next_ = 0;
    }

    string source()
    {
	return source_;
    }

    Token nextToken()
    {
	uint tokStart = next_;
	char c;

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

	    return new IdentifierToken(this, tokStart, next_);
	}

	if (isdigit(c)) {
	    /*
	     * Allow 0xNNN for hex or 0NNN for octal
	     */
	    bool ishex = false;
	    bool isoctal = false;
	    if (c == '0' && next_ < source_.length) {
		c = nextChar;
		if (c != 'x' && c != 'X' && !isdigit(c)) {
		    next_--;
		    return new NumberToken(this, tokStart, next_);
		}
		if (isdigit(c)) {
		    if (c > '7')
			return new ErrorToken(this, tokStart, next_);
		    isoctal = true;
		} else {
		    ishex = true;
		}
	    }
	    for (;;) {
		if (next_ == source_.length)
		    break;
		c = nextChar;
		if (ishex) {
		    if (!isxdigit(c)) {
			next_--;
			break;
		    }
		} else {
		    if (!isdigit(c)) {
			next_--;
			break;
		    }
		    if (isoctal && c > '7')
			return new ErrorToken(this, tokStart, next_);
		}
	    }
	    if (next_ < source_.length) {
		c = nextChar;
		if (c != 'u' && c != 'U')
		    next_--;
	    }
	    return new NumberToken(this, tokStart, next_);
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
	    }

	    toks = matchingToks;
	    if (toks.length == 0) {
		next_ = tokStart + 1;
		return new ErrorToken(this, tokStart, next_);
	    }

	    if (toks.length == 1) {
		string t = toks[0];
		return new Token(this, tokStart, next_);
	    }

	    if (next_ == source_.length) {
		return new ErrorToken(this, tokStart, next_);
	    }

	    c = nextChar;

	    opindex++;
	}
    }

    void pushBack(Token tok)
    {
	next_ = tok.start_;
    }

    char nextChar()
    {
	if (next_ < source_.length)
	    return source_[next_++];
	else
	    return 0;
    }

    abstract string[] tokens();

    string source_;
    uint next_;
}

class CLikeLexer: Lexer
{
    this(string s)
    {
	super(s);
    }

    static this()
    {
	tokens_ = [
	    "/",
	    "/=",
	    ".",
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
    }

    override {
	string[] tokens()
	{
	    return tokens_;
	}
    }

    static string[] tokens_;
}

class DLexer: Lexer
{
    this(string s)
    {
	super(s);
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
    }

    override {
	string[] tokens()
	{
	    return tokens_;
	}
    }

    static string[] tokens_;
}
