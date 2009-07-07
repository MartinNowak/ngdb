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

import objfile.debuginfo;
import machine.machine;

interface Language
{
    string structureType(string baseType);
    string pointerType(string baseType);
    string referenceType(string baseType);
    bool isStringType(Type type);
    string stringConstant(MachineState state, Type type, Location loc);
    string namespaceSeparator();
}

class CLikeLanguage: Language
{
    override {
	string structureType(string baseType)
	{
	    return "struct " ~ baseType;
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
		ulong p = readInteger(loc.readValue(state));
		return _stringConstant(state, p, 0);
	    }
	    return "";
	}
        string namespaceSeparator()
	{
	    return "::";
	}
    }

    string _stringConstant(MachineState state, ulong p, size_t len)
    {
	string sv;
	bool zt = (len == 0);
	bool more;

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
		more = zt ? c != 0 : --len > 0;
	    }
	    sv ~= "\"";
	} catch (Exception e) {
	    sv = "";
	}
	return sv;
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

	    CompoundType ct = cast(CompoundType) type;
	    if (!ct)
		return false;
	    if (ct.length != 2)
		return false;
	    CompoundType.field len = ct[0];
	    if (!len.type.isIntegerType)
		return false;
	    CompoundType.field ptr = ct[1];
	    PointerType pt = cast(PointerType) ptr.type;
	    if (pt && pt.baseType.isCharType)
		return true;
	    return false;
	}
	string stringConstant(MachineState state, Type type, Location loc)
	{
	    PointerType pt = cast(PointerType) type;
	    if (pt)
		return super.stringConstant(state, type, loc);

	    CompoundType ct = cast(CompoundType) type;
	    CompoundType.field len = ct[0];
	    CompoundType.field ptr = ct[1];

	    Location lenLoc = loc.fieldLocation(len.loc);
	    Location ptrLoc = loc.fieldLocation(ptr.loc);

	    return _stringConstant(state,
				   readInteger(ptrLoc.readValue(state)),
				   readInteger(lenLoc.readValue(state)));
	}
        string namespaceSeparator()
	{
	    return ".";
	}
    }
}
