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

module types;

class Type
{
	abstract char[] name();
}

class IntegerType: Type
{
	this(bool isSigned, uint bitWidth)
	{
		isSigned_ = isSigned;
		bitWidth_ = bitWidth;
	}

	bool isSigned()
	{
		return isSigned_;
	}

	uint bitWidth()
	{
		return bitWidth_;
	}

	override
	{
		char[] name()
		{
			char[] result;
			if (isSigned())
				result = "uint";
			else
				result = "int";
			result ~= std.string.toString(biWidth());
			return result;
		}
	}

private:
	bool isSigned_;
	int bitWidth_;
}

class PointerType: Type
{
	this(Type baseType)
	{
		baseType_ = baseType;
	}

	Type baseType()
	{
		return baseType_;
	}

	override
	{
		char[] name()
		{
			return baseType().name() ~ "*";
		}
	}

private:
	Type baseType_;
}
