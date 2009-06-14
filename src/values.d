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

module values;
import types;
import target;
import machine.machine;

interface Location
{
    ubyte[] read();
    void write(ubyte[]);
}

class MemoryLocation: Location
{
    this(Target target, ulong address, size_t size)
    {
    }

    override {
	ubyte[] read()
	{
	    return target_.readMemory(address_, size_);
	}

	void write(ubyte[] val)
	{
	    if (val.length != size_)
		throw new Exception("bad size for MemoryLocation.write");
	    target_.writeMemory(address_, val);
	}
    }

private:
    Target target_;
    ulong address_;
    size_t size_;
}

class RegisterLocation: Location
{
    this(MachineState state, int regno)
    {
	state_ = state;
	regno_ = regno;
    }

    override {
	ubyte[] read()
	{
	    ub val;
	    ubyte[] res;

	    val.reg = state_.getGR(regno_);
	    res[] = val.bytes[0..state_.grWidth(regno_) / 8];
	    return res;
	}

	void write(ubyte[] v)
	{
	    ub val;

	    val.reg = 0;
	    val.bytes[0..v.length] = v[];
	    state_.setGR(regno_, val.reg);
	}
    }

private:
    union ub {
	ulong reg;
	ubyte[ulong.sizeof] bytes;
    }

    MachineState state_;
    int regno_;
}

class Value
{

private:
    Location loc_;
    Type type_;
}
