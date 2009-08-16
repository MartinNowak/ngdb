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

module endian;

interface Endian
{
    /**
     * Convert an integer in host format to machine-native format.
     */
    ulong read(ubyte[] bytes);

    /**
     * Convert an integer in host format to machine-native format.
     */
    ushort read(ushort);

    /**
     * Convert an integer in host format to machine-native format.
     */
    uint read(uint);

    /**
     * Convert an integer in host format to machine-native format.
     */
    ulong read(ulong);

    /**
     * Convert an integer in host format to machine-native format.
     */
    void write(ulong val, ubyte[] bytes);

    /**
     * Convert an integer in host format to machine-native format.
     */
    void write(ushort, out ushort);

    /**
     * Convert an integer in host format to machine-native format.
     */
    void write(uint, out uint);

    /**
     * Convert an integer in host format to machine-native format.
     */
    void write(ulong, out ulong);
}

class LittleEndian: Endian
{
    ulong read(ubyte[] bytes)
    {
	ulong value = 0;
	foreach (b; bytes.reverse)
	    value = (value << 8) | b;
	return value;
    }
    ushort read(ushort v)
    {
	ubyte* p = cast(ubyte*) &v;
	v = p[0] + (p[1] << 8);
	return v;
    }
    uint read(uint v)
    {
	ubyte* p = cast(ubyte*) &v;
	v = p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
	return v;
    }
    ulong read(ulong v)
    {
	ubyte* p = cast(ubyte*) &v;
	for (int i = 0; i < 8; i++)
	    v |= (cast(ulong) p[i]) << 8*i;
	return v;
    }
    void write(ulong val, ubyte[] bytes)
    {
	for (int i = 0; i < bytes.length; i++) {
	    bytes[i] = val & 0xff;
	    val >>= 8;
	}
    }
    void write(ushort v, out ushort res)
    {
	ubyte b[2];
	b[0] = v;
	b[1] = v >> 8;
	res = *(cast(ushort*) &b[0]);
    }
    void write(uint v, out uint res)
    {
	ubyte b[4];
	b[0] = v;
	b[1] = v >> 8;
	b[2] = v >> 16;
	b[3] = v >> 24;
	res = *(cast(uint*) &b[0]);
    }
    void write(ulong v, out ulong res)
    {
	ubyte b[8];
	b[0] = v;
	b[1] = v >> 8;
	b[2] = v >> 16;
	b[3] = v >> 24;
	b[4] = v >> 32;
	b[5] = v >> 40;
	b[6] = v >> 48;
	b[7] = v >> 56;
	res = *(cast(ulong*) &b[0]);
    }
}

class BigEndian: Endian
{
    ulong read(ubyte[] bytes)
    {
	ulong value = 0;
	foreach (b; bytes)
	    value = (value << 8) | b;
	return value;
    }
    ushort read(ushort v)
    {
	ubyte* p = cast(ubyte*) &v;
	v = p[1] + (p[0] << 8);
	return v;
    }
    uint read(uint v)
    {
	ubyte* p = cast(ubyte*) &v;
	v = p[3] + (p[2] << 8) + (p[1] << 16) + (p[0] << 24);
	return v;
    }
    ulong read(ulong v)
    {
	ubyte* p = cast(ubyte*) &v;
	for (int i = 0; i < 8; i++)
	    v = (v << 8) | p[i];
	return v;
    }
    void write(ulong val, ubyte[] bytes)
    {
	for (int i = bytes.length - 1; i >= 0; i--) {
	    bytes[i] = val & 0xff;
	    val >>= 8;
	}
    }
    void write(ushort v, out ushort res)
    {
	ubyte b[2];
	b[1] = v;
	b[0] = v >> 8;
	res = *(cast(ushort*) &b[0]);
    }
    void write(uint v, out uint res)
    {
	ubyte b[4];
	b[3] = v;
	b[2] = v >> 8;
	b[1] = v >> 16;
	b[0] = v >> 24;
	res = *(cast(uint*) &b[0]);
    }
    void write(ulong v, out ulong res)
    {
	ubyte b[8];
	b[7] = v;
	b[6] = v >> 8;
	b[5] = v >> 16;
	b[4] = v >> 24;
	b[3] = v >> 32;
	b[2] = v >> 40;
	b[1] = v >> 48;
	b[0] = v >> 56;
	res = *(cast(ulong*) &b[0]);
    }
}
