/*-
 * Copyright (c) 1984, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ptrace.h	8.2 (Berkeley) 1/4/94
 * $FreeBSD: src/sys/sys/ptrace.h,v 1.28 2006/02/06 09:41:56 davidxu Exp $
 */

module sys.ptrace;
version (GDC)
import std.c.unix.unix;
else
import std.c.freebsd.freebsd;
import std.stdint;

alias int32_t lwpid_t;

enum {
	PT_TRACE_ME	= 0,	/* child declares it's being traced */
	PT_READ_I	= 1,	/* read word in child's I space */
	PT_READ_D	= 2,	/* read word in child's D space */
/* was	PT_READ_U	= 3,	 * read word in child's user structure */
	PT_WRITE_I	= 4,	/* write word in child's I space */
	PT_WRITE_D	= 5,	/* write word in child's D space */
/* was	PT_WRITE_U	= 6,	 * write word in child's user structure */
	PT_CONTINUE	= 7,	/* continue the child */
	PT_KILL		= 8,	/* kill the child process */
	PT_STEP		= 9,	/* single step the child */

	PT_ATTACH	= 10,	/* trace some running process */
	PT_DETACH	= 11,	/* stop tracing a process */
	PT_IO		= 12,	/* do I/O to/from stopped process. */
	PT_LWPINFO	= 13,	/* Info about the LWP that stopped. */
	PT_GETNUMLWPS	= 14,	/* get total number of threads */
	PT_GETLWPLIST	= 15,	/* get thread list */
	PT_CLEARSTEP	= 16,	/* turn off single step */
	PT_SETSTEP	= 17,	/* turn on single step */
	PT_SUSPEND	= 18,	/* suspend a thread */
	PT_RESUME	= 19,	/* resume a thread */

	PT_TO_SCE	= 20,
	PT_TO_SCX	= 21,
	PT_SYSCALL	= 22,

	PT_GETREGS      = 33,	/* get general-purpose registers */
	PT_SETREGS      = 34,	/* set general-purpose registers */
	PT_GETFPREGS    = 35,	/* get floating-point registers */
	PT_SETFPREGS    = 36,	/* set floating-point registers */
	PT_GETDBREGS    = 37,	/* get debugging registers */
	PT_SETDBREGS    = 38,	/* set debugging registers */
	PT_FIRSTMACH    = 64	/* for machine-specific requests */
}

struct ptrace_io_desc {
	int	piod_op;	/* I/O operation */
	void	*piod_offs;	/* child offset */
	void	*piod_addr;	/* parent offset */
	size_t	piod_len;	/* request length */
}

/*
 * Operations in piod_op.
 */
enum {
	PIOD_READ_D	= 1,	/* Read from D space */
	PIOD_WRITE_D	= 2,	/* Write to D space */
	PIOD_READ_I	= 3,	/* Read from I space */
	PIOD_WRITE_I	= 4	/* Write to I space */
}


/* Argument structure for PT_LWPINFO. */
struct ptrace_lwpinfo {
	lwpid_t	pl_lwpid;	/* LWP described. */
	int	pl_event;	/* Event that stopped the LWP. */
	int	pl_flags;	/* LWP flags. */
	sigset_t	pl_sigmask;	/* LWP signal mask */
	sigset_t	pl_siglist;	/* LWP pending signal */
};

/* Value for ptrace_lwpinfo.pl_event */
enum {
	PL_EVENT_NONE	= 0,
	PL_EVENT_SIGNAL	= 1
}

/* Value for ptrace_lwpinfo.pl_flags */
enum {
	PL_FLAG_SA	= 0x01,	/* M:N thread */
	PL_FLAG_BOUND	= 0x02	/* M:N bound thread */
}

extern (C):
	int	ptrace(int _request, pid_t _pid, char *_addr, int _data);
