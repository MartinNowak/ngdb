/*-
 * Copyright (c) 1982, 1986, 1989, 1993, 1994
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
 *	@(#)wait.h	8.2 (Berkeley) 7/10/94
 * $FreeBSD: src/sys/sys/wait.h,v 1.22 2005/11/10 05:00:20 davidxu Exp $
 */

import std.conv : octal;
version (GDC)
import std.c.unix.unix;
else
import std.c.posix.posix;

/*
 * This file holds definitions relevant to the wait4 system call and the
 * alternate interfaces that use it (wait, wait3, waitpid).
 */

/*
 * Macros to test the exit status returned by wait and extract the relevant
 * values.
 */
const int WCOREFLAG	= octal!200;

int _WSTATUS(int x)	{ return x & octal!177; }
const int _WSTOPPED	= octal!177;		/* _WSTATUS if process is stopped */
int WIFSTOPPED(int x)	{ return _WSTATUS(x) == _WSTOPPED; }
int WSTOPSIG(int x)	{ return x >> 8; }
int WIFSIGNALED(int x)	{ return _WSTATUS(x) != _WSTOPPED && _WSTATUS(x) != 0; }
int WTERMSIG(int x)	{ return _WSTATUS(x); }
int WIFEXITED(int x)	{ return _WSTATUS(x) == 0; }
int WEXITSTATUS(int x)	{ return x >> 8; }
int WIFCONTINUED(int x)	{ return x == 0x13; }	/* 0x13 == SIGCONT */
int WCOREDUMP(int x)	{ return x & WCOREFLAG; }

int W_EXITCODE(int ret, int sig) { return (ret << 8) | sig; }
int W_STOPCODE(int sig) { return (sig << 8) | _WSTOPPED; }

/*
 * Option bits for the third argument of wait4.  WNOHANG causes the
 * wait to not hang if there are no stopped or terminated processes, rather
 * returning an error indication in this case (pid==0).  WUNTRACED
 * indicates that the caller should receive status about untraced children
 * which stop due to signals.  If children are stopped and a wait without
 * this option is done, it is as though they were still running... nothing
 * about them is returned.
 */
const int WNOHANG	= 1;	/* Don't hang in wait. */
const int WUNTRACED	= 2;	/* Tell about stopped, untraced children. */
const int WCONTINUED	= 4;	/* Report a job control continued process. */

const int WLINUXCLONE	= 0x80000000;	/* Wait for kthread spawned from linux_clone. */

/*
 * Tokens for special values of the "pid" parameter to wait4.
 */
const int WAIT_ANY	= -1;	/* any process */
const int WAIT_MYPGRP	= 0;	/* any process in my process group */

extern (C):
pid_t	wait(int *);
//pid_t	waitpid(pid_t, int *, int);
struct rusage;
pid_t	wait3(int *, int, rusage *);
pid_t	wait4(pid_t, int *, int, rusage *);
