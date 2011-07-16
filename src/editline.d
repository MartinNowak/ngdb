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

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Christos Zoulas of Cornell University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 *	@(#)histedit.h	8.2 (Berkeley) 1/3/94
 *	$NetBSD: histedit.h,v 1.32 2007/06/10 20:20:28 christos Exp $
 * $FreeBSD: stable/7/include/histedit.h 170547 2007-06-11 06:25:19Z stefanf $
 */

/*
 * histedit.h: Line editor and history interface.
 */

module editline;
import std.c.stdio;

extern (C):

/*
 * ==== Editing ====
 */

struct EditLine;

/*
 * For user-defined function interface
 */
struct LineInfo {
	char	*buffer;
	char	*cursor;
	char	*lastchar;
};

/*
 * EditLine editor function return codes.
 * For user-defined function interface
 */
enum {
    CC_NORM		= 0,
    CC_NEWLINE		= 1,
    CC_EOF		= 2,
    CC_ARGHACK		= 3,
    CC_REFRESH		= 4,
    CC_CURSOR		= 5,
    CC_ERROR		= 6,
    CC_FATAL		= 7,
    CC_REDISPLAY	= 8,
    CC_REFRESH_BEEP	= 9,
}

/*
 * Initialization, cleanup, and resetting
 */
EditLine	*el_init(const(char) *, FILE *, FILE *, FILE *);
void		 el_end(EditLine *);
void		 el_reset(EditLine *);

/*
 * Get a line, a character or push a string back in the input queue
 */
char		*el_gets(EditLine *, int *);
int		 el_getc(EditLine *, char *);
void		 el_push(EditLine *, char *);

/*
 * Beep!
 */
void		 el_beep(EditLine *);

/*
 * High level function internals control
 * Parses argc, argv array and executes builtin editline commands
 */
int		 el_parse(EditLine *, int, char **);

/*
 * Low level editline access functions
 */
int		 el_set(EditLine *, int, ...);
int		 el_get(EditLine *, int, ...);
//#if 0
//unsigned char	_el_fn_complete(EditLine *, int);
//#endif

/*
 * el_set/el_get parameters
 */
enum {
    EL_PROMPT	= 0,	/* , el_pfunc_t);		*/
    EL_TERMINAL	= 1,	/* , char *);		*/
    EL_EDITOR	= 2,	/* , char *);		*/
    EL_SIGNAL	= 3,	/* , int);			*/
    EL_BIND	= 4,	/* , char *, ..., NULL);	*/
    EL_TELLTC	= 5,	/* , char *, ..., NULL);	*/
    EL_SETTC	= 6,	/* , char *, ..., NULL);	*/
    EL_ECHOTC	= 7,	/* , char *, ..., NULL);	*/
    EL_SETTY	= 8,	/* , char *, ..., NULL);	*/
    EL_ADDFN	= 9,	/* , char *, char *	*/
				/* , el_func_t);		*/
    EL_HIST	= 10,	/* , hist_fun_t, char *);	*/
    EL_EDITMODE	= 11,	/* , int);			*/
    EL_RPROMPT	= 12,	/* , el_pfunc_t);		*/
    EL_GETCFN	= 13,	/* , el_rfunc_t);		*/
    EL_CLIENTDATA= 14,	/* , void *);			*/
    EL_UNBUFFERED= 15,	/* , int);			*/
    EL_PREP_TERM= 16,   /* , int);                      */
    EL_GETTC	= 17,	/* , char *, ..., NULL);	*/
    EL_GETFP	= 18,	/* , int, FILE **)		*/
    EL_SETFP	= 19,	/* , int, FILE *)		*/
}
const char* EL_BUILTIN_GETCFN = null;

/*
 * Source named file or $PWD/.editrc or $HOME/.editrc
 */
int		el_source(EditLine *, char *);

/*
 * Must be called when the terminal changes size; If EL_SIGNAL
 * is set this is done automatically otherwise it is the responsibility
 * of the application
 */
void		 el_resize(EditLine *);


/*
 * Set user private data.
 */
void            el_data_set    (EditLine *, void *);
void *          el_data_get    (EditLine *);

/*
 * User-defined function interface.
 */
LineInfo	*el_line(EditLine *);
int		 el_insertstr(EditLine *, const(char) *);
void		 el_deletestr(EditLine *, int);


/*
 * ==== History ====
 */

struct History;

struct HistEvent {
	int		 num;
	char	*str;
}

/*
 * History access functions.
 */
History *	history_init();
void		history_end(History *);
int		history(History *, HistEvent *, int, ...);

enum {
    H_FUNC		= 0,	/* , UTSL		*/
    H_SETSIZE		= 1,	/* , const int);	*/
    H_EVENT		= 1,	/* , const int);	*/
    H_GETSIZE		= 2,	/* , void);		*/
    H_FIRST		= 3,	/* , void);		*/
    H_LAST		= 4,	/* , void);		*/
    H_PREV		= 5,	/* , void);		*/
    H_NEXT		= 6,	/* , void);		*/
    H_CURR		= 8,	/* , const int);	*/
    H_SET		= 7,	/* , int);		*/
    H_ADD		= 9,	/* , char *);	*/
    H_ENTER		= 10,	/* , char *);	*/
    H_APPEND		= 11,	/* , char *);	*/
    H_END		= 12,	/* , void);		*/
    H_NEXT_STR		= 13,	/* , char *);	*/
    H_PREV_STR		= 14,	/* , char *);	*/
    H_NEXT_EVENT	= 15,	/* , const int);	*/
    H_PREV_EVENT	= 16,	/* , const int);	*/
    H_LOAD		= 17,	/* , char *);	*/
    H_SAVE		= 18,	/* , char *);	*/
    H_CLEAR		= 19,	/* , void);		*/
    H_SETUNIQUE		= 20,	/* , int);		*/
    H_GETUNIQUE		= 21,	/* , void);		*/
    H_DEL		= 22,	/* , int);		*/
}


/*
 * ==== Tokenization ====
 */

struct Tokenizer;

/*
 * String tokenization functions, using simplified sh(1) quoting rules
 */
Tokenizer	*tok_init(char *);
void		 tok_end(Tokenizer *);
void		 tok_reset(Tokenizer *);
int		 tok_line(Tokenizer *, LineInfo *,
		    int *, char ***, int *, int *);
int		 tok_str(Tokenizer *, char *,
		    int *, char ***);
