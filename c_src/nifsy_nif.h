// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#ifndef NIFSY_NIF_H
#define NIFSY_NIF_H

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#pragma clang diagnostic ignored "-Wpadded"
#include "erl_nif.h"
#include "uv.h"
#pragma clang diagnostic pop

#ifndef timersub
#define	timersub(tvp, uvp, vvp)						\
	do								\
	{								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0)					\
		{							\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while ((vvp)->tv_usec >= 1000000)
#endif

#define MAX_PER_SLICE		64000	// 64 KB

#ifdef ERTS_DIRTY_SCHEDULERS
	// #define	DIRTINESS	ERL_NIF_DIRTY_JOB_IO_BOUND
	#define	DIRTINESS	0
#else
	#define	DIRTINESS	0
#endif

// #define	NIFSY_DEBUG		1
#ifdef NIFSY_DEBUG
	#define TRACE_F(...)		enif_fprintf(stderr, __VA_ARGS__)
	#define	DEBUG_LOG(string)	TRACE_F("%s\n", string)
#else
	#define TRACE_F(...)		((void)(0))
	#define DEBUG_LOG(string)	((void)(0))
#endif

/*
 * Erlang NIF functions
 */

#define NIF_FUN(function, arity)	\
	static ERL_NIF_TERM	nifsy_ ##function## _ ##arity (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

NIF_FUN(close,		1);
NIF_FUN(open,		2);
NIF_FUN(read,		2);
// NIF_FUN(read_line,	1);
// NIF_FUN(write,		2);

#undef NIF_FUN

#define NIF_FUNC(function, arity)	{#function, arity, nifsy_##function##_##arity, DIRTINESS}

static ErlNifFunc	nifsy_nif_funcs[] = {
	NIF_FUNC(close,		1),
	NIF_FUNC(open,		2),
	NIF_FUNC(read,		2),
	// NIF_FUNC(read_line,	1),
	// NIF_FUNC(write,		2),
};

#undef NIF_FUNC

/*
 * Erlang NIF callbacks
 */

/* Declare common atoms */
#define ATOM(Id)	static ERL_NIF_TERM	ATOM_##Id
	ATOM(append);
	ATOM(cloexec);
	ATOM(closed);
	ATOM(creat);
	ATOM(create);
	ATOM(dsync);
	ATOM(enomem);
	ATOM(eof);
	ATOM(error);
	ATOM(evtonly);
	ATOM(excl);
	ATOM(exlock);
	ATOM(exclusive);
	ATOM(lock);
	ATOM(nofollow);
	ATOM(nonblock);
	ATOM(ok);
	ATOM(rdonly);
	ATOM(rdwr);
	ATOM(read);
	ATOM(read_ahead);
	ATOM(shlock);
	ATOM(symlink);
	ATOM(sync);
	ATOM(trunc);
	ATOM(truncate);
	ATOM(write);
	ATOM(wronly);
#undef ATOM

typedef struct nifsy_context_0_s {
	uint8_t			version;
	char			__padding_0[7];
	ErlNifResourceType	*resource;
	ErlNifMutex		*mutex;
	ErlNifCond		*wakeup;
	ErlNifTid		*tid;
	ErlNifTid		__tid;
	uv_loop_t		*loop;
	bool			stop;
	char			__padding_1[7];
} nifsy_context_0_t;

#define nifsy_context_version	0
#define nifsy_context_t		nifsy_context_0_t

static int	nifsy_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int	nifsy_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void	nifsy_nif_unload(ErlNifEnv *env, void *priv_data);

#endif
