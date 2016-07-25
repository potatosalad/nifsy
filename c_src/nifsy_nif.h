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
	#define	DIRTINESS	ERL_NIF_DIRTY_JOB_IO_BOUND
#else
	#define	DIRTINESS	0
#endif

// #define	NIFSY_DEBUG		1
#ifdef NIFSY_DEBUG
	#define	DEBUG_LOG(...)	enif_fprintf(stderr, __VA_ARGS__)
#else
	#define DEBUG_LOG(...)	((void)(0))
#endif

/*
 * Erlang NIF functions
 */

#define NIF_FUN(function, arity)	\
	static ERL_NIF_TERM	nifsy_ ##function## _ ##arity (ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])

NIF_FUN(close,		1);
NIF_FUN(open,		3);
NIF_FUN(read,		2);
NIF_FUN(read_line,	1);
NIF_FUN(write,		2);

#undef NIF_FUN

#define NIF_FUNC(function, arity)	{#function, arity, nifsy_##function##_##arity, DIRTINESS}

static ErlNifFunc	nifsy_nif_funcs[] = {
	NIF_FUNC(close,		1),
	NIF_FUNC(open,		3),
	NIF_FUNC(read,		2),
	NIF_FUNC(read_line,	1),
	NIF_FUNC(write,		2),
};

#undef NIF_FUNC

/*
 * Erlang NIF callbacks
 */

/* Declare common atoms */
#define ATOM(Id)	static ERL_NIF_TERM	ATOM_##Id
	ATOM(append);
	ATOM(closed);
	ATOM(create);
	ATOM(dsync);
	ATOM(enomem);
	ATOM(eof);
	ATOM(error);
	ATOM(exclusive);
	ATOM(lock);
	ATOM(ok);
	ATOM(read);
	ATOM(sync);
	ATOM(truncate);
	ATOM(write);
#undef ATOM

typedef struct nifsy_priv_data_0_s {
	uint8_t			version;
	char			padding[7];
	ErlNifResourceType	*nifsy_resource;
} nifsy_priv_data_0_t;

#define nifsy_priv_data_version	0
#define nifsy_priv_data_t		nifsy_priv_data_0_t

static int	nifsy_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info);
static int	nifsy_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info);
static void	nifsy_nif_unload(ErlNifEnv *env, void *priv_data);

#endif
