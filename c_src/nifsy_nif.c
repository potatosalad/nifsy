// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "nifsy_nif.h"

/*
 * Macros
 */

// #define	RW_UNLOCK							\
// 	do								\
// 	{								\
// 		if (handle->rwlock != 0) {				\
// 			(void) enif_rwlock_rwunlock(handle->rwlock);	\
// 		}							\
// 	} while (0)

// #define	RW_LOCK								\
// 	do								\
// 	{								\
// 		if (handle->rwlock != 0) {				\
// 			(void) enif_rwlock_rwlock(handle->rwlock);	\
// 		}							\
// 	} while (0)

// #define	RW_LOCK(HANDLE)							\
// 	do								\
// 	{								\
// 		if (HANDLE->rwlock != NULL) {				\
// 			(void) enif_rwlock_rwlock(HANDLE->rwlock);	\
// 		}							\
// 	} while (0)

#define	HANDLE_BADARG_IF(CONDITIONAL, IF_ERROR)				\
	do								\
	{								\
		if ((CONDITIONAL)) {					\
			(IF_ERROR);					\
			return enif_make_badarg(env);			\
		}							\
	} while (0)

#define	RETURN_BADARG_IF(CONDITIONAL)					\
	HANDLE_BADARG_IF(CONDITIONAL, { ((void)(0)); })

#define	HANDLE_UV_ERROR_IF(UV_REQUEST, IF_ERROR)			\
	do								\
	{								\
		int retval;						\
		if ((retval = (UV_REQUEST)) != 0) {			\
			(IF_ERROR);					\
			return enif_make_tuple2(env, ATOM_error,	\
				enif_make_string(env,			\
					uv_strerror(retval),		\
					ERL_NIF_LATIN1));		\
		}							\
	} while (0)

// #define RETURN_UV_ERROR_IF(UV_REQUEST)					\
// 	HANDLE_UV_ERROR_IF(UV_REQUEST, { ((void)(0)); })

// #define	RETURN_BADARG(code)						\
// 	do								\
// 	{								\
// 		if (!(code)) {						\
// 			return enif_make_badarg(env);			\
// 		}							\
// 	} while (0)

// #define	RETURN_ERROR(code, error_atom)					\
// 	do								\
// 	{								\
// 		if (!(code)) {						\
// 			return enif_make_tuple2(env, ATOM_error,	\
// 						error_atom);		\
// 		}							\
// 	} while (0)

// #define	HANDLE_ERROR(code, if_error, error_atom)			\
// 	do								\
// 	{								\
// 		if (!(code)) {						\
// 			(if_error);					\
// 			return enif_make_tuple2(env, ATOM_error,	\
// 						error_atom);		\
// 		}							\
// 	} while (0)

// #define	RETURN_ERROR_IF_NEG(code)					\
// 	do								\
// 	{								\
// 		if ((code) < 0) {					\
// 			return enif_make_tuple2(env, ATOM_error,	\
// 				enif_make_tuple2(env,			\
// 					enif_make_int(env, errno),	\
// 					enif_make_string(env,		\
// 						strerror(errno),	\
// 						ERL_NIF_LATIN1)));	\
// 		}							\
// 	} while (0)

// #define	HANDLE_ERROR_IF_NEG(code, if_error)				\
// 	do								\
// 	{								\
// 		if ((code) < 0) {					\
// 			(if_error);					\
// 			return enif_make_tuple2(env, ATOM_error,	\
// 				enif_make_tuple2(env,			\
// 					enif_make_int(env, errno),	\
// 					enif_make_string(env,		\
// 						strerror(errno),	\
// 						ERL_NIF_LATIN1)));	\
// 		}							\
// 	} while (0)

/*
 * Types
 */

typedef struct nifsy_handle_s {
	ErlNifRWLock	*rwlock;
	ErlNifBinary	*buffer;
	unsigned long	buffer_alloc;
	unsigned long	buffer_offset;
	unsigned long	buffer_size;
	int		file_descriptor;
	int		flags;
	int		mode;
	bool		closed;
	char		__padding_0[3];
} nifsy_handle_t;

typedef struct nifsy_open_options_s {
	unsigned long	read_ahead;
	int		flags;
	int		mode;
	bool		lock;
	char		__padding_0[7];
} nifsy_open_options_t;

typedef struct nifsy_call_s {
	nifsy_context_t	*ctx;
	ERL_NIF_TERM	tag;
	ErlNifPid	pid;
	nifsy_handle_t	*handle;
	uv_fs_t		req;
} nifsy_call_t;

/*
 * Erlang NIF functions
 */

/* Callback functions */
static void	nifsy_close_1_callback(uv_fs_t *req);
static void	nifsy_open_2_callback(uv_fs_t *req);

/* Internal functions */
static bool	nifsy_get_open_options(ErlNifEnv *env, ERL_NIF_TERM list, nifsy_open_options_t *options);

// static bool	decode_options(ErlNifEnv *env, ERL_NIF_TERM list, int *mode, bool *lock);
static int	nifsy_do_close(nifsy_handle_t *handle, bool from_dtor);
static void	nifsy_resource_dtor(ErlNifEnv *env, void *resource);

static ERL_NIF_TERM
nifsy_close_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	nifsy_handle_t *handle = NULL;
	nifsy_call_t *call = NULL;

	RETURN_BADARG_IF(argc != 1
		|| !enif_get_resource(env, argv[0], ctx->resource, (void **)(&handle)));

	// RW_LOCK(handle);

	RETURN_BADARG_IF((call = (nifsy_call_t *)(enif_alloc(sizeof(nifsy_call_t)))) == NULL);

	call->ctx = ctx;
	call->tag = enif_make_ref(env);
	(void) enif_self(env, &(call->pid));
	call->handle = handle;
	call->req.data = (void *)(call);

	HANDLE_UV_ERROR_IF(uv_fs_close(ctx->loop, &(call->req),
		handle->file_descriptor, nifsy_close_1_callback),
		{
			(void) enif_free((void *)(call));
		});

	(void) enif_cond_signal(ctx->wakeup);

	// RW_UNLOCK(handle);

	return enif_make_tuple2(env, ATOM_ok, call->tag);
}

static ERL_NIF_TERM
nifsy_open_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	char path[PATH_MAX + 1];
	nifsy_open_options_t options;
	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	nifsy_handle_t *handle = NULL;
	nifsy_call_t *call = NULL;

	RETURN_BADARG_IF(argc != 2
		|| enif_get_string(env, argv[0], path, PATH_MAX, ERL_NIF_LATIN1) <= 0
		|| !nifsy_get_open_options(env, argv[1], &options)
		|| (handle = (nifsy_handle_t *)(enif_alloc_resource(ctx->resource, sizeof(nifsy_handle_t)))) == NULL);

	TRACE_F("flags: %d\n", options.flags);

	handle->flags = options.flags;
	handle->mode = options.mode;
	handle->closed = false;
	handle->buffer_alloc = options.read_ahead;
	handle->buffer_offset = 0;
	handle->buffer_size = 0;
	handle->rwlock = NULL;

	if (options.lock) {
		HANDLE_BADARG_IF((handle->rwlock = enif_rwlock_create("nifsy")) == NULL,
			{
				(void) enif_release_resource((void *)(handle));
			});
	}

	HANDLE_BADARG_IF((call = (nifsy_call_t *)(enif_alloc(sizeof(nifsy_call_t)))) == NULL,
		{
			(void) enif_release_resource((void *)(handle));
		});

	call->ctx = ctx;
	call->tag = enif_make_ref(env);
	(void) enif_self(env, &(call->pid));
	call->handle = handle;
	call->req.data = (void *)(call);

	HANDLE_UV_ERROR_IF(uv_fs_open(ctx->loop, &(call->req),
		path, handle->flags, handle->mode, nifsy_open_2_callback),
		{
			(void) enif_release_resource((void *)(handle));
			(void) enif_free((void *)(call));
		});

	(void) enif_cond_signal(ctx->wakeup);

	return enif_make_tuple2(env, ATOM_ok, call->tag);
}

/*
 * Callback functions
 */

static void
nifsy_close_1_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_handle_t *handle = call->handle;
	ErlNifEnv *env = NULL;
	int retval;
	ERL_NIF_TERM out;

	TRACE_F("close/1 result: %d\n", req->result);

	env = enif_alloc_env();
	retval = (int)(req->result);

	if (retval < 0) {
		handle->file_descriptor = retval;
		handle->buffer = NULL;
		out = enif_make_tuple2(env, ATOM_error,
			enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1));
	} else {
		out = enif_make_tuple2(env, ATOM_ok,
			enif_make_ulong(env, (unsigned long)(req->result)));
	}

	(void) enif_send(NULL, &(call->pid), env, enif_make_tuple2(env, call->tag, out));

	(void) enif_free_env(env);
	(void) uv_fs_req_cleanup(req);
	(void) enif_free((void *)(call));

	return;
}

static void
nifsy_open_2_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_handle_t *handle = call->handle;
	ErlNifEnv *env = NULL;
	int retval;
	ERL_NIF_TERM out;

	TRACE_F("open/2 result: %d\n", req->result);

	if (handle->flags & O_APPEND)
		TRACE_F("\tO_APPEND\n");
	if (handle->flags & O_CLOEXEC)
		TRACE_F("\tO_CLOEXEC\n");
	if (handle->flags & O_CREAT)
		TRACE_F("\tO_CREAT\n");
	if (handle->flags & O_EVTONLY)
		TRACE_F("\tO_EVTONLY\n");
	if (handle->flags & O_EXCL)
		TRACE_F("\tO_EXCL\n");
	if (handle->flags & O_EXLOCK)
		TRACE_F("\tO_EXLOCK\n");
	if (handle->flags & O_NOFOLLOW)
		TRACE_F("\tO_NOFOLLOW\n");
	if (handle->flags & O_NONBLOCK)
		TRACE_F("\tO_NONBLOCK\n");
	if (handle->flags & O_RDONLY)
		TRACE_F("\tO_RDONLY\n");
	if (handle->flags & O_RDWR)
		TRACE_F("\tO_RDWR\n");
	if (handle->flags & O_SHLOCK)
		TRACE_F("\tO_SHLOCK\n");
	if (handle->flags & O_SYMLINK)
		TRACE_F("\tO_SYMLINK\n");
	if (handle->flags & O_TRUNC)
		TRACE_F("\tO_TRUNC\n");
	if (handle->flags & O_WRONLY)
		TRACE_F("\tO_WRONLY\n");

	env = enif_alloc_env();
	retval = (int)(req->result);

	if (retval < 0) {
		handle->file_descriptor = retval;
		handle->buffer = NULL;
		out = enif_make_tuple2(env, ATOM_error,
			enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1));
	} else {
		handle->file_descriptor = retval;
		handle->buffer = enif_alloc(sizeof(ErlNifBinary));
		(void) enif_alloc_binary(handle->buffer_alloc, handle->buffer);
		out = enif_make_tuple2(env, ATOM_ok,
			enif_make_resource(env, handle));
	}

	enif_send(NULL, &(call->pid), env, enif_make_tuple2(env, call->tag, out));

	(void) enif_release_resource((void *)(handle));
	(void) enif_free_env(env);
	(void) uv_fs_req_cleanup(req);
	(void) enif_free((void *)(call));

	return;
}

/*
 * Internal functions
 */

static bool
nifsy_get_open_options(ErlNifEnv *env, ERL_NIF_TERM list, nifsy_open_options_t *options)
{
	ERL_NIF_TERM head;
	int arity = 0;
	const ERL_NIF_TERM *elements = NULL;
	unsigned long value = 0;

	if (!enif_is_list(env, list)) {
		return false;
	}

	options->flags = 0;
	options->mode = 0;
	options->lock = false;
	options->read_ahead = 0;

	while (enif_get_list_cell(env, list, &head, &list)) {
		if (enif_is_identical(head, ATOM_read_ahead)) {
			options->read_ahead = 0x4000000UL;
#ifdef O_APPEND
		} else if (enif_is_identical(head, ATOM_append)) {
			options->flags |= O_APPEND;
#endif
#ifdef O_CLOEXEC
		} else if (enif_is_identical(head, ATOM_cloexec)) {
			options->flags |= O_CLOEXEC;
#endif
#ifdef O_CREAT
		} else if (enif_is_identical(head, ATOM_creat)) {
			options->flags |= O_CREAT;
#endif
#ifdef O_EVTONLY
		} else if (enif_is_identical(head, ATOM_evtonly)) {
			options->flags |= O_EVTONLY;
#endif
#ifdef O_EXCL
		} else if (enif_is_identical(head, ATOM_excl)) {
			options->flags |= O_EXCL;
#endif
#ifdef O_EXLOCK
		} else if (enif_is_identical(head, ATOM_exlock)) {
			options->flags |= O_EXLOCK;
#endif
#ifdef O_NOFOLLOW
		} else if (enif_is_identical(head, ATOM_nofollow)) {
			options->flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
		} else if (enif_is_identical(head, ATOM_nonblock)) {
			options->flags |= O_NONBLOCK;
#endif
#ifdef O_RDONLY
		} else if (enif_is_identical(head, ATOM_rdonly)) {
			options->flags |= O_RDONLY;
#endif
#ifdef O_RDWR
		} else if (enif_is_identical(head, ATOM_rdwr)) {
			options->flags |= O_RDWR;
#endif
#ifdef O_SHLOCK
		} else if (enif_is_identical(head, ATOM_shlock)) {
			options->flags |= O_SHLOCK;
#endif
#ifdef O_SYMLINK
		} else if (enif_is_identical(head, ATOM_symlink)) {
			options->flags |= O_SYMLINK;
#endif
#ifdef O_TRUNC
		} else if (enif_is_identical(head, ATOM_trunc)) {
			options->flags |= O_TRUNC;
#endif
#ifdef O_WRONLY
		} else if (enif_is_identical(head, ATOM_wronly)) {
			options->flags |= O_WRONLY;
#endif
		} else if (enif_get_tuple(env, head, &arity, &elements) && arity == 2 && enif_is_atom(env, elements[0])) {
			if (enif_is_identical(elements[0], ATOM_read_ahead) && enif_get_ulong(env, elements[1], &value)) {
				options->read_ahead = value;
			} else {
				return false;
			}
		} else {
			return false;
		}
	}

	// macOS oflag documentation
	// O_RDONLY        open for reading only
	// O_WRONLY        open for writing only
	// O_RDWR          open for reading and writing
	// O_NONBLOCK      do not block on open or for data to become available
	// O_APPEND        append on each write
	// O_CREAT         create file if it does not exist
	// O_TRUNC         truncate size to 0
	// O_EXCL          error if O_CREAT and the file exists
	// O_SHLOCK        atomically obtain a shared lock
	// O_EXLOCK        atomically obtain an exclusive lock
	// O_NOFOLLOW      do not follow symlinks
	// O_SYMLINK       allow open of symlinks
	// O_EVTONLY       descriptor requested for event notifications only
	// O_CLOEXEC       mark as close-on-exec

	return true;
}

static int
nifsy_do_close(nifsy_handle_t *handle, bool from_dtor)
{
	if (from_dtor) {
		int result = 0;
		if (handle->file_descriptor >= 0) {
			result = close(handle->file_descriptor);
		}
		if (handle->buffer) {
			(void) enif_release_binary(handle->buffer);
			handle->buffer = NULL;
		}
		return result;
	} else {
		handle->closed = true;
	}

	return 0;
}

static void
nifsy_resource_dtor(ErlNifEnv *env, void *resource)
{
	TRACE_F("destroying\n");
	nifsy_handle_t *handle = (nifsy_handle_t *)(resource);
	if (handle) {
		(void) nifsy_do_close(handle, true);
		if (handle->rwlock != NULL) {
			(void) enif_rwlock_destroy(handle->rwlock);
			handle->rwlock = NULL;
		}
	}
}

/*
 * Erlang NIF callbacks
 */

static void *
nifsy_nif_loop(void *priv_data)
{
	nifsy_context_t *ctx = (nifsy_context_t *)(priv_data);
	int retval = 0;

	for (;;) {
		retval = uv_run(ctx->loop, UV_RUN_DEFAULT);
		(void) enif_cond_wait(ctx->wakeup, ctx->mutex);
		if (ctx->stop) {
			TRACE_F("Loop: %d\n", retval);
			break;
		}
	}

	return NULL;
}

static int
nifsy_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	nifsy_context_t *ctx = NULL;
	ErlNifResourceFlags resource_flags = (ErlNifResourceFlags)(0);
	int retval = 0;

	/* Allocate private data */
	ctx = (nifsy_context_t *)(enif_alloc(sizeof(nifsy_context_t)));

	if (ctx == NULL) {
		return 1;
	}

	/* Initialize common atoms */
	#define ATOM(Id, Value) { ATOM_##Id = enif_make_atom(env, Value); }
		ATOM(append,		"append");
		ATOM(cloexec,		"cloexec");
		ATOM(closed,		"closed");
		ATOM(creat,		"creat");
		ATOM(create,		"create");
		ATOM(dsync,		"dsync");
		ATOM(enomem,		"enomem");
		ATOM(eof,		"eof");
		ATOM(error,		"error");
		ATOM(evtonly,		"evtonly");
		ATOM(excl,		"excl");
		ATOM(exclusive,		"exclusive");
		ATOM(exlock,		"exlock");
		ATOM(lock,		"lock");
		ATOM(nofollow,		"nofollow");
		ATOM(nonblock,		"nonblock");
		ATOM(ok,		"ok");
		ATOM(rdonly,		"rdonly");
		ATOM(rdwr,		"rdwr");
		ATOM(read,		"read");
		ATOM(read_ahead,	"read_ahead");
		ATOM(shlock,		"shlock");
		ATOM(symlink,		"symlink");
		ATOM(sync,		"sync");
		ATOM(trunc,		"trunc");
		ATOM(truncate,		"truncate");
		ATOM(write,		"write");
		ATOM(wronly,		"wronly");
	#undef ATOM

	/* Initialize context */
	ctx->version = nifsy_context_version;
	ctx->resource = NULL;
	ctx->mutex = NULL;
	ctx->wakeup = NULL;
	ctx->tid = NULL;
	ctx->loop = uv_default_loop();
	ctx->stop = false;

	resource_flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

	/* Create context resource */
	ctx->resource = enif_open_resource_type(env, NULL, "nifsy_resource",
		&nifsy_resource_dtor, resource_flags, NULL);

	if (ctx->resource == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create context mutex */
	ctx->mutex = enif_mutex_create("nifsy_mutex");

	if (ctx->mutex == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create context wakeup */
	ctx->wakeup = enif_cond_create("nifsy_wakeup");

	if (ctx->wakeup == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create context thread */
	ctx->tid = &(ctx->__tid);
	retval = enif_thread_create("nifsy_loop", ctx->tid, &nifsy_nif_loop, (void *)(ctx), NULL);

	if (retval != 0) {
		ctx->tid = NULL;
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return retval;
	}

	*priv_data = (void *)(ctx);

	// TRACE_F("loaded\n");

	return 0;
}

static int
nifsy_nif_upgrade(ErlNifEnv *env, void **priv_data, void **old_priv_data, ERL_NIF_TERM load_info)
{
	return nifsy_nif_load(env, priv_data, load_info);
}

static void
nifsy_nif_unload(ErlNifEnv *env, void *priv_data)
{
	TRACE_F("unload nif\n");

	nifsy_context_t *ctx = (nifsy_context_t *)(priv_data);

	if (ctx != NULL) {
		ctx->stop = true;
		if (ctx->tid != NULL) {
			(void) uv_stop(ctx->loop);
			(void) enif_cond_signal(ctx->wakeup);
			(void) enif_thread_join(ctx->__tid, NULL);
			ctx->tid = NULL;
		}
		if (ctx->wakeup != NULL) {
			(void) enif_cond_destroy(ctx->wakeup);
			ctx->wakeup = NULL;
		}
		if (ctx->mutex != NULL) {
			(void) enif_mutex_destroy(ctx->mutex);
			ctx->mutex = NULL;
		}
		(void) enif_free((void *)(ctx));
	}

	return;
}

ERL_NIF_INIT(nifsy_nif, nifsy_nif_funcs, nifsy_nif_load, NULL, nifsy_nif_upgrade, nifsy_nif_unload)
