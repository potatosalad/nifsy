// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "nifsy_nif.h"

/*
 * Macros
 */

// #define	R_LOCK(X)							\
// 	do								\
// 	{								\
// 		if ((X)->rwlock != NULL) {				\
// 			(void) enif_rwlock_rlock((X)->rwlock);		\
// 		}							\
// 	} while (0)

// #define	R_UNLOCK(X)							\
// 	do								\
// 	{								\
// 		if ((X)->rwlock != NULL) {				\
// 			(void) enif_rwlock_runlock((X)->rwlock);	\
// 		}							\
// 	} while (0)

#define	LOOP_WAIT(CTX)							\
	do								\
	{								\
		if ((CTX)->loop_alive == false) {			\
			return ATOM_loop_wait;				\
		}							\
	} while (0)

#define	WAKEUP(CTX)							\
	(void) enif_cond_signal((CTX)->wake_cond)

#define	RW_LOCK(X)							\
	do								\
	{								\
		if ((X)->rwlock != NULL) {				\
			(void) enif_rwlock_rwlock((X)->rwlock);		\
		}							\
	} while (0)

#define	RW_UNLOCK(X)							\
	do								\
	{								\
		if ((X)->rwlock != NULL) {				\
			(void) enif_rwlock_rwunlock((X)->rwlock);	\
		}							\
	} while (0)

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

#define	HANDLE_ERROR_IF(REQUEST, IF_ERROR, ERROR_ATOM)			\
	do								\
	{								\
		if ((REQUEST)) {					\
			(IF_ERROR);					\
			return enif_make_tuple2(env, ATOM_error,	\
				ERROR_ATOM);				\
		}							\
	} while (0)

#define RETURN_ERROR_IF(REQUEST, ERROR_ATOM)				\
	HANDLE_ERROR_IF(REQUEST, { ((void)(0)); }, ERROR_ATOM)

#define	HANDLE_UV_ERROR_IF(UV_REQUEST, IF_ERROR)			\
	do								\
	{								\
		int retval;						\
		if ((retval = (UV_REQUEST)) != 0) {			\
			(IF_ERROR);					\
			return enif_make_tuple2(env,ATOM_error,		\
			enif_make_tuple2(env,				\
			enif_make_atom(env, uv_err_name(retval)),	\
			enif_make_string(env, uv_strerror(retval),	\
				ERL_NIF_LATIN1)));			\
		}							\
	} while (0)

/*
 * Types
 */

typedef struct nifsy_file_s {
	ErlNifRWLock	*rwlock;
	ErlNifBinary	read_ahead;
	unsigned long	read_ahead_bytes;
	unsigned long	read_ahead_offset;
	unsigned long	read_ahead_size;
	unsigned long	read_offset;
	int		fd;
	int		flag;
	int		mode;
	bool		closed;
	char		__padding_0[3];
} nifsy_file_t;

typedef struct nifsy_file_options_s {
	unsigned long	read_ahead_bytes;
	int		flag;
	int		mode;
	bool		lock;
	char		__padding_0[7];
} nifsy_file_options_t;

static nifsy_file_t	*nifsy_file_alloc(nifsy_context_t *ctx, nifsy_file_options_t *options);
static void		nifsy_file_release(nifsy_file_t *file);
static void		nifsy_file_dtor(ErlNifEnv *env, void *resource);
static bool		nifsy_file_options(ErlNifEnv *env, ERL_NIF_TERM list, nifsy_file_options_t *options);

typedef struct nifsy_call_s {
	nifsy_context_t	*ctx;
	ErlNifEnv	*env;
	ErlNifPid	pid;
	ERL_NIF_TERM	tag;
	uv_fs_t		*req;
	nifsy_file_t	*file;
	void		*data;
} nifsy_call_t;

static nifsy_call_t	*nifsy_call_alloc(ErlNifEnv *env, nifsy_file_t *file, void *data);
static void		nifsy_call_free(nifsy_call_t *call);
static void		nifsy_call_cleanup(nifsy_call_t *call);
static int		nifsy_call_reply(nifsy_call_t *call, ERL_NIF_TERM reply);
static ERL_NIF_TERM	nifsy_call_return(ErlNifEnv *env, nifsy_call_t *call);

typedef struct nifsy_read_s {
	ErlNifBinary	out;
	unsigned long	out_bytes;
	unsigned long	read_bytes;
} nifsy_read_t;

/*
 * Erlang NIF functions
 */

/* Callback functions */
static void	nifsy_close_1_callback(uv_fs_t *req);
static void	nifsy_open_2_callback(uv_fs_t *req);
static void	nifsy_read_2_callback(uv_fs_t *req);
static void	nifsy_read_line_1_callback(uv_fs_t *req);

static ERL_NIF_TERM
nifsy_close_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	// TRACE_F("ENTER close/1\n");
	nifsy_file_t *file = NULL;

	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	nifsy_call_t *call = NULL;

	LOOP_WAIT(ctx);

	RETURN_BADARG_IF(argc != 1
		|| !enif_get_resource(env, argv[0], ctx->file_type, (void **)(&file)));

	RW_LOCK(file);

	RETURN_ERROR_IF((call = nifsy_call_alloc(env, file, NULL)) == NULL,
		ATOM_enomem);

	HANDLE_UV_ERROR_IF(uv_fs_close(ctx->loop, call->req, file->fd, nifsy_close_1_callback),
		{
			RW_UNLOCK(file);
			(void) nifsy_call_free(call);
		});

	WAKEUP(ctx);

	RW_UNLOCK(file);

	return nifsy_call_return(env, call);
}

static ERL_NIF_TERM
nifsy_open_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	// TRACE_F("ENTER open/2\n");
	char path[PATH_MAX + 1];
	nifsy_file_options_t options;

	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	nifsy_file_t *file = NULL;
	nifsy_call_t *call = NULL;

	LOOP_WAIT(ctx);

	RETURN_BADARG_IF(argc != 2
		|| enif_get_string(env, argv[0], path, PATH_MAX, ERL_NIF_LATIN1) <= 0
		|| !nifsy_file_options(env, argv[1], &options));

	RETURN_ERROR_IF((file = nifsy_file_alloc(ctx, &options)) == NULL,
		ATOM_enomem);

	HANDLE_ERROR_IF((call = nifsy_call_alloc(env, file, NULL)) == NULL,
		{
			(void) nifsy_file_release(file);
		}, ATOM_enomem);

	HANDLE_UV_ERROR_IF(uv_fs_open(ctx->loop, call->req, path,
		file->flag, file->mode, nifsy_open_2_callback),
		{
			(void) nifsy_call_free(call);
			(void) nifsy_file_release(file);
		});

	WAKEUP(ctx);

	return nifsy_call_return(env, call);
}

static ERL_NIF_TERM
nifsy_read_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	// TRACE_F("ENTER read/2\n");
	nifsy_file_t *file = NULL;
	unsigned long read_bytes = 0;

	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	nifsy_read_t *op = NULL;
	nifsy_call_t *call = NULL;
	ErlNifBinary *rbin = NULL;
	uv_buf_t iov;

	LOOP_WAIT(ctx);

	RETURN_BADARG_IF(argc != 2
		|| !enif_get_resource(env, argv[0], ctx->file_type, (void **)(&file))
		|| file->closed
		|| !enif_get_ulong(env, argv[1], &read_bytes));

	RW_LOCK(file);

	if (file->read_ahead_bytes > 0
			&& file->read_ahead_size > 0
			&& file->read_ahead_size > file->read_ahead_offset
			&& (file->read_ahead_size - file->read_ahead_offset) >= read_bytes) {
		TRACE_F("[A] buffer exists, enough data\n");
		ERL_NIF_TERM out;
		unsigned char *obuf = enif_make_new_binary(env, read_bytes, &out);
		unsigned char *rbuf = file->read_ahead.data + file->read_ahead_offset;
		(void) memcpy(obuf, rbuf, read_bytes);
		file->read_ahead_offset += read_bytes;
		RW_UNLOCK(file);
		return enif_make_tuple2(env, ATOM_ok, out);
	}

	HANDLE_ERROR_IF((op = enif_alloc(sizeof(nifsy_read_t))) == NULL,
		{
			RW_UNLOCK(file);
		}, ATOM_enomem);

	HANDLE_ERROR_IF((call = nifsy_call_alloc(env, file, op)) == NULL,
		{
			(void) enif_free(op);
			RW_UNLOCK(file);
		}, ATOM_enomem);

	HANDLE_ERROR_IF(!enif_alloc_binary(read_bytes, &op->out),
		{
			(void) nifsy_call_free(call);
			(void) enif_free(op);
			RW_UNLOCK(file);
		}, ATOM_enomem);

	op->out_bytes = 0;
	op->read_bytes = read_bytes;

	if (file->read_ahead_bytes > 0
			&& file->read_ahead_size > 0
			&& file->read_ahead_size > file->read_ahead_offset) {
		TRACE_F("[B] buffer exists, not enough data\n");
		unsigned char *rbuf = file->read_ahead.data + file->read_ahead_offset;
		unsigned long rlen = file->read_ahead_size - file->read_ahead_offset;
		(void) memcpy(op->out.data, rbuf, rlen);
		op->out_bytes += rlen;
		file->read_ahead_offset = 0;
		file->read_ahead_size = 0;
	}

	rbin = &op->out;

	if (file->read_ahead_bytes > 0) {
		rbin = &file->read_ahead;
	}

	iov = uv_buf_init((char *)(rbin->data), (unsigned int)(rbin->size));

	HANDLE_UV_ERROR_IF(uv_fs_read(ctx->loop, call->req, file->fd,
		&iov, 1, (int64_t)(file->read_offset), nifsy_read_2_callback),
		{
			file->read_ahead_offset = 0;
			file->read_ahead_size = 0;
			file->read_offset -= op->out_bytes;
			(void) enif_release_binary(&op->out);
			(void) nifsy_call_free(call);
			(void) enif_free(op);
			RW_UNLOCK(file);
		});

	WAKEUP(ctx);

	RW_UNLOCK(file);

	return nifsy_call_return(env, call);
}

static ERL_NIF_TERM
nifsy_read_line_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	// TRACE_F("ENTER read_line/1\n");
	nifsy_file_t *file = NULL;

	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	unsigned char *rbuf = NULL;
	unsigned long rlen = 0;
	nifsy_read_t *op = NULL;
	nifsy_call_t *call = NULL;
	uv_buf_t iov;

	LOOP_WAIT(ctx);

	RETURN_BADARG_IF(argc != 1
		|| !enif_get_resource(env, argv[0], ctx->file_type, (void **)(&file))
		|| file->closed);

	RW_LOCK(file);

	if (file->read_ahead_bytes > 0
			&& file->read_ahead_size > 0
			&& file->read_ahead_size > file->read_ahead_offset) {
		// TRACE_F("[A] buffer exists\n");
		rbuf = file->read_ahead.data + file->read_ahead_offset;
		rlen = file->read_ahead_size - file->read_ahead_offset;
		unsigned char *newline = memchr(rbuf, '\n', rlen);
		if (newline != NULL) {
			// TRACE_F("[B] line found\n");
			ERL_NIF_TERM out;
			newline++;
			rlen = (unsigned long)(newline - rbuf);
			unsigned char *obuf = enif_make_new_binary(env, rlen, &out);
			(void) memcpy(obuf, rbuf, rlen);
			file->read_ahead_offset += rlen;
			RW_UNLOCK(file);
			return enif_make_tuple2(env, ATOM_ok, out);
		}
		TRACE_F("[C] no line found (%llu, %llu, %llu, %llu)\n", file->read_ahead_bytes, file->read_ahead_size, file->read_ahead_offset, rlen);
		file->read_ahead_offset += rlen;
	}

	HANDLE_ERROR_IF((op = enif_alloc(sizeof(nifsy_read_t))) == NULL,
		{
			RW_UNLOCK(file);
		}, ATOM_enomem);

	HANDLE_ERROR_IF((call = nifsy_call_alloc(env, file, op)) == NULL,
		{
			(void) enif_free(op);
			RW_UNLOCK(file);
		}, ATOM_enomem);

	// char tagbuf[512];
	// enif_snprintf(tagbuf, 512, "%T", call->tag);
	// TRACE_F("ENTER %s\n", tagbuf);

	op->out_bytes = 0;
	op->read_bytes = ((file->read_ahead_bytes > 0) ? file->read_ahead_bytes : 0x4000000UL);

	if (rlen > 0) {
		op->out_bytes = rlen;
		rlen = op->read_bytes * 2;
	} else {
		rlen = op->read_bytes;
	}

	HANDLE_ERROR_IF(!enif_alloc_binary(rlen, &op->out),
		{
			(void) nifsy_call_free(call);
			(void) enif_free(op);
			RW_UNLOCK(file);
		}, ATOM_enomem);

	if (rbuf != NULL) {
		(void) memcpy(op->out.data, rbuf, op->out_bytes);
	}

	rbuf = op->out.data + op->out_bytes;
	rlen = op->read_bytes;
	iov = uv_buf_init((char *)(rbuf), (unsigned int)(rlen));

	HANDLE_UV_ERROR_IF(uv_fs_read(ctx->loop, call->req, file->fd,
		&iov, 1, (int64_t)(file->read_offset), nifsy_read_line_1_callback),
		{
			file->read_ahead_offset = 0;
			file->read_ahead_size = 0;
			file->read_offset -= op->out_bytes;
			(void) enif_release_binary(&op->out);
			(void) nifsy_call_free(call);
			(void) enif_free(op);
			RW_UNLOCK(file);
		});

	WAKEUP(ctx);

	RW_UNLOCK(file);

	return nifsy_call_return(env, call);
}

static ERL_NIF_TERM
nifsy_system_info_0(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	TRACE_F("ENTER system_info/0\n");
	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));
	ERL_NIF_TERM out;
	ERL_NIF_TERM tp0;
	ERL_NIF_TERM tp1;

	LOOP_WAIT(ctx);

	tp0 = enif_make_ulong(env, ctx->idles);
	tp0 = enif_make_tuple2(env, ATOM_idle, tp0);
	tp1 = enif_make_ulong(env, ctx->wakes);
	tp1 = enif_make_tuple2(env, ATOM_wake, tp1);
	out = enif_make_list2(env, tp0, tp1);

	return out;
}

/*
 * Callback functions
 */

static void
nifsy_close_1_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_file_t *file = call->file;
	ErlNifEnv *env = call->env;

	int retval;
	ERL_NIF_TERM out;

	// TRACE_F("close/1 result: %d\n", req->result);

	retval = (int)(req->result);

	if (retval < 0) {
		out = enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1);
		out = enif_make_tuple2(env, enif_make_atom(env, uv_err_name(retval)), out);
		out = enif_make_tuple2(env, ATOM_error, out);
	} else {
		file->fd = -1;
		file->closed = true;
		out = enif_make_ulong(env, (unsigned long)(req->result));
		out = enif_make_tuple2(env, ATOM_ok, out);
	}

	// TODO: handle send failures
	(void) nifsy_call_reply(call, out);

	(void) uv_fs_req_cleanup(req);
	(void) nifsy_call_free(call);

	return;
}

static void
nifsy_open_2_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_file_t *file = call->file;
	ErlNifEnv *env = call->env;

	int retval;
	ERL_NIF_TERM out;

	// TRACE_F("open/2 result: %d\n", req->result);

	// if (file->flag & O_APPEND)
	// 	TRACE_F("\tO_APPEND\n");
	// if (file->flag & O_CLOEXEC)
	// 	TRACE_F("\tO_CLOEXEC\n");
	// if (file->flag & O_CREAT)
	// 	TRACE_F("\tO_CREAT\n");
	// if (file->flag & O_EVTONLY)
	// 	TRACE_F("\tO_EVTONLY\n");
	// if (file->flag & O_EXCL)
	// 	TRACE_F("\tO_EXCL\n");
	// if (file->flag & O_EXLOCK)
	// 	TRACE_F("\tO_EXLOCK\n");
	// if (file->flag & O_NOFOLLOW)
	// 	TRACE_F("\tO_NOFOLLOW\n");
	// if (file->flag & O_NONBLOCK)
	// 	TRACE_F("\tO_NONBLOCK\n");
	// if (file->flag & O_RDONLY)
	// 	TRACE_F("\tO_RDONLY\n");
	// if (file->flag & O_RDWR)
	// 	TRACE_F("\tO_RDWR\n");
	// if (file->flag & O_SHLOCK)
	// 	TRACE_F("\tO_SHLOCK\n");
	// if (file->flag & O_SYMLINK)
	// 	TRACE_F("\tO_SYMLINK\n");
	// if (file->flag & O_TRUNC)
	// 	TRACE_F("\tO_TRUNC\n");
	// if (file->flag & O_WRONLY)
	// 	TRACE_F("\tO_WRONLY\n");

	retval = (int)(req->result);
	file->fd = retval;

	if (retval < 0) {
		file->read_ahead_bytes = 0;
		out = enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1);
		out = enif_make_tuple2(env, enif_make_atom(env, uv_err_name(retval)), out);
		out = enif_make_tuple2(env, ATOM_error, out);
	} else if (file->read_ahead_bytes > 0 && !enif_alloc_binary(file->read_ahead_bytes, &file->read_ahead)) {
		file->read_ahead_bytes = 0;
		out = enif_make_tuple2(env, ATOM_error, ATOM_enomem);
	} else {
		out = enif_make_resource(env, file);
		out = enif_make_tuple2(env, ATOM_ok, out);
	}

	// TODO: handle send failures
	(void) nifsy_call_reply(call, out);

	(void) nifsy_file_release(file);
	(void) uv_fs_req_cleanup(req);
	(void) nifsy_call_free(call);

	return;
}

static void
nifsy_read_2_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_file_t *file = call->file;
	nifsy_read_t *op = (nifsy_read_t *)(call->data);
	ErlNifEnv *env = call->env;

	int retval;
	ERL_NIF_TERM out;
	unsigned char *obuf = NULL;
	unsigned char *rbuf = NULL;
	unsigned long rlen = 0;
	ErlNifBinary *rbin = NULL;
	uv_buf_t iov;

	// TRACE_F("read/2 result: %d\n", req->result);

	retval = (int)(req->result);

	if (retval < 0) {
		file->read_ahead_offset = 0;
		file->read_ahead_size = 0;
		file->read_offset -= op->out_bytes;

		out = enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1);
		out = enif_make_tuple2(env, enif_make_atom(env, uv_err_name(retval)), out);
		out = enif_make_tuple2(env, ATOM_error, out);

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_release_binary(&op->out);
		(void) enif_free(op);

		return;
	}

	if (req->result == 0) {
		file->read_ahead_offset = 0;
		file->read_ahead_size = 0;

		if (op->out_bytes == 0) {
			(void) enif_release_binary(&op->out);
			out = ATOM_eof;
		} else {
			out = enif_make_binary(env, &op->out);
			if (op->out.size > op->out_bytes) {
				out = enif_make_sub_binary(env, out, 0, op->out_bytes);
			}
			out = enif_make_tuple2(env, ATOM_ok, out);
		}

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_free(op);

		return;
	}

	rlen = (unsigned long)(req->result);
	file->read_offset += rlen;

	if (file->read_ahead_bytes == 0) {
		op->out_bytes += rlen;

		out = enif_make_binary(env, &op->out);
		if (op->out.size > op->out_bytes) {
			out = enif_make_sub_binary(env, out, 0, op->out_bytes);
		}
		out = enif_make_tuple2(env, ATOM_ok, out);
		
		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_free(op);

		return;
	}

	obuf = op->out.data + op->out_bytes;
	rbuf = file->read_ahead.data;

	file->read_ahead_offset = 0;
	file->read_ahead_size = rlen;

	if ((op->out_bytes + rlen) >= op->read_bytes) {
		rlen = op->read_bytes - op->out_bytes;
		file->read_ahead_offset += rlen;
		(void) memcpy(obuf, rbuf, rlen);
		op->out_bytes += rlen;

		env = enif_alloc_env();
		out = enif_make_binary(env, &op->out);
		if (op->out.size > op->out_bytes) {
			out = enif_make_sub_binary(env, out, 0, op->out_bytes);
		}
		out = enif_make_tuple2(env, ATOM_ok, out);

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_free(op);

		return;
	}

	(void) memcpy(obuf, rbuf, rlen);
	op->out_bytes += rlen;

	rbin = &file->read_ahead;
	iov = uv_buf_init((char *)(rbin->data), (unsigned int)(rbin->size));

	(void) nifsy_call_cleanup(call);
	// TODO: handle errors on read
	(void) uv_fs_read(call->ctx->loop, call->req, file->fd, &iov, 1, (int64_t)(file->read_offset), nifsy_read_2_callback);

	WAKEUP(call->ctx);

	return;
}

static void
nifsy_read_line_1_callback(uv_fs_t *req)
{
	nifsy_call_t *call = (nifsy_call_t *)(req->data);
	nifsy_file_t *file = call->file;
	nifsy_read_t *op = (nifsy_read_t *)(call->data);
	ErlNifEnv *env = call->env;

	int retval;
	ERL_NIF_TERM out;
	unsigned char *obuf = NULL;
	unsigned long olen = 0;
	unsigned char *rbuf = NULL;
	unsigned long rlen = 0;
	uv_buf_t iov;

	char tagbuf[512];
	enif_snprintf(tagbuf, 512, "%T", call->tag);
	TRACE_F("CALLB %s result: %d\n", tagbuf, req->result);

	// TRACE_F("read_line/1 result: %d\n", req->result);

	retval = (int)(req->result);

	if (retval < 0) {
		file->read_ahead_offset = 0;
		file->read_ahead_size = 0;
		file->read_offset -= op->out_bytes;

		out = enif_make_string(env, uv_strerror(retval), ERL_NIF_LATIN1);
		out = enif_make_tuple2(env, enif_make_atom(env, uv_err_name(retval)), out);
		out = enif_make_tuple2(env, ATOM_error, out);

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_release_binary(&op->out);
		(void) enif_free(op);

		return;
	}

	if (req->result == 0) {
		file->read_ahead_offset = 0;
		file->read_ahead_size = 0;

		env = enif_alloc_env();

		if (op->out_bytes == 0) {
			(void) enif_release_binary(&op->out);
			out = ATOM_eof;
		} else {
			out = enif_make_binary(env, &op->out);
			if (op->out.size > op->out_bytes) {
				out = enif_make_sub_binary(env, out, 0, op->out_bytes);
			}
			out = enif_make_tuple2(env, ATOM_ok, out);
		}

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_free(op);

		return;
	}

	rbuf = op->out.data + op->out_bytes;
	rlen = (unsigned long)(req->result);
	file->read_offset += rlen;

	if ((obuf = memchr(rbuf, '\n', rlen)) != NULL) {
		olen = (unsigned long)(obuf - rbuf + 1);
		op->out_bytes += olen;
		obuf++;
		olen = rlen - olen;
		if (file->read_ahead_bytes > 0) {
			file->read_ahead_offset = 0;
			file->read_ahead_size = olen;
			if (olen > 0) {
				(void) memcpy(file->read_ahead.data, obuf, olen);
			}
		} else {
			file->read_offset -= olen;
		}

		out = enif_make_binary(env, &op->out);
		if (op->out.size > op->out_bytes) {
			out = enif_make_sub_binary(env, out, 0, op->out_bytes);
		}
		out = enif_make_tuple2(env, ATOM_ok, out);

		// TODO: handle send failures
		(void) nifsy_call_reply(call, out);

		(void) uv_fs_req_cleanup(req);
		(void) nifsy_call_free(call);
		(void) enif_free(op);

		return;
	}

	op->out_bytes += rlen;
	if (op->out.size < (op->out_bytes + op->read_bytes)) {
		(void) enif_realloc_binary(&op->out, op->out_bytes + (op->read_bytes * 2));
	}
	rbuf = op->out.data + op->out_bytes;
	rlen = op->read_bytes;

	iov = uv_buf_init((char *)(rbuf), (unsigned int)(rlen));

	(void) nifsy_call_cleanup(call);
	// TODO: handle errors on read
	// TRACE_F("calling read_line/1 again\n");
	(void) uv_fs_read(call->ctx->loop, call->req, file->fd, &iov, 1, (int64_t)(file->read_offset), nifsy_read_line_1_callback);

	WAKEUP(call->ctx);

	return;
}

/*
 * Call functions
 */

static nifsy_call_t *
nifsy_call_alloc(ErlNifEnv *env, nifsy_file_t *file, void *data)
{
	nifsy_context_t *ctx = (nifsy_context_t *)(enif_priv_data(env));

	nifsy_call_t *call = NULL;
	uv_fs_t *req = NULL;
	ErlNifEnv *msg_env = NULL;

	if ((call = enif_alloc(sizeof(nifsy_call_t))) == NULL) {
		return NULL;
	}

	if ((req = enif_alloc(sizeof(uv_fs_t))) == NULL) {
		(void) enif_free(call);
		return NULL;
	}

	if ((msg_env = enif_alloc_env()) == NULL) {
		(void) enif_free(req);
		(void) enif_free(call);
		return NULL;
	}

	call->ctx = ctx;
	call->env = msg_env;
	(void) enif_self(env, &call->pid);
	call->tag = enif_make_ref(call->env);
	call->req = req;
	call->file = file;
	call->data = data;

	req->data = (void *)(call);

	return call;
}

static void
nifsy_call_free(nifsy_call_t *call)
{
	if (call == NULL) {
		return;
	}

	if (call->env != NULL) {
		(void) enif_free_env(call->env);
		call->env = NULL;
	}

	if (call->req != NULL) {
		(void) enif_free(call->req);
		call->req = NULL;
	}

	call->ctx = NULL;
	call->file = NULL;
	call->data = NULL;

	(void) enif_free(call);

	return;
}

static void
nifsy_call_cleanup(nifsy_call_t *call)
{
	uv_fs_t req;

	if (call == NULL) {
		return;
	}

	(void) uv_fs_req_cleanup(call->req);

	req.data = (void *)(call);
	(void) memcpy(call->req, &req, sizeof(req));

	return;
}

static int
nifsy_call_reply(nifsy_call_t *call, ERL_NIF_TERM reply)
{
	ERL_NIF_TERM msg;
	int retval;

	if (call->env == NULL) {
		return 0;
	}

	msg = enif_make_tuple2(call->env, call->tag, reply);
	retval = enif_send(NULL, &call->pid, call->env, msg);
	(void) enif_free_env(call->env);
	call->env = NULL;

	if (!retval) {
		(void) enif_fprintf(stderr, "enif_send() failed: %d\n", retval);
	}

	return retval;
}

static ERL_NIF_TERM
nifsy_call_return(ErlNifEnv *env, nifsy_call_t *call)
{
	ERL_NIF_TERM out;
	out = enif_make_copy(env, call->tag);
	out = enif_make_tuple2(env, ATOM_ok, out);
	return out;
}

/*
 * File functions
 */

static nifsy_file_t *
nifsy_file_alloc(nifsy_context_t *ctx, nifsy_file_options_t *options)
{
	nifsy_file_t *file = NULL;
	ErlNifRWLock *rwlock = NULL;

	if ((file = enif_alloc_resource(ctx->file_type, sizeof(nifsy_file_t))) == NULL) {
		return NULL;
	}

	if (options->lock && (rwlock = enif_rwlock_create("nifsy_file_rwlock")) == NULL) {
		(void) enif_free(file);
		return NULL;
	}

	file->rwlock = rwlock;
	file->read_ahead_bytes = options->read_ahead_bytes;
	file->read_ahead_offset = 0;
	file->read_ahead_size = 0;
	file->read_offset = 0;
	file->flag = options->flag;
	file->mode = options->mode;
	file->closed = false;

	return file;
}

static void
nifsy_file_release(nifsy_file_t *file)
{
	(void) enif_release_resource(file);
	return;
}

static void
nifsy_file_dtor(ErlNifEnv *env, void *resource)
{
	// TRACE_F("file destructor\n");

	nifsy_file_t *file = (nifsy_file_t *)(resource);

	if (file != NULL) {
		if (file->fd >= 0) {
			(void) close(file->fd);
			file->fd = -1;
		}
		if (file->rwlock != NULL) {
			(void) enif_rwlock_destroy(file->rwlock);
			file->rwlock = NULL;
		}
	}

	return;
}

static bool
nifsy_file_options(ErlNifEnv *env, ERL_NIF_TERM list, nifsy_file_options_t *options)
{
	ERL_NIF_TERM head;
	int arity = 0;
	const ERL_NIF_TERM *elements = NULL;
	unsigned long value = 0;

	if (!enif_is_list(env, list)) {
		return false;
	}

	options->flag = 0;
	options->mode = 0;
	options->lock = false;
	options->read_ahead_bytes = 0;

	while (enif_get_list_cell(env, list, &head, &list)) {
		if (enif_is_identical(head, ATOM_read_ahead)) {
			options->read_ahead_bytes = 0x4000000UL;
#ifdef O_APPEND
		} else if (enif_is_identical(head, ATOM_append)) {
			options->flag |= O_APPEND;
#endif
#ifdef O_CLOEXEC
		} else if (enif_is_identical(head, ATOM_cloexec)) {
			options->flag |= O_CLOEXEC;
#endif
#ifdef O_CREAT
		} else if (enif_is_identical(head, ATOM_creat)) {
			options->flag |= O_CREAT;
#endif
#ifdef O_EVTONLY
		} else if (enif_is_identical(head, ATOM_evtonly)) {
			options->flag |= O_EVTONLY;
#endif
#ifdef O_EXCL
		} else if (enif_is_identical(head, ATOM_excl)) {
			options->flag |= O_EXCL;
#endif
#ifdef O_EXLOCK
		} else if (enif_is_identical(head, ATOM_exlock)) {
			options->flag |= O_EXLOCK;
#endif
#ifdef O_NOFOLLOW
		} else if (enif_is_identical(head, ATOM_nofollow)) {
			options->flag |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
		} else if (enif_is_identical(head, ATOM_nonblock)) {
			options->flag |= O_NONBLOCK;
#endif
#ifdef O_RDONLY
		} else if (enif_is_identical(head, ATOM_rdonly)) {
			options->flag |= O_RDONLY;
#endif
#ifdef O_RDWR
		} else if (enif_is_identical(head, ATOM_rdwr)) {
			options->flag |= O_RDWR;
#endif
#ifdef O_SHLOCK
		} else if (enif_is_identical(head, ATOM_shlock)) {
			options->flag |= O_SHLOCK;
#endif
#ifdef O_SYMLINK
		} else if (enif_is_identical(head, ATOM_symlink)) {
			options->flag |= O_SYMLINK;
#endif
#ifdef O_TRUNC
		} else if (enif_is_identical(head, ATOM_trunc)) {
			options->flag |= O_TRUNC;
#endif
#ifdef O_WRONLY
		} else if (enif_is_identical(head, ATOM_wronly)) {
			options->flag |= O_WRONLY;
#endif
		} else if (enif_get_tuple(env, head, &arity, &elements) && arity == 2 && enif_is_atom(env, elements[0])) {
			if (enif_is_identical(elements[0], ATOM_read_ahead) && enif_get_ulong(env, elements[1], &value)) {
				options->read_ahead_bytes = value;
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

/*
 * Erlang NIF callbacks
 */

typedef struct nifsy_idle_s {
	uint64_t	ticks;
} nifsy_idle_t;

static void
nifsy_nif_loop_idle(uv_idle_t *handle)
{
	nifsy_context_t *ctx = (nifsy_context_t *)(handle->loop->data);
	nifsy_idle_t *idle = (nifsy_idle_t *)(handle->data);

	ctx->idles++;

	if ((idle->ticks)++ >= 100000UL) {
		(void) uv_idle_stop(&ctx->idle);
	}

	// uv_mutex_lock(&ctx->mutex);
	// // if (uv_cond_timedwait(&ctx->cond, &ctx->mutex, 1000000000ULL) == 0) {
	// if (uv_cond_timedwait(&ctx->cond, &ctx->mutex, 1000000ULL) == 0) {
	// // (void) uv_cond_wait(&ctx->cond, &ctx->mutex);
	// 	ctx->wakes++;
	// }
	// uv_mutex_unlock(&ctx->mutex);

	return;
}

// static void
// nifsy_nif_loop_wake(uv_async_t *handle)
// {
// 	nifsy_context_t *ctx = (nifsy_context_t *)(handle->data);

// 	ctx->wake_count++;
// 	return;
// }

static void *
nifsy_nif_loop(void *priv_data)
{
	nifsy_context_t *ctx = (nifsy_context_t *)(priv_data);
	int retval = 0;

	nifsy_idle_t idle;

	ctx->idle.data = (void *)(&idle);

	(void) uv_idle_init(ctx->loop, &ctx->idle);
	// (void) nifsy_nif_loop_idle;
	// (void) uv_pipe_bind(&ctx->pipe, ".nifsy");

	ctx->loop_alive = true;

	usleep(1);

	(void) enif_cond_signal(ctx->wake_cond);

	(void) enif_mutex_lock(ctx->wake_mutex);

	for (;;) {
		// TRACE_F("timeout: %d\n", uv_backend_timeout(ctx->loop));
		if (ctx->loop_stop) {
			// (void) uv_idle_stop(&ctx->idle);
			ctx->loop_alive = false;
			break;
		}
		// ctx->idle->data = (void *)(enif_monotonic_time(ERL_NIF_MSEC));
		idle.ticks = 0;
		(void) uv_idle_start(&ctx->idle, &nifsy_nif_loop_idle);
		// TRACE_F("monotonic msec: %llu\n", enif_monotonic_time(ERL_NIF_MSEC));
		retval = uv_run(ctx->loop, UV_RUN_DEFAULT);
		(void) retval;
		// ctx->idles++;
		(void) enif_cond_wait(ctx->wake_cond, ctx->wake_mutex);
		ctx->wakes++;
		// sleep(1);
		// TRACE_F("Loop: %d\n", retval);
	}

	(void) enif_mutex_unlock(ctx->wake_mutex);

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
		ATOM(idle,		"idle");
		ATOM(lock,		"lock");
		ATOM(loop_wait,		"loop_wait");
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
		ATOM(wake,		"wake");
		ATOM(write,		"write");
		ATOM(wronly,		"wronly");
	#undef ATOM

	/* Initialize context */
	ctx->version = nifsy_context_version;
	ctx->file_type = NULL;
	ctx->wake_mutex = NULL;
	ctx->wake_cond = NULL;
	// ctx->wakeup = NULL;
	ctx->loop = uv_default_loop();
	ctx->loop_tid = NULL;
	ctx->loop_alive = false;
	ctx->loop_stop = false;
	ctx->idles = 0;
	ctx->wakes = 0;
	// ctx->idle_count = 0;
	// ctx->wake_count = 0;

	// ctx->wake.data = (void *)(ctx);

	// (void) uv_async_init(ctx->loop, &ctx->wake, &nifsy_nif_loop_wake);

	// ctx->idle.data  = (void *)(ctx);
	// ctx->mutex.data = (void *)(ctx);
	// ctx->cond.data  = (void *)(ctx);
	// ctx->pipe.data = (void *)(ctx);

	ctx->loop->data = (void *)(ctx);

	// (void) uv_mutex_init(&ctx->mutex);
	// (void) uv_cond_init(&ctx->cond);

	// (void) uv_pipe_init(ctx->loop, &ctx->pipe, 1);

	resource_flags = (ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

	/* Create file type */
	ctx->file_type = enif_open_resource_type(env, NULL, "nifsy_file_type", &nifsy_file_dtor, resource_flags, NULL);

	if (ctx->file_type == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create wake mutex */
	ctx->wake_mutex = enif_mutex_create("nifsy_wake_mutex");

	if (ctx->wake_mutex == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create wake condition variable */
	ctx->wake_cond = enif_cond_create("nifsy_wake_cond");

	if (ctx->wake_cond == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Allocate loop thread id */
	ctx->loop_tid = enif_alloc(sizeof(ErlNifTid));

	if (ctx->loop_tid == NULL) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
	}

	/* Create loop thread */
	(void) enif_mutex_lock(ctx->wake_mutex);
	retval = enif_thread_create("nifsy_loop", ctx->loop_tid, &nifsy_nif_loop, (void *)(ctx), NULL);

	if (retval != 0) {
		(void) enif_mutex_unlock(ctx->wake_mutex);
		(void) enif_free(ctx->loop_tid);
		ctx->loop_tid = NULL;
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return retval;
	}

	(void) enif_cond_wait(ctx->wake_cond, ctx->wake_mutex);

	(void) enif_mutex_unlock(ctx->wake_mutex);

	if (ctx->loop_alive == false) {
		(void) nifsy_nif_unload(env, (void *)(ctx));
		return 1;
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

	if (ctx == NULL) {
		return;
	}

	ctx->loop_stop = true;
	if (ctx->loop_tid != NULL) {
		(void) uv_stop(ctx->loop);
		WAKEUP(ctx);
		(void) enif_thread_join(*(ctx->loop_tid), NULL);
		(void) enif_free(ctx->loop_tid);
		ctx->loop_tid = NULL;
	}

	if (ctx->wake_cond != NULL) {
		(void) enif_cond_destroy(ctx->wake_cond);
		ctx->wake_cond = NULL;
	}

	if (ctx->wake_mutex != NULL) {
		(void) enif_mutex_destroy(ctx->wake_mutex);
		ctx->wake_mutex = NULL;
	}

	(void) enif_free((void *)(ctx));

	return;
}

ERL_NIF_INIT(nifsy_nif, nifsy_nif_funcs, nifsy_nif_load, NULL, nifsy_nif_upgrade, nifsy_nif_unload)
