// -*- mode: c; tab-width: 8; indent-tabs-mode: 1; st-rulers: [70] -*-
// vim: ts=8 sw=8 ft=c noet

#include "nifsy_nif.h"

/*
 * Macros
 */

#define	RW_UNLOCK							\
	do								\
	{								\
		if (handle->rwlock != 0) {				\
			(void) enif_rwlock_rwunlock(handle->rwlock);	\
		}							\
	} while (0)

#define	RW_LOCK								\
	do								\
	{								\
		if (handle->rwlock != 0) {				\
			(void) enif_rwlock_rwlock(handle->rwlock);	\
		}							\
	} while (0)

#define	RETURN_BADARG(code)						\
	do								\
	{								\
		if (!(code)) {						\
			return enif_make_badarg(env);			\
		}							\
	} while (0)

// #define	RETURN_ERROR(code, error_atom)					\
// 	do								\
// 	{								\
// 		if (!(code)) {						\
// 			return enif_make_tuple2(env, ATOM_error,	\
// 						error_atom);		\
// 		}							\
// 	} while (0)

#define	HANDLE_ERROR(code, if_error, error_atom)			\
	do								\
	{								\
		if (!(code)) {						\
			(if_error);					\
			return enif_make_tuple2(env, ATOM_error,	\
						error_atom);		\
		}							\
	} while (0)

#define	RETURN_ERROR_IF_NEG(code)					\
	do								\
	{								\
		if ((code) < 0) {					\
			return enif_make_tuple2(env, ATOM_error,	\
				enif_make_tuple2(env,			\
					enif_make_int(env, errno),	\
					enif_make_string(env,		\
						strerror(errno),	\
						ERL_NIF_LATIN1)));	\
		}							\
	} while (0)

#define	HANDLE_ERROR_IF_NEG(code, if_error)				\
	do								\
	{								\
		if ((code) < 0) {					\
			(if_error);					\
			return enif_make_tuple2(env, ATOM_error,	\
				enif_make_tuple2(env,			\
					enif_make_int(env, errno),	\
					enif_make_string(env,		\
						strerror(errno),	\
						ERL_NIF_LATIN1)));	\
		}							\
	} while (0)

#define NIFSY_HANDLE_ALLOC(env, handle)					\
	do								\
	{								\
		nifsy_priv_data_t *priv_data;				\
		priv_data = (nifsy_priv_data_t *)(enif_priv_data(env));	\
		handle = (nifsy_handle_t *)(				\
			enif_alloc_resource(				\
				priv_data->nifsy_resource,		\
				sizeof(nifsy_handle_t)));		\
	} while (0)

/*
 * Types
 */

typedef struct nifsy_handle_s {
	int		file_descriptor;
	int		mode;
	ErlNifRWLock	*rwlock;
	ErlNifBinary	*buffer;
	unsigned long	buffer_alloc;
	unsigned long	buffer_offset;
	unsigned long	buffer_size;
	bool		closed;
	char		padding[7];
} nifsy_handle_t;

/*
 * Erlang NIF functions
 */

static bool	decode_options(ErlNifEnv *env, ERL_NIF_TERM list, int *mode, bool *lock);
static int	nifsy_do_close(nifsy_handle_t *handle, bool from_dtor);
static void	nifsy_dtor(ErlNifEnv *env, void *resource);

static ERL_NIF_TERM
nifsy_close_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	nifsy_priv_data_t *priv_data = (nifsy_priv_data_t *)(enif_priv_data(env));
	ErlNifResourceType *resource_type = priv_data->nifsy_resource;
	nifsy_handle_t *handle = NULL;

	RETURN_BADARG(!(argc != 1
		|| !enif_get_resource(env, argv[0], resource_type, (void **)&handle)));

	RW_LOCK;
	int ret = nifsy_do_close(handle, false);
	RW_UNLOCK;

	RETURN_ERROR_IF_NEG(ret);

	return ATOM_ok;
}

static ERL_NIF_TERM
nifsy_open_3(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary filename;
	unsigned long buffer_alloc = 0;
	int mode = 0;
	bool lock = false;

	RETURN_BADARG(!(argc != 3
		|| !enif_inspect_iolist_as_binary(env, argv[0], &filename)
		|| filename.size > PATH_MAX));

	char path[PATH_MAX + 1];
	(void) memcpy(path, filename.data, filename.size);
	(void) memset(path + filename.size, 0, 1);

	RETURN_BADARG(!(strnlen((const char *)(filename.data), filename.size) == 0
		|| !enif_get_ulong(env, argv[1], &buffer_alloc)
		|| !decode_options(env, argv[2], &mode, &lock)));

	int file_descriptor = open(path, mode);

	RETURN_ERROR_IF_NEG(file_descriptor);

	nifsy_handle_t *handle = NULL;
	NIFSY_HANDLE_ALLOC(env, handle);

	if (lock) {
		handle->rwlock = enif_rwlock_create("nifsy");
	} else {
		handle->rwlock = 0;
	}

	handle->file_descriptor = file_descriptor;
	handle->mode = mode;
	handle->closed = false;
	HANDLE_ERROR(handle->buffer = enif_alloc(sizeof(ErlNifBinary)),
		{
			(void) enif_release_resource(handle);
			RW_UNLOCK;
		},
		ATOM_enomem);
	HANDLE_ERROR(enif_alloc_binary(buffer_alloc, handle->buffer),
		{
			(void) enif_release_resource(handle);
			RW_UNLOCK;
		},
		ATOM_enomem);

	handle->buffer_alloc = buffer_alloc;
	handle->buffer_offset = 0;
	handle->buffer_size = 0;

	ERL_NIF_TERM resource = enif_make_resource(env, handle);
	(void) enif_release_resource(handle);

	return enif_make_tuple2(env, ATOM_ok, resource);
}

static ERL_NIF_TERM
nifsy_read_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	nifsy_priv_data_t *priv_data = (nifsy_priv_data_t *)(enif_priv_data(env));
	ErlNifResourceType *resource_type = priv_data->nifsy_resource;
	nifsy_handle_t *handle = NULL;
	unsigned long requested_bytes = 0;

	RETURN_BADARG(!(argc != 2
		|| !enif_get_resource(env, argv[0], resource_type, (void **)&handle)
		|| !enif_get_ulong(env, argv[1], &requested_bytes)
		|| handle->closed
		|| (handle->mode & O_WRONLY)));

	unsigned long buffer_alloc = handle->buffer_alloc;

	RW_LOCK;

	ErlNifBinary return_bytes;
	HANDLE_ERROR(enif_alloc_binary(requested_bytes, &return_bytes),
		{ RW_LOCK; }, ATOM_enomem);

	unsigned long return_bytes_offset = 0;

	if (handle->buffer && handle->buffer_offset != 0) {
		DEBUG_LOG("a buffer exists");
		unsigned char *rem_data = handle->buffer->data + handle->buffer_offset;
		unsigned long rem_data_size = handle->buffer_size - handle->buffer_offset;

		if (rem_data_size >= requested_bytes) {
			DEBUG_LOG("b enough data");
			(void) memcpy(return_bytes.data, rem_data, requested_bytes);
			handle->buffer_offset += requested_bytes;

			RW_UNLOCK;

			return enif_make_tuple2(env, ATOM_ok,
				enif_make_binary(env, &return_bytes));
		} else {
			DEBUG_LOG("c not enough data");
			(void) memcpy(return_bytes.data, rem_data, rem_data_size);
			return_bytes_offset = rem_data_size;
			handle->buffer_offset = 0;
		}
	}

	while (true) {
		DEBUG_LOG("d loop start");
		unsigned long nbytes_read;
		HANDLE_ERROR_IF_NEG(
			nbytes_read = (unsigned long)read(handle->file_descriptor,
				handle->buffer->data, buffer_alloc),
			{
				(void) enif_release_binary(&return_bytes);
				RW_UNLOCK;
			});

		handle->buffer_size = nbytes_read;

		if (!nbytes_read) {
			DEBUG_LOG("e no data");
			if (return_bytes_offset) {
				DEBUG_LOG("f return return_bytes");
				HANDLE_ERROR(enif_realloc_binary(&return_bytes, return_bytes_offset),
					{ RW_UNLOCK; }, ATOM_enomem);
				RW_UNLOCK;
				return enif_make_tuple2(env, ATOM_ok,
					enif_make_binary(env, &return_bytes));
			} else {
				DEBUG_LOG("g eof");
				(void) enif_release_binary(&return_bytes);
				RW_UNLOCK;
				return enif_make_tuple2(env, ATOM_ok, ATOM_eof);
			}
		}

		unsigned long remaining_bytes = requested_bytes - return_bytes_offset;

		if (nbytes_read >= remaining_bytes) {
			DEBUG_LOG("h enough bytes");
			(void) memcpy(return_bytes.data + return_bytes_offset, handle->buffer->data,
				remaining_bytes);
			handle->buffer_offset += remaining_bytes;

			RW_UNLOCK;

			return enif_make_tuple2(env, ATOM_ok,
				enif_make_binary(env, &return_bytes));
		} else {
			DEBUG_LOG("i not enough bytes");
			(void) memcpy(return_bytes.data + return_bytes_offset, handle->buffer->data,
				nbytes_read);
			return_bytes_offset += nbytes_read;
			handle->buffer_offset = 0;
		}
	}
}

static ERL_NIF_TERM
nifsy_read_line_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	nifsy_priv_data_t *priv_data = (nifsy_priv_data_t *)(enif_priv_data(env));
	ErlNifResourceType *resource_type = priv_data->nifsy_resource;
	nifsy_handle_t *handle = NULL;

	RETURN_BADARG(!(argc != 1
		|| !enif_get_resource(env, argv[0], resource_type, (void **)&handle)
		|| handle->closed
		|| (handle->mode & O_WRONLY)));

	unsigned long buffer_alloc = handle->buffer_alloc;

	RW_LOCK;

	ErlNifBinary new_line_buffer;
	new_line_buffer.data = NULL;

	if (handle->buffer && handle->buffer_offset != 0) {
		DEBUG_LOG("a buffer exists");
		unsigned char *newline,
		*rem_data = handle->buffer->data + handle->buffer_offset;
		unsigned long rem_data_size = handle->buffer_size - handle->buffer_offset;

		if ((newline = memchr(rem_data, '\n', rem_data_size))) {
			DEBUG_LOG("b newline found");
			unsigned long line_size = (unsigned long)(newline - rem_data);

			HANDLE_ERROR(enif_alloc_binary(line_size, &new_line_buffer),
				{ RW_UNLOCK; }, ATOM_enomem);

			(void) memcpy(new_line_buffer.data, rem_data, line_size);
			ERL_NIF_TERM new_line_term = enif_make_binary(env, &new_line_buffer);
			handle->buffer_offset = handle->buffer_offset + line_size + 1;

			RW_UNLOCK;

			return enif_make_tuple2(env, ATOM_ok, new_line_term);
		} else {
			DEBUG_LOG("c newline not found");
			HANDLE_ERROR(enif_alloc_binary(rem_data_size, &new_line_buffer),
				{ RW_UNLOCK; }, ATOM_enomem);

			(void) memcpy(new_line_buffer.data, rem_data, rem_data_size);
			handle->buffer_offset = 0;
		}
	}

	while (true) {
		DEBUG_LOG("e loop start");
		unsigned long nbytes_read;
		HANDLE_ERROR_IF_NEG(
			nbytes_read = (unsigned long)read(handle->file_descriptor,
			handle->buffer->data, buffer_alloc),
			{
				if (new_line_buffer.data) {
					(void) enif_release_binary(&new_line_buffer);
				}
				RW_UNLOCK;
			});

		handle->buffer_size = nbytes_read;

		if (!nbytes_read) {
			DEBUG_LOG("f no bytes read");
			if (new_line_buffer.data) {
				DEBUG_LOG("g buffer existed");
				RW_UNLOCK;
				return enif_make_tuple2(env, ATOM_ok,
					enif_make_binary(env, &new_line_buffer));
			} else {
				DEBUG_LOG("h eof");
				RW_UNLOCK;
				return enif_make_tuple2(env, ATOM_ok, ATOM_eof);
			}
		}

		unsigned char *newline;
		if ((newline = memchr(handle->buffer->data, '\n', handle->buffer_size))) {
			DEBUG_LOG("j newline found in read");
			unsigned long line_size = (unsigned long)(newline - handle->buffer->data);

			if (new_line_buffer.data) {
				DEBUG_LOG("k new line buffer existed");
				unsigned long orig_size = new_line_buffer.size;

				HANDLE_ERROR(enif_realloc_binary(&new_line_buffer,
					new_line_buffer.size + line_size),
					{ RW_UNLOCK; }, ATOM_enomem);

				(void) memcpy(new_line_buffer.data + orig_size, handle->buffer->data,
					line_size);
				ERL_NIF_TERM new_line_term = enif_make_binary(env, &new_line_buffer);
				handle->buffer_offset = handle->buffer_offset + line_size + 1;
				RW_UNLOCK;

				return enif_make_tuple2(env, ATOM_ok, new_line_term);
			} else {
				DEBUG_LOG("l new line buffer create");
				HANDLE_ERROR(enif_alloc_binary(line_size, &new_line_buffer),
					{ RW_UNLOCK; }, ATOM_enomem);

				(void) memcpy(new_line_buffer.data, handle->buffer->data, line_size);
				ERL_NIF_TERM new_line_term = enif_make_binary(env, &new_line_buffer);
				handle->buffer_offset = handle->buffer_offset + line_size + 1;
				RW_UNLOCK;

				return enif_make_tuple2(env, ATOM_ok, new_line_term);
			}
		} else {
			DEBUG_LOG("m newline not found");
			if (new_line_buffer.data) {
				DEBUG_LOG("n new line buffer exists");
				unsigned long orig_size = new_line_buffer.size;

				HANDLE_ERROR(
					enif_realloc_binary(&new_line_buffer,
					new_line_buffer.size + handle->buffer_size),
					{ RW_UNLOCK; }, ATOM_enomem);

				(void) memcpy(new_line_buffer.data + orig_size, handle->buffer->data,
					handle->buffer_size);
				handle->buffer_offset = 0;
			} else {
				DEBUG_LOG("o new line buffer not found");
				HANDLE_ERROR(enif_alloc_binary(handle->buffer_size, &new_line_buffer),
					{ RW_UNLOCK; }, ATOM_enomem);

				(void) memcpy(new_line_buffer.data, handle->buffer->data, handle->buffer_size);
				handle->buffer_offset = 0;
			}
		}
	}
}

static ERL_NIF_TERM
nifsy_write_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	nifsy_priv_data_t *priv_data = (nifsy_priv_data_t *)(enif_priv_data(env));
	ErlNifResourceType *resource_type = priv_data->nifsy_resource;
	nifsy_handle_t *handle = NULL;
	ErlNifBinary write_binary;

	RETURN_BADARG(!(argc != 2
		|| !enif_get_resource(env, argv[0], resource_type, (void **)&handle)
		|| handle->closed
		|| !(handle->mode & O_WRONLY)
		|| !enif_inspect_iolist_as_binary(env, argv[1], &write_binary)));

	RW_LOCK;

	unsigned long remaining_buffer_bytes =
		handle->buffer->size - handle->buffer_offset;

	if (remaining_buffer_bytes > write_binary.size) {
		(void) memcpy(handle->buffer->data + handle->buffer_offset,
			write_binary.data, write_binary.size);
		handle->buffer_offset += write_binary.size;
	} else {
		unsigned long write_binary_offset = 0;
		unsigned long write_binary_remaining = write_binary.size;

		while (write_binary_remaining) {
			(void) memcpy(handle->buffer->data + handle->buffer_offset,
				write_binary.data + write_binary_offset,
				remaining_buffer_bytes);

			HANDLE_ERROR_IF_NEG(
				write(handle->file_descriptor,
					handle->buffer->data,
					handle->buffer->size),
				{ RW_UNLOCK; });

			write_binary_remaining -= remaining_buffer_bytes;
			write_binary_offset += remaining_buffer_bytes;

			if (write_binary_remaining < handle->buffer->size) {
				(void) memcpy(handle->buffer->data,
					write_binary.data + write_binary_offset,
					write_binary_remaining);
				handle->buffer_offset = write_binary_remaining;
				write_binary_remaining = 0;
			} else {
				handle->buffer_offset = 0;
				remaining_buffer_bytes = handle->buffer->size;
			}
		}
	}

	RW_UNLOCK;

	return ATOM_ok;
}

/*
 * Internal functions
 */

static bool
decode_options(ErlNifEnv *env, ERL_NIF_TERM list, int *mode, bool *lock)
{
	int m = 0;
	bool l = false;
	ERL_NIF_TERM head;

	while (enif_get_list_cell(env, list, &head, &list)) {
		if (enif_is_identical(head, ATOM_read)) {
			m |= O_RDONLY;
		} else if (enif_is_identical(head, ATOM_write)) {
			m |= O_WRONLY;
		} else if (enif_is_identical(head, ATOM_append)) {
			m |= O_APPEND;
		} else if (enif_is_identical(head, ATOM_create)) {
			m |= O_CREAT;
		} else if (enif_is_identical(head, ATOM_exclusive)) {
			m |= O_EXCL;
		} else if (enif_is_identical(head, ATOM_truncate)) {
			m |= O_TRUNC;
		} else if (enif_is_identical(head, ATOM_sync)) {
			m |= O_SYNC;
		} else if (enif_is_identical(head, ATOM_dsync)) {
			m |= O_DSYNC;
		} else if (enif_is_identical(head, ATOM_lock)) {
			l = true;
		} else {
			return false;
		}
	}

	*mode = m;
	*lock = l;

	return true;
}

static int
nifsy_do_close(nifsy_handle_t *handle, bool from_dtor)
{
	if (from_dtor) {
		int result = close(handle->file_descriptor);
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
nifsy_dtor(ErlNifEnv *env, void *resource)
{
	nifsy_handle_t *handle = (nifsy_handle_t *)(resource);
	(void) nifsy_do_close(handle, true);
	if (handle->rwlock != 0) {
		enif_rwlock_destroy(handle->rwlock);
	}
}

/*
 * Erlang NIF callbacks
 */

static int
nifsy_nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
	/* Allocate private data */
	nifsy_priv_data_t *data = enif_alloc(sizeof(nifsy_priv_data_t));
	if (data == NULL) {
		return 1;
	}

	/* Initialize common atoms */
	#define ATOM(Id, Value) { ATOM_##Id = enif_make_atom(env, Value); }
		ATOM(append,		"append");
		ATOM(closed,		"closed");
		ATOM(create,		"create");
		ATOM(dsync,		"dsync");
		ATOM(enomem,		"enomem");
		ATOM(eof,		"eof");
		ATOM(error,		"error");
		ATOM(exclusive,		"exclusive");
		ATOM(lock,		"lock");
		ATOM(ok,		"ok");
		ATOM(read,		"read");
		ATOM(sync,		"sync");
		ATOM(truncate,		"truncate");
		ATOM(write,		"write");
	#undef ATOM

	ErlNifResourceFlags flags =
		(ErlNifResourceFlags)(ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

	data->version = nifsy_priv_data_version;
	data->nifsy_resource = enif_open_resource_type(env, NULL,
		"nifsy_resource", &nifsy_dtor, flags, NULL);

	*priv_data = (void *)(data);

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
	(void) enif_free(priv_data);
	return;
}

ERL_NIF_INIT(Elixir.Nifsy, nifsy_nif_funcs, nifsy_nif_load, NULL, nifsy_nif_upgrade, nifsy_nif_unload)
