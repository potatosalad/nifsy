%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(nifsy).

%% API
-export([close/1]).
-export([open/2]).
-export([read/2]).
-export([read_line/1]).
-export([system_info/0]).

%% Macros
-define(call(Request),
	case Request of
		{ok, Tag} when is_reference(Tag) ->
			receive
				{Tag, Reply} ->
					Reply
			after
				5000 ->
					io:format("Failed to receive ~p reply from: ~s~n", [Tag, ??Request]),
					{error, timeout}
			end;
		Reply ->
			Reply
	end).

%%%===================================================================
%%% API functions
%%%===================================================================

close(IoDevice) ->
	?call(nifsy_nif:close(IoDevice)).

open(Path, Options) ->
	?call(nifsy_nif:open(binary_to_list(iolist_to_binary(Path)), Options)).

read(IoDevice, Bytes) ->
	?call(nifsy_nif:read(IoDevice, Bytes)).

read_line(IoDevice) ->
	case ?call(nifsy_nif:read_line(IoDevice)) of
		{error, timeout} ->
			io:format("read/2 attempt: ~p~n", [case read(IoDevice, 1024) of
				{ok, B} ->
					byte_size(B);
				E ->
					E
			end]),
			{error, timeout};
		Other ->
			Other
	end.

system_info() ->
	nifsy_nif:system_info().
