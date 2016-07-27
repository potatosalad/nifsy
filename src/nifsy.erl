%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(nifsy).

%% API
-export([close/1]).
-export([open/2]).
-export([read/2]).

%% Macros
-define(call(Request),
	case Request of
		{ok, Tag} when is_reference(Tag) ->
			receive
				{Tag, Reply} ->
					Reply
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
