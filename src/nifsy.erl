%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(nifsy).

%% API
-export([close/1]).
-export([open/2]).

%% Macros
-define(call(Request),
	case Request of
		{ok, Tag} ->
			receive
				{Tag, Reply} ->
					Reply
			end;
		Error ->
			Error
	end).

%%%===================================================================
%%% API functions
%%%===================================================================

close(File) ->
	?call(nifsy_nif:close(File)).

open(Path, Options) ->
	?call(nifsy_nif:open(binary_to_list(iolist_to_binary(Path)), Options)).
