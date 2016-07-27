%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(nifsy_nif).

%% API
-export([close/1]).
-export([open/2]).
-export([read/2]).

-on_load(init/0).

%%%===================================================================
%%% API functions
%%%===================================================================

close(_IoDevice) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

open(_Path, _Options) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

read(_IoDevice, _Bytes) ->
	erlang:nif_error({nif_not_loaded, ?MODULE}).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
init() ->
	SoName = filename:join([priv_dir(), "dev", ?MODULE_STRING]),
	erlang:load_nif(SoName, 0).

%% @private
priv_dir() ->
	case code:priv_dir(nifsy) of
		{error, bad_name} ->
			case code:which(nifsy) of
				Filename when is_list(Filename) ->
					filename:join([filename:dirname(Filename), "../priv"]);
				_ ->
					"../priv"
			end;
		Dir ->
			Dir
	end.
