-module(rsalt).
-compile([no_native]).

-on_load(init/0).
-export([secretbox/3, secretbox_open/3]).

secretbox(Data, Nonce, SecretKey) ->
    nif_secretbox(Data, Nonce, SecretKey).

secretbox_open(Data, Nonce, SecretKey) ->
    nif_secretbox_open(Data, Nonce, SecretKey).

init() ->
    PrivDir = code:priv_dir(?MODULE),
    erlang:load_nif(filename:join(PrivDir, "crates/rsalt/librsalt"), 0).

-define(NOT_LOADED, not_loaded(?LINE)).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

nif_secretbox(_Data, _Nonce, _SecretKey) ->
    ?NOT_LOADED.

nif_secretbox_open(_Data, _Nonce, _SecretKey) ->
    ?NOT_LOADED.

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

roundtrip_test() ->
	SecretKey = crypto:strong_rand_bytes(32),
	Nonce = crypto:strong_rand_bytes(24),
	Data = crypto:strong_rand_bytes(128),

	{ok, Boxed} = secretbox(Data, Nonce, SecretKey),
	{ok, Unboxed} = secretbox_open(Boxed, Nonce, SecretKey),
	?assert(Data =:= Unboxed).

-endif.
