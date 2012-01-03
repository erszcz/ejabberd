-module(ejabberd_riak).

%% Public interface
-export([start_link/1,
         get/2,
         set/3,
         delete/1,
         delete/2,
         list_keys/1,
         mapred_bucket/2,
         collect/3]).

-include("ejabberd.hrl").

start_link(WorkerId) ->
    {Host, Port} = {get_host(), get_port()},
    {ok, Pid} = connect(Host, Port),
    ejabberd_riak_sup:register(WorkerId, Pid),
    {ok, Pid}.

get(Bucket, Key) ->
    case get_obj(Bucket, Key) of
        {ok, Obj} ->
            {ok, binary_to_term(riakc_obj:get_value(Obj))};
        Error ->
            Error
    end.

%% Be careful if/when using real binary data as keys (i.e. not binaries
%% made with term_to_binary/1) as it may cause unintended collisions with
%% keys made with term_to_binary/1 from Erlang native terms.
-spec get_obj(binary(), term()) -> {ok, term()} | {error, any()}.
get_obj(Bucket, Key) when not is_binary(Key) ->
    get_obj(Bucket, term_to_binary(Key));
get_obj(Bucket, BinaryKey) ->
    riakc_pb_socket:get(get_worker(), Bucket, BinaryKey).

-spec set(binary(), term(), term()) -> ok | {error, any()}.
set(Bucket, Key, Value) ->
    BinaryKey = term_to_binary(Key),
    BinaryValue = term_to_binary(Value),
    case get_obj(Bucket, Key) of
        {ok, Obj} ->
            NewObj = riakc_obj:update_value(Obj, BinaryValue),
            riakc_pb_socket:put(get_worker(), NewObj);
        {error, notfound} ->
            NewObj = riakc_obj:new(Bucket, BinaryKey, BinaryValue),
            riakc_pb_socket:put(get_worker(), NewObj);
        Else ->
            Else
    end.

%% Perform operation for each key in bucket.
%% F = fun(RiakWorker::pid(), BinaryKey::binary()).
-spec foreach(fun(), binary()) -> any().
foreach(F, Bucket) ->
    case riakc_pb_socket:list_keys(get_worker(), Bucket) of
        {ok, BinKeys} ->
            lists:foreach(fun(Key) -> F(get_worker(), Key) end, BinKeys);
        Error ->
            Error
    end.

%% Perform operation for each key in bucket.
%% F = fun(RiakWorker::pid(), BinaryKey::binary(), Acc::any()).
-spec collect(fun(), any(), binary()) -> any().
collect(F, Acc0, Bucket) ->
    case riakc_pb_socket:list_keys(get_worker(), Bucket) of
        {ok, BinKeys} ->
            lists:foldl(fun(Key, Acc) ->
                            F(get_worker(), Key, Acc)
                        end,
                        Acc0,
                        BinKeys);
        Error ->
            Error
    end.

%% collect usage example (for values being stringified integers):
%   F = fun(_,E,A) ->
%           case ejabberd_riak:get(<<"test">>, E) of
%               {ok,V} ->
%                   list_to_integer(V) + A;
%               _ ->
%                   A
%           end
%   end,
%   ejabberd_riak:collect(F, 0, <<"test">>).

%% Delete whole bucket.
%% TODO: I feel it's far from elegant.
-spec delete(binary()) -> ok | {error, any()}.
delete(Bucket) ->
    foreach(fun(W, Key) ->
                riakc_pb_socket:delete(W, Bucket, Key)
            end,
            Bucket).

%% Delete object by key.
-spec delete(binary(), term()) -> ok | {error, any()}.
delete(Bucket, Key) ->
    riakc_pb_socket:delete(get_worker(), Bucket, term_to_binary(Key)).

-spec list_keys(binary()) -> {ok, [binary()]} | {error, any()}.
list_keys(Bucket) ->
    case riakc_pb_socket:list_keys(get_worker(), Bucket) of
        {ok, BinKeys} ->
            lists:map(fun erlang:binary_to_term/1, BinKeys);
        Error ->
            Error
    end.

-spec mapred_bucket(binary(), list()) -> any().
mapred_bucket(Bucket, Query) ->
    riakc_pb_socket:mapred_bucket(get_worker(), Bucket, Query).

get_host() ->
    get_config(riak_host, "127.0.0.1").

get_port() ->
    get_config(riak_port, 8087).

get_timeout() ->
    get_config(riak_initial_connection_timeout, 10).

get_config(Key, Default) ->
    case ejabberd_config:get_local_option({Key, ?MYNAME}) of
        undefined ->
            Default;
        Value ->
            Value
    end.

get_worker() ->
    ejabberd_riak_sup:get_worker().

-spec connect(string(), integer()) -> {ok, pid()} | {error, term()}.
connect(Host, Port) ->
    random:seed(now()),
    connect(Host, Port, 10, get_timeout()).

-spec connect(string(), integer(), integer(), integer()) -> {ok, pid()} | {error, term()}.
connect(Host, Port, 0, _) ->
    riakc_pb_socket:start_link(Host, Port);
connect(Host, Port, Retries, WaitTime) ->
    case riakc_pb_socket:start_link(Host, Port) of
        {ok, Pid} ->
            {ok, Pid};
        _Else ->
            timer:sleep(WaitTime+random:uniform(WaitTime)),
            connect(Host, Port, Retries-1, WaitTime*2)
    end.
