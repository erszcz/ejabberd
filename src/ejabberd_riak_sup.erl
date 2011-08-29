-module(ejabberd_riak_sup).

%% Public interface
-export([start_link/0,
         get_worker/0,
         register/2]).

%% Behaviour: supervisor
-behaviour(supervisor).
-export([init/1]).

-include("ejabberd.hrl").

-define(DEFAULT_POOL_SIZE, 4).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

pool_size() ->
    case ejabberd_config:get_local_option({riak_pool_size, ?MYNAME}) of
        I when is_integer(I), I > 0 ->
            I;
        _ ->
            ?DEFAULT_POOL_SIZE
    end.

-spec get_worker() -> pid().
get_worker() ->
    [{seq, Id}] = ets:update_counter(?MODULE, seq, {1,1,pool_size(),1}),
    [{Id, Pid}] = ets:lookup(?MODULE, Id),
    Pid.

clean_table() ->
    lists:foreach(
        fun({Id, Pid}) when is_integer(Id) ->
                case is_process_alive(Pid) of
                    false ->
                        ets:delete(?MODULE, Id);
                    true ->
                        ok
                end;
           (_) ->
                ok
        end,
        ets:tab2list(?MODULE)).

register(Id, Pid) ->
    clean_table(),
    ets:insert(?MODULE, {Id, Pid}).

init(_Args) ->
    PoolSize = pool_size(),

    ?MODULE = ets:new(?MODULE, [named_table, public]),
    ets:insert(?MODULE, {pool_size, PoolSize}),
    ets:insert(?MODULE, {seq, 0}),

    {ok, {{one_for_one, 2 * PoolSize, PoolSize},
          [ {N, {ejabberd_riak, start_link, [N]}, permanent, 2000,
             worker, [ejabberd_riak]} || N <- lists:seq(1, PoolSize) ]
         }}.
