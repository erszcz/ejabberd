-module(re_mapred).

-include("ejabberd_sm.hrl").

-include_lib("eunit/include/eunit.hrl").

-export([read_session_map/3,
         read_session_map/2]).

%%
%% Map Phase
%%

read_session_map(SID, Acc) ->
    {map, {modfun, ?MODULE, read_session_map}, SID, Acc}.

read_session_map({error, notfound}, _, _SID) ->
    [];
read_session_map(Obj, _, SID) ->
    Sessions = case riak_object:get_value(Obj) of
        V when is_binary(V) -> binary_to_term(V);
        V -> V
    end,
    case lists:keyfind(SID, #session.sid, Sessions) of
        false ->
            [];
        Session ->
            [Session]
    end.

%%
%% Tests
%%

read_session_map_test() ->
    S1 = #session{sid = 1},
    S2 = #session{sid = 2},
    S3 = #session{sid = 3},
    O1 = riak_object:new(<<"s">>, <<"1">>, [S1, S2, S3]),
    SID = 2,
    [S2] = read_session_map(O1, test, SID),
    [] = read_session_map({error, notfound}, test, SID).
