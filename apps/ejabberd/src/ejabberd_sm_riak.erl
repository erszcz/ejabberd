-module(ejabberd_sm_riak).

-compile([export_all]).

-include("ejabberd_sm.hrl").

-define(SESSION_BUCKET, <<"session">>).
-define(SESSION_COUNTER_BUCKET, <<"session_counter">>).

create_table() ->
    ok.

%% Recalculates alive sessions when Node goes down 
%% and updates session and session_counter tables 
cleanup(_Node) -> 
	ok.

read_session_storage(SID) ->
   F = fun(_, US, A) ->
           {ok, Session} = ejabberd_riak:get(?SESSION_BUCKET, US),
           case lists:keyfind(SID, #session.sid, Session) of
               false ->
                   A;
               SessionItem ->
                   [SessionItem | A]
                   
           end
   end,

   ejabberd_riak:collect(F, [], ?SESSION_BUCKET).

delete_session_storage(SID, _Server) ->
    Sessions = read_session_storage(SID),

    lists:foreach(fun(El) ->
        {ok, Session} = ejabberd_riak:get(?SESSION_BUCKET, El#session.us),
        ejabberd_riak:set(?SESSION_BUCKET, El#session.us,
           lists:keydelete(El#session.sid, #session.sid, Session))
        end, Sessions).

get_session(User, Server, Resource) ->
    {ok, Session} = ejabberd_riak:get(?SESSION_BUCKET, {User, Server}),
    case lists:keyfind({User, Server, Resource}, #session.usr, Session) of
        false ->
            {error, notfound};
        SessionItem ->
            [SessionItem]
    end.

get_session(User, Server) ->
    case ejabberd_riak:get(?SESSION_BUCKET, {User, Server}) of
        {ok, Session} ->
            [Session];
        _ ->
            []
    end.

set_session_storage(SID, USR, US, Priority, Info) ->
    Session = case ejabberd_riak:get(?SESSION_BUCKET, US) of
       {ok, Sess} ->
			Sess;
		_ -> []
	end,

    ejabberd_riak:set(?SESSION_BUCKET, US,
        lists:keystore(SID, #session.sid, Session, #session{sid = SID,
				      usr = USR,
				      us = US,
				      priority = Priority,
				      info = Info})).

session_update_counter(_Server) ->
	ok.


