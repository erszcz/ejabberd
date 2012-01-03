-module(ejabberd_sm_mnesia).

-compile([export_all]).

-include("ejabberd_sm.hrl").

create_table() ->
	update_tables(),

    mnesia:create_table(session,
			[{ram_copies, [node()]},
			 {attributes, record_info(fields, session)}]),
    mnesia:create_table(session_counter,
			[{ram_copies, [node()]},
			 {attributes, record_info(fields, session_counter)}]),
    mnesia:add_table_index(session, usr),
    mnesia:add_table_index(session, us),
    mnesia:add_table_copy(session, node(), ram_copies),
    mnesia:add_table_copy(session_counter, node(), ram_copies),
    mnesia:subscribe(system).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Update Mnesia tables

update_tables() ->
    case catch mnesia:table_info(session, attributes) of
	[ur, user, node] ->
	    mnesia:delete_table(session);
	[ur, user, pid] ->
	    mnesia:delete_table(session);
	[usr, us, pid] ->
	    mnesia:delete_table(session);
	[sid, usr, us, priority] ->
	    mnesia:delete_table(session);
	[sid, usr, us, priority, info] ->
	    ok;
	{'EXIT', _} ->
	    ok
    end,
    case lists:member(presence, mnesia:system_info(tables)) of
	true ->
	    mnesia:delete_table(presence);
	false ->
	    ok
    end,
    case lists:member(local_session, mnesia:system_info(tables)) of
	true ->
	    mnesia:delete_table(local_session);
	false ->
	    ok
    end.

%% Recalculates alive sessions when Node goes down 
%% and updates session and session_counter tables 
cleanup(Node) -> 
	recount_session_table_storage(Node).

read_session_storage(SID) -> 
	mnesia:dirty_read({session, SID}).

delete_session_storage(SID, Server) ->
    F = fun() ->
		mnesia:delete({session, SID}),
		mnesia:dirty_update_counter(session_counter,
					    jlib:nameprep(Server), -1)
	end,
    mnesia:sync_dirty(F).

get_session(User, Server, Resource) ->
	mnesia:dirty_index_read(session, {User, Server, Resource}, #session.usr).

get_session(User, Server) ->
	mnesia:dirty_index_read(session, {User, Server}, #session.us).

set_session_storage(SID, USR, US, Priority, Info) ->
    F = fun() ->
		mnesia:write(#session{sid = SID,
				      usr = USR,
				      us = US,
				      priority = Priority,
				      info = Info})
	end,
    mnesia:sync_dirty(F).

recount_session_table_storage(Node) ->
    F = fun() ->
		Es = mnesia:select(
		       session,
		       [{#session{sid = {'_', '$1'}, _ = '_'},
			 [{'==', {node, '$1'}, Node}],
			 ['$_']}]),
		lists:foreach(fun(E) ->
				      mnesia:delete({session, E#session.sid})
			      end, Es),
		%% reset session_counter table with active sessions
		mnesia:clear_table(session_counter),
		lists:foreach(fun(Server) ->
				LServer = jlib:nameprep(Server),
				Hs = mnesia:select(session,
				    [{#session{usr = '$1', _ = '_'},
				    [{'==', {element, 2, '$1'}, LServer}],
				    ['$1']}]),
				mnesia:write(
				    #session_counter{vhost = LServer, 
						     count = length(Hs)})
			      end, ?MYHOSTS)
	end,
    mnesia:async_dirty(F).

session_update_counter(Server) ->
    mnesia:dirty_update_counter(session_counter,
				jlib:nameprep(Server), 1).

