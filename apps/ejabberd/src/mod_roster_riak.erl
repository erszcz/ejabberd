-module(mod_roster_riak).

-export([create_table/0,
         delete_item/3,
         remove_user_storage/1,
         read_roster_version_storage/1,
         write_to_roster_storage/1,
         write_to_roster_version_storage/1,
         read_user_roster/1,
         read_roster/1,
         roster_version_storage/1,
         set_items_storage/3,
         process_item_set_storage/7,
         process_subscription_storage/8]).

-include("jlib.hrl").
-include("mod_roster.hrl").

-define(ROSTER_BUCKET, <<"roster">>).
-define(ROSTER_VERSION_BUCKET, <<"roster_version">>).

create_table() ->
    ok.

%% Delete single roster element
delete_item(LUser, LServer, LJID) ->
    US = {LUser, LServer},
    Roster = case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, R} ->
            R;
        {error, notfound} ->
            []
    end,
    ejabberd_riak:set(?ROSTER_BUCKET, US,
        lists:keydelete(LJID, #roster.jid, Roster)).

remove_user_storage(US) ->
    ejabberd_riak:delete(?ROSTER_BUCKET, US).

%% map-reduce version draft
%remove_user_storage(US) ->
    %%% select only objects which contain US user
    %Map = fun() -> ok end,
    %%% 
    %Red = fun() -> ok end,
    %ejabberd_riak:mapred_bucket(?ROSTER_BUCKET,
        %%% when functions are defined in a module accessible by riak's VM
        %%[{map, {modfun, ejabberd_riak_mapred, remove_user_storage_map},
               %%none, false},
         %%{reduce, {modfun, ejabberd_riak_mapred, remove_user_storage_reduce},
                  %%none, false}]).
        %%% for specifying map/reduce phases as closures
        %[{map, {qfun, Map}, none, false},
         %{reduce, {qfun, Red}, none, false}]).

read_roster_version_storage(US) ->
    {ok, Version} = ejabberd_riak:get(?ROSTER_VERSION_BUCKET, US),
    Version.

write_to_roster_storage(Rec = #roster{us=US, jid=LJID}) ->
    Roster = case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, R} ->
            R;
        {error, notfound} ->
            []
    end,
    ejabberd_riak:set(?ROSTER_BUCKET, US,
        lists:keystore(LJID, #roster.jid, Roster, Rec)).

write_to_roster_version_storage(Rec = #roster_version{us=US}) ->
    ejabberd_riak:set(?ROSTER_VERSION_BUCKET, US, Rec).

read_user_roster(US) ->
    case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, Roster} ->
            Roster;
        _ ->
            []
    end.

read_roster({LUser, LServer, LJID}) ->
    US = {LUser, LServer},
    Roster = case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, R} ->
            R;
        {error, notfound} ->
            []
    end,
    case lists:keyfind(LJID, #roster.jid, Roster) of
        false ->
            {error, notfound};
        RosterItem ->
            [RosterItem]
    end.

process_item_set_storage(Attrs, Els, _User, JID, LUser, LServer, LJID) ->
    US = {LUser, LServer},
    Roster = case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, R} ->
            R;
        {error, notfound} ->
            []
    end,
    Item = case lists:keyfind(LJID, #roster.jid, Roster) of
        false ->
            #roster{usj = {LUser, LServer, LJID},
                    us = US,
                    jid = JID};
        I ->
            I#roster{jid = JID,
                     name = "",
                     groups = [],
                     xs = []}
    end,
    Item1 = mod_roster:process_item_attrs(Item, Attrs),
    Item2 = mod_roster:process_item_els(Item1, Els),
    Roster1 = case Item2#roster.subscription of
        remove ->
            lists:keydelete(LJID, #roster.jid, Roster);
        _ ->
            lists:keystore(LJID, #roster.jid, Roster, Item2)
    end,
    ejabberd_riak:set(?ROSTER_BUCKET, US, Roster1),
    %% If the item exist in shared roster, take the
    %% subscription information from there:
    Item3 = ejabberd_hooks:run_fold(roster_process_item,
       LServer, Item2, [LServer]),
    case mod_roster:roster_version_on_db(LServer) of
        true -> 
            Version = sha:sha(term_to_binary(now())),
            ejabberd_riak:set(?ROSTER_VERSION_BUCKET, US,
                #roster_version{us = US, version = Version});
        false ->
            ok
    end,
    {ok, {Item, Item3}}.

process_subscription_storage(Direction, Type, Reason, JID1, US, LUser, LServer, LJID) ->
    US = {LUser, LServer},
    Roster = case ejabberd_riak:get(?ROSTER_BUCKET, US) of
        {ok, R} ->
            R;
        {error, notfound} ->
            []
    end,
    Item = case lists:keyfind(LJID, #roster.jid, Roster) of
        false ->
            JID = {JID1#jid.user,
                   JID1#jid.server,
                   JID1#jid.resource},
            #roster{usj = {LUser, LServer, LJID},
                    us = US,
                    jid = JID};
        I ->
            I
    end,
    NewState = case Direction of
        out ->
            mod_roster:out_state_change(Item#roster.subscription,
                Item#roster.ask,
                Type);
        in ->
            mod_roster:in_state_change(Item#roster.subscription,
                Item#roster.ask,
                Type)
    end,
    AutoReply = case Direction of
        out ->
            none;
        in ->
            mod_roster:in_auto_reply(Item#roster.subscription,
                Item#roster.ask,
                Type)
    end,
    AskMessage = case NewState of
        {_, both} ->
            Reason;
        {_, in}  ->
            Reason;
        _         ->
            ""
    end,
    case NewState of
        none ->
            Roster1 = Roster,
            NextState = {none, AutoReply};
        {none, none} when Item#roster.subscription == none,
                          Item#roster.ask == in ->
            Roster1 = lists:keydelete(LJID, #roster.jid, Roster),
            NextState = {none, AutoReply};
        {Subscription, Pending} ->
            NewItem =
                Item#roster{subscription = Subscription,
                            ask = Pending,
                            askmessage = list_to_binary(AskMessage)},
            Roster1 = lists:keystore(LJID, #roster.jid, Roster, NewItem),
            case mod_roster:roster_version_on_db(LServer) of
                true ->
                    Version = sha:sha(term_to_binary(now())),
                    ejabberd_riak:set(?ROSTER_VERSION_BUCKET, US, 
                        #roster_version{us = US, version = Version});
                false ->
                    ok
            end,
            NextState = {{push, NewItem}, AutoReply}
    end,
    ejabberd_riak:set(?ROSTER_BUCKET, US, Roster1),
    {ok, NextState}.

roster_version_storage(US) ->
    case ejabberd_riak:get(?ROSTER_VERSION_BUCKET, US) of
        {ok, Version} ->
            Version;
        {error, notfound} ->
            not_found;
        {error, Error} ->
            throw(Error)
    end.

set_items_storage(LUser, LServer, Els) ->
    lists:foreach(fun(El) ->
        mod_roster:process_item_set_t(LUser, LServer, El)
        end, Els).
