-module(mod_mam).
-behavior(gen_mod).
-export([start/2, stop/1]).
%% ejabberd handlers
-export([process_mam_iq/3,
         on_send_packet/3,
         on_receive_packet/4,
         on_remove_user/2]).
-include_lib("ejabberd/include/ejabberd.hrl").
-include_lib("ejabberd/include/jlib.hrl").
-include_lib("exml/include/exml.hrl").

%% ----------------------------------------------------------------------
%% Datetime types
-type iso8601_datetime_binary() :: binary().
%% Seconds from 01.01.1970
-type unix_timestamp() :: non_neg_integer().

%% ----------------------------------------------------------------------
%% XMPP types
-type server_hostname() :: binary().
-type escaped_username() :: binary().
-type escaped_jid() :: binary().
-type escaped_resource() :: binary().
-type elem() :: #xmlelement{}.
-type jid() :: tuple().

%% ----------------------------------------------------------------------
%% Constants

mam_ns_string() ->
    "urn:xmpp:mam:tmp".

mam_ns_binary() ->
    <<"urn:xmpp:mam:tmp">>.

default_result_limit() ->
    50.

encode_direction(incoming) -> "I";
encode_direction(outgoing) -> "O".

decode_direction("I") -> incoming;
decode_direction("O") -> outgoing.

%% ----------------------------------------------------------------------
%% gen_mod callbacks

start(Host, Opts) ->
    ?INFO_MSG("mod_mam starting", []),
    IQDisc = gen_mod:get_opt(iqdisc, Opts, one_queue), %% Type
    mod_disco:register_feature(Host, mam_ns_binary()),
    gen_iq_handler:add_iq_handler(ejabberd_sm, Host, mam_ns_binary(),
                                  ?MODULE, process_mam_iq, IQDisc),
    ejabberd_hooks:add(user_send_packet, Host, ?MODULE, on_send_packet, 90),
    ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, on_receive_packet, 90),
    ejabberd_hooks:add(remove_user, Host, ?MODULE, on_remove_user, 50),
    ok.

stop(Host) ->
    ?INFO_MSG("mod_mam stopping", []),
    gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, mam_ns_string()),
    ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, on_send_packet, 90),
    ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, on_receive_packet, 90),
    ejabberd_hooks:delete(remove_user, Host, ?MODULE, on_remove_user, 50),
    ok.

%% ----------------------------------------------------------------------
%% hooks and handlers

%% `To' is an account or server entity hosting the archive.
%% Servers that archive messages on behalf of local users SHOULD expose archives 
%% to the user on their bare JID (i.e. `From.luser'),
%% while a MUC service might allow MAM queries to be sent to the room's bare JID
%% (i.e `To.luser').
process_mam_iq(From=#jid{luser = LUser, lserver = LServer},
               To,
               IQ=#iq{type = get,
                      sub_el = QueryEl = #xmlelement{name = <<"query">>}}) ->
    ?INFO_MSG("Handling mam IQ~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, IQ]),
    QueryID = xml:get_tag_attr_s(<<"queryid">>, QueryEl),
    %% Filtering by date.
    %% Start :: integer() | undefined
    Start = maybe_unix_timestamp(xml:get_path_s(QueryEl, [{elem, <<"start">>}, cdata])),
    End   = maybe_unix_timestamp(xml:get_path_s(QueryEl, [{elem, <<"end">>}, cdata])),
    %% Filtering by contact.
    With  = xml:get_path_s(QueryEl, [{elem, <<"with">>}, cdata]),
    {WithSJID, WithSResource} =
    case With of
        <<>> -> {undefined, undefined};
        _    ->
            WithJID = #jid{lresource = WithLResource} = jlib:binary_to_jid(With),
            WithBareJID = jlib:jid_remove_resource(WithJID),
            {ejabberd_odbc:escape(jlib:jid_to_binary(WithBareJID)),
             case WithLResource of <<>> -> undefined;
                  _ -> ejabberd_odbc:escape(WithLResource) end}
    end,
    %% This element's name is "limit".
    %% But it must be "max" according XEP-0313.
    Max   = maybe_integer(get_one_of_path_bin(QueryEl, [
                    [{elem, <<"set">>}, {elem, <<"max">>}, cdata],
                    [{elem, <<"set">>}, {elem, <<"limit">>}, cdata]
                    ]), default_result_limit()),
    ?INFO_MSG("Parsed data~n\tStart ~p~n\tEnd ~p~n\tQueryId ~p~n\tMax ~p~n"
              "\tWithSJID ~p~n\tWithSResource ~p~n",
              [Start, End, QueryID, Max, WithSJID, WithSResource]),
    SUser = ejabberd_odbc:escape(LUser),
    {selected, _ColumnNames, MessageRows} =
    extract_messages(LServer, SUser, Start, End, Max, WithSJID, WithSResource),
    [send_message(To, From, message_row_to_xml(M, QueryID))
     || M <- MessageRows],
    %% On receiving the query, the server pushes to the client a series of
    %% messages from the archive that match the client's given criteria,
    %% and finally returns the <iq/> result.
    IQ#iq{type = result, sub_el = []}.


%% @doc Handle an outgoing message.
%%
%% Note: for outgoing messages, the server MUST use the value of the 'to' 
%%       attribute as the target JID. 
on_send_packet(From, To, Packet) ->

    ?INFO_MSG("Send packet~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, Packet]),
    handle_package(outgoing, From, To, From, Packet).

%% @doc Handle an incoming message.
%%
%% Note: For incoming messages, the server MUST use the value of the
%%       'from' attribute as the target JID. 
on_receive_packet(_JID, From, To, Packet) ->
    ?INFO_MSG("Receive packet~n    from ~p ~n    to ~p~n    packet ~p.",
              [From, To, Packet]),
    handle_package(incoming, To, From, From, Packet),
    ok.

on_remove_user(User, Server) ->
    LUser = jlib:nodeprep(User),
    LServer = jlib:nameprep(Server),
    SUser = ejabberd_odbc:escape(LUser),
    remove_user(LServer, SUser),
    ?INFO_MSG("Remove user ~p from ~p.", [LUser, LServer]),
    ok.

%% ----------------------------------------------------------------------
%% Helpers

handle_package(Dir,
               _LocalJID=#jid{luser = LUser, lserver = LServer},
               RemoteJID=#jid{lresource = RLResource},
               FromJID=#jid{}, Packet) ->
    IsComplete = is_complete_message(Packet),
    ?INFO_MSG("IsComplete ~p.", [IsComplete]),
    case IsComplete of
        true ->
            SUser = ejabberd_odbc:escape(LUser),
            %% Convert `#jid{}' to prepared `{S,U,R}'
            LRJID = jlib:jid_tolower(RemoteJID),
            BareLRJID = jlib:jid_remove_resource(LRJID),
            SRJID = ejabberd_odbc:escape(jlib:jid_to_binary(LRJID)),
            BareSRJID = ejabberd_odbc:escape(jlib:jid_to_binary(BareLRJID)),
            IsInteresting =
            case behaviour(LServer, SUser, SRJID, BareSRJID) of
                always -> true;
                newer  -> false;
                roster -> is_jid_in_user_roster(LServer, LUser, BareSRJID)
            end,
            ?INFO_MSG("IsInteresting ~p.", [IsInteresting]),
            case IsInteresting of
                true -> 
                    SRResource = ejabberd_odbc:escape(RLResource),
                    SData = ejabberd_odbc:escape(term_to_binary(Packet)),
                    SDir = encode_direction(Dir),
                    FromLJID = jlib:jid_tolower(FromJID),
                    FromSJID = ejabberd_odbc:escape(jlib:jid_to_binary(FromLJID)),
                    archive_message(LServer, SUser, BareSRJID, SRResource, SDir,
                                    FromSJID, SData);
                false -> ok
            end,
            ok;
        false -> ok
    end.

%% @doc Check, that the stanza is a message with body.
%% Servers SHOULD NOT archive messages that do not have a <body/> child tag.
-spec is_complete_message(Packet::#xmlelement{}) -> boolean().
is_complete_message(Packet=#xmlelement{name = <<"message">>}) ->
    case xml:get_tag_attr_s(<<"type">>, Packet) of
    Type when Type == <<"">>;
              Type == <<"normal">>;
              Type == <<"chat">>;
              Type == <<"groupchat">> ->
        case xml:get_subtag(Packet, <<"body">>) of
            false -> false;
            _     -> true
        end;
    _ -> false
    end;
is_complete_message(_) -> false.


%% @doc Form `<forwarded/>' element, according to the XEP.
-spec wrap_message(Packet::elem(), QueryID::binary(),
                   MessageUID::term(), DateTime::calendar:datetime(), FromJID::jid()) ->
        Wrapper::elem().
wrap_message(Packet, QueryID, MessageUID, DateTime, FromJID) ->
    #xmlelement{
        name = <<"message">>,
        attrs = [],
        children = [result(QueryID, MessageUID), forwarded(Packet, DateTime, FromJID)]}.

-spec forwarded(elem(), calendar:datetime(), jid()) -> elem().
forwarded(Packet, DateTime, FromJID) ->
    #xmlelement{
        name = <<"forwarded">>,
        attrs = [{<<"xmlns">>, <<"urn:xmpp:forward:0">>}],
        children = [delay(DateTime, FromJID), Packet]}.

-spec delay(calendar:datetime(), jid()) -> elem().
delay(DateTime, FromJID) ->
    jlib:timestamp_to_xml(DateTime, utc, FromJID, <<>>).


result(QueryID, MessageUID) ->
    %% <result xmlns='urn:xmpp:mam:tmp' queryid='f27' id='28482-98726-73623' />
    #xmlelement{
        name = <<"result">>,
        attrs = [{<<"xmlns">>, mam_ns_binary()},
                 {<<"queryid">>, QueryID},
                 {<<"id">>, MessageUID}],
        children = []}.

example_mess() ->
    {xmlelement,<<"message">>,
     [{<<"xml:lang">>,<<"en">>},{<<"to">>,<<"bob@localhost/res1">>},{<<"type">>,<<"chat">>}],
     [{xmlelement,<<"body">>,[],
     [{xmlcdata,<<"OH, HAI!">>}]}]}.



send_message(From, To, Mess) ->
    ejabberd_sm:route(From, To, Mess).


is_jid_in_user_roster(LServer, LUser, JID) ->
    {Subscription, _Groups} =
    ejabberd_hooks:run_fold(
        roster_get_jid_info, LServer,
        {none, []}, [LUser, LServer, JID]),
    Subscription == from orelse Subscription == both.


behaviour(LServer, SUser, SJID, BareSJID) ->
    case query_behaviour(LServer, SUser, SJID, BareSJID) of
        {selected, ["behaviour"], [{Behavour}]} ->
            case Behavour of
                "A" -> always;
                "N" -> newer;
                "R" -> roster
            end;
        _ -> always %% default for everybody
    end.

query_behaviour(LServer, SUser, SJID, BareSJID) ->
    Result =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT behaviour "
       "FROM mam_config "
       "WHERE local_username='", SUser, "' "
         "AND (remote_jid='' OR remote_jid='", SJID, "'",
               case BareSJID of
                    SJID -> "";
                    _    -> [" OR remote_jid='", BareSJID, "'"]
               end,
         ") "
       "ORDER BY remote_jid DESC "
       "LIMIT 1"]),
    ?INFO_MSG("query_behaviour query returns ~p", [Result]),
    Result.

archive_message(LServer, SUser, BareSJID, SResource, Direction, FromSJID, SData) ->
    Result =
    ejabberd_odbc:sql_query(
      LServer,
      ["INSERT INTO mam_message(local_username, remote_bare_jid, "
                                "remote_resource, message, direction, "
                                "from_jid, added_at) "
       "VALUES ('", SUser,"', '", BareSJID, "', '", SResource, "',"
               "'", SData, "', '", Direction, "', '", FromSJID, "', ",
                integer_to_list(current_unix_timestamp()), ")"]),
    ?INFO_MSG("archive_message query returns ~p", [Result]),
    ok.

remove_user(LServer, SUser) ->
    Result1 =
    ejabberd_odbc:sql_query(
      LServer,
      ["DELETE "
       "FROM mam_config "
       "WHERE local_username='", SUser, "'"]),
    Result2 =
    ejabberd_odbc:sql_query(
      LServer,
      ["DELETE "
       "FROM mam_message "
       "WHERE local_username='", SUser, "'"]),
    ?INFO_MSG("remove_user query returns ~p and ~p", [Result1, Result2]),
    ok.

message_row_to_xml({BUID,BSeconds,BFromJID,BPacket}, QueryID) ->
    Packet = binary_to_term(BPacket),
    FromJID = jlib:binary_to_jid(BFromJID),
    Seconds  = list_to_integer(binary_to_list(BSeconds)),
    DateTime = calendar:now_to_universal_time(seconds_to_now(Seconds)),
    wrap_message(Packet, QueryID, BUID, DateTime, FromJID).

%% Each record is a tuple of form 
%% `{<<"3">>,<<"1366312523">>,<<"bob@localhost">>,<<"res1">>,<<binary>>}'.
%% Columns are `["id","added_at","from_jid","message"]'.
-spec extract_messages(LServer, SUser, IStart, IEnd, IMax, WithSJID, WithSResource) ->
    Result when
    LServer :: server_hostname(),
    SUser   :: escaped_username(),
    IStart  :: unix_timestamp() | undefined,
    IEnd    :: unix_timestamp() | undefined,
    IMax    :: pos_integer(),
    WithSJID :: escaped_jid(),
    WithSResource :: escaped_resource(),
    Result :: {selected,[ColumnName],[Record]},
    ColumnName :: string(),
    Record :: tuple().
extract_messages(LServer, SUser, IStart, IEnd, IMax, WithSJID, WithSResource) ->
    Result =
    ejabberd_odbc:sql_query(
      LServer,
      ["SELECT id, added_at, from_jid, message "
       "FROM mam_message "
       "WHERE local_username='", SUser, "'",
         case IStart of
            undefined -> "";
            _         -> [" AND added_at >= ", integer_to_list(IStart)]
         end,
         case IEnd of
            undefined -> "";
            _         -> [" AND added_at <= ", integer_to_list(IEnd)]
         end,
         case WithSJID of
            undefined -> "";
            _         -> [" AND remote_bare_jid = ", WithSJID]
         end,
         case WithSResource of
            undefined -> "";
            _         -> [" AND remote_resource = ", WithSResource]
         end,
       " ORDER BY added_at"
       " LIMIT ", integer_to_list(IMax)]),
    ?INFO_MSG("query_behaviour query returns ~p", [Result]),
    Result.


%% "maybe" means, that the function may return 'undefined'.
-spec maybe_unix_timestamp(iso8601_datetime_binary()) -> unix_timestamp();
                          (<<>>) -> undefined.
maybe_unix_timestamp(<<>>) -> undefined;
maybe_unix_timestamp(ISODateTime) -> 
    case iso8601_datetime_binary_to_timestamp(ISODateTime) of
        undefined -> undefined;
        Stamp -> now_to_seconds(Stamp)
    end.

-spec current_unix_timestamp() -> unix_timestamp().
current_unix_timestamp() ->
    now_to_seconds(os:timestamp()).

-spec now_to_seconds(erlang:timestamp()) -> unix_timestamp().
now_to_seconds({Mega, Secs, _}) ->
    1000000 * Mega + Secs.

-spec seconds_to_now(unix_timestamp()) -> erlang:timestamp().
seconds_to_now(Seconds) when is_integer(Seconds) ->
    {Seconds div 1000000, Seconds rem 1000000, 0}.

%% @doc Returns time in `now()' format.
-spec iso8601_datetime_binary_to_timestamp(iso8601_datetime_binary()) ->
    erlang:timestamp().
iso8601_datetime_binary_to_timestamp(DateTime) when is_binary(DateTime) ->
    jlib:datetime_string_to_timestamp(binary_to_list(DateTime)).


-spec maybe_integer(binary()) -> integer() | undefined.
maybe_integer(Bin) -> maybe_integer(Bin, undefined).

maybe_integer(<<>>, Def) -> Def;
maybe_integer(Bin, _Def) when is_binary(Bin) ->
    list_to_integer(binary_to_list(Bin)).


get_one_of_path_bin(Elem, List) ->
    get_one_of_path(Elem, List, <<>>).

get_one_of_path(Elem, [H|T], Def) ->
    case xml:get_path_s(Elem, H) of
        Def -> get_one_of_path(Elem, T, Def);
        Val  -> Val
    end;
get_one_of_path(_Elem, [], Def) ->
    Def.
