-module(mod_register_riak).

-compile([export_all]).

-define(REGISTER_BUCKET, <<"register">>).

create_table() -> 
	ok.

check_timeout_storage(Source, Priority, CleanPriority) ->
	Treap = case get_treap() of
			    {ok, []} ->
					treap:empty();
			    {ok, T} ->
					T
			end,
	Treap1 = mod_register:clean_treap(Treap, CleanPriority),
	case treap:lookup(Source, Treap1) of
	    error ->
			Treap2 = treap:insert(Source, Priority, [],
				      Treap1),
			ejabberd_riak:set(?REGISTER_BUCKET, treap, Treap2),
			true;
	    {ok, _, _} ->
			ejabberd_riak:set(?REGISTER_BUCKET, treap, Treap1),
			false
	end.

remove_timeout_storage(Source) ->
	Treap = case get_treap() of
			    {ok, []} ->
					treap:empty();
			    {ok, T} ->
					T
			end,
	Treap1 = treap:delete(Source, Treap),
	ejabberd_riak:set(?REGISTER_BUCKET, treap, Treap1),
	ok.

%%% Helpers

get_treap() ->
    case ejabberd_riak:get(?REGISTER_BUCKET, treap) of
        {ok, Treap} ->
            {ok, Treap};
        {error, notfound} ->
            {ok, []};
        Error ->
            Error
    end.
