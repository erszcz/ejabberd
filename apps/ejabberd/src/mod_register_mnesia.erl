-module(mod_register_mnesia).

-compile([export_all]).

check_timeout_storage(Source, Priority, CleanPriority) ->
	F = fun() ->
		Treap = case mnesia:read(mod_register_ip, treap,
					 write) of
			    [] ->
					treap:empty();
			    [{mod_register_ip, treap, T}] ->
					T
				end,
		Treap1 = mod_register:clean_treap(Treap, CleanPriority),
		case treap:lookup(Source, Treap1) of
		    error ->
				Treap2 = treap:insert(Source, Priority, [],
					      Treap1),
				mnesia:write({mod_register_ip, treap, Treap2}),
				true;
		    {ok, _, _} ->
				mnesia:write({mod_register_ip, treap, Treap1}),
				false
		end
	end,
    case mnesia:transaction(F) of
        {atomic, Res} ->
            Res;
        {aborted, Reason} ->
            {error, Reason}
    end.

remove_timeout_storage(Source) ->
	F = fun() ->
		Treap = case mnesia:read(mod_register_ip, treap,
					 write) of
			    [] ->
					treap:empty();
			    [{mod_register_ip, treap, T}] ->
					T
				end,
		Treap1 = treap:delete(Source, Treap),
		mnesia:write({mod_register_ip, treap, Treap1}),
		ok
	end,
	transaction_no_result(F). 

%%% Helpers

transaction_no_result(F) ->
    case mnesia:transaction(F) of
        {atomic, _} ->
            ok;
        {aborted, Reason} ->
            {error, Reason}
    end.
