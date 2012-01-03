%%%-------------------------------------------------------------------
%%% File : ejabberd_config.erl
%%% Description :
%%% Author : Radoslaw Szymczyszyn <r.szymczyszyn@gmail.com>
%%%-------------------------------------------------------------------
-module(ejabberd_backend).

-export([init/2,
         dispatch/4,
         get/2,
         load/2]).

init(Host, Module) ->
    load(Module, get(Host, Module)).

%% Dispatch a function to appropriate backend module.
%% Use from within generic mod_something to access backend specific
%% variant of some function.
dispatch(Module, Backend, Function, Args) ->
    apply(module_to_bmodule(Module, Backend), Function, Args).

%% Get DB backend per Host/Module combination.
get(_Host, ejabberd_sm) ->
    {Backend, Opts} = ejabberd_config:get_global_option(sm_backend),
    Backend;
get(Host, Module) ->
    {Module, Options} = proplists:lookup(Module,
        ejabberd_config:get_local_option({modules, Host})),
    case proplists:lookup(backend, Options) of
        {backend, Backend} when Backend =:= mnesia;
                                Backend =:= odbc;
                                Backend =:= riak ->
            Backend;
        _ -> undefined
    end.

%% load(some_mod, some_atom) compiles and loads into the VM a module with
%% following content:
%%   -module(some_mod_backend).
%%   -compile([export_all]).
%%   backend() -> some_atom.
%% What for? It allows for runtime initilization of extremely fast
%% global state stored in code memory. Intended use is dispatching backend
%% specific mod_something callbacks.
load(Module, Backend) ->
    ModName = list_to_atom(lists:concat([Module, "_backend"])),
    Code = lists:concat([
        "-module(", ModName,"). ",
        "-compile([export_all]). ",
        "backend() -> ", Backend, ". "]),
    {ModName, Binary} = dynamic_compile:from_string(Code),
    code:load_binary(ModName, lists:concat([ModName, ".erl"]), Binary).

%%% Helpers

module_to_bmodule(Module, Backend) ->
    list_to_atom(lists:concat([Module, "_", Backend])).
