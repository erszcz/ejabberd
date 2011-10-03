-include("ejabberd.hrl").
-include("jlib.hrl").

%% CAUTION: using this macro is valid only after ejabberd_backend:init
%% was called!
-define(DISPATCH(Function, Args),
    ejabberd_backend:dispatch(?MODULE, mod_register_backend:backend(),
        Function, Args)).
