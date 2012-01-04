-include("ejabberd.hrl").
-include("jlib.hrl").

-record(session, {sid, usr, us, priority, info}).
-record(session_counter, {vhost, count}).
-record(state, {}).

%% CAUTION: using this macro is valid only after ejabberd_backend:init
%% was called!
-define(DISPATCH(Function, Args),
    ejabberd_backend:dispatch(?MODULE, ejabberd_sm_backend:backend(),
        Function, Args)).
