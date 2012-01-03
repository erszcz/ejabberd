-module(run_common_test).
-export([ct/0]).

-define(CT_DIR, filename:join([".", "suites"])).
-define(CT_REPORTS, filename:join([".", "reports"])).
-define(CT_CONFIG, "test.config").

ct() ->
    ct:run_test([
        {config, [?CT_CONFIG]},
        {dir, ?CT_DIR},
        {logdir, ?CT_REPORTS}

        %% add suites below like that:

        %% the suite
        %, {suite, "privacy_SUITE"}
        
        %% suite's group no. 1
        %, {group, [management]}
        %% group no. 1 tests
        %, {testcase, get_all_lists_with_active}
        %, {testcase, get_all_lists_with_default}

        %% suite's group no. 2
        %, {group, [blocking]}
        %% group no. 2 tests
        %, {testcase, block_jid_message}
        %, {testcase, block_jid_all}

        , {suite, "login_SUITE"}
 %       , {group, [messages]}
%        , {testcase, messages_story}

        %, {suite, "offline_SUITE"}

        %, {group, [presence]}
        %% with repeat_until_any_ok single test runs fail,
        %% so launch entire group
        %, {testcase, negative_presence_no_mod_offline}
        %, {testcase, negative_presence}

        %, {group, [load]}
        %, {testcase, load_data}

        %, {group, [leakage]}
    ]),
    init:stop(0).
