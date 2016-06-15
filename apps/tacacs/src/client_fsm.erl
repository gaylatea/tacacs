%%%-------------------------------------------------------------------
%% TACACS+ Client Finite State Machine.
%% Handles the delicate dance of username/password authentication,
%% which requires state across multiple messages.
%% Also implements handlers for the other message types.
%%%-------------------------------------------------------------------
-module(client_fsm).
-include_lib("eunit/include/eunit.hrl").
-include("tacacs.hrl").
-behaviour(gen_fsm).

%%====================================================================
%% External API.
%%====================================================================
-export([start_link/0, start/0]).
-export([init/1, terminate/3, handle_event/3, handle_sync_event/4,
  handle_info/3, code_change/4]).
-export([handle_message/3]).

-record(state, {username= <<>>, password= <<>>, remote_addr= <<>>}).

start() ->
  gen_fsm:start(?MODULE, [], []).

start_link() ->
  gen_fsm:start_link(?MODULE, [], []).

init(_Args) ->
  {ok, handle_message, #state{}}.

handle_event(_Event, StateName, StateData) ->
  {next_state, StateName, StateData}.

handle_sync_event(_Event, _From, StateName, StateData) ->
  {reply, ok, StateName, StateData}.

handle_info(_Info, StateName, State) ->
  {next_state, StateName, State}.

terminate(_Reason, _StateName, _State) ->
  ok.

code_change(_OldVsn, StateName, State, _Extra) ->
  {ok, StateName, State}.

%%====================================================================
%% State Machine Callbacks.
%%====================================================================
handle_message(_Data=#tacacs{packet_data=#authen_start{user= <<>>}},
    _From, State) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_GETUSER},
  {reply, Response, handle_message, State};
handle_message(_Data=#tacacs{packet_data=#authen_start{user=Username}},
    _From, State) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_GETPASS},
  {reply, Response, handle_message, State#state{username=Username}};
handle_message(_Data=#tacacs{packet_data=#authen_continue{user_msg= <<>>}},
    _From, State=#state{username= <<>>}) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_GETUSER},
  {reply, Response, handle_message, State};
handle_message(_Data=#tacacs{packet_data=#authen_continue{user_msg= <<>>}},
    _From, State=#state{password= <<>>}) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_GETPASS},
  {reply, Response, handle_message, State};
handle_message(_Data=#tacacs{packet_data=#authen_continue{user_msg=Username}},
    _From, State=#state{username= <<>>}) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_GETPASS},
  {reply, Response, handle_message, State#state{username=Username}};
handle_message(_Data=#tacacs{packet_data=#authen_continue{user_msg=Password}},
    _From, State=#state{password= <<>>}) ->
  Response = #authen_reply{status=?AUTHEN_STATUS_PASS},
  {reply, Response, handle_message, State#state{password=Password}};
handle_message(_Data=#tacacs{type=?AUTHOR}, _From, State) ->
  Response = #author_response{status=?AUTHOR_STATUS_PASS_ADD, args=[]},
  {reply, Response, handle_message, State};
handle_message(_Data=#tacacs{type=?ACCT}, _From, State) ->
  Response = #acct_response{status=?ACCT_STATUS_SUCCESS},
  {reply, Response, handle_message, State}.

%%====================================================================
%% Tests.
%%====================================================================
fsm_ruby_tacacsplus_login_flow_test() ->
  % Ruby's TacacsPlus library exhibits this login behaviour.
  {ok, Pid} = start(),
  BlankLoginResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{type=?AUTHEN, packet_data=#authen_start{user= <<>>}}),
  ?assertEqual(BlankLoginResponse,
    #authen_reply{status=?AUTHEN_STATUS_GETUSER}),

  UsernameResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{type=?AUTHEN,
      packet_data=#authen_continue{user_msg= <<"silversupreme">>}}),
  ?assertEqual(UsernameResponse, #authen_reply{status=?AUTHEN_STATUS_GETPASS}),

  PasswordResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{type=?AUTHEN, packet_data=#authen_continue{user_msg= <<"test">>}}),
  ?assertEqual(PasswordResponse, #authen_reply{status=?AUTHEN_STATUS_PASS}),
  ok.

fsm_username_provided_at_start_test() ->
  % Some clients may put the username in the initial #authen_start{} message.
  {ok, Pid} = start(),
  UserLoginResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{packet_data=#authen_start{user= <<"silversupreme">>}}),
  ?assertEqual(UserLoginResponse,
    #authen_reply{status=?AUTHEN_STATUS_GETPASS}),

  PasswordResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{packet_data=#authen_continue{user_msg= <<"test">>}}),
  ?assertEqual(PasswordResponse, #authen_reply{status=?AUTHEN_STATUS_PASS}),
  ok.

fsm_support_authorization_messages_test() ->
  {ok, Pid} = start(),
  AuthorizationResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{type=?AUTHOR,
      packet_data=#author_request{user= <<"silversupreme">>,
        args=[<<"service=shell">>, <<"cmd=test">>]}}),
  ?assertEqual(AuthorizationResponse,
    #author_response{status=?AUTHOR_STATUS_PASS_ADD, args=[]}),
  ok.

fsm_support_accounting_messages_test() ->
  {ok, Pid} = start(),
  AuthorizationResponse = gen_fsm:sync_send_event(Pid,
    #tacacs{type=?ACCT,
      packet_data=#acct_request{user= <<"silversupreme">>,
        args=[<<"service=shell">>, <<"cmd=test">>]}}),
  ?assertEqual(AuthorizationResponse,
    #acct_response{status=?ACCT_STATUS_SUCCESS}),
  ok.

%%%-------------------------------------------------------------------
