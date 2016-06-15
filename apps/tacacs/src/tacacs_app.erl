%%%-------------------------------------------------------------------
%% @doc tacacs public API
%% @end
%%%-------------------------------------------------------------------

-module(tacacs_app).
-include("tacacs.hrl").

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1, loop/1, send_response/2]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    tacacs_sup:start_link(),
    socket_server:start(?MODULE, 10049, {?MODULE, loop}).

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%--------------------------------------------------------------------
get_server_encryption_key() ->
  application:get_env(tacacs, psk, <<>>).

%%--------------------------------------------------------------------
handle_auth(ok) ->
  #authen_reply{status=?AUTHEN_STATUS_PASS};
handle_auth(err) ->
  #authen_reply{status=?AUTHEN_STATUS_FAIL, server_msg= <<"Access denied.">>};
handle_auth(_TacacsData=#authen_start{user= <<>>}) ->
  #authen_reply{status=?AUTHEN_STATUS_GETUSER};
handle_auth(_TacacsData=#authen_continue{user_msg= <<"silversupreme">>}) ->
  handle_auth(ok);
handle_auth(_TacacsData=#authen_continue{user_msg= <<"anshulk">>}) ->
  handle_auth(ok);
handle_auth(_) ->
  handle_auth(err).

handle_author(ok) ->
  #author_response{status=?AUTHOR_STATUS_PASS_ADD, args=[]};
handle_author(err) ->
  #author_response{status=?AUTHOR_STATUS_FAIL, server_msg= <<"NO WRONG">>, args=[]};
handle_author(_TacacsData=#author_request{args=[<<"service=shell">>,<<"cmd=hello">>]}) ->
  handle_author(err);
handle_author(_) ->
  handle_author(ok).

%%--------------------------------------------------------------------
send_response(Socket, Response) ->
  Serialized = tacacs:serialize(Response, get_server_encryption_key()),
  gen_tcp:send(Socket, Serialized),
  ok.

%%--------------------------------------------------------------------
handle_message(Socket, TacacsData=#tacacs{type=?AUTHEN}) ->
  Response = #tacacs{version=0, type=?AUTHEN,
    sequence=(TacacsData#tacacs.sequence + 1),
    session_id=TacacsData#tacacs.session_id,
    packet_data=handle_auth(TacacsData#tacacs.packet_data)},
  send_response(Socket, Response);
handle_message(Socket, TacacsData=#tacacs{type=?AUTHOR}) ->
  % Always return OK because we don't care about per-command auth.
  Response = #tacacs{version=0, type=?AUTHOR,
    sequence=(TacacsData#tacacs.sequence + 1),
    session_id=TacacsData#tacacs.session_id,
    packet_data=handle_author(TacacsData#tacacs.packet_data)},
  send_response(Socket, Response);
handle_message(Socket, TacacsData=#tacacs{type=?ACCT}) ->
  Response = #tacacs{version=0, type=?ACCT,
    sequence=(TacacsData#tacacs.sequence + 1),
    session_id=TacacsData#tacacs.session_id, packet_data=#acct_response{
      status=?ACCT_STATUS_SUCCESS}},
  send_response(Socket, Response).

%%--------------------------------------------------------------------
loop(Socket) ->
  case gen_tcp:recv(Socket, 0) of
        {ok, Data} ->
            Packet = tacacs:parse(Data, get_server_encryption_key()),
            handle_message(Socket, Packet),
            loop(Socket);
        {error, closed} ->
            ok
    end.

%%====================================================================
%% Internal functions
%%====================================================================
