-type netdata() :: iolist() | bitstring().

-define(AUTHEN, 16#1).
-define(AUTHOR, 16#2).
-define(ACCT, 16#3).

-define(UNENCRYPTED_FLAG, 16#1).
-define(SINGLE_CONNECT_FLAG, 16#4).

-define(AUTHEN_LOGIN, 16#1).
-define(AUTHEN_CHPASS, 16#2).
-define(AUTHEN_SENDPASS, 16#3).
-define(AUTHEN_SENDAUTH, 16#4).

-define(PRIV_LVL_MAX, 16#f).
-define(PRIV_LVL_ROOT, 16#f).
-define(PRIV_LVL_USER, 16#1).
-define(PRIV_LVL_MIN, 16#0).

-define(AUTHEN_TYPE_ASCII, 16#1).
-define(AUTHEN_TYPE_PAP, 16#2).
-define(AUTHEN_TYPE_CHAP, 16#3).
-define(AUTHEN_TYPE_ARAP, 16#4).
-define(AUTHEN_TYPE_MSCHAP, 16#5).

-define(AUTHEN_SVC_NONE, 16#0).
-define(AUTHEN_SVC_LOGIN, 16#1).
-define(AUTHEN_SVC_ENABLE, 16#2).
-define(AUTHEN_SVC_PPP, 16#3).
-define(AUTHEN_SVC_ARAP, 16#4).
-define(AUTHEN_SVC_PT, 16#5).
-define(AUTHEN_SVC_RCMD, 16#6).
-define(AUTHEN_SVC_X25, 16#7).
-define(AUTHEN_SVC_NASI, 16#8).
-define(AUTHEN_SVC_FWPROXY, 16#9).
% This is an Authentication Start packet, used at the beginning of a
% connection to the server to verify that a given user has access to a
% device at all.
-record(authen_start, {
	action :: non_neg_integer(),
	privilege_level :: non_neg_integer(),
	authen_type :: non_neg_integer(),
	service :: non_neg_integer(),
	user :: netdata(),
	port :: netdata(),
	remote_addr= <<"">> :: netdata(),
	data= <<"">> :: netdata()}).

-define(AUTHEN_STATUS_PASS, 16#1).
-define(AUTHEN_STATUS_FAIL, 16#2).
-define(AUTHEN_STATUS_GETDATA, 16#3).
-define(AUTHEN_STATUS_GETUSER, 16#4).
-define(AUTHEN_STATUS_GETPASS, 16#5).
-define(AUTHEN_STATUS_RESTART, 16#6).
-define(AUTHEN_STATUS_ERROR, 16#7).
-define(AUTHEN_STATUS_FOLLOW, 16#21).

-define(REPLY_FLAG_NOECHO, 16#1).
% This is an Authentication Reply packet, used by the server for
% basically two things: to signal success/failure on a given
% authentication attempt, or to request more information (usually a
% password) from the device. They must always have an even sequence
% number.
-record(authen_reply, {
	status :: non_neg_integer(),
	flags=0 :: non_neg_integer(),
	server_msg= <<"">> :: netdata(),
	data= <<"">> :: netdata()}).

-define(CONTINUE_FLAG_ABORT, 16#1).
% This is an Authentication Continue packet, used by the client to
% transmit a password to the server in response to an Authentication
% Reply. They must always have an odd sequence number.
-record(authen_continue, {
	flags=0 :: non_neg_integer(),
	user_msg :: netdata(),
	data= <<"">> :: netdata()}).

% Record types that can be found in the packet_data field.
-type tacacs_inner_data() :: #authen_start{} | #authen_reply{} | #authen_continue{}.

% This is the TACACS+ header, which is always the same for each
% packet type. Fields in here are used for encryption, and for
% figuring out what packet type to parse.
-record(tacacs, {
	version :: non_neg_integer(),
	type :: non_neg_integer(),
  sequence :: non_neg_integer(),
  flags :: non_neg_integer(),
  session_id :: non_neg_integer(),
  packet_data :: netdata() | tacacs_inner_data()}).
