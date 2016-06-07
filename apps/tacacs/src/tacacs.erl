%%%-------------------------------------------------------------------
%% TACACS+ Packet Parser.
%%%-------------------------------------------------------------------
-module(tacacs).
-include_lib("eunit/include/eunit.hrl").
-include("tacacs.hrl").

-export([parse/1, serialize/1]).

-define(tacacs_packet_header,
	<<_MajorVersion:4, MinorVersion:4, PacketType: 8, SequenceNumber: 8, Flags:8,
		SessionId:32, _DataLength:32, Rest/bitstring>>).

%%====================================================================
%% External API.
%%====================================================================
-spec parse(iolist() | bitstring()) -> #tacacs{}.
parse(RawData) ->
	?tacacs_packet_header = RawData,
	parse_data(#tacacs{version=MinorVersion, type=PacketType,
		sequence=SequenceNumber, flags=Flags,
		session_id=SessionId, packet_data=Rest}).

-spec serialize(#tacacs{}) -> bitstring().
serialize(TacacsData) ->
	% Serialize the header here since it's common to all packet types.
	#tacacs{version=MinorVersion,
		type=PacketType, sequence=SequenceNumber, flags=Flags,
		session_id=SessionId, packet_data=Rest} = TacacsData,

	InnerData = serialize_data(Rest),
	DataLength = iolist_size(InnerData),
	HeaderData = <<16#c:4, MinorVersion:4, PacketType:8, SequenceNumber:8,
		Flags:8, SessionId:32, DataLength:32>>,
	<<HeaderData/bitstring, InnerData/bitstring>>.

%%====================================================================
%% Internal API.
%%====================================================================
-spec parse_data(#tacacs{}) -> #tacacs{}.
parse_data(TacacsData=#tacacs{type=?AUTHEN, sequence=1}) ->
	<<Action:8, PrivilegeLevel:8, AuthType:8, Service:8,
		UserBytes:8, PortBytes:8, RemoteAddrBytes:8, DataBytes:8,
		Rest/bitstring>> = TacacsData#tacacs.packet_data,

	UserLength = UserBytes * 8,
	PortLength = PortBytes * 8,
	RemoteAddrLength = RemoteAddrBytes * 8,
	DataLength = DataBytes * 8,

	<<User:UserLength/bitstring, Port:PortLength/bitstring,
		RemoteAddr:RemoteAddrLength/bitstring, Data:DataLength/bitstring,
		_Rest/bitstring>> = Rest,
	TacacsData#tacacs{packet_data=#authen_start{
		action=Action,
		privilege_level=PrivilegeLevel,
		authen_type=AuthType,
		service=Service,
		user=User,
		port=Port,
		remote_addr=RemoteAddr,
		data=Data}};
parse_data(TacacsData=#tacacs{type=?AUTHEN}) when TacacsData#tacacs.sequence rem 2 =:= 0 ->
	<<Status:8, Flags:8, ServerMessageBytes:16, DataBytes:16,
		Rest/bitstring>> = TacacsData#tacacs.packet_data,

	ServerMessageLength = ServerMessageBytes * 8,
	DataLength = DataBytes * 8,

	<<ServerMessage:ServerMessageLength/bitstring, Data:DataLength/bitstring,
		_Rest/bitstring>> = Rest,
	TacacsData#tacacs{packet_data=#authen_reply{
		status=Status,
		flags=Flags,
		server_msg=ServerMessage,
		data=Data}};
parse_data(TacacsData=#tacacs{type=?AUTHEN}) when TacacsData#tacacs.sequence rem 2 =:= 1 ->
	<<UserMessageBytes:16, DataBytes:16, Flags:8,
		Rest/bitstring>> = TacacsData#tacacs.packet_data,

	UserMessageLength = UserMessageBytes * 8,
	DataLength = DataBytes * 8,

	<<UserMessage:UserMessageLength/bitstring, Data:DataLength/bitstring,
		_Rest/bitstring>> = Rest,
	TacacsData#tacacs{packet_data=#authen_continue{
		flags=Flags, user_msg=UserMessage, data=Data}}.

-spec serialize_data(tacacs_inner_data()) -> bitstring().
serialize_data(AuthData=#authen_start{}) ->
	#authen_start{action=Action, privilege_level=PrivilegeLevel,
		authen_type=AuthType, service=Service, user=User, port=Port,
		remote_addr=RemoteAddr, data=Data} = AuthData,

	UserLength = iolist_size(User),
	PortLength = iolist_size(Port),
	RemoteAddrLength = iolist_size(RemoteAddr),
	DataLength = iolist_size(Data),

	<<Action:8, PrivilegeLevel:8, AuthType:8, Service:8,
		UserLength:8, PortLength:8, RemoteAddrLength:8, DataLength:8,
		User/bitstring, Port/bitstring, RemoteAddr/bitstring, Data/bitstring>>;
serialize_data(AuthData=#authen_reply{}) ->
	#authen_reply{status=Status, flags=Flags, server_msg=ServerMessage,
		data=Data} = AuthData,

	ServerMessageLength = iolist_size(ServerMessage),
	DataLength = iolist_size(Data),

	<<Status:8, Flags:8, ServerMessageLength:16, DataLength:16,
		ServerMessage/bitstring, Data/bitstring>>;
serialize_data(AuthData=#authen_continue{}) ->
	#authen_continue{flags=Flags, user_msg=UserMessage, data=Data} = AuthData,

	UserMessageLength = iolist_size(UserMessage),
	DataLength = iolist_size(Data),

	<<UserMessageLength:16, DataLength:16, Flags:8, UserMessage/bitstring,
		Data/bitstring>>.

%%====================================================================
%% Tests.
%%====================================================================
basic_parse_serialize_test() ->
	AuthData = <<1, 1, 1, 1, 4, 4, 4, 4, "testtesttesttest">>,
	AuthLength = iolist_size(AuthData),
	Auth = <<16#c:4, 0:4, 1:8, 1:8, 1:8, 1:32,
		AuthLength:32, AuthData/bitstring>>,
	Data = parse(Auth),
	RawData = serialize(Data),
	?assertEqual(RawData, Auth),
	ok.

commutative_parse_serialize_test() ->
	% This test will roll through each packet type that we support, and
	% simply ensure that they can be serialized, and then parsed, into the
	% exact same data structure.

	% Authentication Start ==============================================
	AuthStart = #tacacs{
		version=0, type=?AUTHEN, sequence=1, flags=?UNENCRYPTED_FLAG, session_id=1,
		packet_data=#authen_start{
			action=?AUTHEN_LOGIN, privilege_level=?PRIV_LVL_USER,
			authen_type=?AUTHEN_TYPE_ASCII, service=?AUTHEN_SVC_LOGIN,
			user= <<"silversupreme">>, port= <<"tty0">>,
			remote_addr= <<"Test Datacentre">>, data= <<"">>}},
	AuthData = serialize(AuthStart),
	AuthStart = parse(AuthData),

	% Authentication Reply ==============================================
	AuthReply = #tacacs{
		version=0, type=?AUTHEN, sequence=2, flags=?UNENCRYPTED_FLAG, session_id=1,
		packet_data=#authen_reply{
			status=?AUTHEN_STATUS_GETPASS, flags=?REPLY_FLAG_NOECHO}},
	AuthReplyData = serialize(AuthReply),
	AuthReply = parse(AuthReplyData),

	% Authentication Continue ===========================================
	AuthContinue = #tacacs{
		version=0, type=?AUTHEN, sequence=3, flags=?UNENCRYPTED_FLAG, session_id=1,
		packet_data=#authen_continue{user_msg= <<"testpassword">>}},
	AuthContinueData = serialize(AuthContinue),
	AuthContinue = parse(AuthContinueData),
	ok.

%%%-------------------------------------------------------------------
