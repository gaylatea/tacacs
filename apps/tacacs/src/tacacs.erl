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
parse_variable_fields(BitData, Lengths) ->
	parse_variable_fields(BitData, Lengths, []).
parse_variable_fields(BitData, [], State) ->
	{BitData, lists:flatten(State)};
parse_variable_fields(BitData, Lengths, State) ->
	[FieldLength|L] = Lengths,
	<<Field:FieldLength, Rest/bitstring>> = BitData,
	parse_variable_fields(Rest, L, lists:append(State, [Field])).

serialize_variable_fields(DataList, ElementLengths) ->
	serialize_variable_fields(DataList, ElementLengths, []).
serialize_variable_fields(DataList, [], State) ->
	{DataList, lists:flatten(State)};
serialize_variable_fields(DataList, ElementLengths, State) ->
	[Field|F] = DataList,
	[FieldLength|L] = ElementLengths,
	Serialized = lists:append(State, [<<Field:FieldLength>>]),
	serialize_variable_fields(F, L, Serialized).

gen_args_field_lengths(Count) ->
	gen_args_field_lengths(Count, []).
gen_args_field_lengths(0, State) ->
	State;
gen_args_field_lengths(Count, State) ->
	gen_args_field_lengths(Count - 1, lists:append(State, [8])).

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
		flags=Flags, user_msg=UserMessage, data=Data}};
parse_data(TacacsData=#tacacs{type=?AUTHOR}) when TacacsData#tacacs.sequence rem 2 =:= 1 ->
	<<AuthenticationMethod:8, PrivilegeLevel:8, AuthenticationType:8,
		AuthenticationService:8, UserBytes:8, PortBytes:8, RemoteAddrBytes:8,
		ArgumentCount:8, Rest/bitstring>> = TacacsData#tacacs.packet_data,

	UserLength = UserBytes * 8,
	PortLength = PortBytes * 8,
	RemoteAddrLength = RemoteAddrBytes * 8,

	ArgLengthFieldLengths = gen_args_field_lengths(ArgumentCount),
	{MoreData, ArgumentLengths} = parse_variable_fields(Rest, ArgLengthFieldLengths),
	<<User:UserLength/bitstring, Port:PortLength/bitstring,
		RemoteAddr:RemoteAddrLength/bitstring, ArgsData/bitstring>> = MoreData,
	{_, Args} = parse_variable_fields(ArgsData, [N*8 || N <- ArgumentLengths]),
	TacacsData#tacacs{packet_data=#author_request{
		authen_method=AuthenticationMethod, priv_lvl=PrivilegeLevel,
		authen_type=AuthenticationType, authen_service=AuthenticationService,
		user=User, port=Port, rem_addr=RemoteAddr, args=Args}};
parse_data(TacacsData=#tacacs{type=?AUTHOR}) when TacacsData#tacacs.sequence rem 2 =:= 0 ->
	<<"">>;
parse_data(TacacsData=#tacacs{type=?ACCT}) when TacacsData#tacacs.sequence rem 2 =:= 0 ->
	<<"">>;
parse_data(TacacsData=#tacacs{type=?ACCT}) when TacacsData#tacacs.sequence rem 2 =:= 1 ->
	<<"">>.

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
		Data/bitstring>>;
serialize_data(AuthData=#author_request{}) ->
	#author_request{authen_method=AuthenicationMethod, priv_lvl=PrivilegeLevel,
		authen_type=AuthenticationType, authen_service=AuthenticationService,
		user=User, port=Port, rem_addr=RemoteAddr, args=Args} = AuthData,

	UserLength = iolist_size(User),
	PortLength = iolist_size(Port),
	RemoteAddrLength = iolist_size(RemoteAddr),
	ArgumentCount = length(Args),

	ArgumentLengths = [iolist_size(X) || X <- Args],
	ArgumentLengthSizes = gen_args_field_lengths(ArgumentCount),
	ArgumentLengthData = serialize_variable_fields(ArgumentLengths, ArgumentLengthSizes),
	ArgumentsData = serialize_variable_fields(Args, ArgumentLengths),

	<<AuthenicationMethod:8, PrivilegeLevel:8, AuthenticationType:8,
		AuthenticationService:8, UserLength:8, PortLength:8, RemoteAddrLength:8,
		ArgumentCount:8, ArgumentLengthData/bitstring, User/bitstring,
		Port/bitstring, RemoteAddr/bitstring, ArgumentsData/bitstring>>;
serialize_data(AuthData=#author_response{}) ->
	<<"">>;
serialize_data(AuthData=#acct_request{}) ->
	<<"">>;
serialize_data(AuthData=#acct_response{}) ->
	<<"">>.

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

blank_parse_variable_fields_test() ->
	IoData = <<1, 2>>,
	FieldLengths = [],
	{IoData, _} = parse_variable_fields(IoData, FieldLengths),
	ok.

parse_variable_fields_test() ->
	IoData = <<1:8, 14:16, 1:8>>,
	FieldLengths = [8, 16],
	{RemainingData, Fields} = parse_variable_fields(IoData, FieldLengths),
	?assertEqual(RemainingData, <<1:8>>),
	?assertEqual(Fields, [1, 14]),
	ok.

gen_args_length_test() ->
	[8, 8, 8, 8] = gen_args_field_lengths(4),
	ok.

serialize_variable_fields_test() ->
	Data = [1, 1, 1, 7],
	Lengths = [8, 8, 8, 8],
	{[], <<1:8, 1:8, 1:8, 7:8>>} = serialize_variable_fields(Data, Lengths),

	ExtraData = [1, 2, 3, 4, 5],
	ExtraLengths = [8, 8, 8],
	{[4, 5], <<1:8, 2:8, 3:8>>} = serialize_variable_fields(ExtraData, ExtraLengths),

	IoListData = [<<"cmd=test">>, <<"words">>],
	IoLengths = [64, 40],
	{[], <<"cmd=testwords">>} = serialize_variable_fields(IoListData, IoLengths),
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

	% Authorization Request =============================================
	AuthorizationRequest = #tacacs{
		version=0, type=?AUTHOR, sequence=1, flags=?UNENCRYPTED_FLAG, session_id=1,
		packet_data=#author_request{
			authen_method=?AUTHEN_METH_LOCAL, priv_lvl=?PRIV_LVL_USER,
			authen_type=?AUTHEN_TYPE_ASCII, authen_service=?AUTHEN_SVC_LOGIN,
			user= <<"silversupreme">>, port= <<"tty0">>,
			rem_addr= <<"Test Datacentre">>,
			args=[<<"cmd=test">>, <<"protocol=unknown">>]}},
	AuthorizationRequestData = serialize(AuthorizationRequest),
	AuthorizationRequest = parse(AuthorizationRequestData),
	ok.

%%%-------------------------------------------------------------------
