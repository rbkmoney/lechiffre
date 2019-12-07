-module(lechiffre_thrift_utils).

-export([serialize/2]).
-export([deserialize/2]).

%% Types

-type thrift_type() ::
    thrift_base_type() |
    thrift_collection_type() |
    thrift_enum_type() |
    thrift_struct_type().

-type thrift_base_type() ::
    bool   |
    double |
    i8     |
    i16    |
    i32    |
    i64    |
    string.

-type thrift_collection_type() ::
    {list, thrift_type()} |
    {set, thrift_type()} |
    {map, thrift_type(), thrift_type()}.

-type thrift_enum_type() ::
    {enum, thrift_type_ref()}.

-type thrift_struct_type() ::
    {struct, thrift_struct_flavor(), thrift_type_ref() | thrift_struct_def()}.

-type thrift_struct_flavor() :: struct | union | exception.

-type thrift_type_ref() :: {module(), Name :: atom()}.

-type thrift_struct_def() :: list({
    Tag :: pos_integer(),
    Requireness :: required | optional | undefined,
    Type :: thrift_struct_type(),
    Name :: atom(),
    Default :: any()
}).

-type thrift_error() :: {thrift, {protocol, any()}}.

-export_type([thrift_type/0]).
-export_type([thrift_error/0]).

%% API

-spec serialize(thrift_type(), term()) ->
    {ok, binary()} | {error, thrift_error()}.

serialize(Type, Data) ->
    {ok, Transport} = thrift_membuffer_transport:new(),
    {ok, Proto} = new_protocol(Transport),
    case thrift_protocol:write(Proto, {Type, Data}) of
        {NewProto, ok} ->
            {_, {ok, Result}} = thrift_protocol:close_transport(NewProto),
            {ok, Result};
        {_NewProto, {error, Reason}} ->
            {error, {thrift, {protocol, Reason}}}
    end.

-spec deserialize(thrift_type(), binary()) ->
    {ok, term()} | {error, thrift_error()}.

deserialize(Type, Data) ->
    {ok, Transport} = thrift_membuffer_transport:new(Data),
    {ok, Proto} = new_protocol(Transport),
    case thrift_protocol:read(Proto, Type) of
        {_NewProto, {ok, Result}} ->
            {ok, Result};
        {_NewProto, {error, Reason}} ->
            {error, {thrift, {protocol, Reason}}}
    end.

%% Internals

-spec new_protocol(any()) -> term().

new_protocol(Transport) ->
    thrift_binary_protocol:new(Transport, [{strict_read, true}, {strict_write, true}]).
