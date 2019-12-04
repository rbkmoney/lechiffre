-module(lechiffre_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-record('BankCard', {
    'token' :: binary()
}).

-export([struct_info/1]).
-export([record_name/1]).

-spec encode_test() -> _.
encode_test() ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{1 => Key}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    {ok, Value} = lechiffre:decode(ThriftType, EncryptedToken, SecretKey),
    ?assertEqual(PaymentToolToken, Value).

-spec unknown_decrypt_key_test() -> _.
unknown_decrypt_key_test() ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{2 => Key}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, {unknown_key_version, 1}}}, ErrorDecode).

-spec wrong_key_test() -> _.
wrong_key_test() ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{1 => WrongKey}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    ErrorDecode = lechiffre:decode(ThriftType, EncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, decryption_validation_failed}}, ErrorDecode).

-spec wrong_encrypted_key_format_test() -> _.
wrong_encrypted_key_format_test() ->
    {ThriftType, PaymentToolToken} = payment_tool_token(),
    Key = crypto:strong_rand_bytes(32),
    WrongKey = crypto:strong_rand_bytes(32),
    SecretKey = #{
        encryption_key => {1, Key},
        decryption_key => #{1 => WrongKey}
    },
    {ok, EncryptedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    <<KV:4/binary, _Format:6/binary, Tail/binary>> = EncryptedToken,
    BadEncryptedToken = <<KV/binary, "edf_v2", Tail/binary>>,
    ErrorDecode = lechiffre:decode(ThriftType, BadEncryptedToken, SecretKey),
    ?assertEqual({error, {decryption_failed, bad_encrypted_data_format}}, ErrorDecode).


-spec payment_tool_token() -> {term(), term()}.
payment_tool_token() ->
    Type = {struct, struct, {lechiffre_tests, 'BankCard'}},
    Token = #'BankCard'{
        token = <<"TOKEN">>
    },
    {Type, Token}.

%% For Thrift compile

-type struct_flavour() :: struct | exception | union.
-type field_num() :: pos_integer().
-type field_name() :: atom().
-type field_req() :: required | optional | undefined.

-type type_ref() :: {module(), atom()}.
-type field_type() ::
    bool | byte | i16 | i32 | i64 | string | double |
    {enum, type_ref()} |
    {struct, struct_flavour(), type_ref()} |
    {list, field_type()} |
    {set, field_type()} |
    {map, field_type(), field_type()}.

-type struct_field_info() ::
    {field_num(), field_req(), field_type(), field_name(), any()}.
-type struct_info() ::
    {struct, struct_flavour(), [struct_field_info()]}.

-type struct_name() ::
    'BankCard'.

-spec struct_info(struct_name()) -> struct_info() | no_return().

struct_info('BankCard') ->
    {struct, struct, [
        {1, required, string, 'token', undefined}
    ]};
struct_info(_) -> erlang:error(badarg).

-spec record_name(struct_name()) -> atom() | no_return().

record_name('BankCard') ->
    'BankCard'.

