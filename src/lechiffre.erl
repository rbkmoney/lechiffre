-module(lechiffre).

%%
-include_lib("lechiffre_proto/include/lechiffre_lechiffre_thrift.hrl").

-type secret_key()      :: lechiffre_crypto:key().
-type encrypted_token() :: binary().

-type exp_date() :: {1..12, pos_integer()}.

-type token() :: #{
    bank_card_token := binary(),
    exp_date        := exp_date(),
    cardholder_name := binary()
}.

-type data()         :: {token, token()}.
-type data_encrypt() :: {token, encrypted_token()}.

-type encode_error() :: {encryption_failed, _Reason} |
                        {serialize_failed, lechiffre_proto_utils:thrift_error()}.

-type decode_error() :: {decryption_failed, _Reason} |
                        {deserialize_failed, lechiffre_proto_utils:thrift_error()}.

-export_type([token/0]).
-export_type([encode_error/0]).
-export_type([decode_error/0]).

-export([encode/2]).
-export([decode/2]).

%% Accsesories

exp_date(#{exp_date := ExpDate}) ->
    ExpDate.

bank_card_token(#{bank_card_token := BankCardToken}) ->
    BankCardToken.

cardholder_name(#{cardholder_name := CardHolderName}) ->
    CardHolderName.

-spec encode(data(), secret_key()) ->
    {ok, encrypted_token()} |
    {error, encode_error()}.

encode({token, Token}, SecretKey) ->
    VersionedToken = marshal(versioned_token, Token),
    ThriftType = {struct, union, {lechiffre_lechiffre_thrift, 'VersionedToken'}},
    case lechiffre_proto_utils:serialize(ThriftType, VersionedToken) of
        {ok, ThriftBin}    -> lechiffre_crypto:encrypt(SecretKey, ThriftBin);
        {error, _} = Error -> Error
    end.

-spec decode(data_encrypt(), secret_key()) ->
    {ok, token()} |
    {error, decode_error()}.

decode({token, EncryptedToken}, SecretKey) ->
    Result = case lechiffre_crypto:decrypt(SecretKey, EncryptedToken) of
        {ok, ThriftBin} ->
            ThriftType = {struct, union, {lechiffre_lechiffre_thrift, 'VersionedToken'}},
            lechiffre_proto_utils:deserialize(ThriftType, ThriftBin);
        DecryptError ->
            DecryptError
    end,
    case Result of
        {ok, TokenThrift} ->
            {ok, unmarshal(versioned_token, TokenThrift)};
        Error ->
            Error
    end.

%%
%% Marshalling
%%

marshal(versioned_token, Token) ->
    {v1, #lchf_Token1{
        cds_token = bank_card_token(Token),
        exp_date = marshal(exp_date, exp_date(Token)),
        cardholder_name = cardholder_name(Token)
    }};
marshal(exp_date, {Month, Year}) ->
    #lchf_ExpDate{
        month = Month,
        year = Year
    }.

unmarshal(versioned_token, {v1, #lchf_Token1{} = Token}) ->
    BankCardToken = Token#lchf_Token1.cds_token,
    ExpDate = Token#lchf_Token1.exp_date,
    CardHolderName = Token#lchf_Token1.cardholder_name,
    #{
        bank_card_token => BankCardToken,
        exp_date        => unmarshal(exp_date, ExpDate),
        cardholder_name => CardHolderName
    };
unmarshal(exp_date, ExpDate) ->
    Month = ExpDate#lchf_ExpDate.month,
    Year = ExpDate#lchf_ExpDate.year,
    {Month, Year}.
