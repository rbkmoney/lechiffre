-module(lechiffre).

-type secret_key()      :: lechiffre_crypto:key().
-type data()            :: term().
-type data_encrypt()    :: binary().

-type encode_error() :: {encryption_failed, _Reason} |
                        {serialize_failed, lechiffre_thrift_utils:thrift_error()}.

-type decode_error() :: {decryption_failed, _Reason} |
                        {deserialize_failed, lechiffre_thrift_utils:thrift_error()}.

-type thrift_type() :: lechiffre_thrift_utils:thrift_type().

-export_type([encode_error/0]).
-export_type([decode_error/0]).

-export([encode/3]).
-export([decode/3]).

-spec encode(thrift_type(), data(), secret_key()) ->
    {ok, data_encrypt()} |
    {error, encode_error()}.

encode(ThriftType, Data, SecretKey) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin}    -> lechiffre_crypto:encrypt(SecretKey, ThriftBin);
        {error, _} = Error -> Error
    end.

-spec decode(thrift_type(), data_encrypt(), secret_key()) ->
    {ok, data()} |
    {error, decode_error()}.

decode(ThriftType, EncryptedData, SecretKey) ->
    case lechiffre_crypto:decrypt(SecretKey, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        DecryptError ->
            DecryptError
    end.
