-module(lechiffre).
-type secret_key()      :: lechiffre_crypto:secret_key().
-type data()            :: term().
-type encrypted_data()  :: binary().

-type encoding_error()  ::  {encryption_failed, lechiffre_crypto:encryption_error()} |
                            {serialization_failed, lechiffre_thrift_utils:thrift_error()}.

-type decoding_error()  ::  {decryption_failed, lechiffre_crypto:decryption_error()} |
                            {deserialization_failed, lechiffre_thrift_utils:thrift_error()}.

-type thrift_type() :: lechiffre_thrift_utils:thrift_type().

-export_type([secret_key/0]).
-export_type([encoding_error/0]).
-export_type([decoding_error/0]).

-export([encode/3]).
-export([decode/3]).

-spec encode(thrift_type(), data(), secret_key()) ->
    {ok, encrypted_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, SecretKey) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin}    -> lechiffre_crypto:encrypt(SecretKey, ThriftBin);
        {error, _} = Error ->
            {error, {serialization_failed, Error}}
    end.

-spec decode(thrift_type(), encrypted_data(), secret_key()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData, SecretKey) ->
    Data = case lechiffre_crypto:decrypt(SecretKey, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        DecryptError ->
            DecryptError
    end,
    case Data of
        {error, {thrift, _} = Error} ->
            {error, {deserialization_failed, Error}};
        Other ->
            Other
    end.
