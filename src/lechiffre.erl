-module(lechiffre).

-define(SECRET_KEYS_TABLE, ?MODULE).

-type options() :: #{
    secret_opts := #{
        encryption_key_path := {key_version(), key_path()},
        decryption_key_path := #{
            key_version() := key_path()
        }
    }
}.

-type key_path()        :: binary().
-type key_version()     :: lechiffre_crypto:key_version().
-type secret_keys()     :: lechiffre_crypto:secret_keys().
-type data()            :: term().
-type encrypted_data()  :: binary().

-type encoding_error()  :: {encryption_failed, lechiffre_crypto:encryption_error()} |
                           {serialization_failed, lechiffre_thrift_utils:thrift_error()}.

-type decoding_error()  :: {decryption_failed, lechiffre_crypto:decryption_error()} |
                           {deserialization_failed, lechiffre_thrift_utils:thrift_error()}.

-type thrift_type()     :: lechiffre_thrift_utils:thrift_type().

-export_type([secret_keys/0]).
-export_type([encoding_error/0]).
-export_type([decoding_error/0]).

%% Supervisor

-export([child_spec/1]).
-export([init/1]).

-export([encode/2]).
-export([encode/3]).
-export([decode/2]).
-export([decode/3]).

-spec child_spec(options()) ->
    supervisor:child_spec() | no_return().

child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec init(options()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.

init(#{secret_opts := Opts}) ->
    SecretKeys = read_secret_keys(Opts),
    ok = create_table(SecretKeys),
    {ok, {#{}, []}}.

-spec encode(thrift_type(), data()) ->
    {ok, encrypted_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data) ->
    SecretKeys = lookup_secret_value(),
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin}    ->
            lechiffre_crypto:encrypt(SecretKeys, ThriftBin);
        {error, _} = Error ->
            {error, {serialization_failed, Error}}
    end.

-spec encode(thrift_type(), data(), secret_keys()) ->
    {ok, encrypted_data()} |
    {error, encoding_error()}.

encode(ThriftType, Data, SecretKeys) ->
    case lechiffre_thrift_utils:serialize(ThriftType, Data) of
        {ok, ThriftBin}    ->
            lechiffre_crypto:encrypt(SecretKeys, ThriftBin);
        {error, _} = Error ->
            {error, {serialization_failed, Error}}
    end.

-spec decode(thrift_type(), encrypted_data()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData) ->
    SecretKeys = lookup_secret_value(),
    case lechiffre_crypto:decrypt(SecretKeys, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        {error, {thrift, _} = Error} ->
            {error, {deserialization_failed, Error}};
        DecryptError ->
            DecryptError
    end.

-spec decode(thrift_type(), encrypted_data(), secret_keys()) ->
    {ok, data()} |
    {error, decoding_error()}.

decode(ThriftType, EncryptedData, SecretKeys) ->
    case lechiffre_crypto:decrypt(SecretKeys, EncryptedData) of
        {ok, ThriftBin} ->
            lechiffre_thrift_utils:deserialize(ThriftType, ThriftBin);
        {error, {thrift, _} = Error} ->
            {error, {deserialization_failed, Error}};
        DecryptError ->
            DecryptError
    end.

%% Internal functions

-spec read_secret_keys(options()) -> secret_keys().

read_secret_keys(Options) ->
    {Ver, EncryptionPath} = maps:get(encrytion_path, Options),
    DecryptionKeysPath = maps:get(decryption_path, Options),
    DecryptionKeys = maps:fold(fun(KeyVer, Path, Acc) ->
        SecretKey = read_key_file(Path),
        Acc#{
            KeyVer => SecretKey
        }
        end, #{}, DecryptionKeysPath),
    EncryptionKey = read_key_file(EncryptionPath),
    #{
        encryption_key => {Ver, EncryptionKey},
        decryption_key => DecryptionKeys
    }.

-spec read_key_file(binary()) -> binary().

read_key_file(SecretPath) ->
    {ok, Secret} = file:read_file(SecretPath),
    string:trim(Secret).

-spec create_table(secret_keys()) -> ok.

create_table(SecretKeys) ->
    _ = ets:new(?SECRET_KEYS_TABLE, [set, private, named_table, {read_concurrency, true}]),
    insert_secret_value(SecretKeys),
    ok.

-spec insert_secret_value(secret_keys()) -> ok.

insert_secret_value(SecretKeys) ->
    true = ets:insert(?SECRET_KEYS_TABLE, [{secret, SecretKeys}]),
    ok.

-spec lookup_secret_value() -> secret_keys().

lookup_secret_value() ->
    [{secret, SecretKeys}] = ets:lookup(?SECRET_KEYS_TABLE, secret),
    SecretKeys.
