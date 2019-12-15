-module(lechiffre_crypto).

-define(MAX_UINT_32, 4294967295).

-type key_version() :: 1..?MAX_UINT_32.
-type key() :: <<_:256>>.
-type decryption_keys() :: #{
    key_version() := key()
}.
-type secret_keys() :: #{
    encryption_key := {key_version(), key()},
    decryption_key := decryption_keys()
}.

-type encryption_params() :: binary().

-type params() :: #{
    version := version(),
    iv      := iv(),
    aad     := aad()
}.

-type iv()      :: binary().
-type tag()     :: binary().
-type aad()     :: binary().
-type version() :: binary().

%% Encrypted Data Format
-record(edf, {
    version     :: version(),
    tag         :: tag(),
    iv          :: iv(),
    aad         :: aad(),
    cipher      :: binary(),
    key_version :: key_version()
}).
-type edf() :: #edf{}.

-type decryption_error() :: {decryption_failed, decryption_validation_failed |
                                                bad_encrypted_data_format |
                                                wrong_data_type |
                                                {unknown_key_version, key_version()}
                                            }.
-type encryption_error() :: {encryption_failed, wrong_data_type}.

-export_type([encryption_params/0]).
-export_type([decryption_keys/0]).
-export_type([encryption_error/0]).
-export_type([decryption_error/0]).
-export_type([secret_keys/0]).
-export_type([key_version/0]).

-export([get_encryption_params/0]).
-export([encrypt/2]).
-export([encrypt/3]).
-export([decrypt/2]).

-spec get_encryption_params() ->
    encryption_params().

get_encryption_params() ->
    decode_params(#{
        version => get_version(),
        iv      => iv(),
        aad     => aad()
    }).

-spec encrypt(secret_keys(), binary()) ->
    {ok, binary()} |
    {error, {encryption_failed, wrong_data_type}}.

encrypt(SecretKeys, Plain) ->
    EncryptionParams = get_encryption_params(),
    encrypt(SecretKeys, Plain, EncryptionParams).

-spec encrypt(secret_keys(), binary(), encryption_params()) ->
    {ok, binary()} |
    {error, {encryption_failed, wrong_data_type}}.

encrypt(#{encryption_key := {KeyVer, Key}}, Plain, EncryptionParams) ->
    Params = encode_params(EncryptionParams),
    Version = get_version(Params),
    IV = iv(Params),
    AAD = aad(Params),
    try
        {Cipher, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Plain}),
        EncryptedData = marshal_edf(#edf{
            version = Version,
            key_version = KeyVer,
            iv = IV,
            aad = AAD,
            cipher = Cipher,
            tag = Tag}),
        {ok, EncryptedData}
    catch error:badarg ->
        {error, {encryption_failed, wrong_data_type}}
    end.

-spec decrypt(secret_keys(), binary()) ->
    {ok, binary()} |
    {error, decryption_error()}.

decrypt(SecretKeys, MarshalledEDF) ->
    try
        #edf{
            iv = IV,
            aad = AAD,
            cipher = Cipher,
            tag = Tag,
            key_version = KeyVer} = unmarshal_edf(MarshalledEDF),
        Key = get_key(KeyVer, SecretKeys),
        crypto:block_decrypt(aes_gcm, Key, IV, {AAD, Cipher, Tag})
    of
        error ->
            {error, {decryption_failed, decryption_validation_failed}};
        Plain ->
            {ok, Plain}
    catch
        throw:bad_encrypted_data_format ->
            {error, {decryption_failed, bad_encrypted_data_format}};
        throw:{unknown_key_version, Ver} ->
            {error, {decryption_failed, {unknown_key_version, Ver}}};
        error:badarg ->
            {error, {decryption_failed, wrong_data_type}}
    end.

%%% Internal functions

-spec get_version() ->
    version().

get_version() ->
    <<"edf_v1">>.

-spec get_version(encryption_params()) ->
    version().

get_version(#{version := Version}) ->
    Version.


-spec get_key(key_version(), secret_keys()) -> key().

get_key(KeyVer, #{decryption_key := Keys}) ->
    case maps:find(KeyVer, Keys) of
        {ok, Key} ->
            Key;
        error ->
            throw({unknown_key_version, KeyVer})
    end.

-spec iv() -> iv().

iv() ->
    crypto:strong_rand_bytes(16).

-spec iv(encryption_params()) -> iv().

iv(#{iv := IV}) ->
    IV.

-spec aad() -> aad().

aad() ->
    crypto:strong_rand_bytes(4).

-spec aad(encryption_params()) -> aad().

aad(#{aad := AAD}) ->
    AAD.

-spec decode_params(params()) ->
    encryption_params().

decode_params(Params) ->
    #{
        version := Ver,
        iv := IV,
        aad := AAD
    } = Params,
    <<Ver/binary, IV/binary, AAD/binary>>.

-spec encode_params(encryption_params()) ->
    params().

encode_params(<<Ver:6/binary, IV:16/binary, AAD:4/binary>>) ->
    #{
        version => Ver,
        iv => IV,
        aad => AAD
    }.

-spec marshal_edf(edf()) -> binary().

marshal_edf(#edf{version = Ver, key_version = KeyVer, tag = Tag, iv = IV, aad = AAD, cipher = Cipher})
    when
        KeyVer > 0 andalso KeyVer < ?MAX_UINT_32, %% max value unsinged integer 4 byte
        bit_size(Tag) =:= 128,
        bit_size(IV) =:= 128,
        bit_size(AAD) =:= 32
    ->
        <<Ver:6/binary, KeyVer:32/integer, Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>.

-spec unmarshal_edf(binary()) -> edf().

unmarshal_edf(<<Ver:6/binary, KeyVer:32/integer, Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>)
when Ver =:= <<"edf_v1">> ->
    #edf{
        version = get_version(),
        tag = Tag,
        iv = IV,
        aad = AAD,
        cipher = Cipher,
        key_version = KeyVer
    };
unmarshal_edf(_Other) ->
    throw(bad_encrypted_data_format).
