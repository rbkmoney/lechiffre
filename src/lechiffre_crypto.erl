-module(lechiffre_crypto).

-type key() :: <<_:256>>.
-type iv()  :: binary().
-type tag() :: binary().
-type aad() :: binary().

%% Encrypted Data Format
-record(edf, {
    version :: binary(),
    tag     :: tag(),
    iv      :: iv(),
    aad     :: aad(),
    cipher  :: binary()
}).
-type edf() :: #edf{}.

-export_type([key/0]).

-export([encrypt/2]).
-export([decrypt/2]).

-spec encrypt(key(), binary()) ->
    {ok, binary()} |
    {error, {encryption_failed, _Reason}}.

encrypt(Key, Plain) ->
    IV = iv(),
    AAD = aad(),
    Version = <<"edf_v1">>,
    try
        {Cipher, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Plain}),
        EncryptedData = marshall_edf(#edf{version = Version, iv = IV, aad = AAD, cipher = Cipher, tag = Tag}),
        {ok, EncryptedData}
    catch _Class:Reason ->
        {error, {enryption_failed, Reason}}
    end.

-spec decrypt(key(), binary()) ->
    {ok, binary()} |
    {error, {decryption_failed, _Reason}}.

decrypt(Key, MarshalledEDF) ->
    try
        #edf{iv = IV, aad = AAD, cipher = Cipher, tag = Tag} = unmarshall_edf(MarshalledEDF),
        crypto:block_decrypt(aes_gcm, Key, IV, {AAD, Cipher, Tag})
    of
        error ->
            {error, {decryption_failed, <<"decryption or validation failed">>}};
        Plain ->
            {ok, Plain}
    catch _Type:Error ->
        {error, {decryption_failed, Error}}
    end.

%%% Internal functions

-spec iv() -> iv().

iv() ->
    crypto:strong_rand_bytes(16).

-spec aad() -> aad().

aad() ->
    crypto:strong_rand_bytes(4).

-spec marshall_edf(edf()) -> binary().

marshall_edf(#edf{version = Ver, tag = Tag, iv = IV, aad = AAD, cipher = Cipher})
    when
        bit_size(Tag) =:= 128,
        bit_size(IV) =:= 128,
        bit_size(AAD) =:= 32
    ->
        <<Ver:6/binary, Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>.

-spec unmarshall_edf(binary()) -> edf().

unmarshall_edf(<<"edf_v1", Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>) ->
    #edf{version = <<"edf_v1">>, tag = Tag, iv = IV, aad = AAD, cipher = Cipher}.

