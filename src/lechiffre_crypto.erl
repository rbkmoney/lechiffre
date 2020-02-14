-module(lechiffre_crypto).

-include_lib("jose/include/jose_jwk.hrl").

-define(IV_SIZE, 16).

-type kid()         :: binary().
-type jwk()         :: {kty(), jose_jwk:key()}.
-type iv()          :: binary().
-type jwe()         :: map().
-type jwe_compact() :: ascii_string().
-type alg_enc()     :: binary().
-type kty()         :: oct | ec | rsa | okt.
-type key_source()  :: binary() |
                       {json_file, file:filename_all()}.

%% base62 string and '.'
-type ascii_string() :: binary().

-type decryption_keys() :: #{
    kid() := jwk()
}.

-type decryption_error() :: {decryption_failed,
    unknown |
    {kid_notfound, kid()} |
    {bad_jwe_header_format, _Reason} |
    {bad_jwe_format, _JweCompact}
}.
-type encryption_error() :: {encryption_failed, {invalid_jwk, encryption_unsupported}}.

-export_type([decryption_keys/0]).
-export_type([encryption_error/0]).
-export_type([decryption_error/0]).
-export_type([jwe_compact/0]).
-export_type([kid/0]).
-export_type([iv/0]).
-export_type([jwk/0]).
-export_type([key_source/0]).
-export_type([alg_enc/0]).

-export([encrypt/2]).
-export([decrypt/2]).
-export([get_jwe_kid/1]).
-export([get_jwk_kid/1]).
-export([get_jwk_alg/1]).
-export([read_jwk/1]).
-export([verify_jwk_alg/1]).
-export([compute_random_iv/0]).

-spec compute_random_iv() -> iv().

compute_random_iv() ->
    crypto:strong_rand_bytes(?IV_SIZE).

-spec read_jwk(key_source()) -> jwk().

read_jwk(Source) when is_binary(Source) ->
    Jwk = jose_jwk:from_binary(Source),
    Kty = get_jwk_kty(Jwk),
    {Kty, Jwk};
read_jwk({json_file, Source}) ->
    Jwk = jose_jwk:from_file(Source),
    Kty = get_jwk_kty(Jwk),
    {Kty, Jwk}.

-spec encrypt(jwk(), binary()) ->
    {ok, jwe_compact()} |
    {error, encryption_error()}.

encrypt({Type, Jwk}, Plain) ->
    try
        #{<<"kid">> := KID} = Jwk#jose_jwk.fields,
        EncryptorWithoutKid = unwrap(
            {invalid_jwk, encryption_unsupported},
            fun() -> jose_jwk:block_encryptor(Jwk) end
        ),
        Encryptor = EncryptorWithoutKid#{<<"kid">> => KID},
        Result = case Type of
            ec ->
                KeyPriv = jose_jwk:generate_key(Jwk),
                Jwe = jose_jwk:box_encrypt(Plain, Encryptor, Jwk, KeyPriv),
                Jwe;
            oct ->
                {_, Jwe} = jose_jwe:block_encrypt(Jwk, Plain, Encryptor),
                Jwe
        end,
        {#{}, Compact} = jose_jwe:compact(Result),
        {ok, Compact}
    catch throw:{?MODULE, Error} ->
        {error, {encryption_failed, Error}}
    end.

-spec decrypt(decryption_keys(), jwe_compact()) ->
    {ok, binary()} |
    {error, decryption_error()}.

decrypt(SecretKeys, JweCompact) ->
    try
        Jwe = expand_jwe(JweCompact),
        Kid = get_jwe_kid(Jwe),
        {_, Jwk} = get_key(Kid, SecretKeys),
        case jose_jwe:block_decrypt(Jwk, Jwe) of
            {error, _JWE} ->
               {error, {decryption_failed, unknown}};
            {DecryptedData, _JWE} ->
                {ok, DecryptedData}
        end
    catch throw:{?MODULE, Error} ->
        {error, {decryption_failed, Error}}
    end.

%%% Internal functions

-spec expand_jwe(jwe_compact()) ->
    jwe() | no_return().

expand_jwe(JweCompact) ->
    try
        {#{}, Jwe} = jose_jwe:expand(JweCompact),
        Jwe
    catch _Type:_Error ->
        throw({?MODULE, {bad_jwe_format, JweCompact}})
    end.

-spec get_jwe_kid(jwe()) ->
    kid() | no_return().

get_jwe_kid(#{<<"protected">> := EncHeader}) ->
    try
        HeaderJson = base64url:decode(EncHeader),
        Header = jsx:decode(HeaderJson, [return_maps]),
        maps:get(<<"kid">>, Header)
    catch _Type:Error ->
        throw({?MODULE, {bad_jwe_header_format, Error}})
    end.

-spec get_jwk_kid(jwk()) -> kid() | notfound.

get_jwk_kid({_, Jwk}) ->
    Fields = Jwk#jose_jwk.fields,
    maps:get(<<"kid">>, Fields, notfound).

-spec get_jwk_alg(jwk()) -> alg_enc() | notfound.

get_jwk_alg({_, Jwk}) ->
    Fields = Jwk#jose_jwk.fields,
    maps:get(<<"alg">>, Fields, notfound).

-spec get_jwk_kty(jose_jwk:key()) -> kty().

get_jwk_kty(Jwk) ->
    case jose_jwk:to_map(Jwk) of
        {_, #{<<"kty">> := <<"EC">>}} ->
            ec;
        {_, #{<<"kty">> := <<"oct">>}} ->
            oct;
        {_, #{<<"kty">> := <<"RSA">>}} ->
            rsa;
        {_, #{<<"kty">> := <<"OKT">>}} ->
            okt
    end.

-spec verify_jwk_alg(alg_enc()) ->
    ok |
    {error, {jwk_alg_unsupported, alg_enc(), [alg_enc()]}}.

verify_jwk_alg(AlgEnc) ->
    {jwe, {alg, AlgList}, _, _} = lists:keyfind(jwe, 1, jose_jwa:supports()),
    case lists:member(AlgEnc, AlgList) of
        true ->
            ok;
        false ->
            {error, {jwk_alg_unsupported, AlgEnc, AlgList}}
    end.

-spec get_key(kid(), decryption_keys()) ->
    jwk() | no_return().

get_key(KID, Keys) ->
    case maps:find(KID, Keys) of
        {ok, Key} ->
            Key;
        error ->
            throw({?MODULE, {kid_notfound, KID}})
    end.

-spec unwrap(_, _) ->
    _ | no_return().

unwrap(Error, Fun) ->
    try Fun()
    catch error: _ ->
        throw({?MODULE, Error})
    end.
