-module(lechiffre_crypto).

-include_lib("jose/include/jose_jwk.hrl").

-type kid()         :: binary().
-type jwk()         :: #jose_jwk{}.
-type iv()          :: binary().
-type jwe()         :: map().
-type jwe_compact() :: binary().

-type decryption_keys() :: #{
    kid() := jwk()
}.
-type encryption_params() :: #{
    iv := iv()
}.
-type decryption_error() :: {decryption_failed,
    wrong_jwk |
    {unknown_kid, kid()} |
    {bad_jwe_header_format, _Reason} |
    {expand_jwe_failed, _JweCompact} |
    _Reason
}.
-type encryption_error() :: {encryption_failed, _Reason}.

-export_type([encryption_params/0]).
-export_type([decryption_keys/0]).
-export_type([encryption_error/0]).
-export_type([decryption_error/0]).
-export_type([kid/0]).
-export_type([iv/0]).
-export_type([jwk/0]).

-export([encrypt/2]).
-export([encrypt/3]).
-export([decrypt/2]).
-export([get_jwe_kid/1]).
-export([get_jwk_kid/1]).
-export([verify_jwk_alg/1]).
-export([compute_random_iv/0]).
-export([compute_iv_hash/2]).

-spec compute_iv_hash(jwk(), binary()) -> iv().

compute_iv_hash(Jwk, Nonce) ->
    Type = sha256,
    JwkBin = erlang:term_to_binary(Jwk),
    crypto:hmac(Type, JwkBin, Nonce, 16).

-spec compute_random_iv() -> iv().

compute_random_iv() ->
    crypto:strong_rand_bytes(16).


-spec encrypt(jwk(), binary()) ->
    {ok, binary()} |
    {error, {encryption_failed, wrong_data_type}}.

encrypt(Key, Plain) ->
    EncryptionParams = #{
        iv => compute_random_iv()
    },
    encrypt(Key, Plain, EncryptionParams).

-spec encrypt(jwk(), binary(), encryption_params()) ->
    {ok, jwe_compact()} |
    {error, {encryption_failed, _Reason}}.

encrypt(JWK, Plain, EncryptionParams) ->
    IV = iv(EncryptionParams),
    % try
        #{<<"kid">> := KID} = JWK#jose_jwk.fields,
        EncryptorWithoutKid = jose_jwk:block_encryptor(JWK),
        JWE = EncryptorWithoutKid#{<<"kid">> => KID},
        {CEK, JWE1} = jose_jwe:next_cek(JWK, JWE),
        {_, EncBlock} = jose_jwe:block_encrypt(JWK, Plain, CEK, IV, JWE1),
        {#{}, Compact} = jose_jwe:compact(EncBlock),
        {ok, Compact}.
    % catch _Type:Error ->
    %     {error, {encryption_failed, Error}}
    % end.

-spec decrypt(decryption_keys(), jwe_compact()) ->
    {ok, binary()} |
    {error, decryption_error()}.

decrypt(SecretKeys, JweCompact) ->
    try
        Jwe = expand_jwe(JweCompact),
        Kid = get_jwe_kid(Jwe),
        Jwk = get_key(Kid, SecretKeys),
        case jose_jwe:block_decrypt(Jwk, Jwe) of
            {error, _JWE} ->
               {error, {decryption_failed, wrong_jwk}};
            {DecryptedData, _JWE} ->
                {ok, DecryptedData}
        end
    catch _Type:Error ->
        {error, {decryption_failed, Error}}
    end.

%%% Internal functions

-spec expand_jwe(jwe_compact()) ->
    jwe().

expand_jwe(JweCompact) ->
    try
        {#{}, Jwe} = jose_jwe:expand(JweCompact),
        Jwe
    catch _Type:_Error ->
        throw({expand_jwe_failed, JweCompact})
    end.

-spec get_jwe_kid(jwe()) ->
    kid().

get_jwe_kid(#{<<"protected">> := EncHeader}) ->
    try
        HeaderJson = base64url:decode(EncHeader),
        Header = jsx:decode(HeaderJson, [return_maps]),
        maps:get(<<"kid">>, Header)
    catch _Type:Error ->
        throw({bad_jwe_header_format, Error})
    end.

-spec get_jwk_kid(jwk()) -> kid() | notfound.

get_jwk_kid(Jwk) ->
    Fields = Jwk#jose_jwk.fields,
    maps:get(<<"kid">>, Fields, notfound).

-spec verify_jwk_alg(jwk()) ->  ok | {wrong_jwk_alg, _}.

verify_jwk_alg(JWK) ->
    Fields = JWK#jose_jwk.fields,
    case maps:get(<<"alg">>, Fields, notfound) of
        <<"dir">> ->
            ok;
        <<"A256KW">> ->
            ok;
        <<"A256GCMKW">> ->
            ok;
        Alg ->
            {wrong_jwk_alg, Alg}
    end.

-spec get_key(kid(), decryption_keys()) -> jwk().

get_key(KID, Keys) ->
    case maps:find(KID, Keys) of
        {ok, Key} ->
            Key;
        error ->
            throw({kid_notfound, KID})
    end.

-spec iv(encryption_params()) -> iv().

iv(#{iv := IV}) ->
    IV.
