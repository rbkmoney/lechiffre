-module(lechiffre_alg_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).
-export([init_per_group/2]).
-export([end_per_group/2]).

-export([test/0]).

-export([
    lechiffre_crypto_encode_ok_test/1,
    lechiffre_crypto_decode_fail_test/1,
    lechiffre_crypto_asym_encode_ok_test/1,
    lechiffre_crypto_asym_decode_fail_test/1,
    lechiffre_crypto_asym_hack_decode_ok_test/1
]).

-type config()      :: [{atom(), term()}].
-type group_name()  :: atom().

-type key_source()  :: lechiffre:key_source().
-type key_sources() :: [key_source()].

-spec all() ->
    [atom()].

all() ->
    Algos = lists:delete(<<"dir">>, lechiffre_crypto:supported_algorithms()),
    lists:foldl(fun(Alg, Acc)->
        GroupName = binary_to_atom(genlib_string:to_lower(Alg), latin1),
        [{group, GroupName}|Acc]
    end, [], Algos).

-spec encryption_and_decryption_tests() ->
    list().

encryption_and_decryption_tests() ->
    [
        lechiffre_crypto_encode_ok_test,
        lechiffre_crypto_decode_fail_test
    ].

-spec asym_encryption_and_decryption_tests() ->
    list().

asym_encryption_and_decryption_tests() ->
    [
        lechiffre_crypto_asym_encode_ok_test,
        lechiffre_crypto_asym_decode_fail_test,
        lechiffre_crypto_asym_hack_decode_ok_test
    ].

-spec groups() ->
    list().

groups() ->
    AlgosSym = lists:delete(<<"dir">>, lechiffre_crypto:supported_algorithms(symmetric)),
    AlgosAsym = lechiffre_crypto:supported_algorithms(asymmetric),
    Group1 = lists:foldl(fun(Alg, Acc)->
        Alg2 = binary_to_atom(genlib_string:to_lower(Alg), latin1),
        [{Alg2, [], encryption_and_decryption_tests()}|Acc]
    end, [], AlgosSym),
    Group2 = lists:foldl(fun(Alg, Acc)->
        Alg2 = binary_to_atom(genlib_string:to_lower(Alg), latin1),
        [{Alg2, [], asym_encryption_and_decryption_tests()}|Acc]
    end, [], AlgosAsym),
    Group1 ++ Group2.

-spec test() ->
    any().

test() ->
    ok.

-spec init_per_suite(config()) ->
    config().

init_per_suite(Config) ->
    Config.

-spec end_per_suite(config()) ->
    ok.

end_per_suite(_C) ->
    ok.

-spec init_per_testcase(atom(), config()) ->
    config().

init_per_testcase(_Name, Config) ->
    Config.

-spec end_per_testcase(atom(), config()) ->
    config().

end_per_testcase(_Name, Config) ->
    Config.


-spec init_per_group(group_name(), config()) ->
    config().

init_per_group(AlgType, Config) ->
    FileName = genlib_string:to_lower(atom_to_binary(AlgType, latin1)),
    [{jwk_file_name, FileName} | Config].

-spec end_per_group(group_name(), config()) ->
    _.

end_per_group(_Group, _C) ->
    ok.

%% TESTS

-spec lechiffre_crypto_encode_ok_test(config()) -> ok.
-spec lechiffre_crypto_decode_fail_test(config()) -> ok.
-spec lechiffre_crypto_asym_encode_ok_test(config()) -> ok.
-spec lechiffre_crypto_asym_decode_fail_test(config()) -> ok.
-spec lechiffre_crypto_asym_hack_decode_ok_test(config()) -> ok.

lechiffre_crypto_encode_ok_test(Config) ->
    FileName = ?config(jwk_file_name, Config),
    FileSource = {json, {file, get_source_file(<<FileName/binary, ".publ.jwk">>, Config)}},
    {Jwk, DecryptionKeys} = read_secret_keys(FileSource, [FileSource]),
    Plain = <<"bukabjaka">>,
    {ok, JweCompact} = lechiffre_crypto:encrypt(Jwk, Plain),
    {ok, Result} = lechiffre_crypto:decrypt(DecryptionKeys, JweCompact),
    ?assertMatch(Plain, Result).

lechiffre_crypto_decode_fail_test(Config) ->
    FileName = ?config(jwk_file_name, Config),
    JwkSource = {json, {file, get_source_file(<<FileName/binary, ".publ.jwk">>, Config)}},
    WrongDecryptionSources = [{json, get_source_binary(<<"oct">>, <<"1">>, <<"dir">>)}],
    {Jwk, DecryptionKeys} = read_secret_keys(JwkSource, WrongDecryptionSources),
    Plain = <<"bukabjaka">>,
    {ok, JweCompact} = lechiffre_crypto:encrypt(Jwk, Plain),
    ErrorDecode = lechiffre_crypto:decrypt(DecryptionKeys, JweCompact),
    ?assertMatch({error, {decryption_failed, _}}, ErrorDecode).

lechiffre_crypto_asym_encode_ok_test(Config) ->
    FileName = ?config(jwk_file_name, Config),
    JwkPublSource = {json, {file, get_source_file(<<FileName/binary,  ".publ.jwk">>, Config)}},
    JwkPrivSources = [{json, {file, get_source_file(<<FileName/binary, ".priv.jwk">>, Config)}}],
    {JwkPubl, JwkPriv} = read_secret_keys(JwkPublSource, JwkPrivSources),
    Plain = <<"bukabjaka">>,
    {ok, JweCompact} = lechiffre_crypto:encrypt(JwkPubl, Plain),
    {ok, Result} = lechiffre_crypto:decrypt(JwkPriv, JweCompact),
    ?assertMatch(Plain, Result).

lechiffre_crypto_asym_decode_fail_test(Config) ->
    FileName = ?config(jwk_file_name, Config),
    JwkPublSource = {json, {file, get_source_file(<<FileName/binary,  ".publ.jwk">>, Config)}},
    {JwkPubl, WrongDecryptionKeys} = read_secret_keys(JwkPublSource, [JwkPublSource]),
    Plain = <<"bukabjaka">>,
    {ok, JweCompact} = lechiffre_crypto:encrypt(JwkPubl, Plain),
    ?assertException(error, function_clause, lechiffre_crypto:decrypt(WrongDecryptionKeys, JweCompact)).

lechiffre_crypto_asym_hack_decode_ok_test(Config) ->
    FileName = ?config(jwk_file_name, Config),
    JwkPublSource = {json, {file, get_source_file(<<FileName/binary,  ".publ.jwk">>, Config)}},
    HackPrivSource = {json, {file, get_source_file(<<FileName/binary,  ".hack.priv.jwk">>, Config)}},
    {JwkPubl, HackKeys} = read_secret_keys(JwkPublSource, [HackPrivSource]),
    Plain = <<"bukabjaka">>,
    {ok, JweCompact} = lechiffre_crypto:encrypt(JwkPubl, Plain),
    {error, {decryption_failed, {kid_notfound, _}}} = lechiffre_crypto:decrypt(HackKeys, JweCompact).
%%

-spec read_secret_keys(key_source(), key_sources()) ->
    {lechiffre_crypto:jwk(), lechiffre_crypto:decryption_keys()}.

read_secret_keys(SourceEncrypt, SourceDecrypt) ->
    #{
        encryption_key := EncryptionKey,
        decryption_keys := DecryptionKeys
    } = lechiffre:read_secret_keys(#{
        encryption_source => SourceEncrypt,
        decryption_sources => SourceDecrypt
    }),
    {EncryptionKey, DecryptionKeys}.

-spec get_source_file(binary(), config()) ->
    binary().

get_source_file(FileName, Config) ->
    filename:join(?config(data_dir, Config), FileName).

-spec get_source_binary(binary(), number(), binary()) ->
    binary().

get_source_binary(Kty, Kid, Alg) ->
    K = base64url:encode(crypto:strong_rand_bytes(32)),
    Map = genlib_map:compact(#{
        <<"alg">>   => Alg,
        <<"kty">>   => Kty,
        <<"k">>     => K,
        <<"kid">>   => Kid
    }),
    {_, JwkBin} = jose_jwk:to_binary(jose_jwk:from(Map)),
    JwkBin.
