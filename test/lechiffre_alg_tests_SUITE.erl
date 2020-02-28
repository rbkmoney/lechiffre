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
    lechiffre_crypto_decode_fail_test/1
]).

-type config()      :: [{atom(), term()}].
-type group_name()  :: atom().

-type key_source()  :: lechiffre:key_source().
-type key_sources() :: [key_source()].

-spec all() ->
    [atom()].

all() ->
    [
        {group, oct_dir},
        {group, oct_a128kw},
        {group, oct_a128gcmkw},
        {group, oct_a192kw},
        {group, oct_a192gcmkw},
        {group, oct_a256kw},
        {group, oct_a256gcmkw},
        {group, ecdh_es},
        {group, ecdh_a128kw},
        {group, ecdh_a192kw},
        {group, ecdh_a256kw},
        {group, rsa1_5},
        {group, rsa_oaep},
        {group, rsa_oaep_256}
    ].

-spec encryption_and_decryption_tests() ->
    list().

encryption_and_decryption_tests() ->
    [
        lechiffre_crypto_encode_ok_test,
        lechiffre_crypto_decode_fail_test
    ].

-spec groups() ->
    list().

groups() ->
    [
        {oct_dir,           [], encryption_and_decryption_tests()},
        {oct_a128kw,        [], encryption_and_decryption_tests()},
        {oct_a128gcmkw,     [], encryption_and_decryption_tests()},
        {oct_a192kw,        [], encryption_and_decryption_tests()},
        {oct_a192gcmkw,     [], encryption_and_decryption_tests()},
        {oct_a256kw,        [], encryption_and_decryption_tests()},
        {oct_a256gcmkw,     [], encryption_and_decryption_tests()},
        {ecdh_es,           [], encryption_and_decryption_tests()},
        {ecdh_a128kw,       [], encryption_and_decryption_tests()},
        {ecdh_a192kw,       [], encryption_and_decryption_tests()},
        {ecdh_a256kw,       [], encryption_and_decryption_tests()},
        {rsa1_5,            [], encryption_and_decryption_tests()},
        {rsa_oaep,          [], encryption_and_decryption_tests()},
        {rsa_oaep_256,      [], encryption_and_decryption_tests()}
    ].

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
    FileSource1 = get_source_binary(<<"oct">>, <<"1">>, <<"dir">>),
    FileSource2 = get_source_binary(<<"oct">>, <<"2">>, <<"dir">>),
    Options = #{
        encryption_source => {json, FileSource1},
        decryption_sources => [
            {json, FileSource1},
            {json, FileSource2}
        ]
    },
    ChildSpec = lechiffre:child_spec(lechiffre, Options),
    {ok, SupPid} = genlib_adhoc_supervisor:start_link({one_for_all, 0, 1}, [ChildSpec]),
    _ = unlink(SupPid),
    Config ++ [{sup_pid, SupPid}].

-spec end_per_testcase(atom(), config()) ->
    config().

end_per_testcase(_Name, Config) ->
    {_, SupPid} = lists:keyfind(sup_pid, 1, Config),
    exit(SupPid, shutdown),
    Config.


-spec init_per_group(group_name(), config()) ->
    config().

init_per_group(AlgType, Config)
when   AlgType =:= oct_dir
orelse AlgType =:= oct_a128kw
orelse AlgType =:= oct_a128gcmkw
orelse AlgType =:= oct_a192kw
orelse AlgType =:= oct_a192gcmkw
orelse AlgType =:= oct_a256kw
orelse AlgType =:= oct_a256gcmkw ->
    FileName = erlang:atom_to_binary(AlgType, latin1),
    FileSource = {json, {file, get_source_file(<<FileName/binary, ".publ.jwk">>, Config)}},
    WrongDecryptionSources = [{json, get_source_binary(<<"oct">>, <<"1">>, <<"dir">>)}],
    add_secret_keys(FileSource, [FileSource], WrongDecryptionSources, Config);
init_per_group(AlgType, Config)
when   AlgType =:= ecdh_es
orelse AlgType =:= ecdh_a128kw
orelse AlgType =:= ecdh_a192kw
orelse AlgType =:= ecdh_a256kw
orelse AlgType =:= rsa1_5
orelse AlgType =:= rsa_oaep
orelse AlgType =:= rsa_oaep_256 ->
    FileName = erlang:atom_to_binary(AlgType, latin1),
    SourcePubl = {json, {file, get_source_file(<<FileName/binary,  ".publ.jwk">>, Config)}},
    SourcePriv = [{json, {file, get_source_file(<<FileName/binary, ".priv.jwk">>, Config)}}],
    WrongDecryptionSources = [SourcePubl],
    add_secret_keys(SourcePubl, SourcePriv, WrongDecryptionSources, Config).

-spec end_per_group(group_name(), config()) ->
    _.

end_per_group(_Group, _C) ->
    ok.

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

-spec add_secret_keys(key_source(), key_sources(), key_sources(), config()) ->
    config().

add_secret_keys(EncryptionSource, DecryptionSources, WrongDecryptionSources, Config) ->
    SecretKeys = lechiffre:read_secret_keys(#{
        encryption_source => EncryptionSource,
        decryption_sources => DecryptionSources
    }),
    WrongDecryptionKeys = lechiffre:read_secret_keys(#{
        decryption_sources => WrongDecryptionSources
    }),
    [
        {secret_keys, SecretKeys},
        {wrong_decryption_keys, WrongDecryptionKeys} |
        Config
    ].

%% TESTS

-spec lechiffre_crypto_encode_ok_test(config()) -> ok.
-spec lechiffre_crypto_decode_fail_test(config()) -> ok.

lechiffre_crypto_encode_ok_test(Config) ->
    Plain = <<"bukabjaka">>,
    #{
        encryption_key := JwkPubl,
        decryption_keys := DecryptionKeys
    } = ?config(secret_keys, Config),
    {ok, JweCompact} = lechiffre_crypto:encrypt(JwkPubl, Plain),
    {ok, Result} = lechiffre_crypto:decrypt(DecryptionKeys, JweCompact),
    ?assertMatch(Plain, Result).

lechiffre_crypto_decode_fail_test(Config) ->
    Plain = <<"bukabjaka">>,
    #{encryption_key := JwkPubl} = ?config(secret_keys, Config),
    DecryptionKeys = ?config(wrong_decryption_keys, Config),
    {ok, JweCompact} = lechiffre_crypto:encrypt(JwkPubl, Plain),
    ErrorDecode = lechiffre_crypto:decrypt(DecryptionKeys, JweCompact),
    ?assertMatch({error, {decryption_failed, {kid_notfound, _}}}, ErrorDecode).
