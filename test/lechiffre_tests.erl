-module(lechiffre_tests).

-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec encode_test() -> _.
encode_test() ->
    Token = #{
        bank_card_token => <<"bank_card_token">>,
        cardholder_name => <<"BukaBjaka">>,
        exp_date        => {01, 30}
    },
    SecretKey = crypto:strong_rand_bytes(32),
    {ok, EncrytpedToken} = lechiffre:encode(Token, SecretKey),
    {ok, Value} = lechiffre:decode(EncrytpedToken, SecretKey),
    ?assertEqual(Token, Value).
