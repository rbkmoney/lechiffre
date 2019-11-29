-module(lechiffre_tests).

-include_lib("damsel/include/dmsl_payment_tool_token_thrift.hrl").
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec encode_test() -> _.
encode_test() ->
    ThriftType = {struct, union, {dmsl_payment_tool_token_thrift, 'PaymentToolToken'}},
    PaymentToolToken = {bank_card_payload, #ptt_BankCardPayload{
        bank_card = #domain_BankCard{
            token = <<"TOKEN">>,
            payment_system = visa,
            bin = <<"">>,
            masked_pan = <<"4026************61">>
        }
    }},
    SecretKey = crypto:strong_rand_bytes(32),
    {ok, EncrytpedToken} = lechiffre:encode(ThriftType, PaymentToolToken, SecretKey),
    {ok, Value} = lechiffre:decode(ThriftType, EncrytpedToken, SecretKey),
    ?assertEqual(PaymentToolToken, Value).
