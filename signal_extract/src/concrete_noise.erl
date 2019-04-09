%%% @author Thomas Arts
%%% @doc  This program describes a conretization of the output of a noise
%%%       symbolic reference specification into commands that occur in an
%%%       abstracted trace.
%%%
%%% @end
%%% Created :  9 Apr 2019 by Thomas Arts

-module(concrete_noise).

-compile([export_all, nowarn_export_all]).

'MERGE'(Bin1, Bin2) ->
    {signal_binary_ops, merge, [Bin1, Bin2]}.

'PUBLIC-KEY'(X) ->
    {enacl, crypto_sign_ed25519_public_to_curve25519, [{signal_binary_ops, extract, [X, 32, 32]}]}.

'GENERATE_KEYPAIR'(_) ->
    {enacl, crypto_sign_ed25519_keypair, []}.

'ENCRYPT'(X, Nonce, Y, Payload) ->
    {enacl, aead_chacha20poly1305_encrypt, [X, Nonce, Y, Payload]}.

'TRUNCATE'(Bin, Length) ->
    {signal_binary_ops, truncate, [Bin, Length]}.

'HASH'(T) ->
    {enacl,generichash, [64, T]}.

%% 'PAYLOAD'(X) ->
%%     X.
