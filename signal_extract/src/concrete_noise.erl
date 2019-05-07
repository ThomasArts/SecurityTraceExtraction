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
  if
    is_binary(Bin2), byte_size(Bin2)==1 ->
      {signal_binary_ops, pad, [Bin1,binary:at(Bin2,0),1]};
    true ->
      {signal_binary_ops, merge, [Bin1, Bin2]}
  end.

'PUBLIC-KEY'(X) ->
  case X of
    {'STORE-PUBLIC-KEY', [Key]}-> 
      Key;
    {'STORE-KEYPAIR', [KeyPair]} ->
      {enacl, crypto_sign_ed25519_public_to_curve25519, 
       [{signal_binary_ops, extract, [KeyPair, 32, 32]}]};
%%    {maps,get,[secret,KeyPair={enacl,crypto_sign_ed25519_keypair,[Id]}]} ->
%%      {enacl, crypto_sign_ed25519_public_to_curve25519, 
%%       [{signal_binary_ops, extract, [KeyPair, 32, 32]}]};
    _ ->
      io:format("public_key(~p)~n",[X]),
      throw(nyi)
  end.

'PRIVATE-KEY'(X) ->
  {enacl, crypto_sign_ed25519_secret_to_curve25519, [X]}.

'GENERATE_KEYPAIR'(X) ->
  {maps, get, [secret, {enacl, crypto_sign_ed25519_keypair, [X]}]}.

'DECRYPT'(X, Nonce, Ad, Payload) ->
  {enacl, aead_chacha20poly1305_decrypt, [X, Nonce, Ad, Payload]}.

'ENCRYPT'(X, Nonce, Y, Payload) ->
  {enacl, aead_chacha20poly1305_encrypt, [X, Nonce, Y, Payload]}.

'DH'(Keypair,Publickey) ->
  {enacl,curve25519_scalarmult,[Keypair,Publickey]}.

'TRUNCATE'(Bin, Length) ->
  {signal_binary_ops, truncate, [Bin, Length]}.

'HASH'(T) ->
  {erlang, element, [2, {enacl,generichash, [64, T]}]}.

'XOR'(B1, B2) ->
  case {bin_size(B1), bin_size(B2)} of
    {N,N} when is_integer(N) ->
      case B2 of
        {signal_binary_ops,pad,[<<>>,Using,Len]} 
          when is_integer(Using), is_integer(Len), (N rem 4)==0 ->
          {signal_binary_ops,xor_words_with_const,[B1,Using]};
        _ -> {'XOR',[B1,B2]}
      end;
    {A,B} -> 
      io:format("computed sizes ~p and ~p for~n~p~nand ~p~n",[A,B,B1,B2]),
      {'XOR',[B1,B2]}
  end.

'PAD_TO_USING'(Bin, Upto, Using) ->
  case bin_size(Bin) of
    BinSize when is_integer(BinSize) ->
%%      case Bin of
%%        {signal_binary_ops,pad,[PaddedBin,Using,PadLength]} ->
%%          case bin_size(PaddedBin) of
%%            PaddedBinSize when is_integer(PaddedBinSize) ->
%%              {signal_binary_ops,pad,[PaddedBin,Using,Upto-PaddedBinSize]};
%%            undefined ->
%%              io:format("Weird! Bin is ~p~n",[Bin]),
%%              {'PAD_TO_USING',[Bin,Upto,Using]}
%%          end;
%%        _ -> 
      {signal_binary_ops,pad,[Bin,Using,Upto-BinSize]};
%%      end;
    undefined ->
      {'PAD_TO_USING',[Bin,Upto,Using]}
  end.

bin_size(Bin) ->
  case Bin of
    _ when is_binary(Bin) ->
      byte_size(Bin);
    {signal_binary_ops,pad,[Binary,_,Len]} ->
      case bin_size(Binary) of
        N when is_integer(N) -> N+Len;
        Other -> Other
      end;
    {erlang,element,[2,{enacl,generichash,[N,_]}]} when is_integer(N) ->
      N;
    _ ->
      undefined
  end.

%% 'PAYLOAD'(X) ->
%%     X.
