%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_test).

-export([client_test/4]).

-include_lib("eunit/include/eunit.hrl").


%% Talks to local echo-server (noise-c)
client_test(Handshake,DH,Crypto,Hash) ->
  KeyDir = code:priv_dir(signal_extract)++"/testing_keys",
  ProtocolName = "Noise" ++ "_" ++ Handshake ++ "_" ++ DH ++ "_" ++ Crypto ++ "_" ++ Hash,
  Prologue = find_echo_prologue(Handshake,DH,Crypto,Hash),
  TestProtocol = enoise_protocol:from_name(ProtocolName),
  io:format("Prologue is ~p~n",[Prologue]),
  ClientPrivKey = get_key:get_key("client_key_25519",KeyDir,priv),
  ClientPubKey  = get_key:get_key("client_key_25519",KeyDir,pub),
  ServerPubKey  = get_key:get_key("server_key_25519",KeyDir,pub),

  {ok, TcpSock} = 
    gen_tcp:connect("localhost", 7002, [{active, once}, binary, {reuseaddr, true}], 1000),

  gen_tcp:send(TcpSock, Prologue), %% "Noise_XK_25519_ChaChaPoly_Blake2b"

  Opts = 
    [ 
      {noise, TestProtocol}
    , {s, enoise_keypair:new(dh25519, ClientPrivKey, ClientPubKey)}
    , {rs, enoise_keypair:new(dh25519, ServerPubKey)}
    , {prologue, Prologue}
    , {timeout, 1000}
    ],

  {ok, EConn, _UselessState} = enoise:connect(TcpSock, Opts),
  ok = enoise:send(EConn, <<"ok\n">>),
  receive
    {noise, EConn, <<"ok\n">>} -> ok
  after 1000 -> error(timeout) end,
  enoise:close(EConn).

find_echo_prologue(Handshake,DH,Crypto,Hash) ->
  HandshakeP = find_echo_handshake(Handshake),
  DHP = find_echo_dh(DH),
  CryptoP = find_echo_crypto(Crypto),
  HashP = find_echo_hash(Hash),
  <<HandshakeP:16,DHP:8,CryptoP:8,HashP:8>>.

find_echo_handshake(Handshake) ->
  if
    Handshake=="NN" -> 16#00;
    Handshake=="KN" -> 16#01;
    Handshake=="NK" -> 16#02;
    Handshake=="KK" -> 16#03;
    Handshake=="NX" -> 16#04;
    Handshake=="KX" -> 16#05;
    Handshake=="XN" -> 16#06;
    Handshake=="IN" -> 16#07;
    Handshake=="XK" -> 16#08;
    Handshake=="IK" -> 16#09;
    Handshake=="XX" -> 16#0A;
    Handshake=="IX" -> 16#0B
  end.

find_echo_dh(DH) ->
  if
    DH=="25519" -> 16#00;
    DH=="448" -> 16#01
  end.

find_echo_crypto(Crypto) ->
  if
    Crypto=="ChaChaPoly" -> 16#00
  end.

find_echo_hash(Hash) ->
  if
    Hash=="SHA256" -> 16#00;
    Hash=="SHA512" -> 16#01;
    Hash=="BLAKE2s" -> 16#02;
    Hash=="BLAKE2b" -> 16#03
  end.


      
      
       




  


