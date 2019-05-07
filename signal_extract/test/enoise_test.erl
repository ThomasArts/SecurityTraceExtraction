%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_test).

-export([client_test/5]).

-include_lib("eunit/include/eunit.hrl").


%% Talks to local echo-server (noise-c)
client_test(Handshake,DH,Crypto,Hash,KnowsRS) ->
  KeyDir = code:priv_dir(signal_extract)++"/testing_keys",
  ProtocolName = "Noise" ++ "_" ++ Handshake ++ "_" ++ DH ++ "_" ++ Crypto ++ "_" ++ Hash,
  KnowsRS = echo_noise:knows_rs(Handshake),
  Prologue = echo_noise:find_echo_prologue(Handshake,DH,Crypto,Hash),
  TestProtocol = enoise_protocol:from_name(ProtocolName),
  io:format("Prologue is ~p~n",[Prologue]),
  ClientPrivKey = get_key:get_key("client_key_25519",KeyDir,priv),
  ClientPubKey  = get_key:get_key("client_key_25519",KeyDir,pub),

  {ok, TcpSock} = 
    gen_tcp:connect("localhost", 7002, [{active, once}, binary, {reuseaddr, true}], 1000),

  gen_tcp:send(TcpSock, Prologue), %% "Noise_XK_25519_ChaChaPoly_Blake2b"

  Opts = 
    [ 
      {noise, TestProtocol}
    , {s, enoise_keypair:new(dh25519, ClientPrivKey, ClientPubKey)}
    , {prologue, Prologue}
    , {timeout, 1000}
    ] ++
    if
      KnowsRS -> 
        ServerPubKey  = get_key:get_key("server_key_25519",KeyDir,pub),
        [{rs, enoise_keypair:new(dh25519, ServerPubKey)}];
      true -> 
        []
    end,
  {ok, EConn, _UselessState} = enoise:connect(TcpSock, Opts),
  ok = enoise:send(EConn, <<"ok\n">>),
  receive
    {noise, EConn, <<"ok\n">>} -> ok
  after 1000 -> error(timeout) end,
  enoise:close(EConn).



      
      
       




  


