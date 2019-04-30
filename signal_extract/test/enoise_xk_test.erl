%%%-------------------------------------------------------------------
%%% @copyright (C) 2018, Aeternity Anstalt
%%%-------------------------------------------------------------------

-module(enoise_xk_test).

-include_lib("eunit/include/eunit.hrl").


%% Talks to local echo-server (noise-c)
client_test() ->
  KeyDir = code:priv_dir(signal_extract)++"/testing_keys",
  TestProtocol = enoise_protocol:from_name("Noise_XK_25519_ChaChaPoly_BLAKE2b"),
  ClientPrivKey = get_key:get_key("client_key_25519",KeyDir,priv),
  ClientPubKey  = get_key:get_key("client_key_25519",KeyDir,pub),
  ServerPubKey  = get_key:get_key("server_key_25519",KeyDir,pub),
  Prologue = <<0,8,0,0,3>>,

  {ok, TcpSock} = 
    gen_tcp:connect("localhost", 7002, [{active, once}, binary, {reuseaddr, true}], 1000),

  gen_tcp:send(TcpSock, Prologue), %% "Noise_XK_25519_ChaChaPoly_Blake2b"

  Opts = [ {noise, TestProtocol}
         , {s, enoise_keypair:new(dh25519, ClientPrivKey, ClientPubKey)}
         , {rs, enoise_keypair:new(dh25519, ServerPubKey)}
         , {prologue, Prologue}],

  {ok, EConn, _UselessState} = enoise:connect(TcpSock, Opts),
  ok = enoise:send(EConn, <<"ok\n">>),
  receive
    {noise, EConn, <<"ok\n">>} -> ok
  after 1000 -> error(timeout) end,
  enoise:close(EConn).


  


