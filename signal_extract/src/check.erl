-module(check).

-include("noise_config.hrl").

%% Checks a worked out example.

-compile(export_all).

check_and_generate(Handshake,DH,Crypto,Hash,TraceFile) ->
  check_and_generate(Handshake,DH,Crypto,Hash,TraceFile,[]).

check_and_generate(Handshake,DH,Crypto,Hash,TraceFile,Options) ->
  io:format("TraceFile is ~p~n",[TraceFile]),
  Message = proplists:get_value(message, Options, <<"ok\n">>),
  PreKeyDir = proplists:get_value(keyDir, Options, "testing_keys"),
  KeyDir = code:priv_dir(signal_extract)++"/"++PreKeyDir,
  signal_extract:noisy_trace(Handshake,DH,Crypto,Hash,TraceFile,Message,KeyDir),
  dump_trace(TraceFile),
  check(Handshake,DH,Crypto,Hash,TraceFile).

check(Handshake,DH,Crypto,Hash,TraceFile) ->
  {TraceSend, TracePayload} = signal_extract:analyze_trace_file(TraceFile),
  {SemanticSend, SemanticPayload} = run_noise:handshake_and_send(Handshake,DH,Crypto,Hash,{'MESSAGE',[]}),
  
  Config = #noise_config{handshake=Handshake,dh=DH,crypto=Crypto,hash=Hash},
  {SendDiff,SendSub} = compare:compare(SemanticSend,TraceSend,Config),
  io:format("~n~nSend Comparison:~n~p~nSubstitution:~n~p~n",[SendDiff,SendSub]), 
  io:format("~nSend substitution:~n**************************~n~n"),
  lists:foreach(fun ({T1,T2}) -> io:format("~nTerm~n~p~nDIFFERS FROM~n~p~n~n",[T1,T2]) end, SendSub), 

  {PayloadDiff,PayloadSub} = compare:compare(SemanticPayload,TracePayload,Config),
  io:format("~n~nPayload Comparison:~n~p~nSubstitution:~n~p~n",[PayloadDiff,PayloadSub]), 
  io:format("~n"),
  io:format("~nPayload substitution:~n*************************~n~n"),
  lists:foreach(fun ({T1,T2}) -> io:format("~nTerm~n~p~nDIFFERS FROM~n~p~n~n",[T1,T2]) end, PayloadSub).

dump_trace(TraceFile) ->
  {ok,PF} = file:open("tracedump.txt",[write]),
  {ok,B} = file:read_file(TraceFile),
  {trace,L} = binary_to_term(B),
  lists:foreach(fun (TraceItem) -> io:format(PF,"~p~n",[TraceItem]) end, L),
  ok = file:close(PF).

check() ->
  check("XK","25519","ChaChaPoly","BLAKE2b","enoise.trace").

check2() ->
  check_and_generate("XK","25519","ChaChaPoly","SHA512","enoise2.trace").

check3() ->
  check_and_generate("IK","25519","ChaChaPoly","SHA512","enoise2.trace").

check4() ->
  check_and_generate("XN","25519","ChaChaPoly","SHA512","enoise2.trace").

check5() ->
  check_and_generate("KK","25519","ChaChaPoly","SHA512","enoise2.trace").

nonints() ->
  nonint_check1(),  
  nonint_check2(),
  os:cmd("cat nonint1.pl nonint2.pl > nonints.pl").

nonint_check1() ->
  check_and_generate("XK","25519","ChaChaPoly","BLAKE2b","nonint1.trace",[{message,<<"msg1">>}]),
  signal_extract:trace_to_prolog("nonint1.trace","nonint1.pl",r1).

nonint_check2() ->
  check_and_generate("XK","25519","ChaChaPoly","BLAKE2b","nonint2.trace",[{message,<<"msg2">>}]),
  signal_extract:trace_to_prolog("nonint2.trace","nonint2.pl",r2).

check(FileName) ->
  check("XK","25519","ChaChaPoly","BLAKE2b",FileName).

check_and_generate(FileName) ->
  check_and_generate("XK",FileName).

check_and_generate(Handshake,FileName) ->
  io:format("~n~n======================================================================~n"),
  io:format("Checking handshake ~s with trace output in ~s~n",[Handshake,FileName]),
  check_and_generate(Handshake,"25519","ChaChaPoly","BLAKE2b",FileName).

  

