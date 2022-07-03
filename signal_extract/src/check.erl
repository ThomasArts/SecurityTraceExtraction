-module(check).

%% Checks a worked out example.

-compile(export_all).

check_and_generate(Handshake,DH,Crypto,Hash,TraceFile) ->
  signal_extract:noisy_trace(Handshake,DH,Crypto,Hash,TraceFile),
  check(Handshake,DH,Crypto,Hash,TraceFile).

check(Handshake,DH,Crypto,Hash,TraceFile) ->
  {TraceSend, TracePayload} = signal_extract:analyze_trace_file(TraceFile),
  {SemanticSend, SemanticPayload} = run_noise:handshake_and_send(Handshake,DH,Crypto,Hash,{'MESSAGE',[]}),
  
  {SendDiff,SendSub} = compare:compare(SemanticSend,TraceSend),
  io:format("~n~nSend Comparison:~n~p~nSubstitution:~n~p~n",[SendDiff,SendSub]), 
  io:format("~nSend substitution:~n**************************~n~n"),
  lists:foreach(fun ({T1,T2}) -> io:format("~p~nDIFFERS FROM~n~p~n~n",[T1,T2]) end, SendSub), 

  {PayloadDiff,PayloadSub} = compare:compare(SemanticPayload,TracePayload),
  io:format("~n~nPayload Comparison:~n~p~nSubstitution:~n~p~n",[PayloadDiff,PayloadSub]), 
  io:format("~n"),
  io:format("~nPayload substitution:~n*************************~n~n"),
  lists:foreach(fun ({T1,T2}) -> io:format("~p~nDIFFERS FROM~n~p~n~n",[T1,T2]) end, PayloadSub).

check() ->
  check("XK","25519","ChaChaPoly","BLAKE2b","enoise.trace").

check2() ->
  check_and_generate("XK","25519","ChaChaPoly","SHA512","enoise2.trace").

check(FileName) ->
  check("XK","25519","ChaChaPoly","BLAKE2b",FileName).

check_and_generate(FileName) ->
  check_and_generate("XK",FileName).

check_and_generate(Handshake,FileName) ->
  check_and_generate(Handshake,"25519","ChaChaPoly","BLAKE2b",FileName).


  

