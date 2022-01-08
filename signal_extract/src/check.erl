-module(check).

-compile(export_all).

check_and_generate(Handshake,DH,Crypto,Hash) ->
  TraceFile = "enoise.trace",
  signal_extract:noisy_trace(Handshake,DH,Crypto,Hash,TraceFile),
  check(Handshake,DH,Crypto,Hash,TraceFile).

check(Handshake,DH,Crypto,Hash,TraceFile) ->
  {TraceSend, TracePayload} = signal_extract:analyze_trace_file(TraceFile),
  {SemanticSend, SemanticPayload} = run_noise:handshake_and_send(Handshake,DH,Crypto,Hash,{'MESSAGE',[]}),
  
  {SendDiff,SendSub} = compare:compare(SemanticSend,TraceSend),
  io:format("~n~nSend Comparison:~n~p~nSubstitution:~n~p~n",[SendDiff,SendSub]), 
  lists:foreach(fun ({T1,T2}) -> io:format("~n Send Subst: ~p~nand ~p~n",[T1,T2]) end, SendSub), 

  {PayloadDiff,PayloadSub} = compare:compare(SemanticPayload,TracePayload),
  io:format("~n~nPayload Comparison:~n~p~nSubstitution:~n~p~n",[PayloadDiff,PayloadSub]), 
  lists:foreach(fun ({T1,T2}) -> io:format("~n Payload Subst: ~p~nand ~p~n",[T1,T2]) end, PayloadSub).

test() ->
  check_and_generate("XK","25519","ChaChaPoly","BLAKE2b").

check() ->
  check("XK","25519","ChaChaPoly","BLAKE2b","enoise.trace").



