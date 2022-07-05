-module(signal_extract).

-include_lib("kernel/include/logger.hrl").

-export([noisy_trace/1,noisy_trace/5]).
-export([register_binaries/3,trace_make_call_deterministic/1]).
-export([get_traces/1,compose_binaries/1,print_array/2]).
-export([print_binary_register/0,show_trace/1,show_registered_trace/1]).

-compile(export_all).

-export([print_call/1,print_full_call/1]).


-record(binary,{value,name,seen,time,source,return,pid}).
-record(item,{loc,item}).


%% rebar3 as test shell

noisy_trace(File) ->
  noisy_trace("XK","25519","ChaChaPoly","BLAKE2b",File).

noisy_trace(Handshake,DH,Crypto,Hash,TraceFileName) ->
  EnoiseModules = 
    [
     enoise, 
     enoise_crypto, 
     enoise_hs_state, enoise_keypair, enoise_protocol, enoise_sym_state, 
     enoise_cipher_state, enoise_connection
    ],
  LoadModules =
    [
     enacl, enacl_nif, unicode_util, gen_tcp, inet_tcp, signal_extract_utils, gen, gen_server, crypto,
     enoise_crypto_basics, signal_extract_utils, enoise_test, code, file, base64, io, get_key
    ],
  lists:foreach(fun code:ensure_loaded/1, EnoiseModules++LoadModules),
  KnowsRS = echo_noise:knows_rs(Handshake),
  test
    (
    fun () -> 
        enoise_test:client_test(Handshake,DH,Crypto,Hash,KnowsRS) 
    end, 
    EnoiseModules,
    TraceFileName
   ).

do_trace(TracedPid,ToPid,Modules) ->
  erlang:trace(TracedPid,true,
               [
                %%call,arity,return_to,
                call,
                set_on_spawn,
                %%'receive',
                send,
                procs,
		ports,
                %%return_to,
                %% set_on_link,
                %%arity,
                %%all,
                timestamp,{tracer,ToPid}
               ]),
  erlang:trace_pattern({'_', '_', '_'}, [{'_', [], [{exception_trace},{return_trace}]}], [global]),
  %% erlang:trace_pattern({'binary', '_', '_'}, [{'_', [], [{exception_trace},{return_trace}]}], [global]),
  %% erlang:trace_pattern({'erlang', '_', '_'}, [{'_', [], [{exception_trace},{return_trace}]}], [global]),
  erlang:trace_pattern({enacl_nif, '_', '_'}, false, []),
  lists:foreach
    (fun (Module) -> 
         erlang:trace_pattern({Module, '_', '_'}, [{'_', [], [{return_trace},{exception_trace}]}], [local]) 
     end,
     Modules).

test(F, Modules, TraceFileName) ->
  Self = self(),
  Tracer = spawn(fun () -> tracer(Self) end),
  Computer = spawn(fun () -> compute(F,Self) end),
  do_trace(Computer,Tracer,Modules),
  receive
    {tracer_started,_} -> ok
  end,
  Computer ! start,
  receive
    {Computer, stopped, Value} -> 
      ?LOG_DEBUG("computed value ~p~n",[Value]), 
      timer:sleep(5000),
      Tracer ! {stop, self(), TraceFileName},
      receive
        {tracer_stopped, Tracer} -> ok
      end
  end.

compute(F,ReportTo) ->
  receive start -> ok end,
  ReturnValue = 
    try F() 
    catch Class:Reason -> 
        io:format("Exception ~p:~p raised. Stacktrace:~n~p~n",[Class,Reason,erlang:get_stacktrace()]),
        {'EXIT',Reason} 
    end,
  ReportTo ! {self(), stopped, ReturnValue}.

tracer(Pid) ->
  Pid!{tracer_started,self()},
  tracer1([]).

tracer1(L) ->
  receive
    {stop, From, FileName} -> 
      ok = file:write_file(FileName, term_to_binary({trace,lists:reverse(L)})),
      From ! {tracer_stopped, self()};
    Tuple when is_tuple(Tuple), size(Tuple)>1, element(1,Tuple)==trace_ts ->
      tracer1([Tuple|L]);
    Other ->
      ?LOG_WARNING("Strange message ~p~n",[Other]),
      tracer1(L)
  end.

get_traces(FileName) ->
  {ok,B} = file:read_file(FileName),
  case binary_to_term(B) of
    {trace,L} ->
      ?LOG_DEBUG("Raw trace file has ~p lines~n",[length(L)]),
      PidTraces = 
        lists:foldl
          (fun (Item,Traces) ->
               trace_ts = element(1,Item),
               Pid = element(2,Item),
               case lists:keyfind(Pid,1,Traces) of
                 false -> 
                   lists:keystore(Pid,1,Traces,{Pid,[Item]});
                 {_,Trace} -> 
                   lists:keyreplace(Pid,1,Traces,{Pid,[Item|Trace]})
               end
           end, [], lists:reverse(L)),
      lists:map
        (fun ({Pid,Trace}) -> {Pid,array:from_list(Trace)} end,
         PidTraces)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

analyze_trace_file(FileName) ->

  %% Later we should generalise this...
  Traces = get_traces(FileName),
  
  PredefinedBinaries = 
    [
    ],

  NonFunctions =
    [
     {enacl, crypto_sign_ed25519_keypair, 0},
     {enoise, gen_tcp_rcv_msg, 2}
    ],

  CollapsableFunctions = 
    [
     {get_key, get_key, 3}
    ],
  
  signal_extract_utils:open_clean_db(),

  ?LOG_DEBUG("~n~nDeterminizing trace...~n"),
  DetTraces = 
    lists:map
      (fun ({Pid,Trace}) -> {Pid,trace_make_call_deterministic(Trace)} end,
       Traces),
  
  ?LOG_DEBUG("~n~nCollapsing functions...~n"),
  CollapsedTraces = 
    lists:map
      (fun ({Pid,Trace}) -> {Pid,collapse_calls(Trace,CollapsableFunctions)} end,
       DetTraces),

  ?LOG_DEBUG("~n~nGiving names to binaries (and finding call sites)...~n"),
  lists:foreach
    (fun ({Pid,A}) -> 
         register_binaries(Pid, A, PredefinedBinaries)
     end, CollapsedTraces),

  ?LOG_DEBUG("Traces:~n"),
  lists:foreach
    (fun ({Pid,Trace}) ->
         ?LOG_DEBUG("~nPid ~p:~n",[Pid]),
         show_trace(Trace)
     end, Traces),

  ?LOG_DEBUG("Collapsed Traces:~n"),
  lists:foreach
    (fun ({Pid,Trace}) ->
         ?LOG_DEBUG("~nPid ~p:~n",[Pid]),
         show_trace(Trace)
     end, CollapsedTraces),

  ?LOG_DEBUG("~n~nTrying to derive binaries using rewriting...~n"),
  compose_binaries(CollapsedTraces),
  
  ?LOG_DEBUG("~n~n~nBinary definitions:~n~n"),
  print_binary_register(),
  
%%  ?LOG_DEBUG("~n~n~nGenerating graphviz model:~n~n"),
%%  ?LOG_DEBUG("Traceback:~n~p~n",
%%            [graphviz_traceback("trace1.dot",Traceback,1,PredefinedBinaries)]),
%%  ?LOG_DEBUG("Traceback:~n~p~n",
%%            [graphviz_traceback("trace2.dot",Traceback,2,PredefinedBinaries)]),

  ?LOG_DEBUG("Before send analysis~n"),
  {Sends,{_Binaries,_}} = sends(CollapsedTraces, NonFunctions),
  [_Port,FirstSend] = lists:nth(1,Sends),
    ?LOG_DEBUG
      ("~n~nThe first send is~n~p~n",
       [FirstSend]),

  ?LOG_DEBUG("Before checking post-protocol send~n"),
  {Results,{Binaries,Counter}} = gen_tcp_sends(CollapsedTraces, NonFunctions),
  lists:foreach
    (fun ({Pid,Sends}) ->
         ?LOG_DEBUG("Pid ~p has ~p sends~n",[Pid,length(Sends)])
     end,
     Results),

  ?LOG_DEBUG("Before checking payload_messages~n"),
  {ReadResults,_} = read_messages(CollapsedTraces, NonFunctions, Binaries, Counter),
  LastPayloadTerm = lists:last(ReadResults),

  {_,FromLastPid} = lists:nth(length(Results),Results),
  LastResultFromLastPid = lists:nth(length(FromLastPid),FromLastPid),
  case LastResultFromLastPid of
    [_,{signal_binary_ops,prefix_len,[LastSend]}] ->
      {LastSend, LastPayloadTerm}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

trace_make_call_deterministic(A) ->
  trace_make_call_deterministic(0,array:size(A),A,array:new(),0,[]).
trace_make_call_deterministic(I,Size,A,B,_J,RemainingCalls) when I>=Size ->
  LastElement = array:get(Size-1,A),
  Pid = element(2,LastElement),
  Ts = element(size(LastElement),LastElement),
  if
    RemainingCalls =/= [] ->
      ?LOG_DEBUG
        ("~n*** Warning: remaining calls:~n  ~p~n",
         [RemainingCalls]),
      {_,Arr} =
        lists:foldl
          (fun (Call,{Index,Arr}) -> 
               {Index+1,
                array:set(Index,{trace_ts, Pid, return_from, Call, undefined, Ts}, Arr)}
           end, {Size,B}, RemainingCalls),
      Arr;
    true -> B
  end;
trace_make_call_deterministic(I,Size,A,B,J,ActiveCalls) ->
  Item = array:get(I,A),
  case Item of
    void ->
      trace_make_call_deterministic(I+1,Size,A,B,J,ActiveCalls);
    {trace_ts, Pid, return_from, Call, _Value, _TimeStamp} ->
      leaving(Call,return_from,Item,I,Size,A,B,J,ActiveCalls);
    {trace_ts, Pid, exception_from, Call, _Value, _TimeStamp} ->
      leaving(Call,exception_from,Item,I,Size,A,B,J,ActiveCalls);
    {trace_ts, _Pid, call, {M,F,Args}, _} ->
      NewB = array:set(J,Item,B),
      trace_make_call_deterministic
        (I+1,Size,A,NewB,J+1,
         [{I,{M,F,length(Args)}}|ActiveCalls]);
    _ ->
      NewB = array:set(J,Item,B),
      trace_make_call_deterministic(I+1,Size,A,NewB,J+1,ActiveCalls)
  end.

leaving(Call,Reason,Item,I,Size,A,B,J,ActiveCalls) ->
  Pid = element(2,Item),
  TimeStamp = element(size(Item),Item),
  case ActiveCalls of
    [{_,Call}|Rest] ->
      NewB = array:set(J,Item,B),
      trace_make_call_deterministic(I+1,Size,A,NewB,J+1,Rest);
    [{OtherI,OtherCall}|_Rest] ->
      ?LOG_DEBUG
        ("~n*** Error: ~p: left (~p) ~p but expected return to~n~p:~p~n",
         [I,Reason,Call,OtherI,OtherCall]),
      ReturnedCall = 
        {trace_ts, Pid, return_from, OtherCall, undefined, TimeStamp},
      {NewActiveCalls,NewA} =
        case delete_call(OtherCall,ActiveCalls) of
          false ->
            {ActiveCalls,A};
          {Index,_,ActiveCalls1} ->
            {ActiveCalls1,array:set(Index,void,A)}
        end,
      NewB = array:set(J,ReturnedCall,B),
      trace_make_call_deterministic(I,Size,NewA,NewB,J+1,NewActiveCalls);
    [] ->
      ?LOG_DEBUG
        ("~n*** Error: ~p: left ~p but there was no active call~n",
         [I,Call]),
      trace_make_call_deterministic(I+1,Size,A,B,J,ActiveCalls)
  end.

delete_call(Call,[]) ->    
  ?LOG_DEBUG
    ("~n*** Error: returned from ~p but there was no active call to that function~n",
     [Call]),
  false;
delete_call(Call,[{I,Call}|Rest]) -> 
  {I,Call,Rest};
delete_call(Call,[OtherItem|Rest]) -> 
  case delete_call(Call,Rest) of
    false -> false;
    {I,Call,Deleted} -> {I,Call,[OtherItem|Deleted]}
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

collapse_calls(A,Collapsables) ->
  collapse_calls(0,A,array:size(A),array:new(),0,Collapsables).
collapse_calls(I,_,Size,B,_,_) when I>=Size ->
  B;
collapse_calls(I,A,Size,B,J,Collapsables) ->
  Item = array:get(I,A),
  BNew = array:set(J,Item,B),
  case Item of
    {trace_ts, Pid, call, {M,F,Args}, _} ->
      Arity = length(Args),
      MFArity = {M,F,Arity},
      case lists:member(MFArity,Collapsables) of
        true ->
          skip_until_return(I+1,A,Size,MFArity,BNew,J+1,[],Collapsables);
        false ->
          collapse_calls(I+1,A,Size,BNew,J+1,Collapsables)
      end;
    _ -> collapse_calls(I+1,A,Size,BNew,J+1,Collapsables)
  end.

skip_until_return(I,A,Size,MFArity={M,F,Arity},B,J,Stack,Collapsables) when I>=Size ->
  ?LOG_DEBUG("~n*** Error: no return for call ~p~n",[MFArity]),
  error(bad);
skip_until_return(I,A,Size,MFArity={M,F,Arity},B,J,Stack,Collapsables) ->
  Item = array:get(I,A),
  case Item of
    {trace_ts, Pid, return_from, MFArity, _, _} when Stack==[] ->
      collapse_calls(I+1,A,Size,array:set(J,Item,B),J+1,Collapsables);
    {trace_ts, Pid, return_from, Call, _, _} ->
      skip_until_return(I+1,A,Size,MFArity,B,J,tl(Stack),Collapsables);
    {trace_ts, Pid, call, Call, _} ->
      skip_until_return(I+1,A,Size,MFArity,B,J,[Call|Stack],Collapsables);
    _ ->
      skip_until_return(I+1,A,Size,MFArity,B,J,Stack,Collapsables)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

register_binaries(Pid,A,Pre) ->
  register_binaries(Pid,0,array:size(A),Pre,A).
register_binaries(Pid,I,Size,_Pre,_A) when I>=Size ->
  ok;
register_binaries(Pid,I,Size,Pre,A) ->
  Item = array:get(I,A),
  TraceItem = #item{loc=I,item=Item},
  Binaries = binaries(TraceItem),
  Timestamp = element(size(TraceItem),TraceItem),
  lists:foreach
    (fun (Binary) ->
         if
           byte_size(Binary) > 1 ->
             case is_registered(Binary) of
               true -> 
                 ok;
               false ->
                 Register =
                   case Item of
                     {trace_ts, Pid, return_from, _Call, _Value, TimeStamp} ->
                       case call_of_function(Pid,I-1,A) of
                         CallSite when is_integer(CallSite) ->
                           CallItem = 
                             #item{loc=CallSite,item=array:get(CallSite,A)},
                           #binary
                             {
                              pid=Pid,
                              seen=produced,
                              value=Binary,
                              source=CallItem,
                              return=TraceItem,
                              time=TimeStamp
                             };
                         _ ->
                           ?LOG_DEBUG
                             ("~n*** Error: cannot find call corresponding to~n  ~p~n",
                              [TraceItem]),
                           error(bad)
                       end;
                     _ -> 
                       #binary
                         {
                          pid=Pid,
                          seen=consumed,
                          source=TraceItem,
                          time=Timestamp,
                          value=Binary
                         }
                   end,
                 register_binary(Binary,Register,Pre)
             end;
           true -> ok
         end
     end, Binaries),
  register_binaries(Pid,I+1,Size,Pre,A).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

compose_binaries(Traces) ->
  lists:foreach
    (fun ({Binary,Register}) ->
         ?LOG_DEBUG("binary ~p~n",[Register]),
         case is_consumed(Register) orelse is_produced(Register) of
           true ->
             Source = source(Register),
             SourcePid = pid(Register),
             ?LOG_DEBUG("~ntrying to compose binary~n~p~n==~p~n",[Register,Binary]),
             {StartTime,EndTime} = 
               case is_produced(Register) of
                 true -> {loc(Source),loc(return(Register))};
                 _ -> call_limits(SourcePid,loc(Source),Traces)
               end,
               case lists:keyfind(SourcePid,1,Traces) of
                 false ->
                   io:format
                     ("~n*** Error: cannot find SourcePid ~p (from ~p) in traces???~n",
                      [SourcePid,Register]),
                   error(bad);
                 _ -> ok
               end,
             {_,A} = lists:keyfind(SourcePid,1,Traces),
             PreContextBinaries = 
               lists:usort(defined_in_call(SourcePid,StartTime,EndTime,A)),
             ?LOG_DEBUG("num of precontextbinaries is ~p~n",
                       [length(PreContextBinaries)]),
             FirstTimeSeen =
               case is_consumed(Register) of
                 true ->
                   loc(Source);
                 false ->
                   loc(return(Register))
               end,
             ContextBinaries =
               lists:filter
                 (fun ({_Binary,BinaryRegister}) ->
                      case is_produced(BinaryRegister) of
                        true ->
                          loc(source(BinaryRegister)) =< FirstTimeSeen;
                        false ->
                          true
                      end
                  end, PreContextBinaries),
             ?LOG_DEBUG
               ("number of binaries is ~p:~n~p~n~n",
                [length(ContextBinaries),ContextBinaries]),
             ?LOG_DEBUG
               ("Limits ~p~n",
                [{StartTime,EndTime}]),
             case rewriteTo(Binary,ContextBinaries) of
               false ->
                 case is_consumed(Register) of
                   true ->
                     ?LOG_DEBUG
                       ("~n*** Warning: the binary~n~p~nis not explainable"
                        ++" from the context~n~p~n",
                        [Binary,ContextBinaries]);
                   false -> ok
                 end;
               Sol ->
                 update_binary
                   (Binary,
                    Register#binary
                    {seen=rewrite,
                     name=name(Register),
                     source=Source,
                     value=Sol})
             end;
           _ -> ok
         end
     end, registers()).

registered_binaries(Term) ->
  lists:foldl
    (fun (Binary,Acc) ->
         case get_binary(Binary) of
           undefined -> Acc;
           Register -> [{Binary,Register}|Acc]
         end
     end, [], binaries(Term)).

defined_in_call(Pid,FromTime,ToTime,A) ->
  Size = array:size(A),
  if
    (FromTime > ToTime) or (ToTime > Size) ->
      ?LOG_DEBUG
        ("~n*** Error: incorrect parameters ~p -> ~p when ~p~n",
         [FromTime,ToTime,Size]),
      error(bad);
    true -> ok
  end,
  defined_in_call(Pid,FromTime,ToTime,-1,array:size(A),A).
defined_in_call(Pid,FromTime,ToTime,Skip,Size,A) ->
  if
    FromTime > ToTime ->
      ?LOG_DEBUG
        ("~n*** Error: defined_in_call(~p,~p)~n",
         [FromTime,ToTime]),
      error(bad);
    true -> ok
  end,
  Item = array:get(FromTime,A),
  case Item of
    {trace_ts, Pid, return_from, _, _, _} ->
      if 
        Skip =< 0 ->
          registered_binaries(Item);
        Skip == 1 ->
          registered_binaries(Item) ++ defined_in_call(Pid,FromTime+1,ToTime,Skip-1,Size,A);
        true ->
          defined_in_call(Pid,FromTime+1,ToTime,Skip-1,Size,A)
      end;
    {trace_ts, Pid, exception_from, _, _, _} ->
      if 
        Skip =< 0 ->
          registered_binaries(Item);
        Skip == 1 ->
          registered_binaries(Item) ++ defined_in_call(Pid,FromTime+1,ToTime,Skip-1,Size,A);
        true ->
          defined_in_call(Pid,FromTime+1,ToTime,Skip-1,Size,A)
      end;
    {trace_ts, Pid, call, _, _} ->
      if 
        Skip =< 0 ->
          registered_binaries(Item) ++ defined_in_call(Pid,FromTime+1,ToTime,Skip+1,Size,A);
        true ->
          defined_in_call(Pid,FromTime+1,ToTime,Skip+1,Size,A)
      end;
    _ ->
      if 
        Skip =< 0 ->
          registered_binaries(Item) ++ defined_in_call(Pid,FromTime+1,ToTime,Skip,Size,A);
        true ->
          defined_in_call(Pid,FromTime+1,ToTime,Skip,Size,A)
      end
  end.

call_to(Item,_MFA,[]) ->
  ?LOG_DEBUG
    ("~n*** Error: call ~p~nwithout return~n",
     [Item]),
  error(bad);
call_to(Item,MFA,Skip=[{Item2,MFA1}|Rest]) ->
  if
    MFA =/= MFA1 ->
      ?LOG_DEBUG
        ("~n*** Warning: calling ~p~nto wrong return ~p~n",
         [Item,Item2]),
      Skip;
      %%error(bad);
    true ->
      Rest
  end.

return_from(Item,_MFA,[]) ->
  ?LOG_DEBUG
    ("~n*** Error: return ~p~nwithout call~n",
     [Item]),
  error(bad);
return_from(Item,MFA,Skip=[{Item2,MFA1}|Rest]) ->
  if
    MFA =/= MFA1 ->
      ?LOG_DEBUG
        ("~n*** Warning: returning ~p~nto wrong call ~p~n",
         [Item,Item2]),
      Skip;
      %%error(bad);
    true ->
      Rest
  end.

return_of_function(Pid,I,A) ->
  return_of_function(Pid,I,[],array:size(A),A).
return_of_function(_Pid,I,Skip,Size,_A) when I>=Size ->
  ?LOG_DEBUG
    ("~n*** Warning: could not find return loc, skip:~n~p~n",
     [Skip]),
  Size-1;
return_of_function(Pid,I,Skip,Size,A) ->
  Item = array:get(I,A),
  case Item of
    {trace_ts, Pid, return_from, MFA, _, _} ->
      if
        Skip == [] -> 
          I;
        true -> 
          return_of_function(Pid,I+1,return_from(Item,MFA,Skip),Size,A)
      end;
    {trace_ts, Pid, exception_from, MFA, _, _} ->
      if
        Skip == [] -> 
          I;
        true -> 
          return_of_function(Pid,I+1,return_from(Item,MFA,Skip),Size,A)
      end;
    {trace_ts, Pid, call, {M,F,Args}, _} ->
      return_of_function(Pid,I+1,[{Item,{M,F,length(Args)}}|Skip],Size,A);
    _ ->
      return_of_function(Pid,I+1,Skip,Size,A)
  end.

call_of_function(Pid,I,A) ->
  call_of_function(Pid,I,[],array:size(A),A).
call_of_function(_Pid,-1,Skip,Size,_A) ->
  ?LOG_DEBUG
    ("~n*** Warning: could not find call loc, skip:~n~p~n",
     [Skip]),
  Size-1;
call_of_function(Pid,I,Skip,Size,A) ->
  Item = array:get(I,A),
  %%?LOG_DEBUG("~p: cof(~p,~p)~n",[I,Skip,Item]),
  case Item of
    {trace_ts, Pid, call, {M,F,Args}, _} ->
      if
        Skip == [] -> I;
        true -> call_of_function(Pid,I-1,call_to(Item,{M,F,length(Args)},Skip),Size,A)
      end;
    {trace_ts, Pid, return_from, MFA, _, _} ->
      call_of_function(Pid,I-1,[{Item,MFA}|Skip],Size,A);
    {trace_ts, Pid, exception_from, MFA, _, _} ->
      call_of_function(Pid,I-1,[{Item,MFA}|Skip],Size,A);
    _ ->
      call_of_function(Pid,I-1,Skip,Size,A)
  end.

call_limits(Pid,I,Traces) ->
  {_,A} = lists:keyfind(Pid,1,Traces),
  CallSite = call_of_function(Pid,I-1,A), 
  ReturnSite = return_of_function(Pid,I,A),
  ?LOG_DEBUG("call_limits(~p) = {~p,~p}~n",[I,CallSite,ReturnSite]),
  ?LOG_DEBUG
    ("pos=~p~nCallsite=~p~nReturnsite=~p~n",
     [array:get(I,A),array:get(CallSite,A),array:get(ReturnSite,A)]),
  {CallSite,ReturnSite}.
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% signal_extract:analyze_trace_file("enoise.trace").

gen_tcp_sends(Traces,NF) ->
  lists:foldr
    (fun ({Pid,Trace},{Terms,{Bs,Cnt}}) ->
         {NTerms,Arg} = gen_tcp_send_collect(Trace,NF,Bs,Cnt),
         {[{Pid,NTerms}|Terms],Arg}
     end, {[], {[],[]}}, Traces).

read_messages(Traces,NF,Bs,Cnt) ->
  lists:foldr
    (fun ({Pid,Trace},{Terms,{Bs,Cnt}}) ->
         {NTerms,Arg} = read_messages_collect(Trace,NF,Bs,Cnt),
         {NTerms++Terms,Arg}
     end, {[], {Bs,Cnt}}, Traces).


sends(Traces,NF) ->
  lists:foldr
    (fun ({Pid,Trace},{Terms,{Bs,Cnt}}) ->
         {NTerms,Arg} = send_collect(Trace,NF,Bs,Cnt),
         {NTerms++Terms,Arg}
     end, {[], {[],[]}}, Traces).

read_messages_collect(Trace,NF,BsP,CntP) ->
  collect_at_event
    (fun (_Time,Event) -> 
         case Event of
           {trace_ts,_,return_from,{enoise_hs_state,read_message,2},_,_} -> true;
           _ -> false
         end
     end, 
     Trace,
     fun ({ok,_,Payload},Time,{Bs,Cnt},_,_) ->
         ?LOG_DEBUG("~nwill expand ~p~n",[Payload]),
         {PayloadTerm,NewBinaries,NewCounter} = expand_term(Payload,Bs,Cnt,NF),
         ?LOG_DEBUG("~npayload ~p~n",[PayloadTerm]),
         {PayloadTerm,{NewBinaries,NewCounter}}
     end,
     {BsP,CntP}).

gen_tcp_send_collect(Trace,NF,BsP,CntP) ->
  collect_at_event
    (fun (_Time,Event) -> 
         case Event of
           {trace_ts,_,call,{gen_tcp,send,_},_} -> true;
           _ -> false
         end
     end, 
     Trace,
     fun (Call,Time,{Bs,Cnt},_,_) ->
         ?LOG_DEBUG("~nwill expand ~p~n",[Call]),
         {ExpandedCall={_M,_F,Args},NewBinaries,NewCounter} = 
           expand_term(Call,Bs,Cnt,NF),
         ?LOG_DEBUG("~nsent ~p~n",[Args]),
         {Args,{NewBinaries,NewCounter}}
     end,
     {BsP,CntP}).

send_collect(Trace,NF,BsP,CntP) ->
  collect_at_event
    (fun (_Time,Event) -> 
         case Event of
           {trace_ts,_,call,{enoise,gen_tcp_snd_msg,_},_} -> true;
           _ -> false
         end
     end, 
     Trace,
     fun (Call,Time,{Bs,Cnt},_,_) ->
         ?LOG_DEBUG("~nwill expand ~p~n",[Call]),
         {ExpandedCall={_M,_F,Args},NewBinaries,NewCounter} = 
           expand_term(Call,Bs,Cnt,NF),
         {Args,{NewBinaries,NewCounter}}
     end,
     {BsP,CntP}).

collect_at_event(EventRecognizer,A,F,Arg) ->
  collect_at_event(EventRecognizer,0,array:size(A),A,F,Arg).
collect_at_event(_EventRecognizer,I,Size,_A,_F,Arg) when I>=Size ->
  {[],Arg};
collect_at_event(EventRecognizer,I,Size,A,F,Arg) ->
  Event = array:get(I,A),
  case EventRecognizer(I,Event) of
    true ->
      {Result,NewArg} = 
        case Event of
          {trace_ts,_,call,Call,_} ->
            F(Call,I,Arg,Size,A);
          {trace_ts,_,return_from,_,FunResult,_} ->
            F(FunResult,I,Arg,Size,A)
        end,
      {Results,NewerArg} = 
        collect_at_event(EventRecognizer,I+1,Size,A,F,NewArg),
      {[Result | Results], NewerArg};
    false ->
      collect_at_event(EventRecognizer,I+1,Size,A,F,Arg)
  end.
  
%% Expands a term with binaries inside, substituting binaries for
%% the function calls that generated them. 
%% Generates variables {var,X} corresponding 
%% to calls of non-deterministic functions.
%% Returns an expanded term and a set of variable definitions.
%%
%% NF == [{M,F,Arity}] listing "non-functional" functions, i.e.,
%% functions with side effects.
%% These include, for instance, functions to generate new keypairs (from nothing).
expand_term(T,Binaries,Counter,NF) ->
  ?LOG_DEBUG("expand_term(~p)~n",[T]),
  case lists:keyfind(T,1,Binaries) of
    {_T, Value} ->
      {Value, Binaries, Counter};
    false ->
      case T of
        {M,F,Args} when is_atom(M), is_atom(F), is_list(Args) ->
          {RewrittenArgs,NewBinaries,NewCounter} =
            lists:foldr
              (fun (Arg,{AccArgs,NBs,Cnt}) ->
                   {RArg,NB1,Cnt1} = expand_term(Arg,NBs,Cnt,NF),
                   {[RArg|AccArgs],NB1,Cnt1}
               end, {[],Binaries,Counter}, Args),
          MFArity = {M,F,length(Args)},
          case lists:member(MFArity,NF) of
            true -> 
              {CounterArg,NewerCounter} = get_mfa_counter(MFArity,NewCounter),
              NewRewrittenMFA = {M,F,RewrittenArgs++[CounterArg]},
              {
                NewRewrittenMFA,
                [{T,NewRewrittenMFA}|NewBinaries], 
                NewerCounter
              };

            false -> 
              {
              {M,F,RewrittenArgs},
              NewBinaries, 
              NewCounter}
            end;
        _ when is_binary(T) ->
          Register = get_binary(T),
          if
            Register == undefined ->
              {T,Binaries,Counter};
            true ->
              case binary_type(Register) of
                rewrite ->
                  expand_term(value(Register),Binaries,Counter,NF);
                produced ->
                  case item(source(Register)) of
                    {trace_ts, _, call, Call, _} ->
                      Return = 
                        case item(return(Register)) of
                          {trace_ts,_,return_from,_,R,_} -> R
                        end,
                      CallAndReturn = extract_return_value(T,Return,Call),
                      true = (CallAndReturn =/= false),
                      if
                        CallAndReturn=/=Call ->
                          ?LOG_DEBUG
                            ("Extractor=~p~n",
                             [CallAndReturn]);
                        true -> ok
                      end,
                      expand_term(CallAndReturn,Binaries,Counter,NF)
                  end;
                _ -> {T, Binaries, Counter}
              end
          end;
        _ when is_list(T) ->
          expand_terms(T,Binaries,Counter,NF);
        _ when is_tuple(T) ->
          {Result,NewBinaries,NewCounter} = expand_terms(tuple_to_list(T),Binaries,Counter,NF),
          {list_to_tuple(Result),NewBinaries,NewCounter};
        _ ->
          {T,Binaries,Counter}
      end
  end.

get_mfa_counter(MFA,Counters) ->
  case lists:keyfind(MFA,1,Counters) of
    false ->
      {0,[{MFA,1}|Counters]};
    {_,Counter} ->
      {Counter,lists:keyreplace(MFA,1,Counters,{MFA,Counter+1})}
  end.

expand_terms([],Binaries,Counter,_NF) ->
  {[],Binaries,Counter};
expand_terms([Hd|Tl],Binaries,Counter,NF) ->
  {RHd,NB1,Cnt1} = expand_term(Hd,Binaries,Counter,NF),
  {RTl,NB2,Cnt2} = expand_term(Tl,NB1,Cnt1,NF),
  {[RHd|RTl],NB2,Cnt2}.

extract_return_value(B,B,Call) ->
  Call;
extract_return_value(B,Tuple,Call) when is_tuple(Tuple) ->
  extract_return_value_from_tuple(B,tuple_to_list(Tuple),Call);
extract_return_value(B,[Hd|Tl],Call) ->
  case extract_return_value(B,Hd,Call) of
    false ->
      case extract_return_value(B,Tl,Call) of
        Extractor when is_tuple(Extractor) ->
          {erlang, tl, [Extractor]};
        false ->
          false
      end;
    Extractor ->
      {erlang, hd, [Extractor]}
  end;
extract_return_value(B,Map,Call) when is_map(Map) ->
  List = maps:to_list(Map),
  case lists:keyfind(B,2,List) of
    false -> false;
    {Key,_} -> {maps,get,[Key,Call]}
  end;
extract_return_value(_B,_Term,_Call) ->
  false.

extract_return_value_from_tuple(B,L,Call) when is_list(L) ->
  extract_return_value_from_tuple(B,1,L,Call).
extract_return_value_from_tuple(_B,_I,[],_Call) ->
  false;
extract_return_value_from_tuple(B,I,[First|Rest],Call) ->
  case extract_return_value(B,First,Call) of
    false ->
      extract_return_value_from_tuple(B,I+1,Rest,Call);
    Extractor ->
      {erlang, element, [I,Extractor]}
  end.

print_call({_,F,Args}) ->
  %%?LOG_DEBUG("~p(~p)~n",[F,Args]),
  io_lib:format("~p(~s)",[F,print_args(Args)]).

print_full_call({M,F,Args}) ->
  io_lib:format("~p:~p(~s)",[M,F,print_args(Args)]).

print_args([]) ->
  "";
print_args([P]) ->
  print_arg(P);
print_args([P|Rest]) ->
  io_lib:format("~s,~s",[print_arg(P),print_args(Rest)]).

print_arg(MFA = {M,F,Args}) when is_atom(M), is_atom(F), is_list(Args) ->
  print_call(MFA);
print_arg(Term) ->
  io_lib:format("~p",[Term]).

extract_call({trace_ts,_,call,Call,_}) ->
  Call.
extract_return({trace_ts,_,return_from,_,Value,_}) ->
  Value.

graphviz_traceback(Filename,Traceback,N,PredefinedBinaries,Counter,NF) ->
  {{ECall0,SCall0,_Time},NTrace} = lists:nth(N,Traceback),
  CallInitState = 
    {[],{state,1,ECall0,SCall0}},
  PredefinedInitState =
    {lists:map(fun ({_,Name}) -> Name end, PredefinedBinaries), 
     {state, 0, {init,predefined,[]}, {init,predefined,[]}}},
  {States,_} =
    lists:foldl
      (fun ({call, _Time, ECall, SCall, _Return, _Consumed, Produced}, Acc={S,I}) ->
           if
             Produced=/=[] ->
               {[{Produced,{state,I,ECall,SCall}}|S], I+1};
             true ->
               Acc
           end
       end, {[CallInitState,PredefinedInitState],2}, NTrace),
  Transitions = 
    lists:foldl
      (fun ({_,{state,I,_,TCall}}, T) ->
           lists:flatmap
             (fun (Binary) -> make_transition(I, Binary, States) end,
              element(2,expand_term(TCall,[],Counter,NF))) ++ T
       end, [], States),
  {ok,F} = file:open(Filename,[write]),
  ?LOG_DEBUG(F,"digraph example {\n",[]),
  lists:foreach(fun ({_,{state,I,{_,Fun,_},_}}) ->
                    if
                      I=/=0 -> 
                        ?LOG_DEBUG(F,"s~p [label=\"~p\"];~n",[I,Fun]);
                      true ->
                        ok
                    end
                end, States),
  lists:foreach(fun ({From,Binary,To}) ->
                    ?LOG_DEBUG(F,"s~p -> s~p [label=\"~p\"]~n",[From,To,Binary])
                end, Transitions),
  ?LOG_DEBUG(F,"}\n",[]),
  file:close(F).

make_transition(From,Binary,States) ->
  case get_binary(Binary) of
    undefined -> 
      [];
    Register ->
      Name = name(Register),
      case find_binary(Name,States) of
        false ->
          [];
        {state,0,_,_} ->
          [{From,Name,From}];
        {state,I,_,_} ->
          [{I,Name,From}]
      end
  end.

find_binary(_,[]) ->
  false;
find_binary(Binary,[{Binaries,State}|Rest]) ->
  case lists:member(Binary,Binaries) of
    true -> State;
    _ -> find_binary(Binary,Rest)
  end.
      
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

is_registered(Binary) ->
  signal_extract_utils:get(Binary) =/= undefined.

register_binary(Binary,Reg,Pre) ->
  case get_binary(Binary) of
    OldReg when is_record(OldReg,binary) ->
      RegType = binary_type(Reg),
      OldRegType = binary_type(OldReg),
      RegTime = binary_time(Reg),
      OldRegTime = binary_time(OldReg),
      IsRegOlder = timer:now_diff(RegTime,OldRegTime) =< 0,
      if
        OldRegType==consumed, IsRegOlder ->
          signal_extract_utils:put(Binary,Reg#binary{name=OldReg#binary.name});
        OldRegType==produced, IsRegOlder ->
          ?LOG_DEBUG
            ("~n*** Warning: item ~p~nconsumed before produced:~n~p~n",
             [OldReg,Reg]),
          error(bad);
        true ->
          ok
      end;
    undefined ->
      Name =
        case lists:keyfind(Binary,1,Pre) of
          false ->
            PreviousCounter =
              case signal_extract_utils:get(counter) of
                undefined -> 0;
                N -> N
              end,
            signal_extract_utils:put(counter,PreviousCounter+1),
            list_to_atom("Binary"++integer_to_list(PreviousCounter));

          {_,Nickname} -> Nickname
        end,
      signal_extract_utils:put(Binary,Reg#binary{name=Name})
  end.

update_binary(Binary,Register) ->
  case get_binary(Binary) of
    OldRegister when is_record(OldRegister,binary) ->
      signal_extract_utils:put(Binary,Register)
  end.

get_binary(Binary) ->
  signal_extract_utils:get(Binary).

is_produced(Binary) ->
  case binary_type(Binary) of
    produced ->
      true;
    _ ->
      false
  end.
is_consumed(Binary) ->
  case binary_type(Binary) of
    consumed ->
      true;
    _ ->
      false
  end.

pid(#binary{pid=Pid}) ->
  Pid.
binary_type(#binary{seen=Type}) ->
  Type.
binary_time(#binary{time=Timestamp}) ->
  Timestamp.
name(#binary{name=Name}) ->
  Name.
source(#binary{source=Source}) ->
  Source.
return(#binary{return=Return}) ->
  Return.
loc(#item{loc=Loc}) ->
  Loc.
item(#item{item=Item}) ->
  Item.
value(#binary{value=Value}) ->
  Value.

subst_with_register(B) when is_binary(B),  byte_size(B)>0 ->
  case get_binary(B) of
    undefined ->
      B;
    Register ->
      name(Register)
  end;
subst_with_register(Tuple) when is_tuple(Tuple) ->
  list_to_tuple(subst_with_register(tuple_to_list(Tuple)));
subst_with_register([Hd|Tl]) ->
  [subst_with_register(Hd)|subst_with_register(Tl)];
subst_with_register(Map) when is_map(Map) ->
  lists:foldl(fun ({Key,Value},M) ->
                  maps:put(Key,Value,M)
              end, #{}, subst_with_register(maps:to_list(Map)));
subst_with_register(T) ->
  T.

num_sort(Name) ->
  String = atom_to_list(Name),
  case string:str(String,"Binary") of
    0 -> 0;
    _ -> list_to_integer(string:substr(String,7,length(String)-6))
  end.

registers() ->
  lists:sort
    (fun ({_,R1},{_,R2}) ->
         num_sort(name(R1)) < num_sort(name(R2))
     end, 
     lists:filter
       (fun ({counter,_}) -> false; 
            ({{nickname,_},_}) -> false; 
            (_) -> true 
        end, 
        signal_extract_utils:to_list())).

binaries(B) when is_binary(B),  byte_size(B)>0 ->
  [B];
binaries(Tuple) when is_tuple(Tuple) ->
  binaries(tuple_to_list(Tuple));
binaries([Hd|Tl]) ->
  binaries(Hd) ++ binaries(Tl);
binaries(Map) when is_map(Map) ->
  binaries(maps:to_list(Map));
binaries(_) ->
  [].

show_trace(A) ->
  print_array(A,false).

show_registered_trace(A) ->
  print_array(A,true).

print_array(A,WithRegister) ->
  print_array(A,0,array:size(A),WithRegister).
print_array(_,I,Size,_WithRegister) when I>=Size ->
  ok;
print_array(A,I,Size,WithRegister) ->
  ?LOG_DEBUG("~p: ~p~n",[I,subst_with_register(array:get(I,A))]),
  print_array(A,I+1,Size,WithRegister).

print_binary_register() ->
  lists:foreach
    (fun ({Binary,Register}) ->
         Name = name(Register),
         Source = source(Register),
         Time = loc(Source),
         Type = binary_type(Register),
         case Type of
           produced ->
             Return = return(Register),
             ?LOG_DEBUG
               ("~n~p : ~p@~p -- ~p ==> ~n  ~p == ~n  ~w~n",
                [Name,
                 Type,
                 Time,
                 subst_with_register(item(Source)),
                 subst_with_register(item(Return)),
                 Binary]);
           rewrite ->
             ?LOG_DEBUG
               ("~n~p : ~p@~p -- ~p == ~n  ~w~n",
                [Name,
                 Type,
                 Time,
                 subst_with_register(value(Register)),
                 Binary]);
           _ ->
             ?LOG_DEBUG
               ("~n~p : ~p@~p -- ~p == ~n  ~w~n",
                [Name,
                 Type,
                 Time,
                 subst_with_register(item(Source)),
                 Binary])
         end
     end, 
     lists:sort
       (fun ({_,R1},{_,R2}) -> 
            ?LOG_DEBUG("R1=~p~nR2=~p~n",[R1,R2]),
            loc(source(R1)) < loc(source(R2)) 
        end,
        registers())).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

rewriteTo(Binary,Binaries) ->
  rewriteTo
    (Binary,
     Binaries,
     [
      fun merge/2,
      truncate(),
      extract(),
      pad(),
      xor_const(),
      prefix_len()
     ]).

rewriteTo(Binary,Binaries,Operators) ->
  Solutions = 
    lists:flatmap
      (fun (Op) -> 
           case Op(Binary,Binaries) of 
             false -> [];
             Sol -> [Sol] 
           end
       end,
       Operators),
  case Solutions of
    [] -> 
      ?LOG_DEBUG
        ("No explanation found using~n~p~n",
         [Binaries]),
      false;
    [Sol] -> 
      verify_solution(Sol,Binary,Binaries);
    Sols ->
      ?LOG_DEBUG
        ("Multiple solutions found using~n~p~nAlts=~p~n",
         [Binaries,Sols]),
      hd(lists:sort(fun le_rewrites/2,Sols))
end.

verify_solution(Sol={M,F,Args},Binary,Binaries) ->
  case apply(M,F,Args) == Binary of
    true ->
      ArgBinaries = lists:filter(fun is_binary/1, Args),
      StrippedBinaries = lists:map(fun ({B,_}) -> B end, Binaries),
      case lists:all(fun (ArgBinary) -> 
                         lists:member(ArgBinary,StrippedBinaries)
                     end,
                     ArgBinaries) of
        true -> 
          Sol;
        false ->
          ?LOG_DEBUG
            ("~n*** Error: the solution~n  ~p~n contains binaries"
             ++" not available in the context~n  ~p~n",
             [Sol,Binaries]),
          error(bad)
      end;
    false ->
      ?LOG_DEBUG
        ("~n*** Error: rewrite solution~n  ~p~nis not equal to ~p~n",
         [Sol,Binary]),
      error(bad)
  end.

le_rewrites(R1,R2) ->
  R1Type = element(2,R1),
  R2Type = element(2,R2),
  le_type_ord(R1Type) =< le_type_ord(R2Type).

le_type_ord(merge) ->
  1;
le_type_ord(xor_words_with_const) ->
  5;
le_type_ord(pad) ->
  10;
le_type_ord(truncate) ->
  12;
le_type_ord(extract) ->
  15.

unary_rewrite(F) ->
  fun (Binary,Binaries) ->
      unary_rewrite(F,Binary,Binaries)
  end.
unary_rewrite(_F,_Binary,[]) ->
  false;
unary_rewrite(F,Binary,[{First,_}|Rest]) ->
  if
    byte_size(First) >= 4 ->
      case occurs_check(Binary,First) of
        true ->
          case F(Binary,First) of
            false ->
              unary_rewrite(F,Binary,Rest);
            Sol ->
              Sol
          end;
        false -> 
          unary_rewrite(F,Binary,Rest)
      end;
    true -> unary_rewrite(F,Binary,Rest)
  end.
  
binary_rewrite(F) ->
  fun (Binary,Binaries) ->
      binary_rewrite(F,Binary,Binaries)
  end.
binary_rewrite(_F,_Binary,[]) ->
  false;
binary_rewrite(F,Binary,[{First,_}|Rest]) ->
  case binary_rewrite1(F,Binary,First,Rest) of
    false -> 
      binary_rewrite(F,Binary,Rest);
    Sol ->
      Sol
  end.
binary_rewrite1(_F,_Binary,_FirstCandidate,[]) ->
  false;
binary_rewrite1(F,Binary,FirstCandidate,[{First,_}|Rest]) ->
  case F(Binary,FirstCandidate,First) of
    false ->
      binary_rewrite1(F,Binary,FirstCandidate,Rest);
    Sol ->
      Sol
  end.

occurs_check(Binary,Candidate) ->
  if
    Binary==Candidate -> 
      false;
    true ->
      CandidateRegister = get_binary(Candidate),
      ?LOG_DEBUG("reg=~p~n",[CandidateRegister]),
      case (CandidateRegister =/= undefined) 
        andalso binary_type(CandidateRegister)==rewrite of
        true ->
          DefinedUsingBinaries = element(3,value(CandidateRegister)),
          lists:all
            (fun (UsedBinary) -> 
                 occurs_check(Binary,UsedBinary) end, 
             DefinedUsingBinaries);
        _ -> true
      end
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% n-merge
%%
merge(Binary,Binaries) ->
  merge(Binary,Binary,Binaries,Binaries,[]).
merge(_,<<>>,_,_,Match) ->
   {signal_binary_ops,merge,lists:reverse(Match)};
merge(_,_,[],_,_) ->
  false;
merge(OrigBinary,Binary,[{First,_Register}|Rest],Binaries,Match) ->
  case occurs_check(OrigBinary,First) of
    true ->
      case binary:longest_common_prefix([Binary,First]) of
        N when N>1, N==byte_size(First) ->
          RestBinary = binary:part(Binary,{N,byte_size(Binary)-N}),
          merge(OrigBinary,RestBinary,Binaries,Binaries,[First|Match]);
        _ ->
          merge(OrigBinary,Binary,Rest,Binaries,Match)
      end;
    false -> 
      merge(OrigBinary,Binary,Rest,Binaries,Match)
  end.

%% Add the length of a binary as a prefix
%%
prefix_len() ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         if
           byte_size(Candidate)+2==byte_size(Binary) ->
             CandidateWithLen = 
               <<(byte_size(Candidate)):16, Candidate/binary>>,
             if
               Binary==CandidateWithLen ->
                 {signal_binary_ops,prefix_len,[Candidate]};
               true -> false
             end;
           true -> false 
         end
     end).

%% truncate a binary
%%
truncate() ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         BinarySize = byte_size(Binary),
         case binary:longest_common_prefix([Binary,Candidate]) of
           BinarySize ->
             {signal_binary_ops,truncate,[Candidate,BinarySize]};
           _ ->
             false
         end
     end).

%% extract a part of a binary
%%
extract() ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         case binary:match(Candidate,Binary) of
           nomatch ->
             false;
           {From,Length} ->
             {signal_binary_ops,extract,[Candidate,From,Length]}
         end
     end).

%% pad with a symbol
%%
pad() ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         ByteSizeBinary = byte_size(Binary),
         ByteSizeCandidate = byte_size(Candidate),
         RemainingSize = ByteSizeBinary-ByteSizeCandidate,
         if
           RemainingSize > 0 ->
             case binary:longest_common_prefix([Binary,Candidate]) of
               ByteSizeCandidate ->
                 <<Pad:8>> = binary:part(Binary,ByteSizeCandidate,1),
                 MFA = {M,F,Args} = 
                   {signal_binary_ops,pad,[Candidate,Pad,RemainingSize]},
                 case Binary == apply(M,F,Args) of
                   true -> MFA;
                   false -> false
                 end;
               _ -> false
             end;
           true -> false
         end
     end).

%% xor with a symbol (be careful with the difference between words and bytes)
xor_const() ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         if
           byte_size(Binary) == byte_size(Candidate) ->
             FirstBinary = binary:first(Binary),
             FirstCandidate = binary:first(Candidate),
             XorArg = FirstBinary bxor FirstCandidate,
             XorCandidate = 
               << <<(Byte bxor XorArg):8>> || <<Byte:8>> <= Candidate >>,
             if
               Binary == XorCandidate ->
                 {signal_binary_ops, xor_words_with_const, [Candidate,XorArg]};
               true ->
                 false
             end;
           true -> false
         end
     end).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

trace_to_prolog(TraceFile,PrologFile) ->
  {ok,PF} = file:open(PrologFile,[write]),
  {ok,B} = file:read_file(TraceFile),
  {trace,L} = binary_to_term(B),
  lists:foreach
        (fun (Fact) ->
           case Fact of
             {trace_ts, Pid, call, {M,F,A}, TimeStamp} ->
               io:format(PF,"event(~s,call(~s,~s,~s),~s).~n",[to_pid(Pid),value_to_prolog(M),value_to_prolog(F),value_to_prolog(A),timestamp_to_prolog(TimeStamp)]);
             {trace_ts, Pid, return_from, {M,F,Arity}, Value, TimeStamp} ->
               io:format(PF,"event(~s,return_from(~s,~s,~s,~s),~s).~n",[to_pid(Pid),value_to_prolog(M),value_to_prolog(F),value_to_prolog(Arity),value_to_prolog(Value),timestamp_to_prolog(TimeStamp)]);
             {trace_ts, Pid, send, Msg, To, TimeStamp} ->
               io:format(PF,"event(~s,send(~s,~s),~s).~n",[to_pid(Pid),value_to_prolog(Msg),value_to_prolog(To),timestamp_to_prolog(TimeStamp)]);
             {trace_ts, Pid, exception_from, {M,F,Arity}, {Class,Reason}, TimeStamp} ->
               io:format(PF,"event(~s,exception_from(~s,~s,~s,~s,~s),~s).~n",[to_pid(Pid),value_to_prolog(M),value_to_prolog(F),value_to_prolog(Arity),value_to_prolog(Class),value_to_prolog(Reason),timestamp_to_prolog(TimeStamp)]);
             Event ->
               io:format("Cannot translate event ~p yet~n",[Event]),
               error(nyi)
           end
         end, L),
   ok = file:close(PF).
      
value_to_prolog(V) ->
  case V of
    _ when is_pid(V) -> to_pid(V);
    _ when is_port(V) -> io_lib:format("port('~p')",[V]);
    _ when is_map(V) -> io_lib:format("map(~s)",[value_to_prolog(maps:to_list(V))]);
    _ when is_reference(V) -> io_lib:format("reference('~p')",[V]);
    _ when is_function(V) -> io_lib:format("function('~p')",[V]);
    _ when is_binary(V) -> io_lib:format("binary(~s)",[value_to_prolog(binary:bin_to_list(V))]);
    T when is_tuple(T) -> io_lib:format("tuple(~s)",[comma_list(lists:map(fun (E) -> value_to_prolog(E) end, tuple_to_list(T)))]);
    [] -> "[]";
    L when is_list(L) -> io_lib:format("[~s]",[comma_list(lists:map(fun (E) -> value_to_prolog(E) end, L))]);
    _ -> io_lib:format("~p",[V])
  end.

comma_list([]) -> "";
comma_list([Element]) -> Element;
comma_list([First|Rest]) -> First ++ "," ++ comma_list(Rest).

to_pid(P) -> io_lib:format("pid('~p')",[P]).

timestamp_to_prolog({T1,T2,T3}) ->
  io_lib:format("timestamp(~p,~p,~p)",[T1,T2,T3]).

%% signal_extract:trace_to_prolog("enoise.trace","enoise.pl").
