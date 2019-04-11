-module(signal_extract).

-export([noisy_trace/0,register_binaries/2,trace_make_call_deterministic/1]).
-export([get_trace/1,compose_binaries/1,traceback_experiment/2,print_array/2]).
-export([print_binary_register/0,show_trace/1,show_registered_trace/1]).

-compile(export_all).

-export([print_call/1,print_full_call/1]).

%%-define(debug,true).
-ifdef(debug).
-define(LOG(X,Y),
	io:format("~p(~p): ~s",[?MODULE,self(),io_lib:format(X,Y)])).
-else.
-define(LOG(X,Y),true).
-endif.



%% rebar3 as test shell

noisy_trace() ->
  noisy_trace("enoise.trace").

noisy_trace(TraceFileName) ->
  EnoiseModules = 
    [
     enoise, 
     enoise_crypto, 
     enoise_hs_state, enoise_keypair, enoise_protocol, enoise_sym_state, 
     enoise_cipher_state, enoise_connection
    ],
  LoadModules =
    [
     enacl, enacl_nif, unicode_util, gen_tcp, inet_tcp, signal_extract_utils, gen, gen_server,
     enoise_crypto_basics, signal_extract_utils, enoise_xk_test, code, file, base64, io
    ],
  lists:foreach(fun code:ensure_loaded/1, EnoiseModules++LoadModules),
  test
    (
    fun () -> enoise_xk_test:client_test() end, 
    EnoiseModules,
    TraceFileName
   ).

do_trace(TracedPid,ToPid,Modules) ->
  erlang:trace(TracedPid,true,
               [
                %%call,arity,return_to,
                call,
                %% 'receive',send,procs,ports,set_on_spawn, -- better not
                return_to,
                %% set_on_link,
                %%arity,
                %%all,
                timestamp,{tracer,ToPid}
               ]),
  erlang:trace_pattern({'_', '_', '_'}, [{'_', [], [{return_trace}]}], [global]),
  erlang:trace_pattern({enacl_nif, '_', '_'}, false, []),
  lists:foreach
    (fun (Module) -> 
         erlang:trace_pattern({Module, '_', '_'}, [{'_', [], [{return_trace}]}], [local]) 
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
      ?LOG("computed value ~p~n",[Value]), 
      timer:sleep(5000),
      Tracer ! {stop, self(), TraceFileName},
      receive
        {tracer_stopped, Tracer} -> ok
      end
  end.

compute(F,ReportTo) ->
  receive start -> ok end,
  ReturnValue = F(),
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
      ?LOG("Warning: strange message ~p~n",[Other]),
      tracer1(L)
  end.

get_trace(FileName) ->
  {ok,B} = file:read_file(FileName),
  case binary_to_term(B) of
    {trace,L} ->
      array:from_list(L)
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

analyze_trace_file(FileName) ->

  %% Later we should generalise this...
  Trace = get_trace(FileName),
  KeyDir = code:priv_dir(signal_extract)++"/testing_keys",
  ClientPrivKey = get_key("client_key_25519",KeyDir,priv),
  ClientPubKey  = get_key("client_key_25519",KeyDir,pub),
  ServerPubKey  = get_key("server_key_25519",KeyDir,pub),
  Prologue = <<0,8,0,0,3>>,
  
  PredefinedBinaries = 
    [
     {Prologue,'Prologue'},
     {ClientPrivKey,'ClientPriv'},
     {ClientPubKey,'ClientPub'},
     {ServerPubKey,'ServerPub'},
     {erlang:list_to_binary(["Noise","_","XK","_","25519","_","ChaChaPoly","_","BLAKE2b"]),'NoiseProt'}
    ],

  io:format("~n~nDeterminizing trace...~n"),
  DetTrace = trace_make_call_deterministic(Trace),
  
  io:format("~n~nGiving names to binaries (and finding call sites)...~n"),
  register_binaries(DetTrace, PredefinedBinaries),
  
  io:format("~n~nTrying to derive binaries using rewriting...~n"),
  compose_binaries(DetTrace),
  
  io:format("~n~n~nTrace:~n~n"),
  show_registered_trace(DetTrace),
  
  io:format("~n~n~nBinary definitions:~n~n"),
  print_binary_register(),
  
  io:format("~n~n~nTracing back calls to enoise:gen_tcp_send:~n~n"),
  Traceback =
    traceback_calls
      (fun (_Time,Event) -> 
           case Event of
             {trace_ts,_,call,{enoise,gen_tcp_snd_msg,_},_} -> true;
             _ -> false
           end
       end,
       PredefinedBinaries,
       DetTrace),
  traceback_experiment(Traceback,PredefinedBinaries),
  
%%  io:format("~n~n~nGenerating graphviz model:~n~n"),
%%  io:format("Traceback:~n~p~n",
%%            [graphviz_traceback("trace1.dot",Traceback,1,PredefinedBinaries)]),
%%  io:format("Traceback:~n~p~n",
%%            [graphviz_traceback("trace2.dot",Traceback,2,PredefinedBinaries)]),

  Sends = sends(DetTrace),
  [_Port,FirstSend] = lists:nth(1,Sends),
  ?LOG
    ("~n~nThe first send is~n~p~n",
     [FirstSend]),
  FirstSend.

get_key(KeyFileName,KeyDir,Type) ->
  FilePath = KeyDir++"/"++KeyFileName++if Type==priv -> ""; Type==pub -> ".pub" end,
  case file:read_file(FilePath) of
    {ok,Base64Bin} when Type==pub -> 
      base64:decode(Base64Bin);
    {ok,Bin} when Type==priv -> 
      Bin;
    _ ->
      io:format("~n*** Error: could not read key file ~s~n",[FilePath]),
      error(bad)
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
      io:format
        ("~n*** Warning: remaining calls:~n  ~p~n",
         [RemainingCalls]),
      {_,Arr} =
        lists:foldl
          (fun (Call,{Index,Arr}) -> 
               {Index+1,
                array:set(Index,{trace_ts, Pid, return_from, Call, undefined, Ts}, Arr)}
           end, {0,B}, RemainingCalls),
      Arr;
    true -> B
  end;
trace_make_call_deterministic(I,Size,A,B,J,ActiveCalls) ->
  Item = array:get(I,A),
  case Item of
    void ->
      trace_make_call_deterministic(I+1,Size,A,B,J,ActiveCalls);
    {trace_ts, Pid, return_from, Call, _Value, TimeStamp} ->
      case ActiveCalls of
        [{_,Call}|Rest] ->
          NewB = array:set(J,Item,B),
          trace_make_call_deterministic(I+1,Size,A,NewB,J+1,Rest);
        [{OtherI,OtherCall}|_Rest] ->
          io:format
            ("~n*** Error: ~p: returned from ~p but expected return to ~p:~p~n",
             [I,Call,OtherI,OtherCall]),
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
          io:format
            ("~n*** Error: ~p: returned from ~p but there was no active call~n",
             [I,Call]),
          trace_make_call_deterministic(I+1,Size,A,B,J,ActiveCalls)
      end;
    {trace_ts, _Pid, call, {M,F,Args}, _} ->
      NewB = array:set(J,Item,B),
      trace_make_call_deterministic
        (I+1,Size,A,NewB,J+1,
         [{I,{M,F,length(Args)}}|ActiveCalls]);
    _ ->
      NewB = array:set(J,Item,B),
      trace_make_call_deterministic(I+1,Size,A,NewB,J+1,ActiveCalls)
  end.

delete_call(Call,[]) ->    
  io:format
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

register_binaries(A,Pre) ->
  register_binaries(0,array:size(A),Pre,A).
register_binaries(I,Size,_Pre,_A) when I>=Size ->
  ok;
register_binaries(I,Size,Pre,A) ->
  TraceItem = array:get(I,A),
  Binaries = binaries(TraceItem),
  lists:foreach
    (fun (Binary) ->
         if
           byte_size(Binary) > 1 ->
             case is_registered(Binary) of
               true -> 
                 ok;
               false ->
                 Register =
                   case TraceItem of
                     {trace_ts, Pid, return_from, _Call, _Value, _TimeStamp} ->
                       case call_of_function(Pid,I-1,A) of
                         CallSite when is_integer(CallSite) ->
                           CallItem = array:get(CallSite,A),
                           {produced,{CallSite,CallItem},{I,TraceItem}};
                         _ ->
                           io:format
                             ("~n*** Error: cannot find call corresponding to~n  ~p~n",
                              [TraceItem]),
                           error(bad)
                       end;
                     _ -> {consumed,{I,TraceItem}}
                   end,
                 register_binary(Binary,Register,Pre)
             end;
           true -> ok
         end
     end, Binaries),
  register_binaries(I+1,Size,Pre,A).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

compose_binaries(A) ->
  lists:foreach
    (fun ({Binary,Register}) ->
         case is_consumed(Register) orelse is_produced(Register) of
           true ->
             Source = source(Register),
             Pid = pid(item(Source)),
             ?LOG("~ntrying to compose binary~n~p~n==~p~n",[Register,Binary]),
             {StartTime,EndTime} = 
               case is_produced(Register) of
                 true -> {time(Source),time(return(Register))};
                 _ -> call_limits(Pid,time(Source),A)
               end,
             PreContextBinaries = 
               lists:usort(defined_in_call(Pid,StartTime,EndTime,A)),
             FirstTimeSeen =
               case is_consumed(Register) of
                 true ->
                   time(Source);
                 false ->
                   time(return(Register))
               end,
             ContextBinaries =
               lists:filter
                 (fun ({_Binary,BinaryRegister}) ->
                      case is_produced(BinaryRegister) of
                        true ->
                          time(source(BinaryRegister)) =< FirstTimeSeen;
                        false ->
                          true
                      end
                  end, PreContextBinaries),
             ?LOG
               ("number of binaries is ~p:~n~p~n~n",
                [length(ContextBinaries),ContextBinaries]),
             ?LOG
               ("Limits ~p~n",
                [{StartTime,EndTime}]),
             case rewriteTo(Binary,ContextBinaries) of
               false ->
                 case is_consumed(Register) of
                   true ->
                     io:format
                       ("~n*** Warning: the binary~n~p~nis not explainable"
                        ++" from the context~n~p~n",
                        [Binary,ContextBinaries]);
                   false -> ok
                 end;
               Sol ->
                 update_binary(Binary,{rewrite,{time(Source),Sol}})
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
  defined_in_call(Pid,FromTime,ToTime,-1,array:size(A),A).
defined_in_call(Pid,FromTime,ToTime,Skip,Size,A) ->
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
  io:format
    ("~n*** Error: call ~p~nwithout return~n",
     [Item]),
  error(bad);
call_to(Item,MFA,Skip=[{Item2,MFA1}|Rest]) ->
  if
    MFA =/= MFA1 ->
      io:format
        ("~n*** Warning: calling ~p~nto wrong return ~p~n",
         [Item,Item2]),
      Skip;
      %%error(bad);
    true ->
      Rest
  end.

return_from(Item,_MFA,[]) ->
  io:format
    ("~n*** Error: return ~p~nwithout call~n",
     [Item]),
  error(bad);
return_from(Item,MFA,Skip=[{Item2,MFA1}|Rest]) ->
  if
    MFA =/= MFA1 ->
      io:format
        ("~n*** Warning: returning ~p~nto wrong call ~p~n",
         [Item,Item2]),
      Skip;
      %%error(bad);
    true ->
      Rest
  end.

return_of_function(Pid,I,A) ->
  return_of_function(Pid,I,[],array:size(A),A).
return_of_function(_Pid,I,_Skip,Size,_A) when I>=Size ->
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
    {trace_ts, Pid, call, {M,F,Args}, _} ->
      return_of_function(Pid,I+1,[{Item,{M,F,length(Args)}}|Skip],Size,A);
    _ ->
      return_of_function(Pid,I+1,Skip,Size,A)
  end.

call_of_function(Pid,I,A) ->
  call_of_function(Pid,I,[],array:size(A),A).
call_of_function(_Pid,-1,_Skip,Size,_A) ->
  Size-1;
call_of_function(Pid,I,Skip,Size,A) ->
  Item = array:get(I,A),
  %%io:format("~p: cof(~p,~p)~n",[I,Skip,Item]),
  case Item of
    {trace_ts, Pid, call, {M,F,Args}, _} ->
      if
        Skip == [] -> I;
        true -> call_of_function(Pid,I-1,call_to(Item,{M,F,length(Args)},Skip),Size,A)
      end;
    {trace_ts, Pid, return_from, MFA, _, _} ->
      call_of_function(Pid,I-1,[{Item,MFA}|Skip],Size,A);
    _ ->
      call_of_function(Pid,I-1,Skip,Size,A)
  end.

call_limits(Pid,I,A) ->
  CallSite = call_of_function(Pid,I-1,A), 
  ReturnSite = return_of_function(Pid,I,A),
  ?LOG("call_limits(~p) = {~p,~p}~n",[I,CallSite,ReturnSite]),
  {CallSite,ReturnSite}.
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% signal_extract:analyze_trace_file("enoise.trace").

sends(Trace) ->
  collect_at_calls
    (fun (_Time,Event) -> 
         case Event of
           {trace_ts,_,call,{enoise,gen_tcp_snd_msg,_},_} -> true;
           _ -> false
         end
     end, 
     Trace,
     fun (Call,Time,_,_) ->
         {ExpandedCall={_M,_F,Args},NewBinaries} = expand_term(Call,[]),
         Args
     end).

traceback_calls(EventRecognizer,Predefs,A) ->
  collect_at_calls
    (EventRecognizer,A,
     fun (Call,Time,_,_) -> 
         {ExpandedCall={_M,_F,Args},NewBinaries} = expand_term(Call,[]),
         ?LOG("~nResult:~n~p~n~n",[Args]),
         {{ExpandedCall,Call,Time},trace_back_binaries(NewBinaries,Predefs,[])}
     end).

collect_at_calls(EventRecognizer,A,F) ->
  collect_at_calls(EventRecognizer,0,array:size(A),A,F).
collect_at_calls(_EventRecognizer,I,Size,_A,_F) when I>=Size ->
  [];
collect_at_calls(EventRecognizer,I,Size,A,F) ->
  Event = array:get(I,A),
  Results = collect_at_calls(EventRecognizer,I+1,Size,A,F),
  case EventRecognizer(I,Event) of
    true ->
      {trace_ts,_,call,Call,_} = Event,
      [F(Call,I,Size,A) | Results];
    false ->
      Results
  end.
  
trace_back_binaries([],_Predefs,_Seen) ->
  [];
trace_back_binaries([Binary|Binaries],Predefs,Seen) ->
  case lists:keyfind(Binary,1,Predefs) of
    {_,_} -> 
      trace_back_binaries(Binaries,Predefs,Seen);
    false -> 
      Register = get_binary(Binary),
      if
        Register == undefined -> 
          trace_back_binaries(Binaries,Predefs,Seen);
        true ->
          Name = name(Register),
          case lists:member(Name,Seen) of
            true -> 
              trace_back_binaries(Binaries,Predefs,Seen);
            false ->
              case binary_type(Register) of
                rewrite ->
                  trace_back_binaries(Binaries,Predefs,Seen);
                _ ->
                  Time = 
                    time(source(Register)),
                  {Consumed,Produced} = 
                    binaries_located_at(Time,Predefs),
                  MFA = {M,F,Args} = 
                    extract_call(item(source(Register))),
                  {ExpandedArgs,NewBinaries} = 
                    expand_terms(Args,Binaries),
                  Return = 
                    subst_with_register(extract_return(item(return(Register)))),
                  Item =
                    {
                    'call', 
                    Time, 
                    {M,F,ExpandedArgs}, 
                    MFA,
                    subst_with_register(Return),
                    Consumed, 
                    Produced
                   },
                  NewSeen = Consumed ++ Produced ++ Seen,
                  [Item|trace_back_binaries(NewBinaries,Predefs,NewSeen)]
              end
          end
      end
  end.

binaries_located_at(Time,Predefs) ->
  lists:foldl
    (fun ({Binary,Register},Acc={Cons,Prod}) ->
         case Time==time(source(Register)) of
           true ->
             case lists:keyfind(Binary,1,Predefs) of
               false ->
                 Name = name(Register),
                 Type = binary_type(Register),
                 ?LOG("time ~p: name=~p type=~p ~n",[Time,Name,Type]),
                 case Type of
                   consumed ->
                     {[Name|Cons],Prod};
                   produced ->
                     {Cons,[Name|Prod]};
                   _ ->
                     Acc
                 end;
               true -> Acc
             end;
           false -> Acc
         end
     end, {[],[]}, registers()).

expand_terms([],Binaries) ->
  {[],Binaries};
expand_terms([Hd|Tl],Binaries) ->
  {RHd,NB1} = expand_term(Hd,Binaries),
  {RTl,NB2} = expand_term(Tl,NB1),
  {[RHd|RTl],NB2}.

expand_term(T,Binaries) ->
  case T of
    {M,F,Args} when is_atom(M), is_atom(F), is_list(Args) ->
      {RewrittenArgs,NewBinaries} =
        lists:foldr
          (fun (Arg,{AccArgs,NBs}) ->
               {RArg,NB1} = expand_term(Arg,NBs),
               {[RArg|AccArgs],NB1}
           end, {[],Binaries}, Args),
      {{M,F,RewrittenArgs},NewBinaries};
    _ when is_binary(T) ->
      Register = get_binary(T),
      if
        Register == undefined ->
          {T,Binaries};
        true ->
          case binary_type(Register) of
            rewrite ->
              expand_term(item(source(Register)),Binaries);
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
                      io:format
                        ("Extractor=~p~n",
                         [CallAndReturn]);
                    true -> ok
                  end,
                  expand_term(CallAndReturn,Binaries)
              end;
            _ ->
              {name(Register),[T|Binaries]}
          end
      end;
    _ when is_list(T) ->
      expand_terms(T,Binaries);
    _ when is_tuple(T) ->
      {Result,NewBinaries} = expand_terms(tuple_to_list(T),Binaries),
      {list_to_tuple(Result),NewBinaries};
    _ ->
      {T,Binaries}
  end.

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
  %%io:format("~p(~p)~n",[F,Args]),
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

traceback_experiment(Traceback,_PredefinedBinaries) ->
  lists:foreach
    (fun ({{OriginatingCall,_,_Time},VariableTrace}) ->
         io:format
           ("~n~n------------------------------------------------------~n"),
         io:format
           ("Starting with ~p:~n~n",[OriginatingCall]),
         lists:foreach
           (fun ({call, Time, Call, _, Return, Consumed, Produced}) ->
                CallString = print_full_call(Call),
                ReturnStr = 
                  if
                    is_atom(Return) -> "";
                    true -> io_lib:format("  returned as ~p~n",[Return])
                  end,
                ConsumedStr = 
                  if
                    Consumed==[] -> "";
                    true -> io_lib:format("  consumed binaries: ~p~n",[Consumed])
                  end,
                ProducedStr =
                  case Produced of
                    [] -> "";
                    [Binary] -> atom_to_list(Binary) ++ " = ";
                    Binaries -> io_lib:format("~p <- ",[Binaries])
                  end,
                io:format
                  ("~s~s at time ~p~n~s~s~n",
                   [ProducedStr,CallString,Time,ConsumedStr,ReturnStr])
            end, VariableTrace)
     end, Traceback).

graphviz_traceback(Filename,Traceback,N,PredefinedBinaries) ->
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
              element(2,expand_term(TCall,[]))) ++ T
       end, [], States),
  {ok,F} = file:open(Filename,[write]),
  io:format(F,"digraph example {\n",[]),
  lists:foreach(fun ({_,{state,I,{_,Fun,_},_}}) ->
                    if
                      I=/=0 -> 
                        io:format(F,"s~p [label=\"~p\"];~n",[I,Fun]);
                      true ->
                        ok
                    end
                end, States),
  lists:foreach(fun ({From,Binary,To}) ->
                    io:format(F,"s~p -> s~p [label=\"~p\"]~n",[From,To,Binary])
                end, Transitions),
  io:format(F,"}\n",[]),
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

register_binary(Binary,Type,Pre) ->
  case is_registered(Binary) of
    true -> ok;
    false ->
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
      signal_extract_utils:put(Binary,{Name,Type})
  end.

update_binary(Binary,Type) ->
  case get_binary(Binary) of
    Register ->
      signal_extract_utils:put(Binary,{name(Register),Type})
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

name({Name,_}) ->
  Name.
source({_,{produced,Source,_}}) ->
  Source;
source({_,{_,Source}}) ->
  Source.
return({_,{produced,_,Return}}) ->
  Return.
binary_type({_,{Type,_,_}}) ->
  Type;
binary_type({_,{Type,_}}) ->
  Type;
binary_type({_,Type}) ->
  Type.
time({Time,_}) ->
  Time.
item({_,Item}) ->
  Item.
sol_type({_,Type,_}) ->
  Type.
sol_args({_,_,Args}) ->
  Args.

pid(Tuple) when element(1,Tuple) == trace_ts ->
  element(2,Tuple).

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
  io:format("~p: ~p~n",[I,subst_with_register(array:get(I,A))]),
  print_array(A,I+1,Size,WithRegister).

print_binary_register() ->
  lists:foreach
    (fun ({Binary,Register}) ->
         Name = name(Register),
         Source = source(Register),
         Time = time(Source),
         Type = binary_type(Register),
         case Type of
           produced ->
             Return = return(Register),
             io:format
               ("~n~p : ~p@~p -- ~p ==> ~n  ~p == ~n  ~w~n",
                [Name,
                 Type,
                 Time,
                 subst_with_register(item(Source)),
                 subst_with_register(item(Return)),
                 Binary]);
           _ ->
             io:format
               ("~n~p : ~p@~p -- ~p == ~n  ~w~n",
                [Name,
                 Type,
                 Time,
                 subst_with_register(item(Source)),
                 Binary])
         end
     end, 
     lists:sort
       (fun ({_,R1},{_,R2}) -> time(source(R1)) < time(source(R2)) end,
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
      xor_const()
     ]).

%%      pad_with(16#5c),
%%      pad_with(16#36),
%%      pad_with(16#0),
%%      pad_one(),
%%      xor_with_pad(16#5c),
%%      xor_with_pad(16#36)
%%     ]).

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
      ?LOG
        ("No explanation found using~n~p~n",
         [Binaries]),
      false;
    [Sol] -> 
      verify_solution(Sol,Binary,Binaries);
    Sols ->
      ?LOG
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
          io:format
            ("~n*** Error: the solution~n  ~p~n contains binaries"
             ++" not available in the context~n  ~p~n",
             [Sol,Binaries]),
          error(bad)
      end;
    false ->
      io:format
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
      ?LOG("reg=~p~n",[CandidateRegister]),
      case (CandidateRegister =/= undefined) 
        andalso binary_type(CandidateRegister)==rewrite of
        true ->
          DefinedUsingBinaries = sol_args(item(source(CandidateRegister))),
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

