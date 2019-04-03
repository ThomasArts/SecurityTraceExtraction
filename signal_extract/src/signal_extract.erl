-module(signal_extract).

-export([noisy_trace/0,register_binaries/2,trace_make_call_deterministic/1]).
-export([get_trace/1,compose_binaries/1,traceback_test/0,print_array/2]).
-export([print_binary_register/0,show_trace/1,show_registered_trace/1]).

-compile(export_all).


%% rebar3 as test shell

noisy_trace() ->
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
     enoise_crypto_basics, signal_extract_utils, enoise_xk_test
    ],
  lists:foreach(fun code:ensure_loaded/1, EnoiseModules++LoadModules),
  %% Tests = test_utils:noise_test_filter(test_utils:noise_test_vectors()),
  %% N = rand:uniform(length(Tests)),
  %% N = 5,
  %% Test = lists:nth(N,Tests),
  %% io:format
  %% ("Running noise test vector~n  ~p~n~n",
  %% [Test]),
  test(fun () -> 
          enoise_xk_test:client_test() 
           %% enoise_tests:noise_interactive(Test) 
       end, 
       %%[enacl,enacl_nif] ++ 
       EnoiseModules
      ).

do_trace(TracedPid,ToPid,Modules) ->
  %%erlang:trace_pattern({'_','_','_'}, true, [local]),
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
  lists:foreach(fun (Module) -> 
                    erlang:trace_pattern({Module, '_', '_'}, [{'_', [], [{return_trace}]}], [local]) 
                end,
                Modules).
 %%erlang:trace_pattern({'_','_','_'}, [], [local]).

test(F, Modules) ->
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
      io:format("computed value ~p~n",[Value]), 
      timer:sleep(5000),
      Tracer ! {stop, self(), "enoise.trace"},
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
      io:format("Warning: strange message ~p~n",[Other]),
      tracer1(L)
  end.

get_trace(FileName) ->
  {ok,B} = file:read_file(FileName),
  case binary_to_term(B) of
    {trace,L} ->
      array:from_list(L)
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
  register_binaries(0,array:size(A),A,Pre).
register_binaries(I,Size,_A,_Pre) when I>=Size ->
  ok;
register_binaries(I,Size,A,Pre) ->
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
  register_binaries(I+1,Size,A,Pre).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

compose_binaries(A) ->
  lists:foreach
    (fun ({Binary,Register}) ->
         case is_consumed(Register) orelse is_produced(Register) of
           true ->
             Source = source(Register),
             Pid = pid(item(Source)),
             io:format("~ntrying to compose binary~n~p~n==~p~n",[Register,Binary]),
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
             io:format
               ("number of binaries is ~p:~n~p~n~n",
                [length(ContextBinaries),ContextBinaries]),
             io:format
               ("Limits ~p~n",
                [{StartTime,EndTime}]),
             case rewriteTo(Binary,ContextBinaries) of
               false ->
                 ok;
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
  io:format("call_limits(~p) = {~p,~p}~n",[I,CallSite,ReturnSite]),
  {CallSite,ReturnSite}.
  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



traceback(EventRecognizer,A) ->
  apply_in_trace(EventRecognizer,A,
                 fun (Event,_,_,_) -> 
                     trace_back_binaries(binaries(Event),[])
                 end).

apply_in_trace(EventRecognizer,A,F) ->
  apply_in_trace(EventRecognizer,0,array:size(A),A,F).
apply_in_trace(_EventRecognizer,I,Size,_A,_F) when I>=Size ->
  ok;
apply_in_trace(EventRecognizer,I,Size,A,F) ->
  Event = array:get(I,A),
  case EventRecognizer(I,Event) of
    true ->
      F(Event,I,Size,A);
    false ->
      ok
  end,
  apply_in_trace(EventRecognizer,I+1,Size,A,F).
  
trace_back_binaries([],_Seen) ->
  ok;
trace_back_binaries([Binary|Binaries],Seen) ->
  case lists:member(Binary,Seen) of
    true -> 
      trace_back_binaries(Binaries,Seen);
    false -> 
      Register = get_binary(Binary),
      if
        Register == undefined -> 
          trace_back_binaries(Binaries,Seen);
        true ->
          NewSeen = [Binary|Seen],
          case binary_type(Register) of
            consumed -> 
              io:format
                ("~nExternal? binary ~p~n~p~nconsumed by call at ~p~n  ~p~n",
                 [
                  subst_with_register(Binary),
                  Binary,
                  time(source(Register)),
                  subst_with_register(extract_call(item(source(Register))))
                 ]),
              trace_back_binaries(Binaries,NewSeen);
            produced ->
              ReturnString =
                case Binary == extract_return(item(return(Register))) of
                  true -> 
                    "";
                  false -> 
                    io_lib:format
                      ("returned as ~p~n",
                       [
                        %%time(return(Register)),
                        subst_with_register(extract_return(item(return(Register))))
                       ])
                end,
              io:format
                ("~nBinary ~p produced at ~p by call~n  ~p~n~s",
                 [
                  subst_with_register(Binary),
                  time(source(Register)),
                  subst_with_register(extract_call(item(source(Register)))),
                  ReturnString
                 ]),
              SourceBinaries = binaries(source(Register)),
              trace_back_binaries(SourceBinaries++Binaries,Seen);
            rewrite ->
              Item = item(source(Register)),
              RewriteType = sol_type(Item),
              ArgBinaries = sol_args(Item),
              Op = sol_op(Item),
              OpString =
                if
                  Op==undefined -> "";
                  true -> " where "++io_lib:format("~p",[Op])
                end,
              io:format
                ("~p ==~n  ~p(~s)~s~n",
                 [
                  subst_with_register(Binary),
                  RewriteType,
                  print_binaries(ArgBinaries),
                  OpString
                 ]),
              trace_back_binaries(ArgBinaries++Binaries,NewSeen)
          end
      end
  end.

print_binaries(Binaries) ->
  lists:foldl
    (fun (Bin,Acc) -> 
         S = io_lib:format("~p",[subst_with_register(Bin)]),
         if
           Acc==[] -> S;
           true -> Acc++","++S
         end
     end, [], Binaries).

extract_call({trace_ts,_,call,Call,_}) ->
  Call.
extract_return({trace_ts,_,return_from,_,Value,_}) ->
  Value.

traceback_test() ->
  A = get_trace("enoise.trace"),
  traceback
    (fun (Time,Event) -> 
         case Event of
           {trace_ts,_,call,Call={enoise,gen_tcp_snd_msg,_},_} ->
%%          {trace_ts,_,call,Call={gen_tcp,send,_},_} ->
             io:format
               ("~n~n~nStarting at ~p with call ~p:~n",
                [Time,subst_with_register(Call)]),
             true;
           _ -> false
         end
     end,
     A).

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
  Type.
time({Time,_}) ->
  Time.
item({_,Item}) ->
  Item.
sol_type({Type,_Args,_}) ->
  Type.
sol_args({_,Args,_}) ->
  Args.
sol_op({_,_,Op}) ->
  Op.

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

registers() ->
  lists:filter
    (fun ({counter,_}) -> false; 
         ({{nickname,_},_}) -> false; 
         (_) -> true 
     end, signal_extract_utils:to_list()).

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
      fun extract/2,
      fun pad_generic/2,
      fun (B,Bs) -> pad_with(B,Bs,16#5c) end,
      fun (B,Bs) -> pad_with(B,Bs,16#36) end,
      fun (B,Bs) -> pad_with(B,Bs,16#0) end,
      merge_pad_and_xor(92),
      merge_pad_and_xor(54),
      pad_and_xor(92),
      pad_and_xor(54)
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
      io:format
        ("No explanation found using~n~p~n",
         [Binaries]),
      false;
    [Sol] -> 
      Sol;
    Sols ->
      io:format
        ("Multiple solutions found using~n~p~nAlts=~p~n",
         [Binaries,Sols]),
      hd(lists:sort(fun le_rewrites/2,Sols))
end.

le_rewrites(R1,R2) ->
  R1Type = element(1,R1),
  R2Type = element(1,R2),
  le_type_ord(R1Type) =< le_type_ord(R2Type).

le_type_ord(merge) ->
  1;
le_type_ord(word_xor_pad) ->
  3;
le_type_ord(merge_with_word_xor_pad) ->
  5;
le_type_ord(padded_with) ->
  10;
le_type_ord(extract_from) ->
  15.

binary_rewrite(_F,_Binary,[]) ->
  false;
binary_rewrite(F,Binary,[{First,_}|Rest]) ->
  if
    byte_size(First) >= 4 ->
      case binary_rewrite1(F,Binary,First,Rest) of
        false -> 
          binary_rewrite(F,Binary,Rest);
        Sol ->
          Sol
      end;
    true -> false
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

merge_pad_and_xor(Pad) ->
  fun (RBinary,Binaries) ->
      binary_rewrite
        (fun (Binary,FirstCandidate,SecondCandidate) ->
             case merge_pad_and_xor(Binary,FirstCandidate,SecondCandidate,Pad) of
               false ->
                 merge_pad_and_xor(Binary,SecondCandidate,FirstCandidate,Pad);
               Sol ->
                 Sol
             end
         end, RBinary, Binaries)
  end.

merge_pad_and_xor(Binary,FirstCandidate,SecondCandidate,Pad) ->
  if
    byte_size(Binary) >= 8,
    byte_size(FirstCandidate) == byte_size(Binary)-4,
    byte_size(SecondCandidate) >= 4 ->
      case occurs_check(Binary,FirstCandidate) 
        andalso occurs_check(Binary,SecondCandidate) of
        true ->
          io:format
            ("checking if ~p~n==~p~n+~p~n",
             [Binary,FirstCandidate,SecondCandidate]),
          <<B1:8, B2:8, B3:8, B4:8, _/binary>> = SecondCandidate,
          B1b = B1 bxor Pad, B2b = B2 bxor Pad, B3b = B3 bxor Pad, B4b = B4 bxor Pad,
          Word = <<B1b, B2b, B3b, B4b>>,
          io:format("Word=~p~n",[Word]),
          if
            Binary == <<FirstCandidate/binary, Word/binary>> ->
              {merge_with_word_xor_pad, [FirstCandidate,SecondCandidate], {pad,Pad}};
            true ->
              false
          end;
        false -> false
      end;
    true -> false
  end.

pad_and_xor(Pad) ->
  fun (RBinary,Binaries) ->
      unary_rewrite
        (fun (Binary,Candidate) ->
             if
               byte_size(Binary) == 4,
               byte_size(Candidate) >= 4 ->
                 <<B1:8, B2:8, B3:8, B4:8, _/binary>> = Candidate,
                 B1b = B1 bxor Pad, B2b = B2 bxor Pad, B3b = B3 bxor Pad, B4b = B4 bxor Pad,
                 Word = <<B1b, B2b, B3b, B4b>>,
                 if
                   Binary == <<Word/binary>> ->
                     {word_xor_pad, [Candidate], {pad,Pad}};
                   true -> false
                 end;
               true -> false
             end
         end, RBinary, Binaries)
  end.

%% n-merge

merge(Binary,Binaries) ->
  if
    byte_size(Binary) >= 4 ->
      merge(Binary,Binary,Binaries,Binaries,[]);
    true ->
      false
  end.

merge(_,<<>>,_,_,Match) ->
   {merge,lists:reverse(Match),undefined};
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
  
occurs_check(Binary,Candidate) ->
  if
    Binary==Candidate -> 
      false;
    true ->
      CandidateRegister = get_binary(Candidate),
      case (CandidateRegister =/= false) andalso binary_type(CandidateRegister)==rewrite of
        true ->
          DefinedUsingBinaries = sol_args(item(source(CandidateRegister))),
          lists:all
            (fun (UsedBinary) -> 
                 occurs_check(Binary,UsedBinary) end, 
             DefinedUsingBinaries);
        _ -> true
      end
  end.

extract(RBinary,Binaries) ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         case binary:match(Candidate,Binary) of
           nomatch ->
             false;
           Match ->
             {extract_from,[Candidate],{part,Match,'of',byte_size(Candidate)}}
         end
     end, RBinary,Binaries).

pad_with(RBinary,Binaries,Symbol) ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         ByteSizeBinary = byte_size(Binary),
         ByteSizeCandidate = byte_size(Candidate),
         if
           ByteSizeCandidate < ByteSizeBinary ->
             NumBytes =
               ByteSizeBinary-ByteSizeCandidate,
             PaddedCandidate = 
               pad_binary(Candidate,NumBytes,Symbol),
             if
               Binary == PaddedCandidate ->
                 {padded_with,[Candidate],{pad,Symbol,count,NumBytes}};
               true ->
                 false
             end;
           true -> false
         end
     end, RBinary, Binaries).

pad_generic(RBinary,Binaries) ->
  unary_rewrite
    (fun (Binary,Candidate) ->
         ByteSizeBinary = byte_size(Binary),
         ByteSizeCandidate = byte_size(Candidate),
         if
           ByteSizeCandidate+1 == ByteSizeBinary ->
             case binary:match(Binary,Candidate) of
               {0,ByteSizeCandidate} ->
                 {padded_with,[Candidate],{pad,binary:last(Candidate),count,1}};
               nomatch ->
                 false
             end;
           true -> false
         end
     end, RBinary, Binaries).

pad_binary(Binary,0,_Symbol) ->
  Binary;
pad_binary(Binary,N,Symbol) when N>0 ->
  pad_binary(<<Binary/binary,Symbol>>,N-1,Symbol).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% enoise_trace:noisy_trace().
%%
%% enoise_trace:register_binaries("enoise.trace").
%% enoise_trace:compose_binaries(enoise_trace:get_trace("enoise.trace")).
%% enoise_trace:show_registered_trace(B).
%% enoise_trace:print_binary_register().
%% 

%% enoise_trace:traceback_test().
   
%% f(B), f(C), B = enoise_trace:trace_make_call_deterministic(enoise_trace:get_trace("enoise.trace")), enoise_trace:register_binaries(B), C = enoise_trace:trace_make_call_deterministic(B), enoise_trace:compose_binaries(B), enoise_trace:traceback_test().

%% f(A), f(B), enoise_trace:register_binaries("enoise.trace"), enoise_trace:print_array(enoise_trace:get_trace("enoise.trace"),false), B = enoise_trace:trace_make_call_deterministic(enoise_trace:get_trace("enoise.trace")), enoise_trace:print_array(B,false).
%%                       


%% f(A),f(B),f(Predefined), Predefined = [{<<0,8,0,0,3>>,'Prologue'},{<<64,168,119,119,151,194,94,141,86,245,144,220,78,53,243,231,168,216,66,199,49,148,202,117,98,40,61,109,170,37,133,122>>,'ClientPrivKey'},{<<115,39,86,77,44,85,192,176,202,11,4,6,194,144,127,123, 34,67,62,180,190,232,251,5,216,168,192,190,134,65,13,64>>,'ClientPubKey'},{<<30,231,212,22,139,223,244,70,37,202,104,94,227,212,90,247,244,208,231,176,178,140,100,129,16,101,82,39,31,130,145,122>>,'ServerPubKey'}], B = enoise_trace:trace_make_call_deterministic(enoise_trace:get_trace("enoise.trace")), enoise_trace:register_binaries(B,Predefined), enoise_trace:compose_binaries(B), enoise_trace:traceback_test(), enoise_trace:show_registered_trace(B), enoise_trace:print_binary_register().
%%
