-module(compare).

-compile(export_all).

%% Try to match the trace term with the semantic term
match(TraceTerm,SemanticTerm) -> 
  match(TraceTerm,SemanticTerm,undefined,undefined).

match(T,S,Tcntx,Scntx) ->
  case {T,S} of
    {T,T} -> 
      true;
    {{_,TF,TArgs}, {SF,SArgs}} when length(TArgs)==length(SArgs) ->
      case (TF==SF) orelse match_functors(TF,SF,length(TArgs)) of
        true -> match_lists(TArgs, SArgs, T, S);
        false -> match_terms(T,S,Tcntx,Scntx)
      end;
    _ -> match_terms(T,S,Tcntx,Scntx)
  end.
        
match_functors(TF,SF,Arity) ->
  case {TF,SF,Arity} of
    {'merge','MERGE',2} ->
      true;
    _ ->
      false
  end.

match_lists(TArgs, SArgs, T, S) ->
  lists:foldl
    (fun ({TArg,SArg},Acc) -> Acc andalso match(TArg,SArg,T,S) end, 
     true, lists:zip(TArgs,SArgs)).

match_terms(TraceTerm, SymbolicTerm, Tcntx, Scntx) ->
  case {TraceTerm,SymbolicTerm} of
    { {_, 'generichash',[64,TArg]}, {'HASH',[SArg]} } ->
      match(TArg,SArg,TraceTerm,SymbolicTerm);
    
    { {_, TF, TArgs}, {SF, SArgs} } when is_atom(TF), is_atom(SF) ->
      io:format
        ("should match ~p/~p and ~p/~p~n",
         [TF,length(TArgs),SF,length(SArgs)]),
      false;

    { {_, TF, TArgs}, _ } when is_atom(TF) ->
      io:format
        ("should match ~p/~p against~n~p~n",
         [TF,length(TArgs),SymbolicTerm]),
      false;

    { _, {SF, SArgs}, _ } when is_atom(SF) ->
      io:format
        ("should match ~p~n against~n~p/~p~n",
         [TraceTerm,SF,length(SArgs)]),
      false;

    _ -> 
      io:format
        ("~nCannot match ~p~n and ~p~nin contexts ~p~nand ~p~n",
         [TraceTerm,SymbolicTerm,Tcntx,Scntx]),
      false
  end.

rewrite(Term,Rules) ->
  case Term of
    _ when is_tuple(Term), 
           size(Term)>=2, 
           is_atom(element(1,Term)), 
           is_list(element(size(Term),Term)) ->
      ArgsPos = size(Term),
      Args = element(ArgsPos,Term),
      RArgs = rewrite(Args,Rules),
      NewTerm = setelement(ArgsPos,Term,RArgs),
      case try_rewrite(NewTerm,Rules) of
        false ->
          NewTerm;
        {true, RewrittenTerm} ->
          rewrite(RewrittenTerm,Rules)
      end;
    [Hd|Tl] ->
      [rewrite(Hd,Rules)|rewrite(Tl,Rules)];
    Map when is_map(Map) ->
      lists:foldl(fun ({Key,Value},M) ->
                      maps:put(Key,Value,M)
                  end, #{}, rewrite(maps:to_list(Map),Rules));
    _ -> Term
  end.
                    
try_rewrite(Application,[]) ->
  false;
try_rewrite(Application,[Rule|Rules]) ->
  case Rule(Application) of
    false ->
      try_rewrite(Application,Rules);
    Other ->
      Other
  end.

rewrite_functors(Mapping) ->
  fun (Application) ->
      ArgsPos = 
        size(Application),
      FunctorPos =
        if
          ArgsPos == 3 -> 2;
          true -> 1
        end,
      Functor = element(FunctorPos,Application),
      Arity = 
        length(element(ArgsPos,Application)),
      io:format("checking for ~p~n",[{Functor,Arity}]),
      case lists:keyfind({Functor,Arity},1,Mapping) of
        false -> 
          false;
        {_,Result} -> 
          {true,{Result,element(ArgsPos,Application)}}
      end
  end.

list_to_binary() ->
  fun (Term) ->
      case Term of
        {'erlang', 'list_to_binary', L} when is_list(L) ->
          {true,list_to_binary(L)};
        _ -> false
      end
  end.

generichash() ->
  fun (Term) ->
      case Term of
        {enacl,generichash,[64,Arg]} -> 
          {true,{'HASH',Arg}};
        _ -> false
      end
  end.
          
pad_2_pad_to_using() ->
  fun (Term) ->
      case Term of
        {signal_binary_ops,pad,[B,Symbol,N]} when is_binary(B) ->
          {true,{'PAD_TO_USING',[B,Symbol,N+byte_size(B)]}};
        _ -> false
      end
  end.

mapping() ->
  [
   {{merge,2},'MERGE'},
   {{truncate,2},'TRUNCATE'},
   {{curve25519_scalarmult,2},'DH'}
  ].

rules() ->
  [
   list_to_binary(),
   generichash(),
   pad_2_pad_to_using(),
   rewrite_functors(mapping())
  ].

test() ->      
  TraceTerm = signal_extract:analyze_trace_file("enoise.trace"),
  {wrote,ST} = noise:test(),
  SemanticTerm =
    case ST of
      _ when is_list(ST) ->
        lists:foldr
          (fun (Write,Acc) -> 
               if
                 Acc == undefined ->
                   Write;
                 true ->
                   noise:'MERGE'(Write,Acc)
               end
           end, undefined, ST);
      Term ->
        Term
    end,
  io:format
    ("~n~n~nTrace term:~n~p~n~n",
     [TraceTerm]),
  io:format
    ("~n~nSemantic term:~n~p~n~n",
     [SemanticTerm]).

%%  NewTraceTerm = rewrite(TraceTerm,rules()),
%%  io:format
%%    ("~nRewritten trace term:~n~p~n",
%%     [NewTraceTerm]),
%%  io:format
%%    ("checking eq ~n~p~nand~n~p~n",
%%     [TraceTerm,SemanticTerm]),
  %% %match(TraceTerm,SemanticTerm).













       

        

      
  



  
