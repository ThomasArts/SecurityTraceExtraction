-module(compare).

-compile(export_all).

%% Try to match the trace term with the semantic term
match(TraceTerm,SemanticTerm) -> 
  match(TraceTerm,SemanticTerm,undefined,undefined,[]).

match(T,S,Tcntx,Scntx,Subst) ->
  case S of
    {F,Args} when is_atom(F), is_list(Args) ->
      case T of
        {M1,F1,Args1} when is_atom(M1), is_atom(F1), is_list(Args1) ->
          FunctorsSubst =
            if
              F==F1 -> Subst;
              true -> add_if_new({F1,F},Tcntx,Scntx,Subst)
            end,
          if
            length(Args)==length(Args1) ->
              lists:foldl
                (fun ({Arg_x,Arg1_x},Sub) -> 
                     match(Arg_x,Arg1_x,T,S,Sub)
                 end, FunctorsSubst, lists:zip(Args1,Args));
            true ->
              io:format
                ("~n*** Error: calls to ~p/~p and ~p/~p cannot be matched:~n"
                 ++"~p~n =/= ~p~n",
                 [F1,length(Args1),F,length(Args),T,S]),
              Subst
          end;
        _ -> add_if_new({T,S},Tcntx,Scntx,Subst)
      end;
    _ ->
      if 
        T==S ->
          Subst;
        true ->
          io:format
            ("~n*** Error: cannot match~n~p~nand ~p~nin context ~p~nand ~p~n",
             [T,S,Tcntx,Scntx]),
          Subst
      end
  end.

add_if_new(Subst={T,S},Tcntx,Scntx,Substs) ->
  check_match(T,S,Tcntx,Scntx,Subst),
  case lists:member(Subst,Substs) of
    true ->
      Substs;
    false ->
      [Subst|Substs]
  end.

check_match(T,S,Tcntx,Scntx,Subst) ->
  if
    is_integer(T) ->
      check(T,S,Tcntx,Scntx,Subst);
    is_integer(S) ->
      check(T,S,Tcntx,Scntx,Subst);
    true ->
      ok
  end.

check(T,S,Tcntx,Scntx,Subst) ->
  io:format
    ("~n** Error: const and non-eq term subst:~n~p~n =/= ~p~n"
    ++"in T=~p~nand in S=~p~n",
     [T,S,Tcntx,Scntx]).

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
  Subst = match(TraceTerm,noise:subst(SemanticTerm,test_match())),
  io:format
    ("~nSubstitution is~n~p~n",
     [Subst]).

test_match() ->
  [
   fun (Term) ->
       case Term of
         {'HASH',[Arg]} ->
           {'generichash',[64,Arg]};
         _ ->
           Term
       end
   end
  ].

%% Problems:
%% matching generichash(64,ArgT) with HASH(ArgS)

%% We define a transformation (for Blake32 from HASH(X) to generichash(64,X)
%% Instead of extract we generate truncate operations for tracing when
%% applicable.










       

        

      
  



  
