%%% @author Thomas Arts
%%% @doc Apply a description to concretize to a symbolic reference trace
%%%
%%% @end
%%% Created :  9 Apr 2019 by Thomas Arts <thomas@SpaceGrey.local>

-module(compare).

-include("noise_config.hrl").

-compile([export_all]).

compare(SemanticTerm,TraceTerm,Config) ->
    compare(concrete_noise,SemanticTerm,TraceTerm,Config).

compare(Concretizer,SemanticTerm,TraceTerm,Config) ->
  Concrete = concretize(list_to_merge(SemanticTerm), Concretizer, Config),
  difference(Concrete, TraceTerm, []).

concretize(List, Concretizer, Config) when is_list(List) ->
    [ concretize(E, Concretizer, Config) || E <- List ];
concretize({Fun, Args}, Concretizer, Config) ->
    ConcreteArgs = concretize(Args, Concretizer, Config),
    try apply(Concretizer, Fun, ConcreteArgs ++ [Config])
    catch _:_ ->
            {Fun, ConcreteArgs}
    end;
concretize(X, _, _) ->
    X.

head_normalize(T) ->
  case T of
    {signal_binary_ops,merge,[<<>>,<<>>]} ->
      <<>>;
    {signal_binary_ops,merge,[TL,<<>>]} ->
      TL;
    {signal_binary_ops,merge,[<<>>,TR]} ->
      TR;
    _ ->
      T
  end.

difference(T1,T2,Subst) ->
  T1N = head_normalize(T1),
%  T2N = head_normalize(T2),
%  diff(T1N,T2,Subst).
  T2N = head_normalize(T2),
  diff(T1N,T2N,Subst).

diff({F, M, As}, {F, M, Bs}, Subs) when length(As) == length(Bs) ->
  {Results, NewSubs} = 
    lists:foldl
      (fun ({A,B},{Rs,S}) -> {R,NewS} = difference(A,B,S), {[R|Rs],NewS} end, {[],Subs},
       lists:zip(As,Bs)),
  case lists:all(fun(eq) -> true; (_) -> false end, Results) of
    true ->
      {eq, NewSubs};
    false ->
      {{F, M, Results}, NewSubs}
    end;
diff(A, A, Subst) ->
    {eq, Subst};
diff(A, {F, M, Args} = B, Subs) when A =/= B ->
    {Same,R} =
        try
          Result = apply(F, M, Args),
          {Result == A, Result}
        catch _:_ -> {false, undefined} end,
    if Same -> {eq, Subs};
       not Same ->
        case lists:member({A,B},Subs) of
          true -> {eq, Subs};
          false -> {{A, '/=', B}, [{A,B}|Subs]}
        end
    end;
diff(A, B, Subs) ->
  case lists:member({A,B},Subs) of
    true -> {eq, Subs};
    false -> {{A, '/=', B}, [{A,B}|Subs]}
  end.

%% difference({F, M, As}, {F, M, Bs}) when length(As) == length(Bs) ->
%%     DiffArgs = [difference(A, B) || {A, B} <- lists:zip(As, Bs)],
%%     case lists:all(fun(eq) -> true; (_) -> false end, DiffArgs) of
%%         true ->
%%             eq;
%%         false ->
%%             {F, M, DiffArgs}
%%     end;
%% difference(A, A) ->
%%     eq;
%% difference(A, {F, M, Args} = B) when A =/= B ->
%%     Same =
%%         try apply(F, M, Args) == A
%%         catch _:_ -> false
%%         end,
%%     if Same -> eq;
%%        not Same -> {A, '/=', B}
%%     end;
%% difference(A, B) ->
%%     {A, '/=',  B}.
%% 

list_to_merge(L) when is_list(L) ->
  %% nicer to reverse the list and foldl over the tl with hd as
  %% first Acc (or simply define a recursive function that is
  %% immediately obvious
  lists:foldr
    (fun (Write, Acc) ->
         if
           Acc == undefined ->
             Write;
           true ->
             noise:'MERGE'(Write, Acc)
         end
     end, undefined, L);
list_to_merge(Term) ->
  Term.
  
