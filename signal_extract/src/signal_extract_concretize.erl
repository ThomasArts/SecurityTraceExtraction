%%% @author Thomas Arts
%%% @doc Apply a description to concretize to a symbolic reference trace
%%%
%%% @end
%%% Created :  9 Apr 2019 by Thomas Arts <thomas@SpaceGrey.local>

-module(signal_extract_concretize).

-compile([export_all]).

start() ->
    start(concrete_noise).

start(Concretizer) ->
    {SemanticTerm, TraceTerm, Binaries} = read(),
    Concrete = concretize(SemanticTerm, Concretizer),
    io:format("****************************************************\n"),
    difference(Concrete, TraceTerm, []).

concretize(List, Concretizer) when is_list(List) ->
    [ concretize(E, Concretizer) || E <- List ];
concretize({Fun, Args}, Concretizer) ->
    ConcreteArgs = concretize(Args, Concretizer),
    try apply(Concretizer, Fun, ConcreteArgs)
    catch _:Error ->
            io:format("~p(~p) --> ~p\n", [Fun, ConcreteArgs, Error]),
            %% If function fails, we might have the wrong concrete arguments
            {Fun, Args}
    end;
concretize(X, _) ->
    X.


difference({F, M, As}, {F, M, Bs}, Subs) when length(As) == length(Bs) ->
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
difference(A, A, Subst) ->
    {eq, Subst};
difference(A, {F, M, Args} = B, Subs) when A =/= B ->
    Same =
        try apply(F, M, Args) == A
        catch _:_ -> false
        end,
    if Same -> {eq, Subs};
       not Same -> 
        case lists:member({A,B},Subs) of
          true -> {eq, Subs};
          false -> {{A, '/=', B}, [{A,B}|Subs]}
        end
    end;
difference(A, B, Subs) ->
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

read() ->
    {TraceTerm, Binaries} = signal_extract:analyze_trace_file("enoise.trace"),
    {wrote, ST} = noise:test(),
    { {'WriteMessage', [ST]}, TraceTerm, Binaries}.
