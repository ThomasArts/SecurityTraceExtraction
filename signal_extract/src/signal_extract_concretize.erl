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
    {SemanticTerm, TraceTerm} = read(),
    Concrete = concretize(SemanticTerm, Concretizer),
    io:format("****************************************************\n"),
    difference(Concrete, TraceTerm).

concretize(List, Concretizer) when is_list(List) ->
    [ concretize(E, Concretizer) || E <- List ];
concretize({Fun, Args}, Concretizer) ->
    ConcreteArgs = concretize(Args, Concretizer),
    try apply(Concretizer, Fun, ConcreteArgs)
    catch _:_ ->
            {Fun, ConcreteArgs}
    end;
concretize(X, _) ->
    X.


difference({F, M, As}, {F, M, Bs}) when length(As) == length(Bs) ->
    {F, M, [difference(A, B) || {A, B} <- lists:zip(As, Bs)]};
difference(A, A) ->
    A;
difference(A, B) ->
    {A, '/=',  B}.


read() ->
  TraceTerm = signal_extract:analyze_trace_file("enoise.trace"),
  {wrote, ST} = noise:test(),
  SemanticTerm =
    case ST of
      _ when is_list(ST) ->
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
           end, undefined, ST);
      Term ->
        Term
    end,
    {SemanticTerm, TraceTerm}.
