%% Check non-interference against two enoise runs
%%

%% Main predicate, to be called with two run identifiers, e.g., nonint(r1,r2).
%%
%% Succeeds if non-interference of the two runs was proved, fails otherwise
%% with a message identifying the problem.
%%
nonint(R1,R2) :-
    open("nonint_traces.pl", write, Stream),
    run(R1,Ps1),
    run(R2,Ps2),
    dump_run(Ps1,Stream),
    dump_run(Ps2,Stream),
    close(Stream),
    length(Ps1,P1len),
    length(Ps2,P2len),
    ( (P1len =\= P2len); (P1len==0) ->
                             format('~nRuns ~w and ~p creates a zero or different number of processes.~n',[R1,R2]),
                             fail;
      nonint(R1,Ps1,R2,Ps2) ).

isEvent(event(Pid,Event,Time,RunId)) :-
    event(Pid,Event,Time,RunId).

%% Using tabling to speed up analysis
:- table run/2.

run(Run,Processes) :-
    findall(P, process(Run,P), UnsortedProcesses),
    predsort(spawnedFirst,UnsortedProcesses,Processes).

%% Using tabling to speed up analysis
:- table process/2.

process(Run,process(Run,Pid,Events)) :-
    events(Run,Pid,UnsortedEvents),
    predsort(timeOrder,UnsortedEvents,SortedEvents),
    collapseEvents(SortedEvents,Events).

pid(event(Pid,_,_,_), Pid).
time(event(_,_,TimeStamp,_),TimeStamp).
action(event(_,Action,_,_),Action).
runId(event(_,_,_,Run),Run).
eventType(Event,ActionType) :-
    action(Event,Action),
    Action =.. [ActionType|_].

isLinkEvent(Event) :-
    action(Event,link(_)).
isCallEvent(Event) :-
    action(Event,call(_,_,_)).
isReturnEvent(Event) :-
    action(Event,return_from(_,_,_,_)).
isNormalReturnEvent(Event) :-
    action(Event,return_from(M,F,Arity,_)),
    \+ member({M,F,Arity},
              [
                  {binary,compile_pattern,1}
                  ,{erlang,monitor,2}
                  ,{erlang,make_ref,0}
		  ,{erlang,spawn_opt,4}
                  ,{enacl,crypto_sign_ed25519_keypair,0}
                  ,{enacl,crypto_sign_ed25519_secret_to_curve25519,1}
                  ,{enacl,crypto_sign_ed25519_public_to_curve25519,1}
                  ,{enacl,generichash,2}
                  ,{enacl,curve25519_scalarmult,2}
                  ,{enoise_crypto_basics,padding,2}
                  ,{enacl,aead_chacha20poly1305_encrypt,4}
		  ,{get_key,get_key,3}
                  ,{base64,decode,1}
		  ,{erlang,open_port,2}
		  ,{gen_tcp,connect,4}
                  ,{gen_server,start_link,3}
              ]).

highModules(
    [
	enoise, enoise_test, enoise_crypto, enoise_crypto_basics,
	enoise_hs_state, enoise_keypair, enoise_protocol, enoise_sym_state, 
	enoise_cipher_state, enoise_connection,
	enacl, enacl_nif, get_key,
	proplists, lists, maps
    ]).

highCalls(
    [
	{erlang,setelement,3}
        ,{proc_lib,init_p,5}
        ,{gen,init_it,6}
        ,{gen_server,init_it,6}
        ,{erlang,'++',2}
    ]).


highSpecialCall(gen_tcp,send,[Port,_],Subst) :-
    get_assoc(enoise(Port),Subst,_).
highSpecialCall(gen_server,start_link,[enoise_connection,_,_],_).
highSpecialCall(gen_server,call,[Pid,_],Subst) :-
    get_assoc(enoise(Pid),Subst,_).

isLowEvent(Event,Subst) :-
    action(Event,send(_,Pid)),
    \+ get_assoc(enoise(Pid),Subst,_).
isLowEvent(Event,Subst) :-
    action(Event,call(M,F,Args)),
    length(Args,Arity),
    highModules(HModules),
    \+ member(M,HModules),
    highCalls(HCalls),
    \+ member({M,F,Arity},HCalls),
    \+ highSpecialCall(M,F,Args,Subst).

module(Event,M) :-
    action(Event,call(M,_,_)).

isHighEvent(Event) :-
    isHighCallEvent(Event), !.
isHighEvent(Event) :-
    isLinkEvent(Event), !.

isHighCallEvent(Event) :-
    isCallEvent(Event),
    module(Event,M),
    member(M,[
     enoise, enoise_test, 
     enoise_crypto, 
     enoise_hs_state, enoise_keypair, enoise_protocol, enoise_sym_state, 
     enoise_cipher_state, enoise_connection
    ]).

pids(Pids) :-
    findall(Pid, ( isEvent(Event), pid(Event,Pid) ), UnsortedPids),
    sort(UnsortedPids,Pids).

events(Run,Pid,Events) :-
    bagof(Event, ( isEvent(Event), pid(Event,Pid), runId(Event,Run) ), Events).
	    
low_events(low_events(Pid,LowEvents)) :-
    code(codes(Pid,Events)),
    include(is_low_event,Events,LowEvents).

isCollapsableCall(file,read_file,1).
isCollapsableCall(get_key,get_key,3).
isCollapsableCall(erlang,open_port,2).
isCollapsableCall(gen_tcp,connect,4).
isCollapsableCall(gen_tcp,send,2).
isCollapsableCall(gen_server,start_link,3).
isCollapsableCall(gen_server,call,2).
isCollapsableCall(gen_server,call,3).

collapseEvents([],[]).
collapseEvents([Event|Rest],[Event|CollapsedCalls]) :-
    isCallEvent(Event),
    action(Event,call(M,F,Args)),
    length(Args,Arity),
    isCollapsableCall(M,F,Arity), !,
    ( collapse(Rest,[Event],CollapsedCalls) ->
      true;
      format('*** ERROR. collapsed call to ~w:~w/~w at event ~w did not terminate~n',[M,F,Arity,Event]),
      fail).
collapseEvents([Event|Rest],[Event|CollapsedCalls]) :-
    collapseEvents(Rest,CollapsedCalls).

collapse([],Stack,[]) :-
    format('*** Warning: a collapsed call did not terminate. Stack:~n~w~n',[Stack]).
collapse([Event|Rest],Stack,CollapsedCalls) :-
    action(Event,call(_,_,_)),
    !,
    collapse(Rest,[Event|Stack],CollapsedCalls).
collapse([Event|Rest],Stack,CollapsedCalls) :-
    [LastCallEvent|RestStack] = Stack,
    action(LastCallEvent,call(M,F,Args)), length(Args,Arity),
    action(Event,return_from(M,F,Arity,_)),
    !,
    ( RestStack == [] ->
      CollapsedCalls=[Event|CollapsedCalls1],
      collapseEvents(Rest,CollapsedCalls1);
      collapse(Rest,RestStack,CollapsedCalls) ).
collapse([Event|_],[LastCallEvent|_],_) :-
    action(LastCallEvent,call(M,F,Args)), length(Args,Arity),
    action(Event,return_from(M1,F1,Arity1)),
    !,
    format('*** ERROR: expected a return from call ~w:~w/~w but got a return from ~w:~w/~w~nat event ~w.~n',[M,F,Arity,M1,F1,Arity1,Event]),
    fail.
collapse([_|Rest],Stack,CollapsedCalls) :-
    collapse(Rest,Stack,CollapsedCalls).

spawnedFirst(Delta,process(_,_,[Event1|_]),process(_,_,[Event2|_])) :-
    time(Event1,Time1),
    time(Event2,Time2),
    lt_or_equal_time(Delta,Time1,Time2).

timeOrder(Delta,Event1,Event2) :-
    time(Event1,Time1),
    time(Event2,Time2),
    lt_or_equal_time(Delta,Time1,Time2).

lt_or_equal_time('<',timestamp(T1_a,_,_),timestamp(T1_b,_,_)) :-
    T1_a < T1_b, !.
lt_or_equal_time('<',timestamp(T1,T2_a,_),timestamp(T1,T2_b,_)) :-
    T2_a < T2_b, !.
lt_or_equal_time('<',timestamp(T1,T2,T3_a),timestamp(T1,T2,T3_b)) :-
    T3_a < T3_b, !.
lt_or_equal_time('=',T,T) :- !.
lt_or_equal_time('>',_,_) :- !.


nonint(R1,Ps1,R2,Ps2) :-
    [process(R1,Pid1,_)|_] = Ps1,
    [process(R2,Pid2,_)|_] = Ps2,
    list_to_assoc(
	[
	    "msg2"-"msg1"

	    %% First processes are high
	    ,enoise(Pid1)-enoise
	    ,enoise(Pid2)-enoise

	    ,"/home/fred/gits/enoise_verification/SecurityTraceExceptionFred/signal_extract/_build/test/lib/signal_extract/priv/testing_keys2"-"/home/fred/gits/enoise_verification/SecurityTraceExceptionFred/signal_extract/_build/test/lib/signal_extract/priv/testing_keys"
	],Subst),
    nonint(R1,Ps1,R2,Ps2,Subst).

nonint(_,[],_,[],_) :- !.
nonint(R1,[P1|Rest1],R2,[P2|Rest2],Sub) :-
    nonint(R1,P1,R2,P2,Sub,NewSub),
    nonint(R1,Rest1,R2,Rest2,NewSub).

nonint(R1,process(R1,Pid1,Events1),R2,process(R2,Pid2,Events2),Sub,NewSub) :-
    put_assoc(Pid2,Sub,Pid1,Sub1),
    nonint(R1,Pid1,Events1,R2,Pid2,Events2,Sub1,NewSub).

nonint(_,_,[],_,_,[],Sub,Sub) :-
    !, format('~n~nTerminated non-interference check successfully.~n').
nonint(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    isLowEvent(Ev1,Sub), !,
    nonint_low(R1,Pid1,Ev1,Rest1,R2,Pid2,Ev2,Rest2,Sub,NewSub).
nonint(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    isLowEvent(Ev2,Sub), !,
    nonint_low(R1,Pid1,Ev1,Rest1,R2,Pid2,Ev2,Rest2,Sub,NewSub).
nonint(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    isEvent(Ev1), isEvent(Ev2), !,
    nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub).
nontint(_,_,[First1|_],_,_,[First2|_],_,_) :-
    format('*** Error: ~w or ~w are not events.~n',[First1,First2]),
    fail.

nonint_low(R1,Pid1,Ev1,Rest1,R2,Pid2,Ev2,Rest2,Sub,NewSub) :-
    assoc_to_list(Sub,SubList),
    include(lowSubst,SubList,LowSubList),
    list_to_assoc(LowSubList,LowSub),
    ( equal_events(Ev1,Ev2,LowSub) ->
      nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub,NewSub);
      format('~n Low events~n   ~w~n and~n    ~w~n are not equal.~n',[Ev1,Ev2]),
      fail ).

lowSubst(pid(_)-pid(_)) :- !.
lowSubst(reference(_)-reference(_)) :- !.
lowSubst(port(_)-port(_)) :- !.
lowSubst(enoise(_)-_) :- !.

nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    isNormalReturnEvent(Ev1), isNormalReturnEvent(Ev2), !,
    nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub,NewSub).
nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    isReturnEvent(Ev1), isReturnEvent(Ev2), !,
    nonint_returns(Ev1,Ev2,Sub,Sub1),
    nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub1,NewSub).
nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
     action(Ev1,receive(Msg1)),
     action(Ev2,receive(Msg2)),
     !,
     ( Msg1==Msg2 ->
       nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub,NewSub);
       diff(Msg1,Msg2,Diff),
       update_assoc_from_diff(Sub,Diff,Subst1),
       nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Subst1,NewSub) ).
nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    action(Ev1,spawn(PidN1,Value1)),
    action(Ev2,spawn(PidN2,Value2)),
    !,
    term_equal(Value1,Value2,Sub),
    ( PidN1==PidN2 ->
      nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub,NewSub);
      put_assoc(PidN2,Sub,PidN1,Subst1),
      nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Subst1,NewSub) ).
nonint_high(R1,Pid1,[Ev1|Rest1],R2,Pid2,[Ev2|Rest2],Sub,NewSub) :-
    ( equal_events(Ev1,Ev2,Sub) ->
      nonint(R1,Pid1,Rest1,R2,Pid2,Rest2,Sub,NewSub) ;
      format('~n Events~n   ~w~n and~n    ~w~n are not equal.~n',[Ev1,Ev2]),
      fail ).

nonint_returns(Return1,Return2,Sub,NewSub) :-
    action(Return1,return_from(M,F,Arity,Value1)),
    action(Return2,return_from(M,F,Arity,Value2)),
    nonint_returns(M,F,Arity,Value1,Value2,Sub,NewSub).

nonint_returns(binary,compile_pattern,1,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(get_key,get_key,3,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(erlang,open_port,2,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(gen_tcp,connect,4,tuple(ok,Value1),tuple(ok,Value2),Sub,NewSub) :-
    !,
    put_assoc(enoise(Value2),Sub,enoise,Subst1),
    put_assoc(enoise(Value1),Subst1,enoise,Subst2),
    put_assoc(Value2,Subst2,Value1,NewSub).
nonint_returns(erlang,spawn_opt,4,Value1,Value2,Sub,NewSub) :-
    !,
    put_assoc(enoise(Value2),Sub,enoise,Subst1),
    put_assoc(enoise(Value1),Subst1,enoise,Subst2),
    put_assoc(Value2,Subst2,Value1,NewSub).
nonint_returns(erlang,monitor,2,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(gen_server,start_link,3,tuple(ok,Value1),tuple(ok,Value2),Sub,NewSub) :-
    !,
    put_assoc(enoise(Value2),Sub,enoise,Subst1),
    put_assoc(enoise(Value1),Subst1,enoise,Subst2),
    put_assoc(Value2,Subst2,Value1,NewSub).
nonint_returns(erlang,make_ref,0,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enacl,crypto_sign_ed25519_keypair,0,Map1,Map2,Sub,NewSub) :-
    Map1=map([tuple(public,Public1),tuple(secret,Secret1)]),
    Map2=map([tuple(public,Public2),tuple(secret,Secret2)]),
    !, put_assoc(Public2,Sub,Public1,Sub1), put_assoc(Secret2,Sub1,Secret1,NewSub).
nonint_returns(enacl,aead_chacha20poly1305_encrypt,4,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enacl,curve25519_scalarmult,2,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enacl,crypto_sign_ed25519_secret_to_curve25519,1,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enacl,crypto_sign_ed25519_public_to_curve25519,1,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enoise_crypto_basics,padding,2,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(base64,decode,1,Value1,Value2,Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(enacl,generichash,2,tuple(ok,Value1),tuple(ok,Value2),Sub,NewSub) :-
    !, put_assoc(Value2,Sub,Value1,NewSub).
nonint_returns(M,F,Arity,V1,V2,_,_) :-
    format('*** Error: cannot handle nonint_returns(~p,~p,~p)~nwith value1=~w~nand value2=~w.~n',[M,F,Arity,V1,V2]),
    fail.

equal_events(Ev1,Ev2,Sub) :-
    pid(Ev1,Pid1),
    action(Ev1,Action1),
    pid(Ev2,Pid2),
    action(Ev2,Action2),
    pid_equal(Pid1,Pid2,Sub),
    term_equal(Action1,Action2,Sub).

term_equal(Action,Action,_) :- !.
term_equal(Action1,Action2,Sub) :-
    term_subst(Action2,SubAction2,Sub),
    ( Action1==SubAction2 ->
      true;
      assoc_to_list(Sub,SubList),
      diff(Action1,SubAction2,SubstDiff),
      format('Terms~n  ~w~n and~n  ~w~n do not match;~n second term substituted:~n  ~w~n~nSubst diff:~n~w~n~nsubst=~w.~n',[Action1,Action2,SubAction2,SubstDiff,SubList]), fail ).

diff(A1,A2,Subst) :-
    diff(A1,A2,[],Subst).
diff(T,T,Subst,Subst) :- !.
diff(binary(B1),binary(B2),Subst,[binary(B2)-binary(B1)|Subst]) :- !.
diff(pid(B1),pid(B2),Subst,[pid(B2)-pid(B1)|Subst]) :- !.
diff(reference(B1),reference(B2),Subst,[reference(B2)-reference(B1)|Subst]) :- !.
diff(port(B1),port(B2),Subst,[port(B2)-port(B1)|Subst]) :- !.
diff(T1,T2,Subst,NewSubst) :-
    compound(T1), compound(T2),
    T1 =.. [Functor1|Args1], T2 =.. [Functor2|Args2],
    !,
    ( Functor1==Functor2 ->
      diffArgs(Args1,Args2,Subst,NewSubst);
      diff(Functor1,Functor2,Subst,NewSubst) ).
diff(T1,T2,Subst,[T2-T1|Subst]).
diffArgs([],[],Subst,Subst).
diffArgs([First1|Rest1],[First2|Rest2],Subst,NewSubst) :-
    diff(First1,First2,Subst,Subst1),
    diffArgs(Rest1,Rest2,Subst1,NewSubst).

update_assoc_from_diff(Subst,[],Subst).
update_assoc_from_diff(Subst,[From-To|Rest],NewSubst) :-
    update_assoc_from_diff(Subst,From,To,Subst1),
    update_assoc_from_diff(Subst1,Rest,NewSubst).

update_assoc_from_diff(Subst,From,To,NewSubst) :-
    From = binary(_), To = binary(_), !,
    put_assoc(From,Subst,To,NewSubst).
update_assoc_from_diff(Subst,From,To,NewSubst) :-
    From = reference(_), To = reference(_), !,
    put_assoc(From,Subst,To,NewSubst).
update_assoc_from_diff(Subst,From,To,NewSubst) :-
    From = pid(_), To = pid(_), !,
    put_assoc(From,Subst,To,NewSubst).
update_assoc_from_diff(Subst,From,To,NewSubst) :-
    From = port(_), To = port(_), !,
    put_assoc(From,Subst,To,NewSubst).
update_assoc_from_diff(_,From,To,_) :-
    format('Terms ~w and ~w are not identical.~n',[From,To]),
    fail.

pid_equal(Pid1,Pid2,Sub) :-
    ( get_assoc(Pid2,Sub,Pid1) ->
      true;
      assoc_to_list(Sub,SubList),
      format('Pids ~w and ~p do not match;~nsubst=~w.~n',[Pid1,Pid2,SubList]), fail ).

term_subst(pid(Pid),SubPid,Sub) :-
    try_subst(pid(Pid),SubPid,Sub), !.
term_subst(binary(Binary),SubBinary,Sub) :-
    subst(binary(Binary),SubBinary,Sub), !.
term_subst(binary(Binary),binary(SubBinary),Sub) :-
    binary_subst(Binary,SubBinary,Sub),
    !.
term_subst(Term,SubTerm,Sub) :-
    atomic(Term), !,
    try_subst(Term,SubTerm,Sub).
term_subst(Term,SubTerm,Sub) :-
    subst(Term,SubTerm,Sub), !.
term_subst(Term,SubTerm,Sub) :-
    Term =.. [Functor|Args],
    term_subst(Functor,SubFunctor,Sub),
    terms_subst(Args,SubArgs,Sub),
    SubTerm =.. [SubFunctor|SubArgs].

is_binary_subst(binary(_)-binary(_)).

strip_binaries(binary(B1)-binary(B2),B1-B2).

binary_subst(Binary,SubstBinary,Sub) :-
    assoc_to_list(Sub,SubList),
    include(is_binary_subst,SubList,Binaries),
    maplist(strip_binaries,Binaries,StrippedBinaries),
    !,
    rewrite(Binary,SubstBinary,StrippedBinaries).

%% Rewrite a binary using a set of substitutions, recursing over the binary reducing it in size
rewrite([],[],_).
rewrite(Binary,SubstBinary,Binaries) :-
    rewrite_here(Binary,Subst,RemainingBinary,Binaries),
    rewrite(RemainingBinary,NewSubst,Binaries),
    append(Subst,NewSubst,SubstBinary).
rewrite([First|Rest],[First|SubstBinary],Binaries) :-
    rewrite(Rest,SubstBinary,Binaries).

% Recurse over all possible substitutions, starting to rewrite at the first character of the binary
rewrite_here(Binary,SubstBinary,RemainingBinary,[From-To|_]) :-
    rewrite_here(Binary,SubstBinary,RemainingBinary,From,To).
rewrite_here(Binary,SubstBinary,RemainingBinary,[_|Rest]) :-
    rewrite_here(Binary,SubstBinary,RemainingBinary,Rest).

%% With a binary and a substitution, look for a prefix of the binary somewhere within the substitution.
rewrite_here(Binary,SubstBinary,RemainingBinary,From,To) :-
    rewrite_with_from(Binary,SubstBinary,RemainingBinary,From,To,0).
rewrite_here(Binary,SubstBinary,RemainingBinary,[_|RestFrom],[_|RestTo]) :-
    rewrite_here(Binary,SubstBinary,RemainingBinary,RestFrom,RestTo).

%% Match a prefix of the binary with a prefix of from, with length at least N (heuristic)
% end of binary
rewrite_with_from([],[],[],_,_,N) :-
    N >= 5.
% end of from
rewrite_with_from(Binary,[],Binary,[],_,N) :-
    N >= 5.
rewrite_with_from([First|Binary],[FirstTo|Subst],RemainingBinary,[First|RestFrom],[FirstTo|RestTo],N) :-
    N1 is N+1,
    rewrite_with_from(Binary,Subst,RemainingBinary,RestFrom,RestTo,N1).
rewrite_with_from(Binary,[],Binary,_,_,N) :-
    N >= 5.


terms_subst([],[],_).
terms_subst([T1|Rest],[SubT|SubRest],Sub) :-
    term_subst(T1,SubT,Sub),
    terms_subst(Rest,SubRest,Sub).

try_subst(T,SubT,Sub) :-
    subst(T,SubT,Sub), !.
try_subst(T,T,_).

subst(T,SubT,Sub) :-
    get_assoc(T,Sub,SubT).

dump_run([],_) :- !.
dump_run([process(_,_,Events)|Rest],Stream) :-
    !,
    dump_events(Events,Stream),
    dump_run(Rest,Stream).
dump_run(Other,_) :-
    format('*** ERROR: dump_run has an incorrect format:~n~w~n',[Other]),
    fail.

dump_events([],_) :- !.
dump_events([Event|Rest],Stream) :-
    !,
    format(Stream,'~w.~n',[Event]),
    dump_events(Rest,Stream).
dump_events(Other,_) :-
    format('*** ERROR: dump_events has an incorrect format:~n~w~n',[Other]),
    fail.

    

    
    
