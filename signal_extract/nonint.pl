isEvent(event(Pid,Event,Time)) :-
    event(Pid,Event,Time).

code(codes(Pid,Events)) :-
    events(Pid,UnsortedEvents),
    predsort(timeOrder,UnsortedEvents,Events).

pid(event(Pid,_,_), Pid).
time(event(_,_,TimeStamp),TimeStamp).
action(event(_,Action,_),Action).

isCallEvent(Event) :-
    action(Event,call(_,_,_)).
isReturnEvent(Event) :-
    action(Event,return_from(_,_,_,_)).

module(Event,M) :-
    action(Event,call(M,_,_)).

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

events(Pid,Events) :-
    bagof(Event, ( isEvent(Event), pid(Event,Pid) ), Events).
	    
low_events(low_events(Pid,LowEvents)) :-
    code(codes(Pid,Events)),
    include(is_low_event,Events,LowEvents).

is_low_event(Event) :-
    \+ isHighCallEvent(Event),
    \+ isReturnEvent(Event),
    !.

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

