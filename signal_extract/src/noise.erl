-module(noise).

-compile(export_all).

-record(state,
        {
          s,e,rs,re,message_patterns,initiator, %% HandshakeState part
          ck,h,                                 %% Symmetric state
          k,n,                                  %% Cipher state
          hash_len=64,
          message_buffer=[],                    %% Message buffer
          binaries=[],                          %% Binaries
          binary_counter=0                      %% For generating binaries
        }).

-record(binary,
        {
          id=undefined,
          value=undefined
        }).

%% We want to symbolically execute a pattern, recording the computations 
%% as a set of boolean bindings.

initialize(HandshakePattern, Initiator, CryptoOps, Prologue, S, E, RS, RE) ->
  HS0 = 
    initializeSymmetric
      (deriveProtocolName(HandshakePattern,CryptoOps),#state{}),
  HS11 = 
    HS0#state
    {
      initiator=Initiator,
      message_patterns = messagePatterns(HandshakePattern)
    },
  HS12 = assign_if_defined(s,S,HS11),
  HS13 = assign_if_defined(e,E,HS12),
  HS14 = assign_if_defined(rs,RS,HS13),
  HS1 = assign_if_defined(re,RE,HS14),

  PublicKeys = 
    extractPublicKeysFromPreMessages(Initiator, HandshakePattern),
  HS2 = 
    lists:foldl
      (fun (PublicKey,HSi) ->
           add_public_key(PublicKey,HSi) 
       end,
       HS1,PublicKeys),
  lists:foldl
    (fun (PublicKey,HSi) -> 
         mixHash(get_key(PublicKey,HSi),HSi) 
     end, 
     HS2, PublicKeys).

get_key(PublicKey,HS) ->
  if
    PublicKey==s ->   
      HS#state.s;
    PublicKey==e ->
      HS#state.e;
    PublicKey==rs ->
      HS#state.rs;
    PublicKey==re ->
      HS#state.re
  end.
    
set_key(PublicKey,Value,HS) ->
  if
    PublicKey==s ->   
      HS#state{s=Value};
    PublicKey==e ->
      HS#state{e=Value};
    PublicKey==rs ->
      HS#state{rs=Value};
    PublicKey==re ->
      HS#state{re=Value}
  end.

initializeSymmetric(ProtocolName,HS) ->
  Hash = hash(pad_to_using(ProtocolName,HS#state.hash_len,0)),
  initializeKey(undefined,HS#state{h=Hash,ck=Hash}).

initializeKey(Key,HS) ->
  HS#state{k=Key,n=0}.

assign_if_defined(Key,Value,HS) ->
  if
    Value =/= undefined ->
      add_public_key(Key,HS);
    true ->
      HS
  end.

add_public_key(PublicKey,HS) ->
  Name = list_to_atom("public_"++atom_to_list(PublicKey)),
  {Binary,HS1} = add_binary(Name,HS),
  set_key(PublicKey,Binary,HS1).

add_binary(Value,HS) ->
  Counter = HS#state.binary_counter,
  Binary = #binary{id=Counter,value=Value},
  {
    Binary,
    HS#state
    {binary_counter=Counter+1,
     binaries=[Binary|HS#state.binaries]}
  }.

deriveProtocolName(Pattern,CryptoOps) ->
  MessagePatternName = findPattern(Pattern),
  <<MessagePatternName/binary,"_":8,CryptoOps/binary>>.

findPattern(Pattern) ->
  case Pattern==xk_pattern() of
    true ->
      <<"XK">>
  end.

xk_pattern() ->
  {
    [{rcv,[s]}],
    [
     {snd,[e,es]},
     {rcv,[e,ee]},
     {snd,[s,se]}
    ]
  }.

extractPublicKeysFromPreMessages(Initiator,HandshakePattern) ->  
  {PreMessages, _} = HandshakePattern,
  InitiatorKeys = extractPublicKeys(Initiator,PreMessages,snd),
  ResponderKeys = extractPublicKeys(Initiator,PreMessages,rcv),
  InitiatorKeys ++ ResponderKeys.

extractPublicKeys(Initiator,PreMessages,Role) ->
  lists:foldr
    (fun (PreMessage,Acc) ->
         case PreMessage of
           {Role,Keys} -> 
             lists:map(fun (Key) -> key_type(Key,Role,Initiator) end,Keys)
               ++Acc;
           _ ->
             Acc
         end
     end, [], PreMessages).

key_type(Key,snd,true) ->
  Key;
key_type(Key,snd,false) ->
  remote_key(Key);
key_type(Key,rcv,true) ->
  remote_key(Key);
key_type(Key,rcv,false) ->
  Key.

remote_key(s) ->
  rs;
remote_key(e) ->
  re.

messagePatterns({_,Patterns}) ->
  Patterns.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Each of the basic cryptographic operations:
%% mixHash, mixkey, dh, ..., return a new boolean

mixHash(Data,HS) ->
  HashValue = hash(merge(HS#state.h,Data)),
  {_Binary,HS1} = add_binary(HashValue,HS),
  HS1#state{h = HashValue}.

merge(Binary1,Binary2) ->
  {merge,Binary1,Binary2}.

hash(Data) ->
  {hash,Data}.

pad_to_using(Binary,Len,Pad) ->
  {pad,Binary,Len,Pad}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test() ->
  initialize
    (
    xk_pattern(), 
    true, 
    <<"25519_ChaChaPoly_BLAKE2b">>, 
    <<0,8,0,0,3>>, 
    s, undefined, undefined, undefined
   ).

           


