-module(noise).

-compile(export_all).

-record(state,
        {
          s,e,rs,re,message_patterns,initiator, %% HandshakeState part
          ck,h,                                 %% Symmetric state
          k,n,                                  %% Cipher state
          hash_len=64,
          counter=0,
          message_buffer=[]                     %% Message buffer
        }).

-record(key,
        {private,public}).

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

  HS15 = mixHash(Prologue,HS1),

  PublicKeys = 
    extractPublicKeysFromPreMessages(Initiator, HandshakePattern),
  HS2 = 
    lists:foldl
      (fun (PublicKey,HSi) ->
           add_public_key(PublicKey,HSi) 
       end,
       HS15,PublicKeys),
  lists:foldl
    (fun (PublicKey,HSi) -> 
         mixHash(get_public_key(PublicKey,HSi),HSi) 
     end, 
     HS2, PublicKeys).

execute_message_pattern(Payloads,HS) ->
  case HS#state.message_patterns of
    [] ->
      HS;
    [MessagePattern|Rest] ->
      HS1 = HS#state{message_patterns=Rest},
      Initiator = HS#state.initiator,
      Messages = 
        case MessagePattern of
          {snd,Msgs} -> Msgs;
          {rcv,Msgs} -> Msgs
        end,
      IsSend =
        case MessagePattern of
          {snd,_} -> true;
          _ -> false
        end,
      if
        (IsSend and Initiator) or (not(IsSend) and not(Initiator)) ->
          writeMessages(Payloads,Messages,HS1);
        true ->
          readMessages(Payloads,Messages,HS1)
      end
  end.

writeMessages([],[],HS) ->
  HS;
  %% split
writeMessages(Payloads,[Message|Rest],HS) ->
  HSP =
    case Message of
      e ->
        {Key,HSK} = generate_keypair(HS),
        HS1 = set_key(e,Key,HSK),
        PubE = get_public_key(e,HS1),
        HS2 = message_append(PubE,HS1),
        mixHash(PubE,HS2);
      s ->
        {Term,HS1} = encryptAndHash(get_public_key(s,HS),HS),
        message_append(Term,HS1);
      ee ->
        {Term,HS1} = dh(e,re,HS),
        mixKey(Term,HS1);
      es ->
        {Term,HS1} = dh(e,rs,HS),
        mixKey(Term,HS1);
      se ->
        {Term,HS1} = dh(s,re,HS),
        mixKey(Term,HS1);
      ss ->
        {Term,HS1} = dh(s,rs,HS),
        mixKey(Term,HS1)
    end,
  {Payload,Payloads1} =
    case Payloads of
      [] -> {<<>>,[]};
      [First|Rest] -> {First,Rest}
    end,
  {EncryptedTerm,HSEAH} = encryptAndHash(Payload,HSP),
  writeMessages(Payloads1,Rest,message_append(EncryptedTerm,HSEAH)).

readMessages(Payloads,Messages,HS) ->
  HS.

message_append(Msg,HS) ->
  HS#state{message_buffer=HS#state.message_buffer++[Msg]}.

generate_keypair(HS) ->
  Counter = HS#state.counter,
  Key =
    #key
    {
      private=list_to_atom("ephemeral_private_"++integer_to_list(Counter)),
      public=list_to_atom("ephemeral_public_"++integer_to_list(Counter))
    },
  {Key,HS#state{counter=Counter+1}}.

dh(KeyName1,KeyName2,HS) ->
  {
    {dh,get_private_key(KeyName1,HS),get_public_key(KeyName2,HS)},
    HS
  }.

encryptAndHash(Text,HS) ->
  {CipherText,HS1} = encryptWithAd(HS#state.h,Text,HS),
  HSH = mixHash(CipherText,HS1),
  {CipherText,HSH}.

mixKey(InputKeyMaterial,HS) ->
  {H,HS1} = 'HKDF'(HS#state.ck, InputKeyMaterial, 2, HS),
  HS2 = HS#state{ck=H},
  TempK =
    if
      HS#state.hash_len==64 ->
        truncate(H,32);
      true ->
        H
    end,
  initializeKey(TempK,HS2).

encryptWithAd(Ad, PlainText, HS) ->
  K = HS#state.k,
  if
    K==empty -> 
      {PlainText,HS};
    true -> 
      N = HS#state.n,
      {{encrypt,K,N,Ad,PlainText},HS#state{n=N+1}}
  end.

truncate(Text,HS) ->
  {{truncate,[Text,32]},HS}.

get_private_key(KeyName,HS) ->
  (get_key(KeyName,HS))#key.public.

get_public_key(KeyName,HS) ->
  (get_key(KeyName,HS))#key.public.

get_key(KeyName,HS) ->
  if
    KeyName==s ->   
      HS#state.s;
    KeyName==e ->
      HS#state.e;
    KeyName==rs ->
      HS#state.rs;
    KeyName==re ->
      HS#state.re
  end.
    
set_key(KeyName,Value,HS) ->
  if
    KeyName==s ->   
      HS#state{s=Value};
    KeyName==e ->
      HS#state{e=Value};
    KeyName==rs ->
      HS#state{rs=Value};
    KeyName==re ->
      HS#state{re=Value}
  end.

initializeSymmetric(ProtocolName,HS) ->
  Hash = 
    if
      byte_size(ProtocolName) =< HS#state.hash_len ->
        pad_to_using(ProtocolName,HS#state.hash_len,0);
      true ->
        hash(ProtocolName)
    end,
  initializeKey(empty,HS#state{h=Hash,ck=Hash}).

initializeKey(Key,HS) ->
  HS#state{k=Key,n=0}.

assign_if_defined(Key,Value,HS) ->
  if
    Value =/= undefined ->
      add_public_key(Key,HS);
    true ->
      HS
  end.

add_public_private_key(KeyName,HS) ->
  PubName = list_to_atom("public_"++atom_to_list(KeyName)),
  PrivName = list_to_atom("private_"++atom_to_list(KeyName)),
  set_key(KeyName,#key{public=PubName,private=PrivName},HS).

add_public_key(PublicKey,HS) ->
  Name = list_to_atom("public_"++atom_to_list(PublicKey)),
  set_key(PublicKey,#key{public=Name},HS).

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

mixHash(Data,HS) ->
  HashValue = hash(merge(HS#state.h,Data)),
  HS#state{h = HashValue}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

'MERGE'(Term1,Term2) ->
  {?FUNCTIONNAME,Term1,Term2}.

'HASH'(Data) ->
  {?FUNCTIONNAME,Data}.

'PAD_TO_USING'(Term,Len,Pad) ->
  {?FUNCTIONNAME,Term,Len,Pad}.

'HKDF'(ChainingKey, InputKeyMaterial, NumOutputs, HS) ->
  TempKey = 'HMAC-HASH'(ChainingKey,InputKeyMaterial),
  Output1 = 'HMAC-HASH'(TempKey,16#1),
  Output2 = 'HMAC-HASH'(TempKey,merge(Output1,16#2)),
  if
    NumOutputs==2 ->
      {Output1,Output2};
    true ->
      Output3 = 'HMAC-HASH'(TempKey,merge(Output2,16#3)),
      {Output1,Output2,Output3}
  end.

'HMAC-HASH'(Key,Text) ->
  {?FUNCTIONNAME,[Key,Text]}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test() ->
  HS0 =
    initialize
      (
      xk_pattern(), 
      true, 
      <<"25519_ChaChaPoly_BLAKE2b">>, 
      <<0,8,0,0,3>>, 
      s, undefined, undefined, undefined
     ),
  execute_message_pattern([],HS0).



           


