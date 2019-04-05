-module(noise).

-compile(export_all).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% State definition, mixing handshake state, symmetric state,
%% and cipher state.
%%

-record(state,
        {
          k,
          n,
          ck,
          h,                     
          s,
          e,
          rs,
          re,
          message_patterns,
          initiator,
          hash_len=64,
          dh_len=32,
          block_len=128,
          dh_spec,cipher_spec,hash_spec,
          message_buffer=[],
          counter=0
        }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Functions
%%

% ----------------------------------------------------------------------

'DH'(KeyName1,KeyName2,State) ->
  {State#state.dh_spec,?FUNCTION_NAME,['PRIVATE-KEY'(KeyName1,State),'PUBLIC-KEY'(KeyName2,State)]}.

'DHLEN'(State,State) ->
  {State#state.dh_spec,?FUNCTION_NAME,State#state.dh_len}.

% ----------------------------------------------------------------------

'ENCRYPT'(K,N,Ad,PlainText,State) ->
  {State#state.cipher_spec,?FUNCTION_NAME,[K,N,Ad,PlainText]}.

'DECRYPT'(K,N,Ad,CipherText,State) ->
  {State#state.cipher_spec,?FUNCTION_NAME,[K,N,Ad,CipherText]}.

'REKEY'(K,State) ->
  {State#state.cipher_spec,?FUNCTION_NAME,[K]}.

% ----------------------------------------------------------------------

'HASH'(Data,State) ->
  {State#state.hash_spec,?FUNCTION_NAME,Data}.

'HASHLEN'(State) ->
  {State#state.hash_spec,?FUNCTION_NAME, [State#state.hash_len]}.

'BLOCKLEN'(State) ->
  {State#state.hash_spec,?FUNCTION_NAME,[State#state.block_len]}.

'HMAC-HASH'(Key,Text,State) ->
  {State#state.hash_spec,?FUNCTION_NAME,[Key,Text]}.

'HKDF'(ChainingKey,InputKeyMaterial,NumOutputs,State) ->
  TempKey = 'HMAC-HASH'(ChainingKey,InputKeyMaterial,State),
  Output1 = 'HMAC-HASH'(TempKey,16#1,State),
  Output2 = 'HMAC-HASH'(TempKey,'MERGE'(Output1,16#2),State),
  if
    NumOutputs==2 ->
      {Output1,Output2};
    true ->
      Output3 = 'HMAC-HASH'(TempKey,'MERGE'(Output2,16#3),State),
      {Output1,Output2,Output3}
  end.

% ----------------------------------------------------------------------

'PRIVATE-KEY'(KeyName,State) ->
  {?FUNCTION_NAME,[get_key(KeyName,State)]}.

'PUBLIC-KEY'(KeyName,State) ->
  {?FUNCTION_NAME,[get_key(KeyName,State)]}.

% ----------------------------------------------------------------------

'MERGE'(Term1,Term2) ->
  {?FUNCTION_NAME,Term1,Term2}.

'PAD_TO_USING'(Term,Len,Pad) ->
  {?FUNCTION_NAME,Term,Len,Pad}.

'TRUNCATE'(Text,Size) ->
  {?FUNCTION_NAME,[Text,Size]}.

% ----------------------------------------------------------------------

%% CipherState functions

initializeKey(Key,State) ->
  State#state{k=Key,n=0}.

hasKey(State) ->
  State#state.k =/= empty.

setNonce(Nonce,State) ->
  State#state{n = Nonce}.

encryptWithAd(Ad,PlainText,State) ->
  K = State#state.k,
  if
    K==empty -> 
      {PlainText,State};
    true -> 
      N = State#state.n,
      {'ENCRYPT'(K,N,Ad,PlainText,State),State#state{n=N+1}}
  end.

decryptWithAd(Ad,CipherText,State) ->
  K = State#state.k,
  if
    K==empty -> 
      {CipherText,State};
    true -> 
      N = State#state.n,
      {'DECRYPT'(K,N,Ad,CipherText,State),State#state{n=N+1}}
  end.

% ----------------------------------------------------------------------

%% SymmetricState functions

initializeSymmetric(ProtocolName,State) ->
  Hash = 
    if
      byte_size(ProtocolName) =< State#state.hash_len ->
        'PAD_TO_USING'(ProtocolName,State#state.hash_len,0);
      true ->
        'HASH'(ProtocolName,State)
    end,
  initializeKey
    (empty,
     State#state
     {
       h = Hash,
       ck = Hash
     }).

mixKey(InputKeyMaterial,State) ->
  {CK,TempK} = 'HKDF'(State#state.ck,InputKeyMaterial,2,State),
  NewState = State#state{ck=CK},
  NewTempK =
    if
      State#state.hash_len==64 ->
        'TRUNCATE'(TempK,32);
      true ->
        TempK
    end,
  initializeKey(NewTempK,NewState).

mixHash(Data,State) ->
  HashValue = 'HASH'('MERGE'(State#state.h,Data),State),
  State#state{h = HashValue}.

mixKeyAndHash(InputKeyMaterial,State) ->
  ok.

getHandshakeHash(State) ->
  h.

encryptAndHash(Text,State) ->
  {CipherText,State1} = encryptWithAd(State#state.h,Text,State),
  StateH = mixHash(CipherText,State1),
  {CipherText,StateH}.

decryptAndHash(Text,State) ->
  {CipherText,State1} = encryptWithAd(State#state.h,Text,State),
  StateH = mixHash(CipherText,State1),
  {CipherText,StateH}.

split() ->
  hs.

% ----------------------------------------------------------------------

%% HandshakeState functions

initialize(ProtocolName,HandshakePattern,Initiator,Prologue,S,E,RS,RE,State) ->
  State1 =
    initializeSymmetric
      (ProtocolName,
       State#state
       {
         initiator=Initiator,
         message_patterns = messagePatterns(HandshakePattern)
       }),

  State2 = assign_if_defined(s,S,State1),
  State3 = assign_if_defined(e,E,State2),
  State4 = assign_if_defined(rs,RS,State3),
  State5 = assign_if_defined(re,RE,State4),

  State6 = mixHash(Prologue,State5),

  PublicKeys = 
    extractPublicKeysFromPreMessages(Initiator, HandshakePattern),

  State7 = 
    lists:foldl
      (fun (PublicKey,S) ->
           add_key(PublicKey,{public_key,PublicKey},S) 
       end,
       State6,PublicKeys),
  lists:foldl
    (fun (PublicKey,S) -> 
         mixHash('PUBLIC-KEY'(PublicKey,S),S) 
     end, 
     State7, PublicKeys).

writeMessages([],[],State) ->
  State;
writeMessages(Payloads,[Message|Rest],State) ->
  StateP =
    case Message of
      e ->
        {Key,State0} = generateKeyPair(State),
        State1 = set_key(e,Key,State0),
        PubE = 'PUBLIC-KEY'(e,State1),
        State2 = message_append(PubE,State1),
        mixHash(PubE,State2);
      s ->
        {Term,State1} = encryptAndHash('PUBLIC-KEY'(s,State),State),
        message_append(Term,State1);
      ee ->
        Term = 'DH'(e,re,State),
        mixKey(Term,State);
      es ->
        Term = 
          if
            State#state.initiator ->
              'DH'(e,rs,State);
            true ->
              'DH'(s,re,State)
          end,
        mixKey(Term,State);
      se ->
        Term = 
          if
            State#state.initiator ->
              'DH'(s,re,State);
            true ->
              'DH'(e,rs,State)
          end,
        mixKey(Term,State);
      ss ->
        Term = 'DH'(s,rs,State),
        mixKey(Term,State)
    end,
  {Payload,Payloads1} =
    case Payloads of
      [] -> {<<>>,[]};
      [First|Rest] -> {First,Rest}
    end,
  {EncryptedTerm,StateEAH} = encryptAndHash(Payload,StateP),
  writeMessages(Payloads1,Rest,message_append(EncryptedTerm,StateEAH)).

readMessages(Payloads,Messages,State) ->
  State.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

assign_if_defined(Key,Value,State) ->
  if
    Value =/= undefined ->
      add_key(Key,{key_pair,Key},State);
    true ->
      State
  end.

execute_message_pattern(Payloads,State) ->
  case State#state.message_patterns of
    [] ->
      State;
    [MessagePattern|Rest] ->
      State1 = State#state{message_patterns=Rest},
      Initiator = State#state.initiator,
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
          writeMessages(Payloads,Messages,State1);
        true ->
          readMessages(Payloads,Messages,State1)
      end
  end.

get_key(KeyName,State) ->
  if
    KeyName==s ->   
      State#state.s;
    KeyName==e ->
      State#state.e;
    KeyName==rs ->
      State#state.rs;
    KeyName==re ->
      State#state.re
  end.
    
set_key(KeyName,Value,State) ->
  if
    KeyName==s ->   
      State#state{s=Value};
    KeyName==e ->
      State#state{e=Value};
    KeyName==rs ->
      State#state{rs=Value};
    KeyName==re ->
      State#state{re=Value}
  end.

% ----------------------------------------------------------------------

message_append(Msg,State) ->
  State#state{message_buffer=State#state.message_buffer++[Msg]}.

add_key(KeyName,Key,State) ->
  set_key(KeyName,Key,State).

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

generateKeyPair(State) ->
  Counter = State#state.counter,
  {
    {ephemeral_key_pair, {Counter,State#state.initiator}}, 
    State#state{counter=Counter+1}
  }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init(ProtoSpec,Initiator,Prologue, S, E, RS, RE) ->
  {ProtocolName, HandshakePattern, InitState} = parseProtocolSpec(ProtoSpec),
  initialize(ProtocolName, HandshakePattern, Initiator, Prologue, S, E, RS, RE, InitState).

parseProtocolSpec({PatternName,DHSpec,CipherSpec,HashSpec}) ->
  ProtocolName = PatternName++"_"++DHSpec++"_"++CipherSpec++"_"++HashSpec,
  HandshakePattern = find_handshake_pattern(PatternName),
  {
    list_to_binary(ProtocolName), 
    HandshakePattern,
    #state
    {
      dh_spec = list_to_atom(DHSpec),
      cipher_spec = list_to_atom(CipherSpec),
      hash_spec = list_to_atom(HashSpec)
    }
  }.

find_handshake_pattern(HandshakeName) ->
  if
    HandshakeName == "XK" ->
      {
        [{rcv,[s]}],
        [
         {snd,[e,es]},
         {rcv,[e,ee]},
         {snd,[s,se]}
        ]
      }
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test() ->
  State0 =
    init
      (
      {"XK","25519","ChaChaPoly","BLAKE2b"},
      true, 
      <<0,8,0,0,3>>, 
      s, undefined, undefined, undefined
     ),
  State = execute_message_pattern([],State0),
  io:format("~p~n",[State#state.message_buffer]).



           


