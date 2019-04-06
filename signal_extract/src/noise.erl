-module(noise).

-export([test/0]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-record(cipherState,
        {
          k,
          n
        }).

-record(symmetricState,
        {
          ck,
          h,                     
          cipherState = #cipherState{}
        }).

-record(handshakeState,
        {
          s,
          e,
          rs,
          re,
          initiator,
          output_buffer=[],
          input_buffer,
          payload_buffer=[],
          counter=0,  %% Numbering local ephemeral key pairs
          symmetricState = #symmetricState{}
        }).

-record(state,
        {
          hash_len,
          dh_len,
          block_len,
          dh_spec,
          cipher_spec,
          hash_spec,
          counter=0,  %% numbering read operations
          handshakeState = #handshakeState{}
        }).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% Functions
%%

% ----------------------------------------------------------------------

'DH'(KeyName1,KeyName2) ->
  {?FUNCTION_NAME,['PRIVATE-KEY'(KeyName1),'PUBLIC-KEY'(KeyName2)]}.

'DHLEN'() ->
  {?FUNCTION_NAME,[]}.

% ----------------------------------------------------------------------

'ENCRYPT'(K,N,Ad,PlainText) ->
  {?FUNCTION_NAME,[K,N,Ad,PlainText]}.

'DECRYPT'(K,N,Ad,CipherText) ->
  {?FUNCTION_NAME,[K,N,Ad,CipherText]}.

'REKEY'(K) ->
  {?FUNCTION_NAME,[K]}.

% ----------------------------------------------------------------------

'HASH'(Data) ->
  {?FUNCTION_NAME, [Data]}.

'HASHLEN'() ->
  {?FUNCTION_NAME, []}.

'BLOCKLEN'() ->
  {?FUNCTION_NAME,[]}.

'HMAC-HASH'(Key,Text) ->
  {?FUNCTION_NAME,[Key,Text]}.

'HKDF'(ChainingKey,InputKeyMaterial,NumOutputs) ->
  TempKey = 'HMAC-HASH'(ChainingKey,InputKeyMaterial),
  Output1 = 'HMAC-HASH'(TempKey,16#1),
  Output2 = 'HMAC-HASH'(TempKey,'MERGE'(Output1,16#2)),
  if
    NumOutputs==2 ->
      {Output1,Output2};
    true ->
      Output3 = 'HMAC-HASH'(TempKey,'MERGE'(Output2,16#3)),
      {Output1,Output2,Output3}
  end.

% ----------------------------------------------------------------------

'PRIVATE-KEY'(KeyName) ->
  {?FUNCTION_NAME,[KeyName]}.

'PUBLIC-KEY'(KeyName) ->
  {?FUNCTION_NAME,[KeyName]}.

'GENERATE_KEYPAIR'(Counter) ->
  {?FUNCTION_NAME,[Counter]}.

'LOCAL_EPHEMERAL'() ->
  {?FUNCTION_NAME,[]}.

'REMOTE_EPHEMERAL'() ->
  {?FUNCTION_NAME,[]}.

'LOCAL_STATIC'() ->
  {?FUNCTION_NAME,[]}.

'REMOTE_STATIC'() ->
  {?FUNCTION_NAME,[]}.

'INPUT_BUFFER'(N) ->
  {?FUNCTION_NAME,[N]}.

'READ'(N,Loc) ->
  {?FUNCTION_NAME,[N,Loc]}.
  
'SKIP'(N,Loc) ->
  {?FUNCTION_NAME,[N,Loc]}.

'SIZE'(Loc) ->
  {?FUNCTION_NAME,[Loc]}.

% ----------------------------------------------------------------------

'IF'(Condition,Expr1,Expr2) ->
  {?FUNCTION_NAME,[Condition,Expr1,Expr2]}.

'EQ'(Expr1,Expr2) ->
  {?FUNCTION_NAME,[Expr1,Expr2]}.

'LEQ'(Expr1,Expr2) ->
  {?FUNCTION_NAME,[Expr1,Expr2]}.

'MERGE'(Term1,Term2) ->
  {?FUNCTION_NAME,[Term1,Term2]}.

'PAD_TO_USING'(Term,Len,Pad) ->
  {?FUNCTION_NAME,[Term,Len,Pad]}.

'TRUNCATE'(Text,Size) ->
  {?FUNCTION_NAME,[Text,Size]}.

% ----------------------------------------------------------------------

%% CipherState functions

initializeKey(Key) ->
  #cipherState{k=Key,n=0}.

hasKey(CipherState) ->
  CipherState#cipherState.k =/= empty.

setNonce(Nonce,CipherState) ->
  CipherState#cipherState{n = Nonce}.

encryptWithAd(Ad,PlainText,CipherState) ->
  K = CipherState#cipherState.k,
  if
    K==empty -> 
      {PlainText,CipherState};
    true -> 
      N = CipherState#cipherState.n,
      {'ENCRYPT'(K,N,Ad,PlainText),CipherState#cipherState{n=N+1}}
  end.

decryptWithAd(Ad,CipherText,CipherState) ->
  K = CipherState#cipherState.k,
  if
    K==empty -> 
      {CipherText,CipherState};
    true -> 
      N = CipherState#cipherState.n,
      {'DECRYPT'(K,N,Ad,CipherText),CipherState#cipherState{n=N+1}}
  end.

% ----------------------------------------------------------------------

%% SymmetricState functions

return_and_modify_cipherState(F,SymmetricState) ->
  {Term,CS} = F(SymmetricState#symmetricState.cipherState),
  {Term,SymmetricState#symmetricState{cipherState=CS}}.

initializeSymmetric(ProtocolName) ->
  Hash = 
    'IF'('LEQ'(byte_size(ProtocolName),'HASHLEN'()),
         'PAD_TO_USING'(ProtocolName,'HASHLEN'(),0),
         'HASH'(ProtocolName)),
  #symmetricState
    {
     h = Hash,
     ck = Hash,
     cipherState = initializeKey(empty)
    }.

mixKey(InputKeyMaterial,SymmetricState) ->
  {CK,TempK} = 'HKDF'(SymmetricState#symmetricState.ck,InputKeyMaterial,2),
  NewSymmetricState = SymmetricState#symmetricState{ck=CK},
  NewTempK =
    'IF'('EQ'('HASHLEN',64),
        'TRUNCATE'(TempK,32),
         TempK),
  NewSymmetricState#symmetricState{cipherState=initializeKey(NewTempK)}.

mixHash(Data,SymmetricState) ->
  HashValue = 'HASH'('MERGE'(SymmetricState#symmetricState.h,Data)),
  SymmetricState#symmetricState{h = HashValue}.

mixKeyAndHash(InputKeyMaterial,SymmetricState) ->
  ok.

getHandshakeHash(SymmetricState) ->
  h.

encryptAndHash(PlainText,SymmetricState) ->
  {CipherText,SymmetricState1} = 
    return_and_modify_cipherState
      (fun (CS) -> encryptWithAd(SymmetricState#symmetricState.h,PlainText,CS) end,
      SymmetricState),
  SymmetricStateH = mixHash(CipherText,SymmetricState1),
  {CipherText,SymmetricStateH}.

decryptAndHash(CipherText,SymmetricState) ->
  {PlainText,SymmetricState1} = 
    return_and_modify_cipherState
      (fun (CS) -> decryptWithAd(SymmetricState#symmetricState.h,CipherText,CS) end,
       SymmetricState),
  SymmetricStateH = mixHash(CipherText,SymmetricState1),
  {PlainText,SymmetricStateH}.

split(SymmetricState) ->
  {Temp_K1, Temp_K2} = 'HKDF'(SymmetricState#symmetricState.ck, <<>>, 2),
  NewTemp_K1 = 
    'IF'('EQ'('HASHLEN',64),
        'TRUNCATE'(Temp_K1,32),
         Temp_K1),
  NewTemp_K2 = 
    'IF'('EQ'('HASHLEN',64),
        'TRUNCATE'(Temp_K2,32),
         Temp_K2),
  {
    initializeKey(NewTemp_K1), 
    initializeKey(NewTemp_K2)
  }.

% ----------------------------------------------------------------------

%% HandshakeState functions

modify_symmetricState(F,HandshakeState) ->
  SS = F(HandshakeState#handshakeState.symmetricState),
  HandshakeState#handshakeState{symmetricState=SS}.

return_and_modify_symmetricState(F,HandshakeState) ->
  {Term,SS} = F(HandshakeState#handshakeState.symmetricState),
  {Term,HandshakeState#handshakeState{symmetricState=SS}}.

initialize(ProtocolName,Handshake,Initiator,Prologue,S,E,RS,RE) ->
  HandshakeState =
    #handshakeState
    {
      initiator=Initiator,
      symmetricState = initializeSymmetric(ProtocolName)
    },

  HandshakeState2 = HandshakeState#handshakeState{s=S},
  HandshakeState3 = HandshakeState2#handshakeState{e=E},
  HandshakeState4 = HandshakeState3#handshakeState{rs=RS},
  HandshakeState5 = HandshakeState4#handshakeState{re=RE},

  HandshakeState6 = 
    modify_symmetricState
      (fun (SS) -> mixHash(Prologue,SS) end,
       HandshakeState5),

  PublicKeys = 
    extractPublicKeysFromPreMessages(Initiator, Handshake),

  HandshakeState7 = 
    lists:foldl
      (fun (Key,AccHandshakeState) ->
           if
             Key==s -> AccHandshakeState#handshakeState{s='LOCAL_STATIC'()};
             Key==e -> AccHandshakeState#handshakeState{e='LOCAL_EPHEMERAL'()};
             Key==rs -> AccHandshakeState#handshakeState{rs='REMOTE_STATIC'()};
             Key==re -> AccHandshakeState#handshakeState{rs='REMOTE_EPHEMERAL'()}
           end
       end,
       HandshakeState6,PublicKeys),

  lists:foldl
    (fun (PublicKey,AccHandshakeState) -> 
         modify_symmetricState
           (fun (SS) -> mixHash('PUBLIC-KEY'(PublicKey),SS) end,
            AccHandshakeState) 
     end, 
     HandshakeState7, PublicKeys).

writeMessage(Message,HS) ->
  IsInitiator = HS#handshakeState.initiator,
  case Message of
    e ->
      {Key,HS0} = generateEmpheralKeyPair(HS),
      HS1 = HS0#handshakeState{e=Key},
      PubE = 'PUBLIC-KEY'(HS1#handshakeState.e),
      HS2 = message_append(PubE,HS1),
      modify_symmetricState(fun (SS) -> mixHash(PubE,SS) end, HS2);
    s ->
      {Term,HS1} = 
        return_and_modify_symmetricState
          (fun (SS) -> encryptAndHash('PUBLIC-KEY'(HS#handshakeState.s),SS) end,
           HS),
      message_append(Term,HS1);
    ee ->
      Term = 'DH'(HS#handshakeState.e,HS#handshakeState.re),
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    es ->
      Term = 
        if
          IsInitiator ->
            'DH'(HS#handshakeState.e,HS#handshakeState.rs);
          true ->
            'DH'(HS#handshakeState.s,HS#handshakeState.re)
        end,
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    se ->
      Term = 
        if
          IsInitiator ->
            'DH'(HS#handshakeState.s,HS#handshakeState.re);
          true ->
            'DH'(HS#handshakeState.e,HS#handshakeState.rs)
        end,
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    ss ->
      Term = 'DH'(HS#handshakeState.s,HS#handshakeState.rs),
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS)
  end.

writeMessages([],Payload,HandshakeState) ->
  {EncryptedTerm,HandshakeStateEAH} = 
    return_and_modify_symmetricState
      (fun (SS) -> encryptAndHash(Payload,SS) end, HandshakeState),
  message_append(EncryptedTerm,HandshakeStateEAH);
writeMessages([Message|Messages],Payload,HandshakeState) ->
  HS = writeMessage(Message,HandshakeState),
  writeMessages(Messages,Payload,HS).

message_append(Msg,HandshakeState) ->
  HandshakeState#handshakeState
    {output_buffer=HandshakeState#handshakeState.output_buffer++[Msg]}.

readMessage(Message,HS) ->
  IsInitiator = HS#handshakeState.initiator,
  case Message of
    e ->
      if
        HS#handshakeState.re == undefined ->
          HS0 = HS#handshakeState
            {
              re = 'READ'('DHLEN'(),HS#handshakeState.input_buffer),
              input_buffer = 'SKIP'('DHLEN'(),HS#handshakeState.input_buffer)
            },
          modify_symmetricState
            (fun (SS) -> mixHash('PUBLIC-KEY'(HS0#handshakeState.re),SS) end, 
             HS0)
      end;
    s ->
      CS = (HS#handshakeState.symmetricState)#symmetricState.cipherState,
      NumBytes = 'IF'(hasKey(CS),'DHLEN'()+16,'DHLEN'),
      Temp = 'READ'(NumBytes,HS#handshakeState.input_buffer),
      if
        HS#handshakeState.rs == undefined ->
          {DecryptedTerm,HS0} = 
            return_and_modify_symmetricState
              (fun (SS) -> decryptAndHash(Temp,SS) end, HS),
          HS0#handshakeState
            {
            rs=DecryptedTerm,
            input_buffer='SKIP'('DHLEN'(),HS#handshakeState.input_buffer)
           }
      end;
    ee ->
      Term = 'DH'(HS#handshakeState.e,HS#handshakeState.re),
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    es ->
      Term =
        if
          IsInitiator ->
            'DH'(HS#handshakeState.e,HS#handshakeState.rs);
          true ->
            'DH'(HS#handshakeState.s,HS#handshakeState.re)
        end,
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    se ->
      Term =
        if
          IsInitiator ->
            'DH'(HS#handshakeState.s,HS#handshakeState.re);
          true ->
            'DH'(HS#handshakeState.e,HS#handshakeState.rs)
        end,
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS);
    ss ->
      Term = 'DH'(HS#handshakeState.s,HS#handshakeState.rs),
      modify_symmetricState(fun (SS) -> mixKey(Term,SS) end, HS)
  end.

readMessages([],HS) ->
  InputBuffer = HS#handshakeState.input_buffer,
  PayloadToDecrypt = 'READ'('SIZE'(InputBuffer),InputBuffer),
  {DecryptedTerm,HS0} = 
    return_and_modify_symmetricState
      (fun (SS) -> decryptAndHash(PayloadToDecrypt,SS) end, HS),
  HS0#handshakeState{payload_buffer=DecryptedTerm};
readMessages([Message|Messages],HandshakeState) ->
  HS = readMessage(Message,HandshakeState),
  readMessages(Messages,HS).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

execute_handshake(ProtocolName,Initiator,Prologue,{S,E,RS,RE},Handshake,Payloads) ->
  State = #state{handshakeState=initialize(ProtocolName,Handshake,Initiator,Prologue,S,E,RS,RE)},
  {_PreHandshake,CommHandshake} = split_handshake(Handshake),
  execute_handshake(CommHandshake,Payloads,State).

execute_handshake([],_Payloads,State) ->
  HS = State#state.handshakeState,
  SS = HS#handshakeState.symmetricState,
  {[], split(SS), State};
execute_handshake([MessagePattern|RestMessagePatterns],Payloads,State) ->
  {Payload,RestPayloads} = 
    case Payloads of
      [FPayload|RPayloads] ->
        {FPayload,RPayloads};
      [] ->
        {[],[]}
    end,
  {Result,NewState} = 
    execute_message_pattern(MessagePattern,Payload,State),
  {Results,Split,FinalState} = 
    execute_handshake(RestMessagePatterns,RestPayloads,NewState),
  {[Result|Results],Split,FinalState}.

execute_message_pattern(MessagePattern,Payload,State) ->
  HS = State#state.handshakeState,
  IsInitiator = HS#handshakeState.initiator,
  Messages = 
    case MessagePattern of
      {snd,Msgs} -> Msgs;
      {rcv,Msgs} -> Msgs
    end,
  IsSender =
    case MessagePattern of
      {snd,_} -> true;
      _ -> false
    end,
  IsWriter = 
    (IsSender and IsInitiator) or (not(IsSender) and not(IsInitiator)),
  if
    IsWriter -> 
      HS1 = writeMessages(Messages,Payload,HS),
      {
        {wrote,HS1#handshakeState.output_buffer}, 
        State#state{handshakeState = HS1#handshakeState{output_buffer=[]}}
      };
    true -> 
      ReadCounter = State#state.counter,
      HS1 = HS#handshakeState{input_buffer = 'INPUT_BUFFER'(ReadCounter)},
      HS2 = readMessages(Messages,HS1),
      {
        {read,HS2#handshakeState.payload_buffer},
        State#state{handshakeState = HS2#handshakeState{input_buffer=undefined,payload_buffer=[]}}
      }
  end.

% ----------------------------------------------------------------------

extractPublicKeysFromPreMessages(Initiator,HandshakePattern) ->  
  {PreMessages,_} = split_handshake(HandshakePattern),
  InitiatorKeys = extractPublicKeys(Initiator,PreMessages,snd),
  ResponderKeys = extractPublicKeys(Initiator,PreMessages,rcv),
  InitiatorKeys ++ ResponderKeys.

extractPublicKeys(Initiator,PreMessages,Role) ->
  lists:foldr
    (fun (PreMessage,Acc) ->
         case PreMessage of
           {Role,Keys} -> 
             lists:map(fun (Key) -> key_type(Key,Role,Initiator) end, Keys)
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

generateEmpheralKeyPair(HandshakeState) ->
  Counter = HandshakeState#handshakeState.counter,
  {
    'GENERATE_KEYPAIR'(Counter),
    HandshakeState#handshakeState{counter=Counter+1}
  }.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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

split_handshake(Handshake) ->
  Handshake.

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
  {ProtocolName, Handshake, _InitialState} = 
    parseProtocolSpec({"XK","25519","ChaChaPoly","BLAKE2b"}),
  Prologue = 
    <<0,8,0,0,3>>,
  Initiator = 
    true,
  {Results,{CS1,CS2},State} =
    execute_handshake(ProtocolName,Initiator,Prologue,{s,undefined,undefined,undefined},Handshake,[]),
  io:format("~n~nResults:~n"),
  lists:foreach
    (fun (Result) ->
         io:format("~p~n~n",[Result])
     end, Results),
  io:format
    ("~nCS1:~n~p~n",
     [CS1]),
  io:format
    ("~nCS2:~n~p~n",
     [CS2]),
  io:format
    ("~nFinal state:~n~p~n",
     [State]).



