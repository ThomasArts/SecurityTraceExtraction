-module(noise).

-export([test/0]).
%% -export(['MERGE'/2]).

%%-define(debug,true).
-ifdef(debug).
-define(LOG(X,Y),
	io:format("~p(~p): ~s",[?MODULE,self(),io_lib:format(X,Y)])).
-else.
-define(LOG(X,Y),true).
-endif.

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
          counter=0,  %% numbering read operations
          payload_counter=0, %% numbering payload
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

'XOR'(B1,B2) ->
  {?FUNCTION_NAME,[B1,B2]}.

%% MERGE is || in the Noise sepcification
'HMAC-HASH'(Key,Text) ->
  Key1 = 'PAD_TO_USING'(Key,'BLOCKLEN'(),0),
  OPad = 'PAD_TO_USING'(<<>>,'BLOCKLEN'(),16#5c),
  IPad = 'PAD_TO_USING'(<<>>,'BLOCKLEN'(),16#36),
  Hash1 = 'HASH'('MERGE'('XOR'(Key1,IPad),Text)),
  Hash2 = 'HASH'('MERGE'('XOR'(Key1,OPad),Hash1)),
  Hash2.

'HKDF'(ChainingKey,InputKeyMaterial,NumOutputs) ->
  TempKey = 'HMAC-HASH'(ChainingKey,InputKeyMaterial),
  Output1 = 'HMAC-HASH'(TempKey,<<16#1>>),
  Output2 = 'HMAC-HASH'(TempKey,'MERGE'(Output1,<<16#2>>)),
  if
    NumOutputs==2 ->
      {Output1,Output2};
    true ->
      Output3 = 'HMAC-HASH'(TempKey,'MERGE'(Output2,<<16#3>>)),
      {Output1,Output2,Output3}
  end.

% ----------------------------------------------------------------------

%% Nondeterministic functions, which are made deterministic through
%% the introduction of a unique (counter) argument.

'GENERATE_KEYPAIR'(Counter) ->
  {?FUNCTION_NAME,[Counter]}.

% ----------------------------------------------------------------------

'PROTOCOL-NAME'() ->
  {?FUNCTION_NAME,[]}.

'PRIVATE-KEY'(KeyName) ->
  {?FUNCTION_NAME,[KeyName]}.

'PUBLIC-KEY'(KeyName) ->
  {?FUNCTION_NAME,[KeyName]}.

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

'PAD_TO_USING'(Term,ResultingLen,Pad) ->
  {?FUNCTION_NAME,[Term,ResultingLen,Pad]}.

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
    'IF'('LEQ'('SIZE'(ProtocolName),'HASHLEN'()),
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
    'IF'('EQ'('HASHLEN'(),64),
        'TRUNCATE'(TempK,32),
         TempK),
  NewSymmetricState#symmetricState{cipherState=initializeKey(NewTempK)}.

mixHash(Data,SymmetricState) ->
  HashValue = 'HASH'('MERGE'(SymmetricState#symmetricState.h,Data)),
  SymmetricState#symmetricState{h = HashValue}.

mixKeyAndHash(InputKeyMaterial,SymmetricState) ->
  error(nyi).

getHandshakeHash(SymmetricState) ->
  error(nyi).

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

  io:format("Public keys are ~p~n",[PublicKeys]),

  HandshakeState7 = 
    lists:foldl
      (fun (Key,AccHandshakeState) ->
           if
             Key==s -> AccHandshakeState#handshakeState{s='LOCAL_STATIC'()};
             Key==e -> AccHandshakeState#handshakeState{e='LOCAL_EPHEMERAL'()};
             Key==rs -> AccHandshakeState#handshakeState{rs='REMOTE_STATIC'()};
             Key==re -> AccHandshakeState#handshakeState{re='REMOTE_EPHEMERAL'()}
           end
       end,
       HandshakeState6,PublicKeys),

  lists:foldl
    (fun (PublicKey,AccHandshakeState) -> 
         modify_symmetricState
           (fun (SS) -> mixHash('PUBLIC-KEY'(key_value(PublicKey,AccHandshakeState)),SS) end,
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

execute_handshake(ProtocolName,Initiator,Prologue,{S,E,RS,RE},Handshake) ->
  State = #state{handshakeState=initialize(ProtocolName,Handshake,Initiator,Prologue,S,E,RS,RE)},
  {_PreHandshake,CommHandshake} = split_handshake(Handshake),
  execute_handshake(CommHandshake,State).

execute_handshake([],State) ->
  HS = State#state.handshakeState,
  SS = HS#handshakeState.symmetricState,
  {[], split(SS), State};
execute_handshake([MessagePattern|RestMessagePatterns],State) ->
  {Result,NewState} = 
    execute_message_pattern(MessagePattern,State),
  {Results,Split,FinalState} = 
    execute_handshake(RestMessagePatterns,NewState),
  {[Result|Results],Split,FinalState}.

execute_message_pattern(MessagePattern,State) ->
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
      PayloadCounter = State#state.payload_counter,
      Payload = {'PAYLOAD',[PayloadCounter]},
      HS1 = writeMessages(Messages,Payload,HS),
      {
        {wrote,HS1#handshakeState.output_buffer}, 
        State#state
        {handshakeState = HS1#handshakeState{output_buffer=[]},
         payload_counter=PayloadCounter+1}
      };
    true -> 
      ReadCounter = State#state.counter,
      HS1 = HS#handshakeState{input_buffer = 'INPUT_BUFFER'(ReadCounter)},
      HS2 = readMessages(Messages,HS1),
      {
        {read,HS2#handshakeState.payload_buffer},
        State#state
        {handshakeState = 
           HS2#handshakeState{input_buffer=undefined,payload_buffer=[]}}
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

key_value(Key,HS) ->
  if
    Key==s -> HS#handshakeState.s;
    Key==e -> HS#handshakeState.e;
    Key==rs -> HS#handshakeState.rs;
    Key==re -> HS#handshakeState.re
  end.

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

protocol_name(HandshakeName,DHType,CipherType,HashType) ->
  list_to_binary("Noise_"++HandshakeName++"_"++DHType++"_"++CipherType++"_"++HashType).

split_handshake(Handshake) ->
  Handshake.

find_handshake(HandshakeName) ->
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

find_dh_parms("25519") ->
  {ok,[{'DHLEN',32}]}.

find_crypto_parms("ChaChaPoly") ->
  {ok,[]}.

find_hash_parms("BLAKE2b") ->
  {ok,[{'HASHLEN',64}, {'BLOCKLEN',128}]}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

zero_args(Functor,Value) ->          
  fun (Term) ->
      case Term of
        {Functor,[]} -> Value;
        _ -> Term
      end
  end.
       
'eq_fun'() ->
  fun (Term) ->
      case Term of
        {'EQ',[I1,I2]} when is_integer(I1), is_integer(I2) ->
          I1 == I2;
        {'EQ',[B1,B2]} when is_binary(B1), is_binary(B2) ->
          B1 == B2;
        _ -> Term
      end
  end.

'leq_fun'() ->
  fun (Term) ->
      case Term of
        {'LEQ',[I1,I2]} when is_integer(I1), is_integer(I2) -> I1 =< I2;
        _ -> Term
      end
  end.

'if_fun'() ->
  fun (Term) ->
      case Term of
        {'IF',[true,Expr1,_]} -> Expr1;
        {'IF',[false,_,Expr2]} -> Expr2;
        _ -> Term
      end
  end.

'size_fun'() ->
  fun (Term) ->
      case Term of
        {'SIZE',[B]} when is_binary(B) -> byte_size(B);
        _ -> Term
      end
  end.

make_subst_list(Defs) ->
  [
   'if_fun'(), 'eq_fun'(), 'leq_fun'(), 'size_fun'()
   | lists:map(fun ({Atom,Value}) -> zero_args(Atom,Value) end, Defs)
  ].

subst({Atom,List},Substs) when is_atom(Atom), is_list(List) ->
  SubstList = subst(List,Substs),
  Term = {Atom,SubstList},
  case do_subst(Term,Substs) of
    Term -> 
      Term;
    OtherTerm -> 
      subst(OtherTerm,Substs);
    _ -> 
      Term
  end;
subst(Tuple,Substs) when is_tuple(Tuple) ->
  list_to_tuple(subst(tuple_to_list(Tuple),Substs));
subst([Hd|Tl],Substs) ->
  [subst(Hd,Substs)|subst(Tl,Substs)];
subst(Map,Substs) when is_map(Map) ->
  lists:foldl(fun ({Key,Value},M) ->
                  maps:put(Key,Value,M)
              end, #{}, subst(maps:to_list(Map),Substs));
subst(T,_) ->
  T.

do_subst(Term,[]) ->
  Term;
do_subst(Term,[First|Rest]) ->
  case First(Term) of
    Term -> do_subst(Term,Rest);
    OtherTerm -> OtherTerm
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

test() ->
  Initiator = true,
  Prologue = <<0,8,0,0,3>>,

  HandshakeType = "XK",
  DHType = "25519",
  CryptoType = "ChaChaPoly",
  HashType = "BLAKE2b",

  Handshake = find_handshake(HandshakeType),
  {ok,DHParms} = find_dh_parms(DHType),
  {ok,CryptoParms} = find_crypto_parms(CryptoType),
  {ok,HashParms} = find_hash_parms(HashType),
  ProtocolParms = [{'PROTOCOL-NAME',protocol_name(HandshakeType, DHType, CryptoType, HashType)}],
  io:format
    ("Protocol name is ~p~n",
     [proplists:get_value('PROTOCOL-NAME',ProtocolParms)]),
  Parms = DHParms ++ CryptoParms ++ HashParms ++ ProtocolParms,

  {Results,{CS1,CS2},State} =
    execute_handshake
      ('PROTOCOL-NAME'(),
       Initiator,
       Prologue,
       {s,undefined,undefined,undefined},
       Handshake),

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
     [State]),

  FirstResult = 
    lists:nth(1,Results),
  io:format
    ("Parms:~n~p~n",[Parms]),
  SubstResult = 
    subst(FirstResult,make_subst_list(Parms)),
  io:format
    ("~n~nSubstituted results is~n~p~n",
     [SubstResult]),
  SubstResult.

  
  


