-module(run_noise).

-include_lib("kernel/include/logger.hrl").
-compile(export_all).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

protocol_name(HandshakeName,DHType,CipherType,HashType) ->
  list_to_binary("Noise_"++HandshakeName++"_"++DHType++"_"++CipherType++"_"++HashType).

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
      };
    HandshakeName == "XN" ->
      {
        [],
        [
         {snd,[e]},
         {rcv,[e,ee]},
         {snd,[s,se]}
        ]
      };
    HandshakeName == "XX" ->
      {
        [],
        [
         {snd,[e]},
         {rcv,[e,ee,s,es]},
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

'plus_fun'() ->
  fun (Term) ->
      case Term of
        {'PLUS',[I1,I2]} when is_integer(I1), is_integer(I2) -> I1+I2;
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

'payload_fun'() ->
  fun (Term) ->
      case Term of
        {'PAYLOAD',[_]} -> <<>>;
        _ -> Term
      end
  end.

make_subst_list(Defs) ->
  [
   'if_fun'(), 'eq_fun'(), 'leq_fun'(), 'size_fun'(), 'payload_fun'(), 'plus_fun'()
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

handshake_and_send(HandshakeType,DHType,CryptoType,HashType,Message) ->
  Initiator = true,
  Handshake = find_handshake(HandshakeType),
  {ok,DHParms} = find_dh_parms(DHType),
  {ok,CryptoParms} = find_crypto_parms(CryptoType),
  {ok,HashParms} = find_hash_parms(HashType),
  ProtocolParms = [{'PROTOCOL-NAME',protocol_name(HandshakeType, DHType, CryptoType, HashType)}],
  io:format
    ("Running noise protocol ~p~n",
     [proplists:get_value('PROTOCOL-NAME',ProtocolParms)]),
  Parms = DHParms ++ CryptoParms ++ HashParms ++ ProtocolParms,
  Prologue = echo_noise:find_echo_prologue(HandshakeType,DHType,CryptoType,HashType),
  {Results,{CS1,CS2},State} =
    noise:execute_handshake
      (noise:'PROTOCOL-NAME'(),
       Initiator,
       Prologue,
       {noise:'STORE-KEYPAIR'(noise:'LOCAL_STATIC'()),undefined,undefined,undefined},
       Handshake),

  {Result,_} = noise:encryptWithAd(<<>>,Message,CS1),
  Subst = make_subst_list(Parms),
  SendTerm = subst(Result,Subst),

  PayloadBuffers = 
    lists:foldl
      (fun ({read,P},Acc) -> [P|Acc];
           (_,Acc) -> Acc
       end, [], Results),

  PayloadTerm = 
    if
      PayloadBuffers==[] ->
        undefined;
      true ->
        subst(lists:last(PayloadBuffers),Subst)
    end,

  ?LOG_INFO("SendTerm:~n~p~n",[SendTerm]),
  ?LOG_INFO("PayloadTerm:~n~p~n",[PayloadTerm]),

  {
    SendTerm,
    PayloadTerm
  }.
  

