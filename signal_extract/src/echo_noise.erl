-module(echo_noise).

-compile(export_all).

knows_rs(Handshake) ->
  (Handshake=="IK") or (Handshake=="K") or (Handshake=="KK")
    or (Handshake=="N") or (Handshake=="NK") or (Handshake=="XK")
    or (Handshake=="NK1") or (Handshake=="X") or (Handshake=="X1K")
    or (Handshake=="XK1") or (Handshake=="X1K1") or (Handshake=="K1K")
    or (Handshake=="KK1") or (Handshake=="K1K1") or (Handshake=="I1K")
    or (Handshake=="IK1") or (Handshake=="I1K1").

find_echo_prologue(Handshake,DH,Crypto,Hash) ->
  HandshakeP = find_echo_handshake(Handshake),
  DHP = find_echo_dh(DH),
  CryptoP = find_echo_crypto(Crypto),
  HashP = find_echo_hash(Hash),
  <<HandshakeP:16,DHP:8,CryptoP:8,HashP:8>>.

find_echo_handshake(Handshake) ->
  if
    Handshake=="NN" -> 16#00;
    Handshake=="KN" -> 16#01;
    Handshake=="NK" -> 16#02;
    Handshake=="KK" -> 16#03;
    Handshake=="NX" -> 16#04;
    Handshake=="KX" -> 16#05;
    Handshake=="XN" -> 16#06;
    Handshake=="IN" -> 16#07;
    Handshake=="XK" -> 16#08;
    Handshake=="IK" -> 16#09;
    Handshake=="XX" -> 16#0A;
    Handshake=="IX" -> 16#0B
  end.

find_echo_dh(DH) ->
  if
    DH=="25519" -> 16#00;
    DH=="448" -> 16#01
  end.

find_echo_crypto(Crypto) ->
  if
    Crypto=="ChaChaPoly" -> 16#00
  end.

find_echo_hash(Hash) ->
  if
    Hash=="SHA256" -> 16#00;
    Hash=="SHA512" -> 16#01;
    Hash=="BLAKE2s" -> 16#02;
    Hash=="BLAKE2b" -> 16#03
  end.
