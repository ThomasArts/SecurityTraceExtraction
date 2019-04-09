-module(signal_binary_ops).

-export([merge/1,merge/2,extract/3,pad/3,pad_to_size/3,xor_words_with_const/2]).

merge([]) ->
  <<>>;
merge([B|Rest]) ->
  BRest = merge(Rest),
  <<B/binary,BRest/binary>>.

merge(B1,B2) ->
  <<B1/binary, B2/binary>>.

extract(B,Start,Length) ->
  binary:part(B,Start,Length).

pad(Binary,Symbol,Count) ->
  pad0(Binary,Symbol,Count).

pad_to_size(Data, PadByte, MinSize) ->
  case byte_size(Data) of
    N when N >= MinSize ->
      Data;
    N ->
      PadData = << <<PadByte:8>> || _ <- lists:seq(1, MinSize - N) >>,
      <<Data/binary, PadData/binary>>
  end.

xor_words_with_const(Key,Pad) ->
  <<PadWord:32>> = <<Pad:8, Pad:8, Pad:8, Pad:8>>,
  << <<(Word bxor PadWord):32>> || <<Word:32>> <= Key >>.

pad0(Binary,_Symbol,0) ->
  Binary;
pad0(Binary,Symbol,N) when N>0 ->
  pad0(<<Binary/binary,Symbol>>,Symbol,N-1).

  
