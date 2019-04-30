-module(get_key).

-export([get_key/3]).

get_key(KeyFileName,KeyDir,Type) ->
  FilePath = KeyDir++"/"++KeyFileName++if Type==priv -> ""; Type==pub -> ".pub" end,
  case file:read_file(FilePath) of
    {ok,Base64Bin} when Type==pub -> 
      base64:decode(Base64Bin);
    {ok,Bin} when Type==priv -> 
      Bin;
    _ ->
      io:format("~n*** Error: could not read key file ~s~n",[FilePath]),
      error(bad)
  end.
