-module(signal_extract_utils). 

-export([put/2,get/1,to_list/0,ensure_open/0,open_clean_db/0]).
-export([cmd/1,cmd_with_status/1]).

put(Key,Value) ->
  ensure_open(),
  ets:insert(?MODULE,{Key,Value}).

get(Key) ->
  ensure_open(),
  try ets:lookup(?MODULE,Key) of
    [{Key,Value}] -> Value;
    _ -> undefined
  catch _:_ -> false end.
      
num_sort(Name) ->
  String = atom_to_list(Name),
  case string:str(String,"Binary") of
    0 -> 0;
    _ -> list_to_integer(string:substr(String,7,length(String)-6))
  end.

to_list() ->
  ensure_open(),
  lists:sort
    (fun ({_,R1},{_,R2}) ->
         num_sort(signal_extract:name(R1)) < num_sort(signal_extract:name(R2))
     end, 
     lists:filter
       (fun ({Key,_Value}) -> 
            case Key of
              counter -> false;
              {nickname,_} -> false;
              _ -> true
            end
        end, 
        ets:tab2list(?MODULE))).

ensure_open() ->
  case ets:info(?MODULE) of
    undefined ->
      open_db();
    _ ->
      ok
  end.

open_db() ->
  spawn(fun () ->
	    try ets:new(?MODULE,[named_table,public]), wait_forever()
	    catch _:_ -> ensure_open() end
	end),
  wait_until_stable().

wait_forever() ->
  receive _ -> wait_forever() end.

wait_until_stable() ->
  case ets:info(?MODULE) of
    undefined ->
      timer:sleep(10),
      wait_until_stable();
    _ ->
      ok
  end.

open_clean_db() ->
  ensure_open(),
  ets:delete_all_objects(?MODULE).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

cmd(Command) ->
  {Status,Result} = cmd_with_status(Command),
  if
    Status =/= 0 ->
      io:format
        ("command ~s failed with exit code ~p:~n  ~s~n",
         [Command,Status,Result]),
      error({bad,Command,Status});
    true ->
      ok
  end.

cmd_with_status(Command) ->
  Port = open_port({spawn, Command}, [stream, in, eof, hide, exit_status, stderr_to_stdout]),
  get_data(Port, []).

get_data(Port, Sofar) ->
    receive
    {Port, {data, Bytes}} ->
        get_data(Port, [Sofar|Bytes]);
      {Port, eof} ->
        Port ! {self(), close},
        receive
        {Port, closed} ->
            true
        end,
        receive
        {'EXIT',  Port,  _} ->
            ok
        after 1 ->              % force context switch
            ok
        end,
        ExitCode =
            receive
            {Port, {exit_status, Code}} ->
                Code
        end,
        {ExitCode, lists:flatten(lists:reverse(Sofar))}
    end.