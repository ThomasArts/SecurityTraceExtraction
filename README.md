SecurityTraceExtraction
=================

Extracting behavioural descriptions from runs (Erlang traces) of security protocols.
In particular we focus on verifying such behavioural descriptions obtained from
tracing the [enoise implementation](https://github.com/aeternity/enoise) of the [Noise protocol](https://noiseprotocol.org/).

Build
-----

First download and compile [noise-c](https://github.com/rweather/noise-c) -- an
implementation of the noise protocol in the C programming language. In the following we
assume that it was downloaded in the directory ../noise-c. Next build signal_extract tool:
    
    $ cd signal_extract; rebar3 compile


Obtaining a trace and analyzing it
-----------------------------------

    $ cd signal_extract
    
    $ bash scripts/start_noise_c.sh                       # Start the noise-c command in one shell
    $ rebar3 shell                                        # Starts erlang in another shell
    
    % Execute a protocol handshake using the XK pattern, save the resulting trace in
    % enoise.trace, and analyse the resulting trace:
    > check:check_and_generate("XK","25519","ChaChaPoly","BLAKE2b","enoise.trace"). 

For more debugging output try instead:
    
    $ rebar shell --config config/logger.config 
   

Checking non-interference
-------------------------

Note that an installation of SWI-Prolog (or a compatable Prolog) is required.

    $ cd signal_extract

    $ swipl
    
    ?- consult('noint.pl').
    
    ?- consult('../traces/noints.pl').
    
    ? nonint(r1,r2).
    
    ...


Creating new keys
-----------------

New keys (ed25519, etc) can be created using the echo-keygen program distributed with noise-c (https://rweather.github.io/noise-c/example_echo.html)




