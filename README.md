signal_extraction
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
   
   $ bash scripts/start_noise_c.sh                       # Starts noise-c command

   $ rebar3 as test shell

   > signal_extract:noisy_trace("enoise.trace").         % Saves trace in file enoise.trace

   > signal_extract:analyze_trace_file("enoise.trace").  % Analyzes trace file
   

As an option try out check:check() function which checks a worked through example.



