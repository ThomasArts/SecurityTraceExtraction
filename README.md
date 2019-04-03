signal_extraction
=================

Extracting behavioural descriptions from runs (Erlang traces) of security protocols.
In particular we focus on verifying such behavioural descriptions obtained from
tracing the [enoise implementation](https://github.com/aeternity/enoise) of the [Noise protocol](https://noiseprotocol.org/).

Build
-----

First download and compile [noise-c](https://github.com/rweather/noise-c) -- an
implementation of the noise protocol in the C programming language. In the following we
assume that it was downloaded in the directory ../noise-c.

   $ rebar3 compile


Obtaining a trace and analyzing it
-----------------------------------

   $ rebar3 ...



