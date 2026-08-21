#!/usr/bin/env escript
% Copyright 2026 Jerry David Chan, Konareef.ai
% SPDX-License-Identifier: Apache-2.0

%%! -sname floatparity
%%
%% parity.erl — Erlang half of the konareef-toml/v1 R8 float-parity
%% sweep. Reads the JSON sample file produced by the Go `floatparity`
%% command, reconstructs each IEEE-754 double bit-identically from its
%% hex bit pattern, formats it with erlang:float_to_binary/2 [short],
%% and reports every value whose Erlang form differs from the Go form.
%%
%% Usage:
%%   go run ./internal/canon/floatparity > samples.json
%%   escript internal/canon/floatparity/parity.erl samples.json
%%
%% Exit 0 = full parity (spec lockable on the float axis).
%% Exit 1 = at least one divergence (printed with bit pattern + both
%%          formattings, classified as exponent-form-only vs digit
%%          difference — the distinction that decides §10 item 1a/1b).
%% Exit 2 = usage error.
%%
%% Requires Erlang/OTP 27+ for the built-in `json` module and
%% binary:decode_hex/1 (OTP 24+).

main([Path]) ->
    {ok, Raw} = file:read_file(Path),
    Doc = json:decode(Raw),
    Samples = maps:get(<<"samples">>, Doc),
    Divergences = lists:filtermap(fun check_sample/1, Samples),
    Total = length(Samples),
    case Divergences of
        [] ->
            io:format("OK -- ~p samples, full Go/Erlang float parity~n", [Total]),
            halt(0);
        _ ->
            io:format("DIVERGENCE -- ~p of ~p samples differ:~n",
                      [length(Divergences), Total]),
            lists:foreach(fun print_divergence/1, Divergences),
            halt(1)
    end;
main(_) ->
    io:format(standard_error,
              "usage: escript parity.erl <samples.json>~n", []),
    halt(2).

%% check_sample reconstructs the double from its hex bits, formats it
%% the Erlang way, and returns {true, Divergence} when it disagrees
%% with the Go output, or false when the two forms are byte-identical.
check_sample(Sample) ->
    BitsHex = maps:get(<<"bits">>, Sample),
    GoOut   = maps:get(<<"go">>, Sample),
    Bits    = binary:decode_hex(BitsHex),
    <<Float:64/big-float>> = Bits,
    ErlOut  = erlang:float_to_binary(Float, [short]),
    case ErlOut =:= GoOut of
        true  -> false;
        false -> {true, {BitsHex, GoOut, ErlOut, classify(GoOut, ErlOut)}}
    end.

%% classify distinguishes the two kinds of divergence. A formatting-only
%% difference (one side decimal, the other exponent form, but the same
%% significant digits) is mechanically reconcilable -> §10 item 1(a)
%% with a documented post-processing step. A difference in the actual
%% significant digits is not -> §10 item 1(b), an explicit algorithm.
classify(GoOut, ErlOut) ->
    case digits(GoOut) =:= digits(ErlOut) of
        true  -> formatting_only;
        false -> digit_difference
    end.

%% digits extracts just the significant decimal digits from a formatted
%% float, dropping the sign, decimal point, exponent marker, and any
%% leading/trailing zeros, so two representations of the same value
%% compare equal regardless of decimal-vs-exponent notation.
digits(Bin) ->
    Lower = string:lowercase(Bin),
    %% Drop everything from an exponent marker onward.
    Mantissa = hd(binary:split(Lower, <<"e">>)),
    Stripped = binary:replace(
                 binary:replace(Mantissa, <<".">>, <<>>, [global]),
                 <<"-">>, <<>>, [global]),
    string:trim(Stripped, both, "0").

print_divergence({BitsHex, GoOut, ErlOut, Kind}) ->
    io:format("  bits=~s  go=~s  erlang=~s  [~p]~n",
              [BitsHex, GoOut, ErlOut, Kind]).
