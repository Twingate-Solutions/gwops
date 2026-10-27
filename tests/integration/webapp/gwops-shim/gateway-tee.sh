#!/bin/sh
# Rig-only shim for --gatorcast runs: gwops' recording path reads the gateway's stderr, so stderr
# stays on stderr. A copy also goes to stdout (gwops logs it as gateway.line), minus asciicast
# lines so recorded terminal output stays out of the container log.
# The copy carries client request headers verbatim, and the gateway emits recording payloads
# whatever recording.enabled says; the rig scrubs it (rig/logfilter.py) before run.log.
# The pre-flight validation spawn (config.yaml.next) keeps its stderr: gwops classifies that text.
case "$*" in
  *.next*) exec /usr/local/bin/gateway "$@" ;;
esac
fifo="/tmp/gateway-stderr.$$"
mkfifo "$fifo"
( tee /dev/stderr < "$fifo" | grep --line-buffered -v '"asciicast"'; rm -f "$fifo" ) &
exec /usr/local/bin/gateway "$@" 2> "$fifo"
