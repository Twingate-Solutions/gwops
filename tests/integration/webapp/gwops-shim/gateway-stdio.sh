#!/bin/sh
# Rig-only shim: merge the gateway's stderr into stdout so gwops logs it as gateway.line.
# The merged stream carries client request headers verbatim, and the gateway emits recording
# payloads whatever recording.enabled says; the rig scrubs it (rig/logfilter.py) before run.log.
# The pre-flight validation spawn (config.yaml.next) keeps its stderr: gwops classifies that text.
case "$*" in
  *.next*) exec /usr/local/bin/gateway "$@" ;;
  *) exec /usr/local/bin/gateway "$@" 2>&1 ;;
esac
