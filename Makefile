PYTHON ?= python

# Image build knobs; override on the command line, e.g.
# `make image GATEWAY_TAG=2.0.0 GATEWAY_DIGEST=sha256:<64 hex>`.
# Pin tag and digest together, never `latest`; the Dockerfile rejects any tag that is not
# 2.X.Y or 2.X.Y-dev-<git sha>.
IMAGE ?= gwops-gateway:dev
GATEWAY_TAG ?= 2.0.0
GATEWAY_DIGEST ?= sha256:4993a7db015f7c2091d55f1c7a36c3e0c277137cb9937a46e9ced2c17456a6d1

.PHONY: lint test verify-pin image preflight-ci integration-webapp

lint:
	ruff check src tests
	mypy src

test:
	pytest

# Verify that GATEWAY_TAG still resolves to GATEWAY_DIGEST in the registry. Docker
# builds by digest and ignores the tag, so a mismatched pair would bake the wrong
# GWOPS_GATEWAY_VERSION over the binary; a re-pushed preview tag also fails here.
verify-pin:
	@actual=$$(docker buildx imagetools inspect "twingate/gateway:$(GATEWAY_TAG)" --format '{{json .Manifest}}' 		| $(PYTHON) -c "import json, sys; print(json.load(sys.stdin)['digest'])") 		|| { echo "ERROR: cannot resolve twingate/gateway:$(GATEWAY_TAG)" >&2; exit 1; }; 	if [ "$$actual" != "$(GATEWAY_DIGEST)" ]; then 		echo "ERROR: twingate/gateway:$(GATEWAY_TAG) resolves to $$actual, not GATEWAY_DIGEST $(GATEWAY_DIGEST)" >&2; 		exit 1; 	fi; 	echo "twingate/gateway:$(GATEWAY_TAG) resolves to $$actual"

# Wrap the gateway binary from the official image, pinned by GATEWAY_TAG and GATEWAY_DIGEST.
image: verify-pin
	docker build --build-arg GATEWAY_TAG=$(GATEWAY_TAG) \
		--build-arg GATEWAY_DIGEST=$(GATEWAY_DIGEST) \
		-t $(IMAGE) .

# Preflight CI runner: validate rendered golden configs against a real gateway binary.
# Override GATEWAY_BIN and CONFIGS on the command line, e.g.:
#   make preflight-ci GATEWAY_BIN=/path/to/gateway CONFIGS="tests/fixtures/rendered/minimal.yaml"
GATEWAY_BIN ?= gateway
CONFIGS ?= tests/fixtures/rendered/minimal.yaml

preflight-ci:
	$(PYTHON) -m gwops.ci.preflight $(GATEWAY_BIN) $(CONFIGS)

# Live web-app rig against an operator-approved test tenant (local Docker, project .venv). Not part
# of `test`. Run `make image` first. Refuses to start unless every IT_* variable is set.
# HOLD=1 keeps the rig up after the assertions until <run dir>/HOLD is deleted (HOLD_MAX=secs).
# GATORCAST=1 adds a Gatorcast recording sink and its evidence assertions; GATORCAST_SSH=1 adds the SSH leg.
ifeq ($(OS),Windows_NT)
RIG_PY := .venv/Scripts/python.exe
else
RIG_PY := .venv/bin/python
endif

integration-webapp:
	@[ -n "$${IT_TWINGATE_API_KEY:-}" ] || { echo "ERROR: IT_TWINGATE_API_KEY is not set" >&2; exit 1; }
	@[ -n "$${IT_TWINGATE_NETWORK:-}" ] || { echo "ERROR: IT_TWINGATE_NETWORK is not set" >&2; exit 1; }
	@[ -n "$${IT_TWINGATE_REMOTE_NETWORK_ID:-}" ] || { echo "ERROR: IT_TWINGATE_REMOTE_NETWORK_ID is not set" >&2; exit 1; }
	@[ -n "$${IT_APPROVED_NETWORK:-}" ] || { echo "ERROR: IT_APPROVED_NETWORK is not set" >&2; exit 1; }
	@[ -n "$${IT_APPROVED_REMOTE_NETWORK_ID:-}" ] || { echo "ERROR: IT_APPROVED_REMOTE_NETWORK_ID is not set" >&2; exit 1; }
	$(RIG_PY) -m tests.integration.webapp.run $(if $(filter 1,$(HOLD)),--hold) $(if $(HOLD_MAX),--hold-max $(HOLD_MAX)) $(if $(filter 1,$(GATORCAST)),--gatorcast) $(if $(filter 1,$(GATORCAST_SSH)),--gatorcast-ssh)
