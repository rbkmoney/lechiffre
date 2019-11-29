REBAR ?= $(shell which rebar3 2>/dev/null || which ./rebar3)

COMPOSE_HTTP_TIMEOUT := 300
export COMPOSE_HTTP_TIMEOUT

UTILS_PATH := build_utils
TEMPLATES_PATH := .

# Name of the service
SERVICE_NAME := lechiffre
# Service image default tag
SERVICE_IMAGE_TAG ?= $(shell git rev-parse HEAD)
# The tag for service image to be pushed with
SERVICE_IMAGE_PUSH_TAG ?= $(SERVICE_IMAGE_TAG)

# Base image for the service
BASE_IMAGE_NAME := service-erlang
BASE_IMAGE_TAG := da0ab769f01b650b389d18fc85e7418e727cbe96

BUILD_IMAGE_TAG := 4536c31941b9c27c134e8daf0fd18848809219c9

CALL_ANYWHERE := \
	submodules \
	all compile xref lint dialyze test cover \
	start devrel release clean distclean

CALL_W_CONTAINER := $(CALL_ANYWHERE)

.PHONY: $(CALL_W_CONTAINER) all

all: compile

-include $(UTILS_PATH)/make_lib/utils_container.mk
-include $(UTILS_PATH)/make_lib/utils_image.mk

$(SUBTARGETS): %/.git: %
	git submodule update --init $<
	touch $@

submodules: $(SUBTARGETS)

compile:
	$(REBAR) compile

test:
	$(REBAR) eunit

clean:
	$(REBAR) clean

distclean:
	$(REBAR) clean -a

xref:
	$(REBAR) xref

dialyze:
	$(REBAR) dialyzer
