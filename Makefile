# Don't bully me for makefiling this, I hate docker's interface

UNAME=$(shell whoami)
UID=$(shell id -u)
GID=$(shell id -g)
IMAGE_NAME=ghidra-$(UNAME)
CONTAINER_NAME=ghidra-$(UNAME)-container

.PHONY: build shell

build:
	docker build -t $(IMAGE_NAME) --build-arg guest_uid=$(UID) --build-arg guest_gid=$(GID) --build-arg guest_name=$(UNAME) .

shell:
	docker run -it --rm --entrypoint="" $(IMAGE_NAME) bash

