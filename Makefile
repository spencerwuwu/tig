# Don't bully me for makefiling this, I hate docker's interface

UNAME=$(shell whoami)
UID=$(shell id -u)
GID=$(shell id -g)
IMAGE_NAME=ghidra-$(UNAME)
CONTAINER_NAME=ghidra-$(UNAME)-container

.PHONY: build run clean shell

build:
	docker build -t ghidra-$(UNAME) --build-arg guest_uid=$(UID) --build-arg guest_gid=$(GID) --build-arg guest_name=$(UNAME) .

#run:
#	docker run --rm -it --name $(CONTAINER_NAME) -v $(PWD)/:/docker_shared $(IMAGE_NAME)

clean:
	docker rm -f $(CONTAINER_NAME)
	docker rmi $(IMAGE_NAME)

# Open a shell in an already running container
shell:
	docker exec -it $(CONTAINER_NAME) bash

