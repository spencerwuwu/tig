IMAGE_NAME=ghidra-bbextract

.PHONY: build shell

build:
	docker build -t $(IMAGE_NAME) .

shell:
	docker run -it --rm --entrypoint="" $(IMAGE_NAME) bash

