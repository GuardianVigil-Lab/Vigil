# Vigil — Build & Orchestration Makefile

IMAGE_NAME ?= vigil:local
CORE_IMAGE ?= vigil:core
GHCR_IMAGE ?= ghcr.io/guardianvigil-lab/vigil:latest
GHCR_CORE_IMAGE ?= ghcr.io/guardianvigil-lab/vigil:core

.PHONY: help build build-core build-full test lint run shell clean publish

help:
	@echo "Vigil Build Targets:"
	@echo "  make build       - Build local full Docker container image"
	@echo "  make build-core  - Build lean core Docker container image (~150MB)"
	@echo "  make build-full  - Build full Docker container image (~1.2GB)"
	@echo "  make test        - Run Python self-checks & test suites"
	@echo "  make lint        - Lint scripts & configuration files"
	@echo "  make run         - Run complete review against current directory"
	@echo "  make shell       - Drop into container debug shell"
	@echo "  make publish     - Tag and push images to GHCR"

build: build-full

build-core:
	docker build --target core -t $(CORE_IMAGE) -f Dockerfile .

build-full:
	docker build --target full -t $(IMAGE_NAME) -f Dockerfile .

test:
	python3 engine/anti_fabrication/detector.py --self-check
	python3 -m unittest discover -s tests
	python3 -m py_compile engine/vapt/*.py engine/code_review/*.py engine/synthesizer/*.py

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check engine/ || echo "ruff not found, skipping"
	@command -v shellcheck >/dev/null 2>&1 && shellcheck install.sh runners/*.sh vigil.sh entrypoint.sh || echo "shellcheck not found, skipping"

run:
	./bin/vigil review

shell:
	./bin/vigil --shell

publish:
	docker tag $(CORE_IMAGE) $(GHCR_CORE_IMAGE)
	docker push $(GHCR_CORE_IMAGE)
	docker tag $(IMAGE_NAME) $(GHCR_IMAGE)
	docker push $(GHCR_IMAGE)

clean:
	rm -rf reports/raw/*
