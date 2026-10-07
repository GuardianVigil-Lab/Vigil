# Vigil — Build & Orchestration Makefile

IMAGE_NAME ?= vigil:local
GHCR_IMAGE ?= ghcr.io/guardianvigil-lab/vigil:latest

.PHONY: help build test lint run shell clean publish

help:
	@echo "Vigil Build Targets:"
	@echo "  make build    - Build local Docker container image"
	@echo "  make test     - Run Python self-checks & test suites"
	@echo "  make lint     - Lint scripts & configuration files"
	@echo "  make run      - Run complete review against current directory"
	@echo "  make shell    - Drop into container debug shell"
	@echo "  make publish  - Tag and push image to GHCR"

build:
	docker build -t $(IMAGE_NAME) -f Dockerfile .

test:
	python3 engine/anti_fabrication/detector.py --self-check
	python3 -m unittest discover -s tests
	python3 -m py_compile engine/vapt/*.py engine/code_review/*.py engine/synthesizer/*.py

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check engine/ || echo "ruff not found, skipping"
	@command -v shellcheck >/dev/null 2>&1 && shellcheck runners/*.sh vigil.sh entrypoint.sh || echo "shellcheck not found, skipping"

run:
	./bin/vigil review

shell:
	./bin/vigil --shell

publish:
	docker tag $(IMAGE_NAME) $(GHCR_IMAGE)
	docker push $(GHCR_IMAGE)

clean:
	rm -rf reports/raw/*
