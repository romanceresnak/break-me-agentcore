PY ?= python3
N  ?= 2000

.PHONY: install compile test campaign scenarios serve lambda deploy clean

install:
	$(PY) -m pip install -r requirements.txt

compile:            ## rules/rules.yaml -> generated/*
	$(PY) compiler/compile.py

test: compile       ## every rule, every catalog attack, MCP channel, usefulness
	$(PY) -m pytest -q tests

campaign: compile   ## red agent vs blue agent, 4-config ablation -> results/
	$(PY) -m breakme campaign --n $(N)

scenarios: compile
	$(PY) -m breakme scenarios

serve: compile      ## Glass Box + arena on http://localhost:8080
	$(PY) -m breakme serve --port 8080

lambda: compile     ## build/tool_api: package + compiled rules + Linux wheels (Tool API and arena Lambdas)
	rm -rf build/tool_api && mkdir -p build/tool_api
	$(PY) -m pip install --quiet --target build/tool_api --platform manylinux2014_x86_64 \
	  --only-binary=:all: --python-version 3.12 cedarpy pyyaml
	cp -r breakme generated build/tool_api/
	find build/tool_api -name __pycache__ -prune -exec rm -rf {} +

deploy: lambda
	cd infra/terraform && terraform init -upgrade && terraform apply

clean:
	rm -rf build results .pytest_cache
