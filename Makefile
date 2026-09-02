.PHONY: help up up-monitoring down logs scan report test lint build clean demo-local

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

up: ## Start the demo stack (Vault, fake KMS, mock Voltage, keycensus)
	docker compose up -d --build

up-monitoring: ## Same, plus Prometheus + Grafana
	docker compose --profile monitoring up -d --build

down: ## Stop everything
	docker compose --profile monitoring down

logs: ## Follow keycensus logs
	docker compose logs -f keycensus

scan: ## One-shot scan inside the running container, results land in ./out
	docker compose exec keycensus keycensus scan -c /config/keycensus.yml -o /out
	docker compose cp keycensus:/out ./out
	@echo "open out/report.html"

report: ## Open the live report URL
	@echo "http://localhost:9742/report.html"

test: ## Run unit tests
	python -m pytest -q

lint: ## Lint + format check
	ruff check keycensus tests demo mock-voltage grafana
	ruff format --check keycensus tests demo mock-voltage grafana

build: ## Build container images
	docker compose build

clean: down ## Stop and remove volumes and outputs
	docker compose --profile monitoring down -v
	rm -rf out

demo-local: ## Generate demo certs into demo/certs (no Docker)
	python demo/make_demo_certs.py demo/certs
