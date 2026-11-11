# Convenience wrapper around docker compose for the GHSA-673q-mjm6-r5xr PoC.
.PHONY: build up down exploit exploit-patched evidence logs clean demo help

build:            ## Build victim (vuln + patched) and poc images
	docker compose build victim victim-patched poc

up: build         ## Start both victims in the background
	docker compose up -d victim victim-patched
	@echo "victim (vulnerable) -> http://localhost:3000"
	@echo "victim (patched)    -> http://localhost:3001"

exploit:          ## Run the remote exploit against the VULNERABLE victim
	docker compose run --rm poc

exploit-patched:  ## Run the same exploit against the PATCHED victim (should fail safely)
	docker compose run --rm poc-patched

help:             ## Show the poc client's own flags (-h)
	docker compose run --rm poc -h

evidence:         ## Side-by-side root-cause reproducers (vuln vs patched)
	docker compose run --rm evidence

demo: up          ## Full demo: start victims, pwn the vulnerable one, show the patch holds
	@sleep 2
	@echo "\n==================== EXPLOIT vs VULNERABLE (:3000) ===================="
	-@docker compose run --rm poc
	@echo "\n==================== EXPLOIT vs PATCHED (:3001) ======================"
	-@docker compose run --rm poc-patched

logs:             ## Tail victim logs
	docker compose logs -f victim victim-patched

down:             ## Stop and remove containers
	docker compose down

clean: down       ## Remove built images too
	-docker image rm ghsa-673q-victim:19.2.8 ghsa-673q-victim:19.2.9 ghsa-673q-poc ghsa-673q-evidence 2>/dev/null || true
