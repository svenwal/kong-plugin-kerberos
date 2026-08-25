COMPOSE := docker compose -f test/docker-compose.yml

.PHONY: help test test-clean dev down logs shell lint gss-check

help:
	@echo "make test        run the end to end suite (leaves the stack running)"
	@echo "make test-clean  rebuild everything from scratch, then run the suite"
	@echo "make dev         bring the stack up and leave it running"
	@echo "make down        tear the stack down, including the realm database"
	@echo "make logs        follow the Kong logs"
	@echo "make shell       shell in the Kerberos client container (kinit, curl)"
	@echo "make lint        run luacheck over the plugin sources"
	@echo "make gss-check   run the standalone GSS-API round trip inside Kong"
	@echo ""
	@echo "ONLY=<substring> restricts 'make test' to matching cases"

dev:
	$(COMPOSE) up -d --build kdc upstream upstream-krb kong
	@echo "proxy: http://localhost:$${KONG_PROXY_PORT:-18000}  admin: http://localhost:$${KONG_ADMIN_PORT:-18001}"

test: dev
	# kong.yml is read at boot, so always restart before asserting on it
	$(COMPOSE) restart kong
	$(COMPOSE) run --rm client

test-clean:
	$(COMPOSE) down -v
	$(COMPOSE) build
	$(COMPOSE) up -d kdc upstream upstream-krb kong
	$(COMPOSE) run --rm client

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f kong

shell:
	$(COMPOSE) run --rm --entrypoint bash client

# Exercises the FFI layer directly, without Kong in the picture. Useful when a
# Kerberos problem needs to be isolated from routing and plugin config.
gss-check:
	$(COMPOSE) run --rm --no-deps \
		-v "$(CURDIR)/test/tools:/tools:ro" \
		--entrypoint /usr/local/openresty/luajit/bin/luajit \
		kong /tools/gss_roundtrip.lua

lint:
	docker run --rm -v "$(CURDIR):/src" -w /src ghcr.io/lunarmodules/luacheck:latest \
		kong/
