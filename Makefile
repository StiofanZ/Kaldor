DIST ?= dist
.PHONY: build package
build package:
	sh package.sh "$@" "$(DIST)"
