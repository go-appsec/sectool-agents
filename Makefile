.PHONY: build clean test test-cover bench lint

build:
	$(MAKE) -C secagent build
	@mkdir -p bin
	cp secagent/bin/secagent bin/secagent

clean:
	rm -rf bin/
	$(MAKE) -C secagent clean

test:
	$(MAKE) -C secagent test

test-cover:
	$(MAKE) -C secagent test-cover

bench:
	$(MAKE) -C secagent bench

lint:
	$(MAKE) -C secagent lint
