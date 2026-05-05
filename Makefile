.PHONY: build clean test test-cover bench lint

build:
	$(MAKE) -C secagent build
	@mkdir -p bin
	cp secagent/bin/secagent bin/secagent

clean:
	rm -rf bin/ secagent/bin/
	$(MAKE) -C secagent clean

test:
	$(MAKE) -C secagent test
	cd claude-controller && python3 -m unittest discover tests

lint:
	$(MAKE) -C secagent lint
