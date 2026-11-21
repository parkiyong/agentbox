.PHONY: all build build-agentd test test-go test-ts test-react test-py dev clean

all: build test

build: build-agentd
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/agentbox-runner ./cmd/agentbox-runner
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/agentbox ./cmd/agentbox

build-agentd:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/agentd ./cmd/agentd

test: test-go test-ts test-react test-py

test-go:
	go test -race ./...

test-ts:
	cd sdks/typescript && npm test

test-react:
	cd sdks/react && npm run build

test-py:
	cd sdks/python && PYTHONPATH=. python3 -m unittest discover -s tests -v

dev: build
	./bin/agentbox dev

clean:
	rm -rf bin sdks/typescript/dist sdks/react/dist
