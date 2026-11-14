BIN      := rkk
VERSION  := 1.0.0
LDFLAGS  := -s -w
GOFLAGS  := -trimpath

.PHONY: all build cross test fmt vet clean

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) .

cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/rkk-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/rkk-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=386   go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/rkk-linux-386 .
	cd dist && sha256sum rkk-linux-* > SHA256SUMS

# 用不包含真实木马的模拟感染目录自测：布防 → 巡检 → 复检
test:
	./tools/make-test-fixture.sh /tmp/rkk-fixture
	@echo "--- 扫描（应报出感染）"
	RKK_ROOT=/tmp/rkk-fixture ./$(BIN) scan || true
	@echo "--- 巡检（应自动清零）"
	RKK_ROOT=/tmp/rkk-fixture ./$(BIN) patrol -aggressive
	@echo "--- 复检"
	RKK_ROOT=/tmp/rkk-fixture ./$(BIN) scan

fmt:
	gofmt -w *.go

vet:
	go vet ./...

clean:
	rm -f $(BIN) rkk-linux-* dist/rkk-linux-*
