# Воспроизводимая сборка mz: один и тот же коммит и версия Go дают побайтно тот же бинарник.
GOFLAGS_BUILD := -trimpath -ldflags='-s -w -buildid='

.PHONY: binaries
binaries: build/mz-darwin-arm64 build/mz-darwin-amd64

build/mz-darwin-%: FORCE
	CGO_ENABLED=0 GOOS=darwin GOARCH=$* go build $(GOFLAGS_BUILD) -o $@ ./cmd/mz

.PHONY: FORCE
FORCE:
