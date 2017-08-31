PLATFORMS := darwin/amd64 linux/amd64 linux/386 linux/arm windows/amd64 windows/386

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))

release: $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build -o 'dist/acme-wf.$(os)-$(arch)' main.go

.PHONY: release $(PLATFORMS)
