.PHONY: build build-dll build-dll32 clean

BINARY_NAME=hash-validator
DLL_NAME=hash-validator.dll
DLL32_NAME=hash-validator32.dll

build:
	go build -o $(BINARY_NAME) ./cmd/validator/main.go

build-dll:
	go build -buildmode=c-shared -o $(DLL_NAME) ./lib/main/

build-dll32:
	powershell -Command "$$env:GOOS='windows'; $$env:GOARCH='386'; $$env:CGO_ENABLED='1'; $$env:CC='gcc'; go build -buildmode=c-shared -o $(DLL32_NAME) ./lib/main/"

clean:
	del /Q $(BINARY_NAME) $(DLL_NAME) $(DLL32_NAME) *.h 2>nul || exit 0
