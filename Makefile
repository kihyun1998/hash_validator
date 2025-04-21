.PHONY: build build-dll clean

BINARY_NAME=hash-validator
DLL_NAME=hash-validator.dll

build:
	go build -o $(BINARY_NAME) ./cmd/validator/main.go

build-dll:
	go build -buildmode=c-shared -o $(DLL_NAME) ./lib/main/

clean:
	rm -f $(BINARY_NAME)
	rm -f $(DLL_NAME)
	rm -f *.h