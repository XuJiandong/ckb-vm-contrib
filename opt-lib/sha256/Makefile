CLANG_VERSION ?= 19
CLANG = clang-$(CLANG_VERSION)
CLANG_FORMAT = clang-format-$(CLANG_VERSION)
LD = ld.lld-$(CLANG_VERSION)
LLVM_OBJDUMP = llvm-objdump-$(CLANG_VERSION)
LLVM_STRIP = llvm-strip-$(CLANG_VERSION)

.PHONY: all run check asm fmt clean

# -flto enables Link Time Optimization for better cross-module optimization (~4% cycle reduction)
# May increase compile time and can occasionally cause issues with specific toolchain configurations

CFLAGS = --target=riscv64 -march=rv64imc_zba_zbb_zbc_zbs -flto \
		-O3 -g \
		-nodefaultlibs \
		-isystem ../../deps/musl/release/include \
		-fdata-sections -ffunction-sections

LDFLAGS = -static --gc-sections -L../../deps/musl/release/lib -L../../deps/compiler-rt-builtins-riscv/build \
		-lc -lgcc -lcompiler-rt

%.o: %.c
	$(CLANG) $(CFLAGS) -c -o $@ $<

all: main.o sha256.o
	$(LD) $(LDFLAGS) -o main $^
	$(LLVM_STRIP) -s main

run:
	ckb-debugger --bin main

main.o sha256.o test_sha256.o: sha256.h

test_sha256.o: test/test_sha256.c
	$(CLANG) $(CFLAGS) -c -o $@ $<

target/test_sha256: test_sha256.o sha256.o
	mkdir -p target
	$(LD) $(LDFLAGS) -o $@ $^
	$(LLVM_STRIP) -s $@

check: target/test_sha256
	ckb-debugger --bin $<

asm: sha256.o
	$(LLVM_OBJDUMP) -d -S sha256.o

fmt:
	$(CLANG_FORMAT) --style="{BasedOnStyle: Google, IndentWidth: 4}" -i *.c *.h test/*.c

clean:
	rm -f main.o sha256.o test_sha256.o main target/test_sha256
