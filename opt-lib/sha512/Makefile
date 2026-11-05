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

all: main.o sha512.o
	$(LD) $(LDFLAGS) -o main $^
	$(LLVM_STRIP) -s main

run:
	ckb-debugger --bin main

main.o sha512.o test_sha512.o: sha512.h

test_sha512.o: test/test_sha512.c
	$(CLANG) $(CFLAGS) -c -o $@ $<

target/test_sha512: test_sha512.o sha512.o
	mkdir -p target
	$(LD) $(LDFLAGS) -o $@ $^
	$(LLVM_STRIP) -s $@

check: target/test_sha512
	ckb-debugger --bin $<

asm: sha512.o
	$(LLVM_OBJDUMP) -d -S sha512.o

fmt:
	clang-format --style="{BasedOnStyle: Google, IndentWidth: 4}" -i *.c *.h test/*.c

clean:
	rm -f main.o sha512.o test_sha512.o main target/test_sha512
