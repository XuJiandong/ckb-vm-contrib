CLANG_VERSION ?= 19
CLANG = clang-$(CLANG_VERSION)
CLANG_FORMAT = clang-format-$(CLANG_VERSION)
LD = ld.lld-$(CLANG_VERSION)
LLVM_OBJDUMP = llvm-objdump-$(CLANG_VERSION)
LLVM_STRIP = llvm-strip-$(CLANG_VERSION)

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

all: main.o fips202.o
	$(LD) $(LDFLAGS) -o main $^
	$(LLVM_STRIP) -s main

run:
	ckb-debugger --bin main

asm: fips202.o
	$(LLVM_OBJDUMP) -d -S fips202.o

fmt:
	$(CLANG_FORMAT) --style="{BasedOnStyle: Google, IndentWidth: 4}" -i *.c *.h

clean:
	rm -f main.o fips202.o main
