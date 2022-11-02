CC ?= ${CROSS_COMPILE}gcc
LD ?= ${CROSS_COMPILE}ld
AR ?= ${CROSS_COMPILE}ar
NM ?= ${CROSS_COMPILE}nm

OBJCOPY ?= ${CROSS_COMPILE}objcopy
OBJDUMP ?= ${CROSS_COMPILE}objdump
READELF ?= ${CROSS_COMPILE}readelf

CFLAGS  += -Wall -I./
CFLAGS  += -I${TEEC_EXPORT}/include
CFLAGS  += `pkg-config --cflags openssl`

LDFLAGS += -lteec -lseteec -lckteec
LDFLAGS += -L${TEEC_EXPORT}/lib
LDFLAGS +=  `pkg-config --libs openssl`

BINARY = fio-se05x-cli
OBJS = fio_pkcs11.o fio_ssl.o fio_util.o isoc_7816.o main.o

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC)  -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
