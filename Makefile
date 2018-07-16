BUILD_DIR ?= $(shell pwd)
INSTALL_DIR ?= $(BUILD_DIR)
PRO_EXE ?= $(INSTALL_DIR)/zyc_attendance
SRCS=$(wildcard $(BUILD_DIR)/*.c)
OBJS = $(patsubst %.c,%.o, $(SRCS))

#CFLAGS = "$CFLAGS -g2"
LDFLAGS += -lev  -lm  -ljson-c 

$(PRO_EXE):$(OBJS)
	@$(CC) $^ $(LDFLAGS) -o $@
	@rm $(OBJS)

$(OBJS):%.o:%.c
	@$(CC) -c $(CFLAGS) $< -o $@

install:
	@echo "$(PRO_EXE)"

clean:
	rm -rf $(OBJS) $(PRO_EXE)

