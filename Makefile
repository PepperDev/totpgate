CC       ?= musl-gcc
CFLAGS   ?= -std=c99 -pedantic -pedantic-errors -O3 -Wall -Wextra -flto \
            -MMD -MP -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE
LDFLAGS  ?= -static -flto
LDLIBS   ?=

SRC_DIR   = src
TEST_DIR  = test
OBJ_DIR   = obj
BIN_DIR   = bin

SRCS      = $(wildcard $(SRC_DIR)/*.c)
MAIN_SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/client.c
LIB_SRCS  = $(filter-out $(MAIN_SRCS), $(SRCS))
MAIN_OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(MAIN_SRCS))
LIB_OBJS  = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(LIB_SRCS))
DEPS      = $(OBJS:.o=.d)

#  Test sources — exclude netlink test (has stubs that conflict)
TEST_SRCS   = $(filter-out $(TEST_DIR)/mock_%.c $(TEST_DIR)/test_netlink.c, \
                $(wildcard $(TEST_DIR)/*.c))
TEST_OBJS   = $(patsubst $(TEST_DIR)/%.c, $(OBJ_DIR)/test_%.o, $(TEST_SRCS))
MOCK_SRCS   = $(wildcard $(TEST_DIR)/mock_*.c)
MOCK_OBJS   = $(patsubst $(TEST_DIR)/mock_%.c, $(OBJ_DIR)/mock_%.o, $(MOCK_SRCS))
# Library objects that have a mock counterpart — exclude from test link
MOCKED_LIBS = $(patsubst $(TEST_DIR)/mock_%.c, $(OBJ_DIR)/%.o, $(MOCK_SRCS))
TEST_LIB_OBJS = $(filter-out $(MOCKED_LIBS), $(LIB_OBJS))

DAEMON    = $(BIN_DIR)/totpgated
CLIENT    = $(BIN_DIR)/totpgate
TEST_BIN  = $(BIN_DIR)/test_runner
NL_BIN    = $(BIN_DIR)/test_netlink

OBJS      = $(MAIN_OBJS) $(LIB_OBJS)

.PHONY: all daemon client test netlink-test clean style coverage

all: daemon client

daemon: $(DAEMON)

client: $(CLIENT)

#  Shared library objects (no main/client)
$(LIB_OBJS): | $(OBJ_DIR)

#  Daemon
$(DAEMON): $(OBJ_DIR)/main.o $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

#  Client
$(CLIENT): $(OBJ_DIR)/client.o $(filter-out $(OBJ_DIR)/totp.o, $(LIB_OBJS)) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

#  Main test runner — link together test object files + library objects (without main)
$(TEST_BIN): $(TEST_OBJS) $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/test_%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

#  Netlink test — separate binary (defines syscall stubs, links against real netlink.o)
$(NL_BIN): $(OBJ_DIR)/netlink_test_stubs.o $(OBJ_DIR)/netlink.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/netlink_test_stubs.o: $(TEST_DIR)/test_netlink.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

test: $(TEST_BIN) $(NL_BIN)
	./$(TEST_BIN)
	./$(NL_BIN)

style:
	indent -linux -120 -i2 -nut $(SRC_DIR)/*.c $(SRC_DIR)/*.h $(TEST_DIR)/*.c $(TEST_DIR)/*.h 2>/dev/null || true

COVERAGE_DIR = $(OBJ_DIR)/coverage
COVERAGE_CFLAGS = -fprofile-arcs -ftest-coverage -O0 -g
COVERAGE_LDFLAGS = -static --coverage

$(OBJ_DIR)/cov_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -c -o $@ $<

$(OBJ_DIR)/cov_test_%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(OBJ_DIR)/cov_nl_stubs.o: $(TEST_DIR)/test_netlink.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(BIN_DIR)/test_runner_cov: $(patsubst $(OBJ_DIR)/test_%.o, $(OBJ_DIR)/cov_test_%.o, $(TEST_OBJS)) \
                            $(patsubst $(OBJ_DIR)/%.o, $(OBJ_DIR)/cov_%.o, $(LIB_OBJS)) | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_netlink_cov: $(OBJ_DIR)/cov_nl_stubs.o $(OBJ_DIR)/cov_netlink.o | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

coverage: $(BIN_DIR)/test_runner_cov $(BIN_DIR)/test_netlink_cov
	@rm -f $(SRC_DIR)/*.gcda $(SRC_DIR)/*.gcno
	./$(BIN_DIR)/test_runner_cov
	./$(BIN_DIR)/test_netlink_cov
	@echo "=== Line coverage per module ==="
	@for src in $(LIB_SRCS); do \
		base=$$(basename $$src .c); \
		if [ -f "$(OBJ_DIR)/cov_$${base}.gcda" ]; then \
			gcov -n "$(OBJ_DIR)/cov_$${base}" 2>/dev/null | head -5; \
		fi; \
	done
	@gcov -n $(OBJ_DIR)/cov_main 2>/dev/null | head -5 || true
	@rm -f $(SRC_DIR)/*.gcda $(SRC_DIR)/*.gcno

$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

-include $(DEPS)
