CC       ?= musl-gcc
CFLAGS   ?= -std=c99 -pedantic -pedantic-errors -O3 -Wall -Wextra -flto \
            -MMD -MP -D_POSIX_C_SOURCE=200112L -D_DEFAULT_SOURCE \
            -fstack-protector-strong -D_FORTIFY_SOURCE=2
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
#  and daemon test (needs separate binary with mocks + main_core.o)
TEST_SRCS   = $(filter-out $(TEST_DIR)/mock_%.c $(TEST_DIR)/test_netlink.c \
                $(TEST_DIR)/test_daemon.c $(TEST_DIR)/test_client.c \
                $(TEST_DIR)/test_privdrop.c, $(wildcard $(TEST_DIR)/*.c))
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
DAEMON_TEST_BIN = $(BIN_DIR)/test_daemon
CLIENT_TEST_BIN = $(BIN_DIR)/test_client

OBJS      = $(MAIN_OBJS) $(LIB_OBJS)

.PHONY: all daemon client test daemon-test netlink-test clean style coverage

all: daemon client

daemon: $(DAEMON)

client: $(CLIENT)

#  Shared library objects (no main/client)
$(LIB_OBJS): | $(OBJ_DIR)

#  Daemon
$(DAEMON): $(OBJ_DIR)/main.o $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

#  Client
$(CLIENT): $(OBJ_DIR)/client.o $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

#  Main test runner — link together test object files + library objects (without main)
$(TEST_BIN): $(TEST_OBJS) $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/test_%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

#  Daemon test object — explicit rule (pattern test_%.o → test/%.c doesn't match)
$(OBJ_DIR)/test_daemon.o: $(TEST_DIR)/test_daemon.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -DBUILD_DAEMON_TEST_MAIN -c -o $@ $<

#  Client test object — explicit rule for standalone binary
$(OBJ_DIR)/test_client.o: $(TEST_DIR)/test_client.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -DBUILD_CLIENT_TEST_MAIN -c -o $@ $<

#  Daemon core object — compiled without main() for test linking
$(OBJ_DIR)/main_core.o: $(SRC_DIR)/main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -DDAEMON_CORE_ONLY -c -o $@ $<

#  Client core object — compiled without main() for test linking
$(OBJ_DIR)/client_core.o: $(SRC_DIR)/client.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -DCLIENT_CORE_ONLY -c -o $@ $<

#  Mock objects — replace real implementations at link time
$(OBJ_DIR)/mock_%.o: $(TEST_DIR)/mock_%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

#  Daemon test binary — links main_core.o + mocks + library objects
$(DAEMON_TEST_BIN): $(OBJ_DIR)/test_daemon.o $(OBJ_DIR)/main_core.o $(MOCK_OBJS) $(TEST_LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

#  Client test binary — links client_core.o + library objects (no mocks needed)
$(CLIENT_TEST_BIN): $(OBJ_DIR)/test_client.o $(OBJ_DIR)/client_core.o $(LIB_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

#  Netlink test — separate binary (defines syscall stubs, links against real netlink.o)
$(NL_BIN): $(OBJ_DIR)/netlink_test_stubs.o $(OBJ_DIR)/netlink.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/netlink_test_stubs.o: $(TEST_DIR)/test_netlink.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

#  Privdrop test — separate binary (defines libc stubs, links against real privdrop.o)
PRIVDROP_BIN = $(BIN_DIR)/test_privdrop

$(PRIVDROP_BIN): $(OBJ_DIR)/test_privdrop.o $(OBJ_DIR)/privdrop.o | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/test_privdrop.o: $(TEST_DIR)/test_privdrop.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

test: $(TEST_BIN) $(NL_BIN) $(DAEMON_TEST_BIN) $(CLIENT_TEST_BIN) $(PRIVDROP_BIN)
	./$(TEST_BIN)
	./$(NL_BIN)
	./$(DAEMON_TEST_BIN)
	./$(CLIENT_TEST_BIN)
	./$(PRIVDROP_BIN)

style:
	indent -linux -l120 -i2 -nut $(SRC_DIR)/*.c $(SRC_DIR)/*.h $(TEST_DIR)/*.c $(TEST_DIR)/*.h 2>/dev/null || true
	find $(SRC_DIR) $(TEST_DIR) -name '*~' -delete

COVERAGE_DIR = $(OBJ_DIR)/coverage
COVERAGE_CFLAGS = -fprofile-arcs -ftest-coverage -O0 -g
COVERAGE_LDFLAGS = -static --coverage

$(OBJ_DIR)/cov_%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -c -o $@ $<

$(OBJ_DIR)/cov_test_%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(OBJ_DIR)/cov_nl_stubs.o: $(TEST_DIR)/test_netlink.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

#  Daemon test coverage object — explicit rule for test_daemon.c
$(OBJ_DIR)/cov_test_daemon.o: $(TEST_DIR)/test_daemon.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -DBUILD_DAEMON_TEST_MAIN -c -o $@ $<

$(OBJ_DIR)/cov_test_client.o: $(TEST_DIR)/test_client.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -DBUILD_CLIENT_TEST_MAIN -c -o $@ $<

$(OBJ_DIR)/cov_main_core.o: $(SRC_DIR)/main.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -DDAEMON_CORE_ONLY -c -o $@ $<

$(OBJ_DIR)/cov_client_core.o: $(SRC_DIR)/client.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -DCLIENT_CORE_ONLY -c -o $@ $<

$(OBJ_DIR)/cov_mock_%.o: $(TEST_DIR)/mock_%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

$(BIN_DIR)/test_runner_cov: $(patsubst $(OBJ_DIR)/test_%.o, $(OBJ_DIR)/cov_test_%.o, $(TEST_OBJS)) \
                            $(patsubst $(OBJ_DIR)/%.o, $(OBJ_DIR)/cov_%.o, $(LIB_OBJS)) | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_netlink_cov: $(OBJ_DIR)/cov_nl_stubs.o $(OBJ_DIR)/cov_netlink.o | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_daemon_cov: $(OBJ_DIR)/cov_test_daemon.o $(OBJ_DIR)/cov_main_core.o \
                             $(patsubst $(OBJ_DIR)/mock_%.o, $(OBJ_DIR)/cov_mock_%.o, $(MOCK_OBJS)) \
                             $(patsubst $(OBJ_DIR)/%.o, $(OBJ_DIR)/cov_%.o, $(TEST_LIB_OBJS)) | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_client_cov: $(OBJ_DIR)/cov_test_client.o $(OBJ_DIR)/cov_client_core.o \
                             $(patsubst $(OBJ_DIR)/%.o, $(OBJ_DIR)/cov_%.o, $(LIB_OBJS)) | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(BIN_DIR)/test_privdrop_cov: $(OBJ_DIR)/cov_test_privdrop.o $(OBJ_DIR)/cov_privdrop.o | $(BIN_DIR)
	$(CC) $(COVERAGE_LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/cov_test_privdrop.o: $(TEST_DIR)/test_privdrop.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(COVERAGE_CFLAGS) -I$(SRC_DIR) -c -o $@ $<

coverage: $(BIN_DIR)/test_runner_cov $(BIN_DIR)/test_netlink_cov $(BIN_DIR)/test_daemon_cov $(BIN_DIR)/test_client_cov $(BIN_DIR)/test_privdrop_cov
	@rm -f $(SRC_DIR)/*.gcda $(SRC_DIR)/*.gcno
	./$(BIN_DIR)/test_runner_cov
	./$(BIN_DIR)/test_netlink_cov
	./$(BIN_DIR)/test_daemon_cov
	./$(BIN_DIR)/test_client_cov
	./$(BIN_DIR)/test_privdrop_cov
	@echo "=== Line coverage per module ==="
	@for src in $(LIB_SRCS); do \
		base=$$(basename $$src .c); \
		if [ -f "$(OBJ_DIR)/cov_$${base}.gcda" ]; then \
			gcov -n "$(OBJ_DIR)/cov_$${base}" 2>/dev/null | head -5; \
		fi; \
	done
	@gcov -n $(OBJ_DIR)/cov_main_core 2>/dev/null | head -5 || true
	@gcov -n $(OBJ_DIR)/cov_client_core 2>/dev/null | head -5 || true
	@rm -f $(SRC_DIR)/*.gcda $(SRC_DIR)/*.gcno

$(OBJ_DIR) $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

-include $(DEPS)
