#include "test_runner.h"
#include "udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int g_occupy_fd = -1;

static void setup_occupy(void)
{
  if (g_occupy_fd >= 0)
    return;
  g_occupy_fd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(g_occupy_fd >= 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(22999);
  int ret = bind(g_occupy_fd, (struct sockaddr *)&addr, sizeof(addr));
  ASSERT_INT_EQ(ret, 0);
}

static void teardown_occupy(void)
{
  if (g_occupy_fd >= 0) {
    close(g_occupy_fd);
    g_occupy_fd = -1;
  }
}

static void test_open_success(void)
{
  int fd = udp_open(22222);
  ASSERT_TRUE(fd >= 0);
  close(fd);
}

static void test_open_and_recv(void)
{
  int fd = udp_open(22222);
  ASSERT_TRUE(fd >= 0);

  int snd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(snd >= 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(22222);

  const unsigned char payload[] = "HelloUDP";
  int ret = sendto(snd, payload, sizeof(payload), 0,
                   (struct sockaddr *)&dst, sizeof(dst));
  ASSERT_INT_EQ(ret, (int)sizeof(payload));

  unsigned char buf[64];
  uint32_t src_ip;
  uint16_t src_port;
  ret = udp_recv(fd, buf, sizeof(buf), &src_ip, &src_port);
  ASSERT_INT_EQ(ret, (int)sizeof(payload));
  ASSERT_INT_EQ(memcmp(buf, payload, sizeof(payload)), 0);
  ASSERT_INT_EQ((int)src_ip, (int)htonl(INADDR_LOOPBACK));
  ASSERT_TRUE(src_port != 0);

  ret = udp_recv(fd, buf, sizeof(buf), &src_ip, &src_port);
  ASSERT_INT_EQ(ret, -1);

  close(snd);
  close(fd);
}

static void test_open_bind_fail(void)
{
  setup_occupy();
  int fd = udp_open(22999);
  ASSERT_INT_EQ(fd, -1);
  teardown_occupy();
}

static void test_recv_small_buf(void)
{
  int fd = udp_open(22224);
  ASSERT_TRUE(fd >= 0);

  int snd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(snd >= 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(22224);

  const unsigned char payload[] = "ABCDEFGHIJ";
  int ret = sendto(snd, payload, sizeof(payload), 0,
                   (struct sockaddr *)&dst, sizeof(dst));
  ASSERT_INT_EQ(ret, (int)sizeof(payload));

  unsigned char buf[4];
  uint32_t src_ip;
  uint16_t src_port;
  ret = udp_recv(fd, buf, sizeof(buf), &src_ip, &src_port);
  ASSERT_INT_EQ(ret, 4);
  ASSERT_INT_EQ(memcmp(buf, "ABCD", 4), 0);
  ASSERT_INT_EQ((int)src_ip, (int)htonl(INADDR_LOOPBACK));
  ASSERT_TRUE(src_port != 0);

  close(snd);
  close(fd);
}

static void test_null_ptrs(void)
{
  int fd = udp_open(22225);
  ASSERT_TRUE(fd >= 0);

  int snd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(snd >= 0);

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  dst.sin_port = htons(22225);

  const unsigned char payload[] = "test";
  int ret = sendto(snd, payload, sizeof(payload), 0,
                   (struct sockaddr *)&dst, sizeof(dst));
  ASSERT_INT_EQ(ret, (int)sizeof(payload));

  unsigned char buf[64];
  ret = udp_recv(fd, buf, sizeof(buf), NULL, NULL);
  ASSERT_INT_EQ(ret, (int)sizeof(payload));
  ASSERT_INT_EQ(memcmp(buf, payload, sizeof(payload)), 0);

  close(snd);
  close(fd);
}

TEST_GROUP(udp)
{
TEST(test_open_success),
      TEST(test_open_and_recv), TEST(test_open_bind_fail), TEST(test_recv_small_buf), TEST(test_null_ptrs), END_TEST};
