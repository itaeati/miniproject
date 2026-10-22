#define _GNU_SOURCE
#include "header.h"
#include "onnxruntime_c_api.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <linux/inet_diag.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif

/* 24개 네트워크 침입 탐지 클래스 정의 */
#define NUM_CLASSES 24
#define CLASS_NORMAL 15
#define CLASS_SSH_PATATOR 18
#define CLASS_FTP_PATATOR 10
#define CLASS_BRUTE_FORCE 20

#ifndef ENABLE_INLINE_DROP
#define ENABLE_INLINE_DROP 1
#endif

static const char *CLASS_NAMES[NUM_CLASSES] = {
	"Analysis", "Backdoor", "Bot", "DDoS", "DoS",
	"DoS GoldenEye", "DoS Hulk", "DoS SlowHTTPTest", "DoS Slowloris", "Exploits",
	"FTP Patator", "Fuzzers", "Generic", "Heartbleed", "Infiltration",
	"Normal", "Port Scan", "Reconnaissance", "SSH Patator", "Shellcode",
	"Web Attack - Brute Force", "Web Attack - SQL Injection", "Web Attack - XSS", "Worms"
};

/* =========================================================================
 * 0. 런타임 설정 (하드코딩 제거: 모든 값은 CLI 옵션으로 변경 가능)
 * ========================================================================= */
struct config {
	unsigned int queue_num;
	char model_path[PATH_MAX];
	char vocab_path[PATH_MAX];
	char log_path[PATH_MAX];
	char ready_file[PATH_MAX];
	int intra_threads;
	unsigned int inspect_first;       /* 신규 세션: 검증 완료 전까지 최소 N개 페이로드 패킷 전수 검사 */
	unsigned int sample_rate;         /* 검증 완료 세션: 페이로드 패킷을 1/K 확률로 무작위 재검사 (0=비활성) */
	unsigned int job_queue_max;       /* 추론 대기열 상한 (초과 시 DROP: fail-closed) */
	unsigned int kernel_queue_maxlen; /* 커널 NFQUEUE 최대 길이 (초과 시 커널 DROP: fail-closed) */
	unsigned int new_flow_rate;       /* IP당 초당 신규 플로우 상한 (초과 시 IP 일시 차단) */
	unsigned int halfopen_per_ip;     /* IP당 half-open(페이로드 없는 신규) 세션 상한 */
	unsigned int halfopen_global;     /* 전체 half-open 세션 상한 */
	unsigned int ip_block_sec;        /* 빈도 초과 IP 차단 시간 */
	unsigned int bf_threshold;        /* Patator 계열 판정 시 요구되는 연결 빈도 */
	unsigned int bf_window_sec;
	unsigned int new_timeout;         /* half-open 세션 만료 */
	unsigned int tcp_idle_timeout;
	unsigned int udp_idle_timeout;
	unsigned int close_timeout;       /* FIN/RST 이후 만료 */
	unsigned int block_timeout;       /* 차단 세션 유지 시간 (마지막 패킷 기준) */
};

static struct config cfg = {
	.queue_num = 0,
	.intra_threads = 4,
	.inspect_first = 3,
	.sample_rate = 8,
	.job_queue_max = 32,
	.kernel_queue_maxlen = 1024,
	.new_flow_rate = 20,
	.halfopen_per_ip = 32,
	.halfopen_global = 4096,
	.ip_block_sec = 60,
	.bf_threshold = 5,
	.bf_window_sec = 60,
	.new_timeout = 30,
	.tcp_idle_timeout = 600,
	.udp_idle_timeout = 60,
	.close_timeout = 10,
	.block_timeout = 300,
};

/* =========================================================================
 * 0-1. 통계 카운터 (SIGUSR1 또는 종료 시 출력)
 * ========================================================================= */
struct stats {
	atomic_ulong rx;
	atomic_ulong accept_new_syn;
	atomic_ulong accept_no_payload;
	atomic_ulong accept_inspected;
	atomic_ulong accept_sampled_skip;   /* 검증 완료 세션에서 샘플링 제외로 허용 */
	atomic_ulong accept_other_proto;
	atomic_ulong drop_attack;
	atomic_ulong drop_blocked_session;
	atomic_ulong drop_unknown_flow;     /* SYN 없이 시작된 미등록 TCP 플로우 */
	atomic_ulong drop_unparsable;
	atomic_ulong drop_job_queue_full;   /* 부하 시 fail-closed */
	atomic_ulong drop_table_full;
	atomic_ulong drop_ip_blocked;
	atomic_ulong drop_rate_exceeded;
	atomic_ulong drop_halfopen_ip;
	atomic_ulong drop_halfopen_global;
	atomic_ulong drop_infer_error;
	atomic_ulong inferences;
	atomic_ulong enobufs;
	atomic_ulong verdict_fail;
};
static struct stats g_stats;
#define STAT_INC(f) atomic_fetch_add_explicit(&g_stats.f, 1, memory_order_relaxed)

static volatile sig_atomic_t stop_flag = 0;
static volatile sig_atomic_t dump_flag = 0;
static volatile sig_atomic_t rescan_flag = 0;

static time_t mono_now(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

/* =========================================================================
 * 1. WordPiece 어휘 사전 로드 및 토큰화
 * ========================================================================= */
#define VOCAB_HASH_SIZE 131072
#define VOCAB_PROBE_MAX 256
#define VOCAB_WORD_MAX 64
struct vocab_entry {
	char word[VOCAB_WORD_MAX];
	int id;
	int is_used;
};
static struct vocab_entry g_vocab[VOCAB_HASH_SIZE];
static int64_t g_tok_unk = -1, g_tok_cls = -1, g_tok_sep = -1;

static uint32_t hash_word(const char *str)
{
	uint32_t hash = 5381;
	while (*str)
		hash = ((hash << 5) + hash) + (uint8_t)(*str++);
	return hash & (VOCAB_HASH_SIZE - 1);
}

static int vocab_insert(const char *word, int id)
{
	uint32_t idx = hash_word(word);
	for (int i = 0; i < VOCAB_PROBE_MAX; i++)
	{
		uint32_t cur = (idx + i) & (VOCAB_HASH_SIZE - 1);
		if (!g_vocab[cur].is_used)
		{
			g_vocab[cur].is_used = 1;
			snprintf(g_vocab[cur].word, sizeof(g_vocab[cur].word), "%s", word);
			g_vocab[cur].id = id;
			return 0;
		}
	}
	return -1;
}

static int vocab_lookup(const char *word)
{
	uint32_t idx = hash_word(word);
	for (int i = 0; i < VOCAB_PROBE_MAX; i++)
	{
		uint32_t cur = (idx + i) & (VOCAB_HASH_SIZE - 1);
		if (g_vocab[cur].is_used && strcmp(g_vocab[cur].word, word) == 0)
			return g_vocab[cur].id;
		if (!g_vocab[cur].is_used)
			break;
	}
	return -1;
}

static int load_vocab(const char *path, int *failed_inserts)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	char line[256];
	int id = 0;
	*failed_inserts = 0;
	while (fgets(line, sizeof(line), f))
	{
		line[strcspn(line, "\r\n")] = '\0';
		if (strlen(line) < VOCAB_WORD_MAX && vocab_insert(line, id) == 0)
			;
		else
			(*failed_inserts)++;
		id++;
	}
	fclose(f);
	return id;
}

static int tokenize_word(const char *word, int64_t *out_tokens, int max_tokens)
{
	int len = (int)strlen(word);
	int count = 0, start = 0;
	while (start < len && count < max_tokens)
	{
		int end = len, found_id = -1, match_end = start;
		/* 하위 문자열 버퍼(sub[64]) 경계 보장: "##" 접두어 2바이트 + NUL 1바이트 */
		if (end - start > VOCAB_WORD_MAX - 3)
			end = start + VOCAB_WORD_MAX - 3;
		while (start < end)
		{
			char sub[VOCAB_WORD_MAX];
			int sub_len = end - start;
			if (start > 0)
			{
				sub[0] = '#';
				sub[1] = '#';
				memcpy(sub + 2, word + start, sub_len);
				sub[sub_len + 2] = '\0';
			}
			else
			{
				memcpy(sub, word + start, sub_len);
				sub[sub_len] = '\0';
			}
			int id = vocab_lookup(sub);
			if (id >= 0)
			{
				found_id = id;
				match_end = end;
				break;
			}
			end--;
		}
		if (found_id == -1)
		{
			out_tokens[count++] = g_tok_unk;
			start++;
		}
		else
		{
			out_tokens[count++] = found_id;
			start = match_end;
		}
	}
	return count;
}

#define ET_BERT_SEQ_LEN 128
struct bert_engine_ctx {
	const OrtApi *api;
	OrtEnv *env;
	OrtSession *session;
	OrtMemoryInfo *mem_info;
	int is_initialized;
};
static struct bert_engine_ctx g_bert = {0};

/* =========================================================================
 * 2. 패킷 파싱 (IPv4 / IPv6 확장 헤더 체인 / TCP / UDP)
 * ========================================================================= */
struct flow_key {
	uint8_t family; /* 4 또는 6 */
	uint8_t proto;  /* IPPROTO_TCP / IPPROTO_UDP */
	uint16_t sport;
	uint16_t dport;
	uint8_t saddr[16];
	uint8_t daddr[16];
};

struct pkt_info {
	struct flow_key key;
	uint8_t ttl, tos, tcp_flags, tcp_doff;
	unsigned int ip_len;         /* L3 전체 길이 */
	unsigned int l4_payload_off; /* 패킷 시작 기준 애플리케이션 페이로드 오프셋 */
	unsigned int l4_payload_len;
};

enum parse_result { PARSE_OK = 0, PARSE_OTHER = 1, PARSE_FAIL = 2 };

static int parse_l4(const unsigned char *p, unsigned int end, unsigned int off, uint8_t proto, struct pkt_info *pi)
{
	if (proto == IPPROTO_TCP)
	{
		if (off + sizeof(tcpheader) > end)
			return PARSE_FAIL;
		const tcpheader *tcp = (const tcpheader *)(p + off);
		unsigned int doff = (tcp->offset_res >> 4) & 0x0F;
		if (doff < 5 || off + doff * 4 > end)
			return PARSE_FAIL;
		pi->key.proto = IPPROTO_TCP;
		pi->key.sport = ntohs(tcp->srcport);
		pi->key.dport = ntohs(tcp->dstport);
		pi->tcp_flags = tcp->flags;
		pi->tcp_doff = (uint8_t)doff;
		pi->l4_payload_off = off + doff * 4;
		pi->l4_payload_len = end - pi->l4_payload_off;
		pi->ip_len = 20 + (end - off); /* L3 헤더 길이(IPv4 20B / IPv6 40B+확장헤더) 정규화 */
		return PARSE_OK;
	}
	if (proto == IPPROTO_UDP)
	{
		if (off + sizeof(udpheader) > end)
			return PARSE_FAIL;
		const udpheader *udp = (const udpheader *)(p + off);
		unsigned int ulen = ntohs(udp->length);
		if (ulen < sizeof(udpheader) || off + ulen > end)
			return PARSE_FAIL;
		pi->key.proto = IPPROTO_UDP;
		pi->key.sport = ntohs(udp->srcport);
		pi->key.dport = ntohs(udp->dstport);
		pi->l4_payload_off = off + sizeof(udpheader);
		pi->l4_payload_len = ulen - sizeof(udpheader);
		pi->ip_len = 20 + ulen; /* L3 헤더 길이 정규화 */
		return PARSE_OK;
	}
	return PARSE_OTHER;
}

static int parse_packet(const unsigned char *p, unsigned int len, struct pkt_info *pi)
{
	memset(pi, 0, sizeof(*pi));
	pi->tcp_doff = 5;
	if (len < 1)
		return PARSE_FAIL;

	uint8_t version = (p[0] >> 4) & 0x0F;
	if (version == 4)
	{
		if (len < sizeof(Packet))
			return PARSE_FAIL;
		const Packet *ip = (const Packet *)p;
		unsigned int ihl = (ip->verihl & 0x0F) * 4;
		unsigned int tot = ntohs(ip->length);
		if (ihl < 20 || tot < ihl || tot > len)
			return PARSE_FAIL;
		pi->key.family = 4;
		memcpy(pi->key.saddr, ip->srcip, 4);
		memcpy(pi->key.daddr, ip->dstip, 4);
		pi->ip_len = tot;
		pi->ttl = ip->ttl;
		pi->tos = ip->tos;
		if (ntohs(ip->offset) & 0x1FFF) /* 비첫 단편: L4 헤더 없음 → 검사 불가 */
			return (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) ? PARSE_FAIL : PARSE_OTHER;
		return parse_l4(p, tot, ihl, ip->protocol, pi);
	}
	if (version == 6)
	{
		if (len < sizeof(Packet_Jumbo))
			return PARSE_FAIL;
		const Packet_Jumbo *ip6 = (const Packet_Jumbo *)p;
		unsigned int end = 40 + ntohs(ip6->length);
		if (end > len)
			return PARSE_FAIL;
		pi->key.family = 6;
		memcpy(pi->key.saddr, ip6->srcip, 16);
		memcpy(pi->key.daddr, ip6->dstip, 16);
		pi->ip_len = end;
		pi->ttl = ip6->hlimit;
		pi->tos = (uint8_t)((ntohl(ip6->ver_tc_fl) >> 20) & 0xFF);

		uint8_t nh = ip6->nextheader;
		unsigned int off = 40;
		for (int i = 0; i < 16; i++) /* 확장 헤더 체인 순회 */
		{
			switch (nh)
			{
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				return parse_l4(p, end, off, nh, pi);
			case 0:  /* Hop-by-Hop */
			case 43: /* Routing */
			case 60: /* Destination Options */
				if (off + 8 > end)
					return PARSE_FAIL;
				nh = p[off];
				off += (p[off + 1] + 1) * 8;
				break;
			case 44: /* Fragment */
				if (off + 8 > end)
					return PARSE_FAIL;
				if (((p[off + 2] << 8) | p[off + 3]) & 0xFFF8) /* 비첫 단편 */
					return PARSE_FAIL;
				nh = p[off];
				off += 8;
				break;
			case 51: /* AH */
				if (off + 8 > end)
					return PARSE_FAIL;
				nh = p[off];
				off += (p[off + 1] + 2) * 4;
				break;
			default: /* ESP(50), No Next Header(59), ICMPv6 등 */
				return PARSE_OTHER;
			}
			if (off > end)
				return PARSE_FAIL;
		}
		return PARSE_FAIL; /* 비정상적으로 긴 확장 헤더 체인 */
	}
	return PARSE_FAIL;
}

static void addr_to_str(uint8_t family, const uint8_t *addr, char *out, size_t outlen)
{
	if (!inet_ntop(family == 6 ? AF_INET6 : AF_INET, addr, out, outlen))
		snprintf(out, outlen, "UNKNOWN");
}

/* =========================================================================
 * 3. 해시 (기동 시 무작위 시드: 해시 충돌 유도 공격 완화)
 * ========================================================================= */
static uint32_t g_hash_seed = 0;

static uint32_t hash_bytes(const void *data, size_t len)
{
	const uint8_t *b = data;
	uint32_t h = 2166136261u ^ g_hash_seed;
	for (size_t i = 0; i < len; i++)
	{
		h ^= b[i];
		h *= 16777619u;
	}
	h ^= h >> 16;
	h *= 0x85ebca6bu;
	h ^= h >> 13;
	return h;
}

static uint64_t g_rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rng_next(void) /* xorshift64*: 샘플링 위치 예측 방지용 */
{
	uint64_t x = g_rng_state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	g_rng_state = x;
	return (uint32_t)((x * 0x2545F4914F6CDD1Dull) >> 32);
}

/* =========================================================================
 * 4. IP별 상태 (신규 플로우 빈도, 브루트포스 빈도, half-open 수, 일시 차단)
 * ========================================================================= */
#define IP_TABLE_SIZE 16384 /* 2의 거듭제곱 */
#define TABLE_PROBE 32

struct ip_entry {
	uint8_t used;
	uint8_t family;
	uint8_t addr[16];
	time_t last_seen;
	time_t rate_window;
	uint32_t rate_count;
	time_t bf_window;
	uint32_t bf_count;
	uint32_t halfopen;
	time_t block_until;
};
static struct ip_entry g_ip[IP_TABLE_SIZE];

static int ip_evictable(const struct ip_entry *e, time_t now)
{
	time_t idle = (time_t)(cfg.bf_window_sec > 2 ? cfg.bf_window_sec : 2);
	return e->halfopen == 0 && e->block_until <= now && e->last_seen + idle < now;
}

static struct ip_entry *ip_get(uint8_t family, const uint8_t *addr, time_t now, int create)
{
	size_t alen = (family == 4) ? 4 : 16;
	uint8_t k[17] = {0};
	k[0] = family;
	memcpy(k + 1, addr, alen);
	uint32_t idx = hash_bytes(k, sizeof(k)) & (IP_TABLE_SIZE - 1);
	struct ip_entry *reuse = NULL, *lru = NULL;
	for (int i = 0; i < TABLE_PROBE; i++)
	{
		struct ip_entry *e = &g_ip[(idx + i) & (IP_TABLE_SIZE - 1)];
		if (e->used && e->family == family && memcmp(e->addr, addr, alen) == 0)
			return e;
		if (!reuse && (!e->used || ip_evictable(e, now)))
			reuse = e;
		else if (e->used && e->halfopen == 0 && e->block_until <= now && e->bf_count == 0 &&
		         (!lru || e->last_seen < lru->last_seen))
			lru = e;
	}
	if (!reuse)
		reuse = lru;
	if (!create || !reuse)
		return NULL;
	memset(reuse, 0, sizeof(*reuse));
	reuse->used = 1;
	reuse->family = family;
	memcpy(reuse->addr, addr, alen);
	reuse->last_seen = now;
	reuse->rate_window = now;
	reuse->bf_window = now;
	return reuse;
}

/* 신규 플로우 기록: 1초 윈도우 빈도 초과 시 1 반환 */
static int ip_note_new_flow(struct ip_entry *ip, time_t now)
{
	ip->last_seen = now;
	if (ip->rate_window != now)
	{
		ip->rate_window = now;
		ip->rate_count = 0;
	}
	ip->rate_count++;
	return ip->rate_count > cfg.new_flow_rate;
}

/* 브루트포스(Patator / Brute Force) 분류 누적: 윈도우 내 임계값 이상이면 1 반환 */
static int ip_note_bf(struct ip_entry *ip, time_t now)
{
	if (!ip)
		return 1; /* IP 테이블 포화 시 fail-closed (M4) */
	ip->last_seen = now;
	if (now - ip->bf_window >= (time_t)cfg.bf_window_sec)
	{
		ip->bf_window = now;
		ip->bf_count = 0;
	}
	ip->bf_count++;
	return ip->bf_count >= cfg.bf_threshold;
}

/* =========================================================================
 * 5. 세션 상태 머신 (5-tuple 키, 만료/삭제/교체 지원)
 * ========================================================================= */
#define SESSION_TABLE_SIZE 65536 /* 2의 거듭제곱 */

typedef enum {
	SESSION_STATE_NEW = 1,         /* 신규: 검증 미완료 → 모든 페이로드 패킷 검사 */
	SESSION_STATE_ESTABLISHED = 2, /* 검증 완료: 무작위 샘플링 재검사 */
	SESSION_STATE_BLOCKED = 3,     /* 공격 판정: 즉시 DROP */
} session_state_t;

struct session {
	uint8_t used;
	uint8_t state;
	uint8_t closing;  /* FIN/RST 관측 */
	uint8_t halfopen; /* half-open 카운트 반영 여부 */
	uint32_t gen;     /* 슬롯 재사용 식별 */
	struct flow_key key;
	uint32_t payload_pkts;
	uint32_t verified_pkts;
	uint32_t pending;
	time_t last_seen;
	time_t expires;
	const char *label;
};
static struct session g_sess[SESSION_TABLE_SIZE];
static uint32_t g_sess_gen = 0;
static uint32_t g_halfopen_total = 0;
static pthread_mutex_t g_tab_lock = PTHREAD_MUTEX_INITIALIZER;

static void halfopen_release(struct session *s, time_t now)
{
	if (!s->halfopen)
		return;
	s->halfopen = 0;
	if (g_halfopen_total > 0)
		g_halfopen_total--;
	struct ip_entry *ip = ip_get(s->key.family, s->key.saddr, now, 0);
	if (ip && ip->halfopen > 0)
		ip->halfopen--;
}

static void session_free(struct session *s, time_t now)
{
	halfopen_release(s, now);
	s->used = 0;
}

static struct session *session_find(const struct flow_key *k, time_t now)
{
	uint32_t idx = hash_bytes(k, sizeof(*k)) & (SESSION_TABLE_SIZE - 1);
	for (int i = 0; i < TABLE_PROBE; i++)
	{
		struct session *s = &g_sess[(idx + i) & (SESSION_TABLE_SIZE - 1)];
		if (s->used && memcmp(&s->key, k, sizeof(*k)) == 0)
		{
			if (s->expires <= now && s->pending == 0)
			{
				session_free(s, now);
				return NULL;
			}
			return s;
		}
	}
	return NULL;
}

/* 빈 슬롯 → 만료 슬롯 → half-open → closing → 비차단 LRU(last_seen 최소) 슬롯 순으로 할당. 없으면 NULL(DROP) */
static struct session *session_insert(const struct flow_key *k, session_state_t st, time_t now)
{
	uint32_t idx = hash_bytes(k, sizeof(*k)) & (SESSION_TABLE_SIZE - 1);
	struct session *pick = NULL, *victim_ho = NULL, *victim_cl = NULL, *victim_lru = NULL;
	for (int i = 0; i < TABLE_PROBE && !pick; i++)
	{
		struct session *s = &g_sess[(idx + i) & (SESSION_TABLE_SIZE - 1)];
		if (!s->used || (s->expires <= now && s->pending == 0))
			pick = s;
		else if (s->pending == 0 && s->state != SESSION_STATE_BLOCKED)
		{
			if (s->state == SESSION_STATE_NEW && s->payload_pkts == 0)
			{
				if (!victim_ho || s->last_seen < victim_ho->last_seen)
					victim_ho = s;
			}
			else if (s->closing)
			{
				if (!victim_cl || s->last_seen < victim_cl->last_seen)
					victim_cl = s;
			}
			else if (!victim_lru || s->last_seen < victim_lru->last_seen)
			{
				victim_lru = s;
			}
		}
	}
	if (!pick)
		pick = victim_ho ? victim_ho : (victim_cl ? victim_cl : victim_lru);
	if (!pick)
		return NULL;
	if (pick->used)
		session_free(pick, now);
	memset(pick, 0, sizeof(*pick));
	pick->used = 1;
	pick->state = (uint8_t)st;
	pick->gen = ++g_sess_gen;
	pick->key = *k;
	pick->last_seen = now;
	pick->label = "Normal";
	return pick;
}

static void session_touch(struct session *s, time_t now)
{
	s->last_seen = now;
	if (s->state == SESSION_STATE_BLOCKED)
		s->expires = now + cfg.block_timeout;
	else if (s->closing)
	{
		if (s->expires > now + (time_t)cfg.close_timeout)
			s->expires = now + cfg.close_timeout;
	}
	else if (s->key.proto == IPPROTO_UDP)
		s->expires = now + cfg.udp_idle_timeout;
	else if (s->payload_pkts == 0)
		s->expires = now + cfg.new_timeout;
	else
		s->expires = now + cfg.tcp_idle_timeout;
}

static void sweep_tables(time_t now)
{
	pthread_mutex_lock(&g_tab_lock);
	for (int i = 0; i < SESSION_TABLE_SIZE; i++)
	{
		struct session *s = &g_sess[i];
		if (s->used && s->expires <= now && s->pending == 0)
			session_free(s, now);
	}
	for (int i = 0; i < IP_TABLE_SIZE; i++)
	{
		if (g_ip[i].used && ip_evictable(&g_ip[i], now) && g_ip[i].last_seen + 600 < now)
			g_ip[i].used = 0;
	}
	pthread_mutex_unlock(&g_tab_lock);
}

/* /proc/net/tcp(6)의 32비트 hex 워드는 호스트 바이트 순서 값이므로 memcpy로 원래 바이트 배열 복원 */
static int proc_hex_addr(const char *hex, uint8_t *out, int words)
{
	for (int w = 0; w < words; w++)
	{
		char tmp[9];
		memcpy(tmp, hex + w * 8, 8);
		tmp[8] = '\0';
		char *endp;
		uint32_t v = (uint32_t)strtoul(tmp, &endp, 16);
		if (*endp != '\0')
			return -1;
		memcpy(out + w * 4, &v, 4);
	}
	return 0;
}

static void register_preexisting_dir(const struct flow_key *k, unsigned int state, time_t now, int *total, int *fresh)
{
	if (session_find(k, now))
		return;
	struct session *s = session_insert(k, state == 0x01 ? SESSION_STATE_ESTABLISHED : SESSION_STATE_NEW, now);
	if (!s)
		return;
	if (state == 0x01)
	{
		s->payload_pkts = cfg.inspect_first;
		s->verified_pkts = cfg.inspect_first;
		s->expires = now + cfg.tcp_idle_timeout;
		(*total)++;
	}
	else
	{
		s->expires = now + cfg.new_timeout;
		(*fresh)++;
	}
}

/**
 * @brief 큐 바인드 이후 기수립 연결(/proc/net/tcp, tcp6)을 양방향(INPUT 및 OUTPUT)으로 등록.
 *        ESTABLISHED(01) → 검증 완료 상태, SYN_RECV(03) → 신규(검증 필요) 상태.
 */
static void load_preexisting_sessions(time_t now)
{
	static const char *files[2] = {"/proc/net/tcp", "/proc/net/tcp6"};
	int total = 0, fresh = 0;
	pthread_mutex_lock(&g_tab_lock);
	for (int fi = 0; fi < 2; fi++)
	{
		FILE *f = fopen(files[fi], "r");
		if (!f)
			continue;
		int words = (fi == 0) ? 1 : 4;
		char line[512];
		if (!fgets(line, sizeof(line), f))
		{
			fclose(f);
			continue;
		}
		while (fgets(line, sizeof(line), f))
		{
			char loc[40], rem[40];
			unsigned int sl, loc_port, rem_port, state;
			if (sscanf(line, " %u: %39[0-9A-Fa-f]:%x %39[0-9A-Fa-f]:%x %x", &sl, loc, &loc_port, rem, &rem_port, &state) < 6)
				continue;
			if (state != 0x01 && state != 0x03)
				continue;
			if ((int)strlen(loc) != words * 8 || (int)strlen(rem) != words * 8)
				continue;
			struct flow_key k_in, k_out;
			memset(&k_in, 0, sizeof(k_in));
			uint8_t la[16] = {0}, ra[16] = {0};
			if (proc_hex_addr(loc, la, words) < 0 || proc_hex_addr(rem, ra, words) < 0)
				continue;
			static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
			if (words == 4 && memcmp(ra, v4mapped, 12) == 0 && memcmp(la, v4mapped, 12) == 0)
			{
				k_in.family = 4;
				memcpy(k_in.saddr, ra + 12, 4);
				memcpy(k_in.daddr, la + 12, 4);
			}
			else
			{
				k_in.family = (words == 1) ? 4 : 6;
				memcpy(k_in.saddr, ra, words * 4);
				memcpy(k_in.daddr, la, words * 4);
			}
			k_in.proto = IPPROTO_TCP;
			k_in.sport = (uint16_t)rem_port; /* 원격 → 로컬 (INPUT 방향) */
			k_in.dport = (uint16_t)loc_port;
			register_preexisting_dir(&k_in, state, now, &total, &fresh);

			/* 로컬 → 원격 (OUTPUT 방향) 동시 등록 */
			k_out = k_in;
			memcpy(k_out.saddr, k_in.daddr, 16);
			memcpy(k_out.daddr, k_in.saddr, 16);
			k_out.sport = (uint16_t)loc_port;
			k_out.dport = (uint16_t)rem_port;
			register_preexisting_dir(&k_out, state, now, &total, &fresh);
		}
		fclose(f);
	}
	pthread_mutex_unlock(&g_tab_lock);
	printf("[+] [기존 연결 보호] 수립 세션 %d개(ESTABLISHED), 핸드셰이크 진행 세션 %d개(검증 대상) 등록 완료.\n", total, fresh);
	fflush(stdout);
}

/* =========================================================================
 * 6. 로그 기록 (버퍼 경계 보장)
 * ========================================================================= */
static int g_log_fd = -1;

static void buf_appendf(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
	if (*off >= cap - 1)
		return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	*off += (size_t)n;
	if (*off > cap - 1) /* 잘린 경우 실제 기록된 길이로 상한 */
		*off = cap - 1;
}

/**
 * @brief 차단 패킷 16진수 Hex Dump 기록. 기록 길이는 항상 버퍼 크기 이내.
 */
static int log_abnormal_packet(int fd, const char *label, unsigned int packet_id, const struct flow_key *k,
                               const unsigned char *pkt, unsigned int pkt_len)
{
	if (fd < 0 || !pkt || pkt_len == 0)
		return -1;

	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	addr_to_str(k->family, k->saddr, src, sizeof(src));
	addr_to_str(k->family, k->daddr, dst, sizeof(dst));

	static const char trailer[] = "\n----------------------------------------\n";
	char log_buf[4096];
	size_t off = 0;
	size_t body_cap = sizeof(log_buf) - sizeof(trailer); /* 트레일러 공간 예약 */
	size_t hex_cap = body_cap - 40;                      /* 잘림 안내 문자열("\n... (truncated N bytes)") 공간 예약 */
	buf_appendf(log_buf, body_cap, &off,
	            "\n[ATTACK DETECTED: %s] Packet ID: %u | %s:%u -> %s:%u | Length: %u bytes\nHex Dump:\n",
	            label, packet_id, src, k->sport, dst, k->dport, pkt_len);
	unsigned int i;
	for (i = 0; i < pkt_len && off + 4 < hex_cap; i++)
	{
		buf_appendf(log_buf, hex_cap, &off, "%02x ", pkt[i]);
		if ((i + 1) % 16 == 0)
			buf_appendf(log_buf, hex_cap, &off, "\n");
	}
	if (i < pkt_len)
		buf_appendf(log_buf, body_cap, &off, "\n... (truncated %u bytes)", pkt_len - i);
	memcpy(log_buf + off, trailer, sizeof(trailer) - 1);
	off += sizeof(trailer) - 1;

	if (write(fd, log_buf, off) < 0)
	{
		perror("File Write Failed!");
		return -1;
	}
	return 0;
}

static void log_rate_event(const char *label, const struct flow_key *k)
{
	char src[INET6_ADDRSTRLEN];
	addr_to_str(k->family, k->saddr, src, sizeof(src));
	printf("\n[!] [빈도 기반 차단] %s | 출발지 %s 를 %u초간 차단 (신규 플로우 상한 %u/초 초과)\n",
	       label, src, cfg.ip_block_sec, cfg.new_flow_rate);
	fflush(stdout);
	if (g_log_fd >= 0)
	{
		char b[256];
		int n = snprintf(b, sizeof(b), "\n[RATE BLOCK: %s] src=%s block=%us limit=%u/s\n----------------------------------------\n",
		                 label, src, cfg.ip_block_sec, cfg.new_flow_rate);
		if (n > 0 && write(g_log_fd, b, (size_t)n < sizeof(b) ? (size_t)n : sizeof(b) - 1) < 0)
			perror("File Write Failed!");
	}
}

/* =========================================================================
 * 7. 모델 추론 (실패 시 -1 반환 → 호출자는 DROP: fail-closed)
 * ========================================================================= */
static int et_bert_classify_packet(const unsigned char *payload, unsigned int payload_len,
                                   unsigned int ip_len, uint16_t src_port, uint16_t dst_port,
                                   uint8_t ip_ttl, uint8_t ip_tos, uint8_t tcp_offset, uint8_t tcp_flags)
{
	if (!g_bert.is_initialized)
		return -1;

	int64_t input_ids[ET_BERT_SEQ_LEN] = {0};
	int64_t attention_mask[ET_BERT_SEQ_LEN] = {0};

	input_ids[0] = g_tok_cls;
	attention_mask[0] = 1;
	int count = 1;

	/* 1. 네트워크 플로우 헤더 특징 정규화 및 토큰화
	 * - L3/L4 가변 옵션(TCP Timestamp doff=8 등), IPv4/IPv6 헤더 길이 편차, 라우팅 홉(TTL),
	 *   클라이언트 임시 포트(ephemeral port >= 1024)에 의한 WordPiece 서브워드 분할 수 변동 및
	 *   포지셔널 임베딩 이동(positional shift) 오염을 방지하기 위해 RFC 표준 기본 헤더로 정규화 */
	(void)ip_len;
	(void)ip_ttl;
	(void)ip_tos;
	(void)tcp_flags;
	int can_sport = (src_port >= 1024 && src_port > dst_port) ? 50000 : (int)src_port;
	int can_dport = (dst_port >= 1024 && dst_port > src_port) ? 50000 : (int)dst_port;
	int can_doff  = (tcp_offset > 0) ? 5 : 0;
	int can_iplen = ((tcp_offset > 0) ? 40 : 28) + (int)payload_len;
	int can_ttl   = 64;
	int can_tos   = 0;
	int can_flags = (tcp_offset > 0) ? 24 : 0;

	int header_vals[] = {
		0, 0, can_iplen, -1,
		can_sport, can_dport, can_iplen, (int)payload_len,
		can_ttl, can_tos, can_doff, can_flags, -1
	};

	for (int i = 0; i < 13 && count < ET_BERT_SEQ_LEN - 1; i++)
	{
		char s[32];
		snprintf(s, sizeof(s), "%d", header_vals[i]);
		int64_t tok[8];
		int ntok = tokenize_word(s, tok, 8);
		for (int j = 0; j < ntok && count < ET_BERT_SEQ_LEN - 1; j++)
		{
			input_ids[count] = tok[j];
			attention_mask[count] = 1;
			count++;
		}
	}

	/* 2. 페이로드 10진수 바이트 토큰화 */
	for (unsigned int i = 0; payload && i < payload_len && count < ET_BERT_SEQ_LEN - 1; i++)
	{
		char s[16];
		snprintf(s, sizeof(s), "%u", payload[i]);
		int64_t tok[8];
		int ntok = tokenize_word(s, tok, 8);
		for (int j = 0; j < ntok && count < ET_BERT_SEQ_LEN - 1; j++)
		{
			input_ids[count] = tok[j];
			attention_mask[count] = 1;
			count++;
		}
	}

	input_ids[count] = g_tok_sep;
	attention_mask[count] = 1;

	/* 3. ONNX 텐서 생성 */
	int64_t input_shape[2] = {1, ET_BERT_SEQ_LEN};
	OrtValue *input_tensors[2] = {NULL, NULL};
	const char *input_names[2] = {"input_ids", "attention_mask"};
	const char *output_names[1] = {"logits"};
	OrtValue *output_tensor = NULL;
	int best_class = -1;

	OrtStatus *st = g_bert.api->CreateTensorWithDataAsOrtValue(
		g_bert.mem_info, input_ids, sizeof(input_ids),
		input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &input_tensors[0]);
	if (st)
		goto fail;
	st = g_bert.api->CreateTensorWithDataAsOrtValue(
		g_bert.mem_info, attention_mask, sizeof(attention_mask),
		input_shape, 2, ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64, &input_tensors[1]);
	if (st)
		goto fail;

	/* 4. 모델 추론 실행 */
	st = g_bert.api->Run(g_bert.session, NULL, input_names, (const OrtValue *const *)input_tensors, 2,
	                     output_names, 1, &output_tensor);
	if (st || !output_tensor)
		goto fail;

	float *logits = NULL;
	st = g_bert.api->GetTensorMutableData(output_tensor, (void **)&logits);
	if (st || !logits)
		goto fail;

	float max_score = -1e30f;
	for (int c = 0; c < NUM_CLASSES; c++)
	{
		if (logits[c] > max_score)
		{
			max_score = logits[c];
			best_class = c;
		}
	}
	STAT_INC(inferences);
	goto out;

fail:
	if (st)
	{
		fprintf(stderr, "[!] [추론 오류] %s\n", g_bert.api->GetErrorMessage(st));
		g_bert.api->ReleaseStatus(st);
	}
	best_class = -1;
out:
	if (output_tensor)
		g_bert.api->ReleaseValue(output_tensor);
	if (input_tensors[0])
		g_bert.api->ReleaseValue(input_tensors[0]);
	if (input_tensors[1])
		g_bert.api->ReleaseValue(input_tensors[1]);
	return best_class;
}

/* =========================================================================
 * 8. 판정 전송 (테스트 시 교체 가능하도록 함수 포인터 사용)
 * ========================================================================= */
static struct mnl_socket *g_nl = NULL;

static int send_verdict_nl(unsigned int packet_id, unsigned int verdict_id)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(cfg.queue_num);

	struct nfqnl_msg_verdict_hdr vh = {
		.verdict = htonl(verdict_id),
		.id = htonl(packet_id),
	};
	mnl_attr_put(nlh, NFQA_VERDICT_HDR, sizeof(vh), &vh);

	for (int attempt = 0; attempt < 2; attempt++)
	{
		if (mnl_socket_sendto(g_nl, nlh, nlh->nlmsg_len) >= 0)
			return 0;
		if (errno != EINTR && errno != ENOBUFS && errno != EAGAIN)
			break;
	}
	STAT_INC(verdict_fail);
	perror("[!] verdict 전송 실패");
	return -1;
}

static int (*g_send_verdict)(unsigned int, unsigned int) = send_verdict_nl;

/* =========================================================================
 * 8-1. 공격 차단 시 TCP 세션 즉시 종료 (M5: SOCK_DESTROY + Raw TCP RST 전송)
 *      서버 측 소켓 잔류(재전송/타임아웃 대기)를 즉시 해제하고 상대방에게 RST 전달
 * ========================================================================= */
static int g_diag_fd = -1;
static int g_rst4_fd = -1;
static int g_rst6_fd = -1;

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFFu) + (sum >> 16);
	return (uint16_t)(~sum);
}

static uint16_t tcp_pseudo_csum(const void *saddr, const void *daddr, size_t alen,
                                const void *tcp_pkt, size_t tcp_len)
{
	uint32_t sum = 0;
	const uint16_t *p = saddr;
	for (size_t i = 0; i < alen / 2; i++)
		sum += ntohs(p[i]);
	p = daddr;
	for (size_t i = 0; i < alen / 2; i++)
		sum += ntohs(p[i]);
	sum += IPPROTO_TCP;
	sum += (uint32_t)tcp_len;
	p = tcp_pkt;
	for (size_t i = 0; i < tcp_len / 2; i++)
		sum += ntohs(p[i]);
	if (tcp_len & 1)
		sum += (uint32_t)(((const uint8_t *)tcp_pkt)[tcp_len - 1] << 8);
	return htons(csum_fold(sum));
}

static int sock_destroy_one(uint8_t family, const uint8_t *src, uint16_t sport,
                            const uint8_t *dst, uint16_t dport)
{
	if (g_diag_fd < 0)
		return 0;
	struct {
		struct nlmsghdr nlh;
		struct inet_diag_req_v2 req;
	} msg;
	memset(&msg, 0, sizeof(msg));
	msg.nlh.nlmsg_len = sizeof(msg);
	msg.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
	msg.nlh.nlmsg_flags = NLM_F_REQUEST;
	msg.req.sdiag_family = family;
	msg.req.sdiag_protocol = IPPROTO_TCP;
	msg.req.idiag_states = (1U << 1);
	msg.req.id.idiag_sport = htons(sport);
	msg.req.id.idiag_dport = htons(dport);
	memcpy(msg.req.id.idiag_src, src, family == AF_INET ? 4 : 16);
	memcpy(msg.req.id.idiag_dst, dst, family == AF_INET ? 4 : 16);
	msg.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
	msg.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
	uint8_t rbuf[512];
	while (recv(g_diag_fd, rbuf, sizeof(rbuf), MSG_DONTWAIT) > 0)
		;
	if (send(g_diag_fd, &msg, sizeof(msg), MSG_DONTWAIT) < 0)
		return 0;

	ssize_t n = recv(g_diag_fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
	if (n < (ssize_t)(sizeof(struct nlmsghdr) + sizeof(struct inet_diag_msg)))
		return 0;
	const struct nlmsghdr *rnlh = (const struct nlmsghdr *)rbuf;
	if (rnlh->nlmsg_type != SOCK_DIAG_BY_FAMILY)
		return 0;
	const struct inet_diag_msg *rep = (const struct inet_diag_msg *)(rbuf + sizeof(struct nlmsghdr));
	/* TCP_LISTEN(10) 등 비연결 소켓은 절대 해제하지 않고 수립된 연결만 정확히 쿠키로 지정 해제 */
	if (rep->idiag_state == 10 || rep->idiag_state == 0)
		return 0;

	msg.nlh.nlmsg_type = SOCK_DESTROY;
	msg.req.id = rep->id;
	return send(g_diag_fd, &msg, sizeof(msg), MSG_DONTWAIT) >= 0 ? 1 : 0;
}

static void send_raw_rst4(const uint8_t *srcip, uint16_t sport, const uint8_t *dstip, uint16_t dport,
                          uint32_t seq_net, uint32_t ack_net, uint8_t flags)
{
	if (g_rst4_fd < 0)
		return;
	uint8_t b[sizeof(Packet) + sizeof(tcpheader)];
	memset(b, 0, sizeof(b));
	Packet *ip = (Packet *)b;
	tcpheader *th = (tcpheader *)(b + sizeof(Packet));

	ip->verihl = 0x45;
	ip->length = htons(sizeof(b));
	ip->id = htons(0);
	ip->offset = htons(0x4000);
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	memcpy(ip->srcip, srcip, 4);
	memcpy(ip->dstip, dstip, 4);

	th->srcport = htons(sport);
	th->dstport = htons(dport);
	th->seq = seq_net;
	th->ack = ack_net;
	th->offset_res = (5 << 4);
	th->flags = flags;
	th->checksum = tcp_pseudo_csum(ip->srcip, ip->dstip, 4, th, sizeof(*th));

	struct sockaddr_in dst = {.sin_family = AF_INET};
	memcpy(&dst.sin_addr, ip->dstip, 4);
	if (sendto(g_rst4_fd, b, sizeof(b), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst)) < 0) { /* ignore */ }
}

static void send_raw_rst6(const uint8_t *srcip, uint16_t sport, const uint8_t *dstip, uint16_t dport,
                          uint32_t seq_net, uint32_t ack_net, uint8_t flags)
{
	if (g_rst6_fd < 0)
		return;
	uint8_t b[sizeof(Packet_Jumbo) + sizeof(tcpheader)];
	memset(b, 0, sizeof(b));
	Packet_Jumbo *ip6 = (Packet_Jumbo *)b;
	tcpheader *th = (tcpheader *)(b + sizeof(Packet_Jumbo));

	ip6->ver_tc_fl = htonl(0x60000000u);
	ip6->length = htons(sizeof(tcpheader));
	ip6->nextheader = IPPROTO_TCP;
	ip6->hlimit = 64;
	memcpy(ip6->srcip, srcip, 16);
	memcpy(ip6->dstip, dstip, 16);

	th->srcport = htons(sport);
	th->dstport = htons(dport);
	th->seq = seq_net;
	th->ack = ack_net;
	th->offset_res = (5 << 4);
	th->flags = flags;
	th->checksum = tcp_pseudo_csum(ip6->srcip, ip6->dstip, 16, th, sizeof(*th));

	struct sockaddr_in6 dst6 = {.sin6_family = AF_INET6};
	memcpy(&dst6.sin6_addr, ip6->dstip, 16);
	if (sendto(g_rst6_fd, b, sizeof(b), MSG_DONTWAIT, (struct sockaddr *)&dst6, sizeof(dst6)) < 0) { /* ignore */ }
}

static void terminate_blocked_tcp(const struct pkt_info *pi, const unsigned char *pkt)
{
	if (!pi || !pkt || pi->key.proto != IPPROTO_TCP)
		return;

	int local_destroyed = 0;
	/* 1. 로컬 서버/클라이언트 소켓 즉시 해제 (커널 SOCK_DESTROY가 상대방에게도 RST 자동 송신) */
	if (pi->key.family == 4)
	{
		local_destroyed += sock_destroy_one(AF_INET, pi->key.daddr, pi->key.dport, pi->key.saddr, pi->key.sport);
		local_destroyed += sock_destroy_one(AF_INET, pi->key.saddr, pi->key.sport, pi->key.daddr, pi->key.dport);
		/* Dual-Stack(AF_INET6 IPV6_V6ONLY=0) 서버 소켓(::ffff:x.x.x.x) 대응 */
		uint8_t s6[16] = {0}, d6[16] = {0};
		s6[10] = 0xff; s6[11] = 0xff; memcpy(s6 + 12, pi->key.saddr, 4);
		d6[10] = 0xff; d6[11] = 0xff; memcpy(d6 + 12, pi->key.daddr, 4);
		local_destroyed += sock_destroy_one(AF_INET6, d6, pi->key.dport, s6, pi->key.sport);
		local_destroyed += sock_destroy_one(AF_INET6, s6, pi->key.sport, d6, pi->key.dport);
	}
	else if (pi->key.family == 6)
	{
		local_destroyed += sock_destroy_one(AF_INET6, pi->key.daddr, pi->key.dport, pi->key.saddr, pi->key.sport);
		local_destroyed += sock_destroy_one(AF_INET6, pi->key.saddr, pi->key.sport, pi->key.daddr, pi->key.dport);
	}

	/* 2. 원격 송신단 및 포워딩(FORWARD) 경로 원격 서버 즉시 해제를 위해 Raw TCP RST 전송 */
	unsigned int tcp_hdr_len = (unsigned int)pi->tcp_doff * 4;
	if (pi->l4_payload_off < tcp_hdr_len)
		return;
	const tcpheader *in_th = (const tcpheader *)(pkt + pi->l4_payload_off - tcp_hdr_len);
	uint32_t next_seq = htonl(ntohl(in_th->seq) + pi->l4_payload_len);

	if (pi->key.family == 4)
	{
		send_raw_rst4(pi->key.daddr, pi->key.dport, pi->key.saddr, pi->key.sport,
		              in_th->ack, next_seq, TCP_FLAG_RST | TCP_FLAG_ACK);
		if (local_destroyed == 0) /* 포워딩(FORWARD) 환경: 원격 서버 측 소켓도 RST로 즉시 해제 */
			send_raw_rst4(pi->key.saddr, pi->key.sport, pi->key.daddr, pi->key.dport,
			              in_th->seq, in_th->ack, TCP_FLAG_RST | TCP_FLAG_ACK);
	}
	else if (pi->key.family == 6)
	{
		send_raw_rst6(pi->key.daddr, pi->key.dport, pi->key.saddr, pi->key.sport,
		              in_th->ack, next_seq, TCP_FLAG_RST | TCP_FLAG_ACK);
		if (local_destroyed == 0)
			send_raw_rst6(pi->key.saddr, pi->key.sport, pi->key.daddr, pi->key.dport,
			              in_th->seq, in_th->ack, TCP_FLAG_RST | TCP_FLAG_ACK);
	}
}

/* =========================================================================
 * 9. 추론 작업 대기열 + 워커 스레드 (수신 루프 비차단, 상한 초과 시 DROP)
 * ========================================================================= */
struct job {
	unsigned int packet_id;
	uint32_t gen;
	uint8_t order_only; /* 0: 추론 수행, 1: 샘플링 제외 패킷 순서 보장, 2: 제어 패킷 순서 보장 */
	struct pkt_info info;
	unsigned char *pkt;
	unsigned int pkt_len;
};

static struct job **g_jobs = NULL;
static unsigned int g_job_head = 0, g_job_count = 0;
static pthread_mutex_t g_job_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_job_cond = PTHREAD_COND_INITIALIZER;
static int g_worker_stop = 0;

static int job_push(struct job *j)
{
	int ok = 0;
	pthread_mutex_lock(&g_job_lock);
	if (g_job_count < cfg.job_queue_max)
	{
		g_jobs[(g_job_head + g_job_count) % cfg.job_queue_max] = j;
		g_job_count++;
		ok = 1;
		pthread_cond_signal(&g_job_cond);
	}
	pthread_mutex_unlock(&g_job_lock);
	return ok;
}

static struct job *job_pop(void)
{
	pthread_mutex_lock(&g_job_lock);
	while (g_job_count == 0 && !g_worker_stop)
		pthread_cond_wait(&g_job_cond, &g_job_lock);
	struct job *j = NULL;
	if (g_job_count > 0)
	{
		j = g_jobs[g_job_head];
		g_job_head = (g_job_head + 1) % cfg.job_queue_max;
		g_job_count--;
	}
	pthread_mutex_unlock(&g_job_lock);
	return j;
}

static void job_free(struct job *j)
{
	if (j)
	{
		free(j->pkt);
		free(j);
	}
}

/* 워커 판정 반영. 반환: NF_ACCEPT / NF_DROP */
static unsigned int process_job(struct job *j)
{
	time_t now = mono_now();
	const struct pkt_info *pi = &j->info;

	/* 이미 차단된 세션이면 추론 생략 */
	pthread_mutex_lock(&g_tab_lock);
	struct session *s = session_find(&pi->key, now);
	if (s && s->gen == j->gen && s->state == SESSION_STATE_BLOCKED)
	{
		if (s->pending > 0)
			s->pending--;
		pthread_mutex_unlock(&g_tab_lock);
		STAT_INC(drop_blocked_session);
		return NF_DROP;
	}
	if (j->order_only)
	{
		if (s && s->gen == j->gen && s->pending > 0)
			s->pending--;
		pthread_mutex_unlock(&g_tab_lock);
		if (j->order_only == 1)
			STAT_INC(accept_sampled_skip);
		else
			STAT_INC(accept_no_payload);
		return NF_ACCEPT;
	}
	pthread_mutex_unlock(&g_tab_lock);

	int cls = et_bert_classify_packet(j->pkt + pi->l4_payload_off, pi->l4_payload_len,
	                                  pi->ip_len, pi->key.sport, pi->key.dport,
	                                  pi->ttl, pi->tos, pi->tcp_doff, pi->tcp_flags);

	const char *label;
	int attack;
	pthread_mutex_lock(&g_tab_lock);
	if (cls < 0)
	{
		label = "Inference Error (fail-closed)";
		attack = 1;
	}
	else
	{
		label = CLASS_NAMES[cls];
		if (cls == CLASS_NORMAL)
			attack = 0;
		else if (cls == CLASS_SSH_PATATOR || cls == CLASS_FTP_PATATOR || cls == CLASS_BRUTE_FORCE)
		{
			/* Brute Force 계열: 단일 정상 연결 오탐 방지를 위해 브루트포스 분류 누적 빈도 확인 */
			struct ip_entry *ip = ip_get(pi->key.family, pi->key.saddr, now, 1);
			attack = ip_note_bf(ip, now);
		}
		else
			attack = 1;
	}

	s = session_find(&pi->key, now);
	if (s && s->gen != j->gen)
		s = NULL;
	if (s)
	{
		if (s->pending > 0)
			s->pending--;
		if (attack)
		{
			s->state = SESSION_STATE_BLOCKED;
			s->label = label;
			session_touch(s, now);
		}
		else if (s->state == SESSION_STATE_NEW)
		{
			if (cls == CLASS_NORMAL)
			{
				s->verified_pkts++;
				if (s->verified_pkts >= cfg.inspect_first)
					s->state = SESSION_STATE_ESTABLISHED;
			}
			else
			{
				s->verified_pkts = 0; /* 비정상(임계값 미달 Patator 등) 관측 시 연속 정상 카운트 초기화 */
			}
		}
	}
	int became_est = (s && !attack && s->state == SESSION_STATE_ESTABLISHED);
	pthread_mutex_unlock(&g_tab_lock);

	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	addr_to_str(pi->key.family, pi->key.saddr, src, sizeof(src));
	addr_to_str(pi->key.family, pi->key.daddr, dst, sizeof(dst));

	if (!attack)
	{
		printf("\n[+] [세션 검사 통과] %s:%u -> %s:%u (%u bytes) | 판정: [%s]%s\n",
		       src, pi->key.sport, dst, pi->key.dport, pi->l4_payload_len,
		       cls >= 0 ? CLASS_NAMES[cls] : "-", became_est ? " | 검증 완료" : "");
		fflush(stdout);
		STAT_INC(accept_inspected);
		return NF_ACCEPT;
	}

	printf("\n[!] [세션 공격 차단] %s:%u -> %s:%u (%u bytes) | 판정: [%s] (차단 및 기록)\n",
	       src, pi->key.sport, dst, pi->key.dport, pi->l4_payload_len, label);
	fflush(stdout);
	log_abnormal_packet(g_log_fd, label, j->packet_id, &pi->key, j->pkt, j->pkt_len);
	if (cls < 0)
		STAT_INC(drop_infer_error);
	else
		STAT_INC(drop_attack);
#if ENABLE_INLINE_DROP
	return NF_DROP;
#else
	return cls < 0 ? NF_DROP : NF_ACCEPT;
#endif
}

static void *worker_main(void *arg)
{
	(void)arg;
	struct job *j;
	while ((j = job_pop()) != NULL)
	{
		unsigned int v = process_job(j);
		g_send_verdict(j->packet_id, v);
		if (v == NF_DROP && j->pkt && j->info.key.proto == IPPROTO_TCP)
			terminate_blocked_tcp(&j->info, j->pkt);
		job_free(j);
	}
	return NULL;
}

/* =========================================================================
 * 10. 패킷 정책 결정 (수신 스레드). 반환: 1=판정 전송 완료/위임, 0=처리 안 함
 * ========================================================================= */
static void verdict_now(unsigned int id, unsigned int v)
{
	g_send_verdict(id, v);
}

/* 검사 대상 패킷을 워커에 위임. 대기열 초과 시 DROP(fail-closed). 호출 시 g_tab_lock 보유 */
static void enqueue_or_drop(struct session *s, unsigned int packet_id, const struct pkt_info *pi,
                            const unsigned char *pkt, unsigned int len, uint8_t order_only)
{
	struct job *j = calloc(1, sizeof(*j));
	unsigned char *copy = (!order_only && j) ? malloc(len) : NULL;
	if (!j || (!order_only && !copy))
	{
		free(j);
		if (order_only != 2)
			s->payload_pkts--;
		STAT_INC(drop_job_queue_full);
		verdict_now(packet_id, NF_DROP);
		return;
	}
	if (!order_only)
		memcpy(copy, pkt, len);
	j->packet_id = packet_id;
	j->gen = s->gen;
	j->order_only = order_only;
	j->info = *pi;
	j->pkt = copy;
	j->pkt_len = order_only ? 0 : len;
	s->pending++;
	if (!job_push(j))
	{
		s->pending--;
		if (order_only != 2)
			s->payload_pkts--; /* 재전송 패킷이 같은 순번으로 다시 검사되도록 복원 */
		job_free(j);
		STAT_INC(drop_job_queue_full);
		verdict_now(packet_id, NF_DROP);
	}
}

static void handle_payload(struct session *s, unsigned int packet_id, const struct pkt_info *pi,
                           const unsigned char *pkt, unsigned int len, time_t now)
{
	if (pi->l4_payload_len == 0)
	{
		if (s->state == SESSION_STATE_ESTABLISHED && !s->closing)
			session_touch(s, now);
		if (s->pending > 0 && (pi->tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)))
			enqueue_or_drop(s, packet_id, pi, NULL, 0, 2);
		else
		{
			STAT_INC(accept_no_payload);
			verdict_now(packet_id, NF_ACCEPT);
		}
		return;
	}
	halfopen_release(s, now);
	s->payload_pkts++;
	session_touch(s, now);

	int inspect = (s->state == SESSION_STATE_NEW) ||
	              (cfg.sample_rate > 0 && (rng_next() % cfg.sample_rate) == 0);
	if (inspect)
		enqueue_or_drop(s, packet_id, pi, pkt, len, 0);
	else if (s->pending > 0)
		enqueue_or_drop(s, packet_id, pi, NULL, 0, 1);
	else
	{
		STAT_INC(accept_sampled_skip);
		verdict_now(packet_id, NF_ACCEPT);
	}
}

/* 신규 플로우 허용 여부 공통 검사(IP 차단/빈도/half-open). 통과 시 ip 반환, 거부 시 NULL(판정 전송 완료) */
static struct ip_entry *admit_new_flow(unsigned int packet_id, const struct pkt_info *pi, int count_halfopen, time_t now)
{
	struct ip_entry *ip = ip_get(pi->key.family, pi->key.saddr, now, 1);
	if (!ip)
	{
		STAT_INC(drop_table_full);
		verdict_now(packet_id, NF_DROP);
		return NULL;
	}
	if (ip->block_until > now)
	{
		ip->last_seen = now;
		STAT_INC(drop_ip_blocked);
		verdict_now(packet_id, NF_DROP);
		return NULL;
	}
	if (ip_note_new_flow(ip, now))
	{
		ip->block_until = now + cfg.ip_block_sec;
		log_rate_event(pi->key.proto == IPPROTO_TCP ? "SYN Flood / Scan (rate)" : "UDP Flood (rate)", &pi->key);
		STAT_INC(drop_rate_exceeded);
		verdict_now(packet_id, NF_DROP);
		return NULL;
	}
	if (count_halfopen)
	{
		if (ip->halfopen >= cfg.halfopen_per_ip)
		{
			STAT_INC(drop_halfopen_ip);
			verdict_now(packet_id, NF_DROP);
			return NULL;
		}
		if (g_halfopen_total >= cfg.halfopen_global)
		{
			STAT_INC(drop_halfopen_global);
			verdict_now(packet_id, NF_DROP);
			return NULL;
		}
	}
	return ip;
}

static void process_packet(const unsigned char *pkt, unsigned int len, unsigned int packet_id)
{
	STAT_INC(rx);
	struct pkt_info pi;
	int pr = parse_packet(pkt, len, &pi);
	if (pr == PARSE_FAIL)
	{
		STAT_INC(drop_unparsable);
		verdict_now(packet_id, NF_DROP);
		return;
	}
	if (pr == PARSE_OTHER)
	{
		STAT_INC(accept_other_proto);
		verdict_now(packet_id, NF_ACCEPT);
		return;
	}

	time_t now = mono_now();
	pthread_mutex_lock(&g_tab_lock);
	struct session *s = session_find(&pi.key, now);

	if (pi.key.proto == IPPROTO_TCP)
	{
		int syn = (pi.tcp_flags & TCP_FLAG_SYN) && !(pi.tcp_flags & TCP_FLAG_ACK);
		if (syn)
		{
			/* SYN 재전송: half-open 상태 그대로 허용 */
			if (s && s->state == SESSION_STATE_NEW && s->payload_pkts == 0 && !s->closing && s->pending == 0)
			{
				session_touch(s, now);
				pthread_mutex_unlock(&g_tab_lock);
				STAT_INC(accept_new_syn);
				verdict_now(packet_id, NF_ACCEPT);
				return;
			}
			/* 동일 5-tuple 재사용(ESTABLISHED/BLOCKED 포함) → 기존 상태 폐기 후 신규 세션으로 재검증 (C2) */
			if (s && s->pending == 0)
				session_free(s, now);
			else if (s)
			{
				pthread_mutex_unlock(&g_tab_lock);
				STAT_INC(drop_unknown_flow);
				verdict_now(packet_id, NF_DROP);
				return;
			}
			struct ip_entry *ip = admit_new_flow(packet_id, &pi, 1, now);
			if (!ip)
			{
				pthread_mutex_unlock(&g_tab_lock);
				return;
			}
			s = session_insert(&pi.key, SESSION_STATE_NEW, now);
			if (!s)
			{
				pthread_mutex_unlock(&g_tab_lock);
				STAT_INC(drop_table_full);
				verdict_now(packet_id, NF_DROP);
				return;
			}
			s->halfopen = 1;
			ip->halfopen++;
			g_halfopen_total++;
			session_touch(s, now);
			pthread_mutex_unlock(&g_tab_lock);

			char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
			addr_to_str(pi.key.family, pi.key.saddr, src, sizeof(src));
			addr_to_str(pi.key.family, pi.key.daddr, dst, sizeof(dst));
			printf("\n[*] [신규 TCP SYN 접속] %s:%u -> %s:%u | 핸드셰이크 허용 (페이로드 검증 대기)\n",
			       src, pi.key.sport, dst, pi.key.dport);
			fflush(stdout);
			STAT_INC(accept_new_syn);
			verdict_now(packet_id, NF_ACCEPT);
			return;
		}

		if (s && s->state == SESSION_STATE_BLOCKED)
		{
			s->last_seen = now; /* 만료 시각(expires)을 연장하지 않아 영구 오차단 방지 (C2) */
			pthread_mutex_unlock(&g_tab_lock);
			STAT_INC(drop_blocked_session);
			verdict_now(packet_id, NF_DROP);
			return;
		}

		/* SYN 없이 시작된 미등록 플로우: 기수립 연결은 기동 시 /proc 에서 이미 등록됨 → DROP */
		if (!s)
		{
			pthread_mutex_unlock(&g_tab_lock);
			STAT_INC(drop_unknown_flow);
			verdict_now(packet_id, NF_DROP);
			return;
		}
		if ((pi.tcp_flags & TCP_FLAG_RST) && pi.l4_payload_len == 0 && s->pending == 0)
		{
			/* RST 수신 및 대기 추론 없음 → 세션 즉시 삭제 (C2) */
			session_free(s, now);
			pthread_mutex_unlock(&g_tab_lock);
			STAT_INC(accept_no_payload);
			verdict_now(packet_id, NF_ACCEPT);
			return;
		}
		if ((pi.tcp_flags & (TCP_FLAG_FIN | TCP_FLAG_RST)) && !s->closing)
		{
			s->closing = 1;
			s->expires = now + cfg.close_timeout;
		}
		handle_payload(s, packet_id, &pi, pkt, len, now);
		pthread_mutex_unlock(&g_tab_lock);
		return;
	}

	if (s && s->state == SESSION_STATE_BLOCKED)
	{
		s->last_seen = now;
		pthread_mutex_unlock(&g_tab_lock);
		STAT_INC(drop_blocked_session);
		verdict_now(packet_id, NF_DROP);
		return;
	}

	/* UDP: 핸드셰이크가 없으므로 첫 데이터그램부터 신규 세션으로 검사 */
	if (!s)
	{
		if (!admit_new_flow(packet_id, &pi, 0, now))
		{
			pthread_mutex_unlock(&g_tab_lock);
			return;
		}
		s = session_insert(&pi.key, SESSION_STATE_NEW, now);
		if (!s)
		{
			pthread_mutex_unlock(&g_tab_lock);
			STAT_INC(drop_table_full);
			verdict_now(packet_id, NF_DROP);
			return;
		}
	}
	handle_payload(s, packet_id, &pi, pkt, len, now);
	pthread_mutex_unlock(&g_tab_lock);
}

/* =========================================================================
 * 11. Netlink / NFQUEUE
 * ========================================================================= */
static void sig_handler(int sig)
{
	if (sig == SIGUSR1)
		dump_flag = 1;
	else if (sig == SIGUSR2)
		rescan_flag = 1;
	else
		stop_flag = 1;
}

static int parse_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFQA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	(void)data;
	struct nlattr *tb[NFQA_MAX + 1] = {};

	if (mnl_attr_parse(nlh, sizeof(struct nfgenmsg), parse_attr_cb, tb) < 0)
		return MNL_CB_OK;
	if (!tb[NFQA_PACKET_HDR])
		return MNL_CB_OK;

	struct nfqnl_msg_packet_hdr *ph = mnl_attr_get_payload(tb[NFQA_PACKET_HDR]);
	unsigned int packet_id = ntohl(ph->packet_id);
	if (!tb[NFQA_PAYLOAD])
	{
		STAT_INC(drop_unparsable);
		verdict_now(packet_id, NF_DROP);
		return MNL_CB_OK;
	}
	const unsigned char *payload = mnl_attr_get_payload(tb[NFQA_PAYLOAD]);
	unsigned int payload_len = mnl_attr_get_payload_len(tb[NFQA_PAYLOAD]);
	process_packet(payload, payload_len, packet_id);
	return MNL_CB_OK;
}

static int nfq_config(struct mnl_socket *nl, char *buf, void (*fill)(struct nlmsghdr *))
{
	struct nlmsghdr *nlhdr = mnl_nlmsg_put_header(buf);
	nlhdr->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
	nlhdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlhdr, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(cfg.queue_num);
	fill(nlhdr);

	uint32_t seq = (uint32_t)time(NULL) ^ (uint32_t)rng_next();
	nlhdr->nlmsg_seq = seq;
	if (mnl_socket_sendto(nl, nlhdr, nlhdr->nlmsg_len) < 0)
		return -1;
	/* 커널 ACK 확인: 설정 실패(예: 다른 프로세스가 큐 점유)를 탐지 */
	ssize_t n = mnl_socket_recvfrom(nl, buf, MNL_SOCKET_BUFFER_SIZE);
	if (n < 0)
		return -1;
	return mnl_cb_run(buf, n, seq, mnl_socket_get_portid(nl), NULL, NULL) < 0 ? -1 : 0;
}

static void fill_bind(struct nlmsghdr *n)
{
	struct nfqnl_msg_config_cmd cmd = {.command = NFQNL_CFG_CMD_BIND};
	mnl_attr_put(n, NFQA_CFG_CMD, sizeof(cmd), &cmd);
}
static void fill_unbind(struct nlmsghdr *n)
{
	struct nfqnl_msg_config_cmd cmd = {.command = NFQNL_CFG_CMD_UNBIND};
	mnl_attr_put(n, NFQA_CFG_CMD, sizeof(cmd), &cmd);
}
static void fill_params(struct nlmsghdr *n)
{
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(0xffff),
		.copy_mode = NFQNL_COPY_PACKET,
	};
	mnl_attr_put(n, NFQA_CFG_PARAMS, sizeof(params), &params);
}
static void fill_flags(struct nlmsghdr *n)
{
	/* FAIL_OPEN 명시적 해제: 큐 초과 시 커널이 DROP (fail-closed) */
	uint32_t flags = htonl(0);
	uint32_t mask = htonl(NFQA_CFG_F_FAIL_OPEN);
	mnl_attr_put(n, NFQA_CFG_FLAGS, sizeof(uint32_t), &flags);
	mnl_attr_put(n, NFQA_CFG_MASK, sizeof(uint32_t), &mask);
}
static void fill_maxlen(struct nlmsghdr *n)
{
	uint32_t maxlen = htonl(cfg.kernel_queue_maxlen);
	mnl_attr_put(n, NFQA_CFG_QUEUE_MAXLEN, sizeof(uint32_t), &maxlen);
}

static void print_stats(void)
{
#define P(f) printf("  %-22s : %lu\n", #f, atomic_load(&g_stats.f))
	printf("\n[통계]\n");
	P(rx); P(accept_new_syn); P(accept_no_payload); P(accept_inspected); P(accept_sampled_skip);
	P(accept_other_proto); P(drop_attack); P(drop_blocked_session); P(drop_unknown_flow);
	P(drop_unparsable); P(drop_job_queue_full); P(drop_table_full); P(drop_ip_blocked);
	P(drop_rate_exceeded); P(drop_halfopen_ip); P(drop_halfopen_global); P(drop_infer_error);
	P(inferences); P(enobufs); P(verdict_fail);
#undef P
	fflush(stdout);
}

static void usage(const char *prog)
{
	printf("Usage: %s [options]\n"
	       "  -q, --queue N              NFQUEUE 번호 (기본 %u)\n"
	       "  -m, --model PATH           ONNX 모델 경로 (기본 <실행파일 디렉터리>/models/et_bert.onnx)\n"
	       "  -v, --vocab PATH           어휘 사전 경로 (기본 <실행파일 디렉터리>/models/tokenizer.model)\n"
	       "  -l, --log PATH             차단 로그 경로 (기본 <실행파일 디렉터리>/packet/abnormal.txt)\n"
	       "  -t, --threads N            추론 intra-op 스레드 수 (기본 %d)\n"
	       "      --inspect-first N      신규 세션 전수 검사 패킷 수 (기본 %u)\n"
	       "      --sample-rate K        검증 완료 세션 1/K 무작위 재검사, 0=비활성 (기본 %u)\n"
	       "      --job-queue N          추론 대기열 상한 (기본 %u)\n"
	       "      --kernel-queue N       커널 큐 최대 길이 (기본 %u)\n"
	       "      --new-flow-rate N      IP당 초당 신규 플로우 상한 (기본 %u)\n"
	       "      --halfopen-per-ip N    IP당 half-open 상한 (기본 %u)\n"
	       "      --halfopen-global N    전체 half-open 상한 (기본 %u)\n"
	       "      --ip-block-sec N       빈도 초과 IP 차단 시간 (기본 %u)\n"
	       "      --bf-threshold N       Patator 계열 차단 연결 빈도 (기본 %u)\n"
	       "      --bf-window N          브루트포스 빈도 윈도우 초 (기본 %u)\n"
	       "      --tcp-idle N / --udp-idle N / --new-timeout N / --close-timeout N / --block-timeout N\n",
	       prog, cfg.queue_num, cfg.intra_threads, cfg.inspect_first, cfg.sample_rate, cfg.job_queue_max,
	       cfg.kernel_queue_maxlen, cfg.new_flow_rate, cfg.halfopen_per_ip, cfg.halfopen_global,
	       cfg.ip_block_sec, cfg.bf_threshold, cfg.bf_window_sec);
}

static int parse_uint(const char *s, unsigned int *out)
{
	char *end;
	errno = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno || *end != '\0' || s[0] == '-' || v > UINT_MAX)
		return -1;
	*out = (unsigned int)v;
	return 0;
}

static int parse_args(int argc, char **argv)
{
	char exe_dir[PATH_MAX] = ".";
	ssize_t n = readlink("/proc/self/exe", exe_dir, sizeof(exe_dir) - 1);
	if (n > 0)
	{
		exe_dir[n] = '\0';
		char *slash = strrchr(exe_dir, '/');
		if (slash)
			*slash = '\0';
	}
	snprintf(cfg.model_path, sizeof(cfg.model_path), "%s/models/et_bert.onnx", exe_dir);
	snprintf(cfg.vocab_path, sizeof(cfg.vocab_path), "%s/models/tokenizer.model", exe_dir);
	snprintf(cfg.log_path, sizeof(cfg.log_path), "%s/packet/abnormal.txt", exe_dir);

	enum { O_INSPECT = 1000, O_SAMPLE, O_JOBQ, O_KQ, O_RATE, O_HOIP, O_HOG, O_BLOCK, O_BFT, O_BFW,
	       O_TCPIDLE, O_UDPIDLE, O_NEWTO, O_CLOSETO, O_BLOCKTO, O_READY };
	static const struct option opts[] = {
		{"queue", required_argument, 0, 'q'}, {"model", required_argument, 0, 'm'},
		{"vocab", required_argument, 0, 'v'}, {"log", required_argument, 0, 'l'},
		{"threads", required_argument, 0, 't'}, {"help", no_argument, 0, 'h'},
		{"ready-file", required_argument, 0, O_READY},
		{"inspect-first", required_argument, 0, O_INSPECT}, {"sample-rate", required_argument, 0, O_SAMPLE},
		{"job-queue", required_argument, 0, O_JOBQ}, {"kernel-queue", required_argument, 0, O_KQ},
		{"new-flow-rate", required_argument, 0, O_RATE}, {"halfopen-per-ip", required_argument, 0, O_HOIP},
		{"halfopen-global", required_argument, 0, O_HOG}, {"ip-block-sec", required_argument, 0, O_BLOCK},
		{"bf-threshold", required_argument, 0, O_BFT}, {"bf-window", required_argument, 0, O_BFW},
		{"tcp-idle", required_argument, 0, O_TCPIDLE}, {"udp-idle", required_argument, 0, O_UDPIDLE},
		{"new-timeout", required_argument, 0, O_NEWTO}, {"close-timeout", required_argument, 0, O_CLOSETO},
		{"block-timeout", required_argument, 0, O_BLOCKTO}, {0, 0, 0, 0}};

	int c;
	while ((c = getopt_long(argc, argv, "q:m:v:l:t:h", opts, NULL)) != -1)
	{
		unsigned int v = 0;
		if (c != 'm' && c != 'v' && c != 'l' && c != O_READY && c != 'h' && c != '?' && parse_uint(optarg, &v) < 0)
		{
			fprintf(stderr, "[ERROR] 잘못된 숫자 값: %s\n", optarg);
			return -1;
		}
		switch (c)
		{
		case 'q': if (v > 65535) { fprintf(stderr, "[ERROR] 큐 번호 범위 초과\n"); return -1; } cfg.queue_num = v; break;
		case 'm': snprintf(cfg.model_path, sizeof(cfg.model_path), "%s", optarg); break;
		case 'v': snprintf(cfg.vocab_path, sizeof(cfg.vocab_path), "%s", optarg); break;
		case 'l': snprintf(cfg.log_path, sizeof(cfg.log_path), "%s", optarg); break;
		case O_READY: snprintf(cfg.ready_file, sizeof(cfg.ready_file), "%s", optarg); break;
		case 't': cfg.intra_threads = (int)(v ? v : 1); break;
		case O_INSPECT: cfg.inspect_first = v ? v : 1; break;
		case O_SAMPLE: cfg.sample_rate = v; break;
		case O_JOBQ: cfg.job_queue_max = v ? v : 1; break;
		case O_KQ: cfg.kernel_queue_maxlen = v ? v : 1; break;
		case O_RATE: cfg.new_flow_rate = v; break;
		case O_HOIP: cfg.halfopen_per_ip = v; break;
		case O_HOG: cfg.halfopen_global = v; break;
		case O_BLOCK: cfg.ip_block_sec = v; break;
		case O_BFT: cfg.bf_threshold = v; break;
		case O_BFW: cfg.bf_window_sec = v ? v : 1; break;
		case O_TCPIDLE: cfg.tcp_idle_timeout = v; break;
		case O_UDPIDLE: cfg.udp_idle_timeout = v; break;
		case O_NEWTO: cfg.new_timeout = v; break;
		case O_CLOSETO: cfg.close_timeout = v; break;
		case O_BLOCKTO: cfg.block_timeout = v; break;
		case 'h': usage(argv[0]); exit(0);
		default: usage(argv[0]); return -1;
		}
	}
	return 0;
}

static void release_model(void)
{
	if (!g_bert.api)
		return;
	if (g_bert.session) { g_bert.api->ReleaseSession(g_bert.session); g_bert.session = NULL; }
	if (g_bert.mem_info) { g_bert.api->ReleaseMemoryInfo(g_bert.mem_info); g_bert.mem_info = NULL; }
	if (g_bert.env) { g_bert.api->ReleaseEnv(g_bert.env); g_bert.env = NULL; }
	g_bert.is_initialized = 0;
}

/**
 * @brief 이기종(big.LITTLE / DynamIQ) CPU 토폴로지 실측 감지 (Rule 3 & Rule 7).
 *        런타임 sysfs cpufreq를 읽어 고성능(Perf) 코어 셋과 고효율(Eff) 코어 셋을 분리.
 */
static void detect_cpu_clusters(cpu_set_t *perf_set, cpu_set_t *eff_set, int *perf_cnt, int *eff_cnt)
{
	CPU_ZERO(perf_set);
	CPU_ZERO(eff_set);
	*perf_cnt = 0;
	*eff_cnt = 0;

	unsigned long freqs[64] = {0};
	unsigned long min_f = ULONG_MAX, max_f = 0;
	int n_cpus = 0;
	for (int c = 0; c < 64; c++)
	{
		char path[128];
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", c);
		FILE *f = fopen(path, "r");
		if (!f)
			continue;
		unsigned long khz = 0;
		if (fscanf(f, "%lu", &khz) == 1 && khz > 0)
		{
			freqs[c] = khz;
			if (khz < min_f)
				min_f = khz;
			if (khz > max_f)
				max_f = khz;
			n_cpus++;
		}
		fclose(f);
	}
	if (n_cpus == 0 || max_f <= min_f)
		return;
	for (int c = 0; c < 64; c++)
	{
		if (freqs[c] == 0)
			continue;
		if (freqs[c] > min_f)
		{
			CPU_SET(c, perf_set);
			(*perf_cnt)++;
		}
		else
		{
			CPU_SET(c, eff_set);
			(*eff_cnt)++;
		}
	}
}

/* 모델·어휘 로드 및 자체 추론 시험. 실패 시 -1 (호출자는 기동 중단: fail-closed) */
static int init_model(void)
{
	int failed = 0;
	int vocab_count = load_vocab(cfg.vocab_path, &failed);
	if (vocab_count <= 0)
	{
		fprintf(stderr, "[ERROR] [WordPiece] 어휘 사전 로드 실패: %s\n", cfg.vocab_path);
		return -1;
	}
	g_tok_unk = vocab_lookup("[UNK]");
	g_tok_cls = vocab_lookup("[CLS]");
	g_tok_sep = vocab_lookup("[SEP]");
	if (g_tok_unk < 0 || g_tok_cls < 0 || g_tok_sep < 0 || failed > 0)
	{
		fprintf(stderr, "[ERROR] [WordPiece] 어휘 사전 이상: 특수 토큰 누락 또는 등록 실패 %d개\n", failed);
		return -1;
	}
	printf("[+] [WordPiece] 어휘 사전 로드 완료: %s (%d개 토큰, [UNK]=%ld [CLS]=%ld [SEP]=%ld)\n",
	       cfg.vocab_path, vocab_count, (long)g_tok_unk, (long)g_tok_cls, (long)g_tok_sep);

	cpu_set_t perf_set, eff_set;
	int perf_cnt = 0, eff_cnt = 0;
	detect_cpu_clusters(&perf_set, &eff_set, &perf_cnt, &eff_cnt);
	if (perf_cnt > 0 && cfg.intra_threads <= perf_cnt)
	{
		if (sched_setaffinity(0, sizeof(perf_set), &perf_set) == 0)
			printf("[+] [CPU Affinity] 고성능 클러스터(%d코어)에 ONNX 추론 스레드 풀 고정 완료\n", perf_cnt);
	}

	g_bert.api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
	if (!g_bert.api)
	{
		fprintf(stderr, "[ERROR] ONNX Runtime API 버전 불일치\n");
		return -1;
	}
	OrtStatus *st = g_bert.api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "et_bert", &g_bert.env);
	OrtSessionOptions *opts = NULL;
	if (!st)
		st = g_bert.api->CreateSessionOptions(&opts);
	if (!st)
		st = g_bert.api->SetIntraOpNumThreads(opts, cfg.intra_threads);
	if (!st)
		st = g_bert.api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault, &g_bert.mem_info);
	if (!st)
		st = g_bert.api->CreateSession(g_bert.env, cfg.model_path, opts, &g_bert.session);
	if (opts)
		g_bert.api->ReleaseSessionOptions(opts);
	if (st)
	{
		fprintf(stderr, "[ERROR] [ET-BERT] 모델 로드 실패 (%s): %s\n", cfg.model_path, g_bert.api->GetErrorMessage(st));
		g_bert.api->ReleaseStatus(st);
		return -1;
	}
	g_bert.is_initialized = 1;

	struct timespec a, b;
	clock_gettime(CLOCK_MONOTONIC, &a);
	static const unsigned char probe[] = "GET / HTTP/1.1\r\n\r\n";
	int cls = et_bert_classify_packet(probe, sizeof(probe) - 1, 60, 40000, 80, 64, 0, 5, 0x18);
	clock_gettime(CLOCK_MONOTONIC, &b);
	if (cls < 0)
	{
		fprintf(stderr, "[ERROR] [ET-BERT] 자체 추론 시험 실패\n");
		return -1;
	}
	double ms = (b.tv_sec - a.tv_sec) * 1000.0 + (b.tv_nsec - a.tv_nsec) / 1e6;
	printf("[+] [ET-BERT] 모델 탑재 완료: %s (intra-op %d스레드, 시험 추론 %.1f ms)\n",
	       cfg.model_path, cfg.intra_threads, ms);
	return 0;
}

int main(int argc, char **argv)
{
	static char buf[65536 + 16384];
	int exit_code = 0;
	pthread_t worker;
	int worker_started = 0;

	if (parse_args(argc, argv) < 0)
		return 2;

	uint64_t seed[2] = {0, 0};
	if (getrandom(seed, sizeof(seed), 0) != sizeof(seed))
	{
		seed[0] = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
		seed[1] = seed[0] * 0x9E3779B97F4A7C15ull;
	}
	g_hash_seed = (uint32_t)seed[0];
	g_rng_state = seed[1] ? seed[1] : 0x9E3779B97F4A7C15ull;

	struct sigaction sa = {.sa_handler = sig_handler};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	{
		char dir_buf[PATH_MAX];
		snprintf(dir_buf, sizeof(dir_buf), "%s", cfg.log_path);
		char *last_slash = strrchr(dir_buf, '/');
		if (last_slash && last_slash != dir_buf)
		{
			*last_slash = '\0';
			(void)mkdir(dir_buf, 0755);
		}
	}
	g_log_fd = open(cfg.log_path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (g_log_fd < 0)
	{
		perror("FD open Failed!");
		return 1;
	}

	/* 1. 모델 로드 실패 시 기동 중단 (fail-closed) */
	if (init_model() < 0)
	{
		release_model();
		close(g_log_fd);
		return 1;
	}

	g_jobs = calloc(cfg.job_queue_max, sizeof(*g_jobs));
	if (!g_jobs)
	{
		perror("calloc");
		release_model();
		close(g_log_fd);
		return 1;
	}

	/* 2. Netlink 소켓 */
	g_nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!g_nl)
	{
		perror("mnl_socket_open Failed!");
		exit_code = 1;
		goto cleanup;
	}
	if (mnl_socket_bind(g_nl, 0, MNL_SOCKET_AUTOPID) != 0)
	{
		perror("mnl_socket_bind Failed!");
		exit_code = 1;
		goto cleanup;
	}
	unsigned int portid = mnl_socket_get_portid(g_nl);
	int nl_fd = mnl_socket_get_fd(g_nl);

	if (nfq_config(g_nl, buf, fill_bind) < 0)
	{
		fprintf(stderr, "[ERROR] 큐 %u 바인드 실패: %s\n", cfg.queue_num, strerror(errno));
		exit_code = 1;
		goto cleanup;
	}
	if (nfq_config(g_nl, buf, fill_params) < 0 || nfq_config(g_nl, buf, fill_maxlen) < 0 ||
	    nfq_config(g_nl, buf, fill_flags) < 0)
	{
		fprintf(stderr, "[ERROR] 큐 %u 설정 실패: %s\n", cfg.queue_num, strerror(errno));
		exit_code = 1;
		goto unbind;
	}

	/* 3. 부하 대응: 수신 버퍼 확대, ENOBUFS 비보고(초과분은 커널 DROP), 1초 수신 타임아웃(주기 정리) */
	int rcvbuf = 8 * 1024 * 1024;
	if (setsockopt(nl_fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
		setsockopt(nl_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	int one = 1;
	setsockopt(nl_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));
	struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
	setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* 3-1. 차단 세션 즉시 해제용 소켓 (M5: SOCK_DESTROY 및 Raw TCP RST 송신) */
	g_diag_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
	g_rst4_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (g_rst4_fd >= 0)
		setsockopt(g_rst4_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	g_rst6_fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
	if (g_rst6_fd >= 0)
		setsockopt(g_rst6_fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one));

	/* 4. 큐 바인드 이후 기수립 연결 등록 (바인드 이전 연결은 /proc 에, 이후 연결은 SYN 으로 관측됨) */
	load_preexisting_sessions(mono_now());

	/* 5. 추론 워커 기동 (시그널은 수신 스레드에서만 처리) */
	sigset_t set, old;
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &set, &old);
	if (pthread_create(&worker, NULL, worker_main, NULL) != 0)
	{
		pthread_sigmask(SIG_SETMASK, &old, NULL);
		perror("pthread_create");
		exit_code = 1;
		goto unbind;
	}
	worker_started = 1;
	pthread_sigmask(SIG_SETMASK, &old, NULL);

	/* 수신 스레드는 고효율(Eff) 코어로 분리하여 추론 연산과의 CPU 경합 방지 */
	{
		cpu_set_t perf_set, eff_set;
		int perf_cnt = 0, eff_cnt = 0;
		detect_cpu_clusters(&perf_set, &eff_set, &perf_cnt, &eff_cnt);
		if (eff_cnt > 0 && perf_cnt > 0 && cfg.intra_threads <= perf_cnt)
			sched_setaffinity(0, sizeof(eff_set), &eff_set);
	}

	if (cfg.ready_file[0] != '\0')
	{
		int rfd = open(cfg.ready_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (rfd >= 0)
		{
			if (write(rfd, "1\n", 2) < 0) { /* ignore */ }
			close(rfd);
		}
	}

	printf("[+] [NFQUEUE] 큐 %u 수신 시작 (fail-closed, 커널 큐 %u, 추론 대기열 %u, 신규 세션 %u패킷 전수 검사, 1/%u 샘플링)\n",
	       cfg.queue_num, cfg.kernel_queue_maxlen, cfg.job_queue_max, cfg.inspect_first, cfg.sample_rate);
	fflush(stdout);

	time_t next_sweep = mono_now() + 1;
	while (!stop_flag)
	{
		if (rescan_flag)
		{
			rescan_flag = 0;
			load_preexisting_sessions(mono_now());
		}
		ssize_t r = mnl_socket_recvfrom(g_nl, buf, sizeof(buf));
		if (rescan_flag)
		{
			rescan_flag = 0;
			load_preexisting_sessions(mono_now());
		}
		if (r < 0)
		{
			if (errno == ENOBUFS)
			{
				STAT_INC(enobufs);
				fprintf(stderr, "[!] netlink 수신 버퍼 초과(ENOBUFS): 초과 패킷은 커널에서 DROP, 수신 계속\n");
			}
			else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
			{
				perror("[ERROR] mnl_socket_recvfrom");
				exit_code = 1;
				break;
			}
		}
		else
		{
			mnl_cb_run(buf, r, 0, portid, queue_cb, NULL);
		}

		time_t now = mono_now();
		if (now >= next_sweep)
		{
			sweep_tables(now);
			next_sweep = now + 1;
		}
		if (dump_flag)
		{
			dump_flag = 0;
			print_stats();
		}
	}

unbind:
	if (worker_started)
	{
		pthread_mutex_lock(&g_job_lock);
		g_worker_stop = 1;
		pthread_cond_broadcast(&g_job_cond);
		pthread_mutex_unlock(&g_job_lock);
		pthread_join(worker, NULL); /* 대기 작업은 모두 판정 후 종료 */
	}
	nfq_config(g_nl, buf, fill_unbind);
cleanup:
	print_stats();
	if (g_diag_fd >= 0)
		close(g_diag_fd);
	if (g_rst4_fd >= 0)
		close(g_rst4_fd);
	if (g_rst6_fd >= 0)
		close(g_rst6_fd);
	if (g_nl)
		mnl_socket_close(g_nl);
	release_model();
	free(g_jobs);
	if (g_log_fd >= 0)
		close(g_log_fd);
	return exit_code;
}
