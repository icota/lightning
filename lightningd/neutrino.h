#ifndef LIGHTNING_LIGHTNINGD_NEUTRINO_H
#define LIGHTNING_LIGHTNINGD_NEUTRINO_H


//#include "../libbtc/include/btc/vector.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <bitcoin/block.h>
#include <bitcoin/tx.h>

// Copied over from libbtc


typedef uint8_t uint256[32];
typedef uint8_t uint160[20];

static const unsigned int BTC_MAX_P2P_MSG_SIZE = 0x02000000;

static const unsigned int BTC_P2P_HDRSZ = 24; //(4 + 12 + 4 + 4)  magic, command, length, checksum

//static uint256 NULLHASH = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

enum service_bits {
    BTC_NODE_NETWORK = (1 << 0),
    BTC_NODE_COMPACT_FILTERS = (1 << 6),
};

//static const char* BTC_MSG_VERSION = "version";
//static const char* BTC_MSG_VERACK = "verack";
//static const char* BTC_MSG_PING = "ping";
//static const char* BTC_MSG_PONG = "pong";
//static const char* BTC_MSG_GETDATA = "getdata";
//static const char* BTC_MSG_GETHEADERS = "getheaders";
//static const char* BTC_MSG_HEADERS = "headers";
//static const char* BTC_MSG_GETBLOCKS = "getblocks";
//static const char* BTC_MSG_BLOCK = "block";
//static const char* BTC_MSG_INV = "inv";
static const char* const BTC_MSG_TX = "tx";

//static const char* BTC_MSG_GETCFILTERS = "getcfilters";
//static const char* BTC_MSG_CFILTER = "cfilter";

//static const char* BTC_MSG_GETCFHEADERS = "getcfheaders";
//static const char* BTC_MSG_CFHEADERS = "cfheaders";

//static const char* BTC_MSG_GETCFCHECKPT = "getcfcheckpt";
//static const char* BTC_MSG_CFCHECKPT = "cfcheckpt";


enum BTC_INV_TYPE {
    BTC_INV_TYPE_ERROR = 0,
    BTC_INV_TYPE_TX = 1,
    BTC_INV_TYPE_BLOCK = 2,
    BTC_INV_TYPE_FILTERED_BLOCK = 3,
    BTC_INV_TYPE_CMPCT_BLOCK = 4,
};

static const unsigned int MAX_HEADERS_RESULTS = 2000;
static const int BTC_PROTOCOL_VERSION = 70014;

typedef struct btc_p2p_msg_hdr_ {
    unsigned char netmagic[4];
    char command[12];
    uint32_t data_len;
    unsigned char hash[4];
} btc_p2p_msg_hdr;

typedef struct btc_p2p_inv_msg_ {
    uint32_t type;
    uint256 hash;
} btc_p2p_inv_msg;

typedef struct btc_p2p_address_ {
    uint32_t time;
    uint64_t services;
    unsigned char ip[16];
    uint16_t port;
} btc_p2p_address;

typedef struct btc_p2p_version_msg_ {
    int32_t version;
    uint64_t services;
    int64_t timestamp;
    btc_p2p_address addr_recv;
    btc_p2p_address addr_from;
    uint64_t nonce;
    char useragent[128];
    int32_t start_height;
    uint8_t relay;
} btc_p2p_version_msg;


struct peer {
	char* address;
	struct list_node list;
};

struct neutrino {
	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	struct list_head peers;
	int num_peers;

	unsigned char netmagic[4];
};


struct neutrino *new_neutrino(const tal_t *ctx, struct lightningd *ld, struct log *log);
int get_p2p_peers_from_dns(struct neutrino* neutrino, const char* seed, int port, int family);
int connect_to_p2p_peer(struct peer *peer);
void broadcast_hex_tx(const struct neutrino* neutrino, const char *hextx, struct peer* peer);
void get_txout(const struct bitcoin_txid *txid, const u32 outnum);
void get_output(unsigned int blocknum, unsigned int txnum, unsigned int outnum);
void get_raw_block(const struct bitcoin_blkid *blockid);
void get_block_hash(u32 height);
void get_block_count(void);
void estimate_fees(void);
void create_p2p_message(char* out, const unsigned char netmagic[4], const char* command, const void* data, uint32_t data_len);

void get_compact_filters(void);
void get_compact_filter_headers(void);
void get_compact_filter_checkpoint(void);

#endif /* LIGHTNING_LIGHTNINGD_NEUTRINO_H */
