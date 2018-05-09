#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <ccan/io/io.h>
#include <lightningd/log.h>


#include "neutrino.h"

struct neutrino *new_neutrino(const tal_t *ctx, struct lightningd *ld,
			      struct log *log)
{
	struct neutrino *neutrino;

	neutrino = tal(NULL, struct neutrino);
	neutrino->ld = ld;
	neutrino->log = log;

	unsigned char testnet_netmagic[4] = {0x0b, 0x11, 0x09, 0x07};
	memcpy(neutrino->netmagic, testnet_netmagic, 4);

	list_head_init(&neutrino->peers);

	// connect to p2p
	int ret = get_p2p_peers_from_dns(neutrino, "testnet-seed.bitcoin.jonasschnelli.ch", 18333, AF_INET);

	if (!ret) {
		log_debug(neutrino->log, "failed to get peers from DNS");
	}

	return neutrino;
}

int get_p2p_peers_from_dns(struct neutrino* neutrino, const char* seed, int port, int family)
{
    if (!seed || (family != AF_INET && family != AF_INET6) || port > 99999) {
	return 0;
    }
    struct addrinfo hints, *ai_trav = NULL, *ai_res = NULL;;

    char def_port[6] = {0};

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    int gai_err = getaddrinfo(seed, NULL, &hints, &ai_res);
    if (gai_err)
	return 0;

    ai_trav = ai_res;
    while (ai_trav != NULL) {
	int maxlen = 256;
	char* ipaddr = calloc(1, maxlen);
	if (ai_trav->ai_family == AF_INET) {
	    assert(ai_trav->ai_addrlen >= sizeof(struct sockaddr_in));
	    inet_ntop(ai_trav->ai_family, &((struct sockaddr_in*)(ai_trav->ai_addr))->sin_addr, ipaddr, maxlen);
	}

	if (ai_trav->ai_family == AF_INET6) {
	    assert(ai_trav->ai_addrlen >= sizeof(struct sockaddr_in6));
	    inet_ntop(ai_trav->ai_family, &((struct sockaddr_in6*)(ai_trav->ai_addr))->sin6_addr, ipaddr, maxlen);
	}

	memcpy(ipaddr + strlen(ipaddr), ":", 1);
	memcpy(ipaddr + strlen(ipaddr), def_port, strlen(def_port));

	struct peer *peer = malloc(sizeof(*peer));

	peer->address = ipaddr;
	list_add(&neutrino->peers, &peer->list);
	neutrino->num_peers++;

	//vector_add(ips_out, ipaddr);

	ai_trav = ai_trav->ai_next;
    }
    freeaddrinfo(ai_res);
    return neutrino->num_peers;
}

int connect_to_p2p_peer(struct peer *peer)
{
	return -1;
}

void broadcast_hex_tx(const struct neutrino* neutrino, const char *hextx, struct peer* peer)
{

	char* sendtx_msg = "what";
	create_p2p_message(sendtx_msg, neutrino->netmagic, BTC_MSG_TX, hextx, sizeof(hextx));
	//cstring* p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, BTC_MSG_TX, tx_ser->str, tx_ser->len);
	//cstr_free(tx_ser, true);
	//btc_node_send(node, p2p_msg);

	//TODO: write to node in a c-lightning way
}

void get_txout(const struct bitcoin_txid *txid, const u32 outnum)
{

}

void get_output(unsigned int blocknum, unsigned int txnum, unsigned int outnum)
{

}

void get_raw_block(const struct bitcoin_blkid *blockid)
{

}

void get_block_hash(u32 height)
{

}

void get_block_count(void)
{
	//version ≥ 106 gives us this in the version message
	// parse it separately
	//4	start_height	int32_t	The last block received by the emitting node
}

void estimate_fees(void)
{

}

void create_p2p_message(char* out, const unsigned char netmagic[4], const char* command, const void* data, uint32_t data_len)
{
	// put this outside
	//out[BTC_P2P_HDRSZ + data_len];

	/* network identifier (magic number) */
	memcpy(&out[0], netmagic, 4);

	/* command string */
	char command_null[12];
	memset(command_null, 0, 12);
	memcpy(command_null, command, strlen(command));
	//memset(command_null+strlen(command), 0, 12-strlen(command));
	memcpy(&out[4], command_null, 12);

	/* data length, always 4 bytes */
	uint32_t data_len_le = htole32(data_len);
	memcpy(&out[16], &data_len_le, 4);

	/* data checksum (first 4 bytes of the double sha256 hash of the pl) */
	//uint256 msghash;
	struct sha256_double message_hash;

	sha256_double(&message_hash, data, data_len);

	//btc_hash(data, data_len, msghash);

	memcpy(&out[20], &message_hash, 4);
	//cstr_append_buf(s, &msghash[0], 4);

	/* data payload */
	if (data_len > 0) {
		memcpy(&out[24], &data, data_len);
		//cstr_append_buf(s, data, data_len);
	}
}

// BIP-157/158

void get_compact_filters(void)
{

}

void get_compact_filter_headers(void)
{

}

void get_compact_filter_checkpoint(void)
{

}
