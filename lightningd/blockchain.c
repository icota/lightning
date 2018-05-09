#include "blockchain.h"



struct blockchain *new_blockchain(const tal_t *ctx, struct lightningd *ld, struct log *log)
{
	struct blockchain *blockchain = tal(ctx, struct blockchain);

	//blockchain->chainparams
	blockchain->neutrino = new_neutrino(blockchain, ld, log);
	//call new_neutrino
	//neutrino_setup();
	//blockchain.sendrawtx = bitcoind_sendrawtx_;

	//neutrino

	return blockchain;
}
