#ifndef LIGHTNING_LIGHTNINGD_BLOCKCHAIN_H
#define LIGHTNING_LIGHTNINGD_BLOCKCHAIN_H

//#include <bitcoin/chainparams.h>
//#include <bitcoin/tx.h>

#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

#include "bitcoind.h"
#include "neutrino.h"

//define
typedef void (*sendrawtx_function)(struct bitcoind *bitcoind,
			  const char *hextx,
			  void (*cb)(struct bitcoind *bitcoind,
				     int exitstatus, const char *msg, void *),
			    void *arg);

struct blockchain {
	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	/* Are we currently running a bitcoind request (it's ratelimited) */
	bool req_running;

	/* Pending requests. */
	struct list_head pending;

	/* What network are we on? */
	const struct chainparams *chainparams;

	/* If non-zero, time we first hit a bitcoind error. */
	struct timemono first_error_time;

	/* Ignore results, we're shutting down. */
	bool shutdown;

	// TODO: void* to neutrino and others
	struct neutrino *neutrino;

	/* Mix-and-match function pointers */
	sendrawtx_function sendrawtx;
};

struct blockchain *new_blockchain(const tal_t *ctx, struct lightningd *ld, struct log *log);

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    int exitstatus, const char *msg, void *),
			 void *arg);

#define bitcoind_sendrawtx(bitcoind_, hextx, cb, arg)			\
	bitcoind_sendrawtx_((bitcoind_), (hextx),			\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct bitcoind *,	\
						int, const char *),	\
			    (arg))

void bitcoind_estimate_fees_(struct bitcoind *bitcoind,
			     const u32 blocks[], const char *estmode[],
			     size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg);

#define bitcoind_estimate_fees(bitcoind_, blocks, estmode, num, cb, arg) \
	bitcoind_estimate_fees_((bitcoind_), (blocks), (estmode), (num), \
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    const u32 *),	\
				(arg))

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			     void (*cb)(struct bitcoind *bitcoind,
					u32 blockcount,
					void *arg),
			     void *arg);

#define bitcoind_getblockcount(bitcoind_, cb, arg)			\
	bitcoind_getblockcount_((bitcoind_),				\
				typesafe_cb_preargs(void, void *,	\
						    (cb), (arg),	\
						    struct bitcoind *,	\
						    u32 blockcount),	\
				(arg))

void bitcoind_getblockhash_(struct bitcoind *bitcoind,
			    u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct bitcoin_blkid *blkid,
				       void *arg),
			    void *arg);
#define bitcoind_getblockhash(bitcoind_, height, cb, arg)		\
	bitcoind_getblockhash_((bitcoind_),				\
			       (height),				\
			       typesafe_cb_preargs(void, void *,	\
						   (cb), (arg),		\
						   struct bitcoind *,	\
						   const struct bitcoin_blkid *), \
			       (arg))

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct bitcoin_blkid *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg);
#define bitcoind_getrawblock(bitcoind_, blkid, cb, arg)			\
	bitcoind_getrawblock_((bitcoind_), (blkid),			\
			      typesafe_cb_preargs(void, void *,		\
						  (cb), (arg),		\
						  struct bitcoind *,	\
						  struct bitcoin_block *), \
			      (arg))

void bitcoind_getoutput_(struct bitcoind *bitcoind,
			 unsigned int blocknum, unsigned int txnum,
			 unsigned int outnum,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *output,
				    void *arg),
			 void *arg);
#define bitcoind_getoutput(bitcoind_, blocknum, txnum, outnum, cb, arg)	\
	bitcoind_getoutput_((bitcoind_), (blocknum), (txnum), (outnum),	\
			    typesafe_cb_preargs(void, void *,		\
						(cb), (arg),		\
						struct bitcoind *,	\
						const struct bitcoin_tx_output*), \
			    (arg))

void bitcoind_gettxout(struct bitcoind *bitcoind,
		       const struct bitcoin_txid *txid, const u32 outnum,
		       void (*cb)(struct bitcoind *bitcoind,
				  const struct bitcoin_tx_output *txout,
				  void *arg),
		       void *arg);


#endif /* LIGHTNING_LIGHTNINGD_BLOCKCHAIN_H */