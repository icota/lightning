struct trusted_server {
	/* Where to do logging. */
	struct log *log;

	/* Main lightningd structure */
	struct lightningd *ld;

	char* address;
	int port;
};



void estimate_fees(void);
