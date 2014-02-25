#ifndef PI_BGP_SEC_EXT_UTILS
#define PI_BGP_SEC_EXT_UTILS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pbgp.h>
#include <sys/queue.h>

#include "bgpd.h"

/*
 * A simple rapresentation of an nlri
 */
struct nlri_s {
	uint32_t prefix;
	uint8_t pfixlen;
};
typedef struct nlri_s nlri_t;

/*
 * Rapresentation of the aspath graph for an nlri
 */
struct pi_path {
	SLIST_ENTRY(pi_path) entry;
	struct adj_list_node {
		uint32_t asnum;
		SLIST_ENTRY(adj_list_node) entry;
	};
	SLIST_HEAD(adj_list, adj_list_node) adjs;

	uint32_t as;
	uint8_t ref; //counter of references
	time_t ts;
	ibe_signature_t signature;
};
typedef struct pi_path pi_path_t;

struct pi_rbnlri {
	nlri_t nlri;
	time_t announced_ts;

	//possible paths for the same prefix
	SLIST_HEAD(adj_pi_path, pi_path) paths;

	RB_ENTRY(pi_rbnlri)	 entry;
};
typedef struct pi_rbnlri pi_rbnlri_t;


/* Compare two nodes */
int
rbnlri_cmp_node(struct pi_rbnlri *e1, struct pi_rbnlri *e2 );

RB_HEAD(pi_tables_tree, pi_rbnlri_t) se_table;
/* making needed function prototype */
RB_GENERATE(pi_tables_tree, pi_rbnlri_t, entry, rbnlri_cmp_node);

/* Alloc elements */
int
//rbnlri_init(struct pi_tables_tree **head);
rbnlri_init();

/*
 * Add the new elem to the prefix tree. If secupd->aspath is NULL, than just set the
 * announced timestamp for the nlri spicified in the nlri_sec_upd_t.
 */
int
rbnlri_addelem(struct pi_tables_tree *head ,nlri_sec_upd_t *secupd);

/*
 * Search for the entry into the prefix tree with the specified nlri and aspath.
 * If the aspath is null than just take the prefix as key.
 *
 * @return
 * 	If an entry is found than point node to the right entry and return 0.
 * 	If no correspondig entry is found, than set node to NULL and return -1.
 */
int
rbnlri_searchelem(pi_rbnlri_t **node, struct pi_tables_tree *head, nlri_t *pfix, struct aspath *asp);

/*
 * Delete all entries with the corresponding prefix
 */
int
rbnlri_delnlri(struct pi_tables_tree *head ,nlri_t *pfix);

/* Free memory for the rb tree */
void
rbnlri_clear(struct pi_tables_tree *head);

/* retrieve timestamps array */
int
rbnlri_gettspath(time_t **tspath, struct pi_tables_tree *head, nlri_t *pfix, struct aspath *asp);

#endif
