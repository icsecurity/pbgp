#include "sec_ext_utils.h"

/*
struct nlri_s {
	uint32_t prefix;
	uint8_t pfixlen;
};
typedef struct nlri_s nlri_t;

struct pi_rbnlri {
	nlri_t nlri;
	time_t announced_ts;
	//possible paths for the same prefix
	SLIST_HEAD(adj_pi_path,pi_path) paths;

	RB_ENTRY(pi_rbnlri)	 entry;
};
typedef struct pi_rbnlri pi_rbnlri_t;

*/

/* Comapare two nodes */
int
rbnlri_cmp_node(struct pi_rbnlri *e1, struct pi_rbnlri *e2 )
{
    return ( memcmp(&(e1->nlri), &(e1->nlri), sizeof(nlri_t)) );
}

/* Alloc elements */
int
rbnlri_init()
{
    RB_INITIALIZER(&se_table);
    return 0; // always return 0 ?
}

int get_aselem(uint32_t *asnum, uint8_t *asp_curs, uint8_t pos)
{
    if ( (asnum = malloc(sizeof(uint32_t))) == NULL)
        return -1;

    *asnum = htonl(*((uint32_t*)( asp_curs + (pos * 4) )));
    return 0;
}
/*
 * Add the new elem to the prefix tree. If secupd->aspath is NULL, than just set the
 * announced timestamp for the nlri spicified in the nlri_sec_upd_t.
 */
int
rbnlri_addelem(struct pi_tables_tree *head ,nlri_sec_upd_t *secupd)
{
    struct pi_nlri_t *n = NULL;
    struct pi_nlri_t *res = NULL;

    if ((n = malloc(sizeof(struct pi_nlri))) == NULL)
        goto erralloc;

    /*
    struct nlri_sec_upd {
	struct aspath *asp;
	SLIST_HEAD(timelist,tsl_entry) tslist;
	nlri_t nlri;
    ibe_signature_t *signature; //aggregated signature
    */

    memcpy((void*) &(n->nlri), (void*) &(secupd->nlri), sizeof(nlri_t)); /* FIX NRLI DATA */

    SLIST_INIT(&(head->paths)); /* Init of ASPATH LIST */

    if (secupd->aspath == NULL)
    {
        n->announced_ts = ; // TODO :::: ????
    }
    else
    {
        uint8_t *asp_curs = NULL;
        uint8_t i = 0;

        /* we populate these struct: 	SLIST_HEAD(adj_pi_path, pi_path) paths; */
        asp_curs = secupd->aspath->data +2;

        // TODO: RIMANE IL PROBLEMA DELLA COERENZA DEI RIFERIEMTNI
        for (i=0; i < secupd->aspath->ascnt; i++)
        {
            uint32_t as_tmp = 0;

            if ( get_aselem(&as_tmp, asp_curs, i ) == 0 )
                goto aspathalloc;

            pi_path_t *tmp_path = NULL;
            if ( (tmp_path = malloc(sizeof(struct pi_path))) == NULL)
                goto aspathalloc;

            tmp_path->as = as_tmp;
            tmp_path->ref = 0 ; //counter of references... TODO .. CONSISTENCY
            memcpy(&(tmp_path->ts), secupd->tsarray + (sizeof(time_t)*i) , sizeof(time_t)) ;

            if ( i == 0) // FIRST ELEMENT (ADD SIGNATURE)
                tmp_path->ibe_signature_t = secupd->signature; // COME E' FATTO???? E' CORRETTO ??

            SLIST_INIT(&(tmp_path->adjs));

            if ( i < secupd->aspath->ascnt - 1) // NOT LAST ELEMENT
            {
                uint32_t as_next = 0;
                if ( get_aselem(&as_next, asp_curs, i + 1) == 0 )
                    goto aspathalloc;

                adj_list_node *tmp_as_entry = NULL;
                if ( (tmp_as_entry = malloc(sizeof(struct adj_list_node))) == NULL)
                    goto aspathalloc;
                tmp_as_entry->asnum = as_next;

                SLIST_INSERT_HEAD(&(tmp_path->adjs), tmp_path, entry);
            }

            SLIST_INSERT_HEAD(&(head->paths), tmp_path, entry);
        }

        free(asp_curs);
        asp_curs = NULL;
    }

    // The RB_INSERT() macro inserts the new element elm into the tree.  Upon
    // success, NULL is returned.  If a matching element already exists in the
    // tree, the insertion is aborted, and a pointer to the existing element is
    // returned.
    // FORSE QUESTO VA SPOSTATO SOPRA PERCHE' SE VA MALE L'INSERIMENTO NON FACCIO ALTRO ???
    res = RB_INSERT(pi_tables_tree, head, n);
    if (res != NULL)
        goto inserterr;


    // If we are here, received element exists. We need update it.

    return 0;

aspathalloc:
    // TODO: qui dovrei liberare la memoria della struttura ad albero ?
    log_warnx("Unable to CREATE AS into RB ENTRY");
    return -1;

inserterr:
    log_warnx("Unable to INSERT into RB struct");
    return -1;

erralloc:
    log_warnx("Node memory allocation error");
    return -1;

}

int
rbnlri_gettspath(time_t **tspath, struct pi_tables_tree *head, nlri_t *pfix, struct aspath *asp)
{
    //TODO: restituire la lista dei timestamp per l ASPATH
    return -1;
}

/*
 * Search for the entry into the prefix tree with the specified nlri and aspath.
 * If the aspath is null than just take the prefix as key.
 *
 * @return
 * 	If an entry is found than point node to the right entry and return 0.
 * 	If no correspondig entry is found, than set node to NULL and return -1.
 */
int
rbnlri_searchelem(pi_rbnlri_t **node, struct pi_tables_tree *head, nlri_t *pfix, struct aspath *asp)
{

}

/*
 * Delete all entries with the corresponding prefix
 */
int
rbnlri_delnlri(struct pi_tables_tree *head ,nlri_t *pfix)
{

}

/* Free memory for the rb tree */
void
rbnlri_clear(struct pi_tables_tree  *head)
{
    struct pi_rbnlri *n;
    RB_FOREACH(n, pi_tables_tree, head) {
        struct pi_rbnlri *app;
        app = RB_REMOVE(pi_tables_tree, head, n);
        free(app);
        // The RB_REMOVE() macro removes the element elm from the tree pointed by
        // head.  RB_REMOVE() returns elm.

    }
}
#endif
