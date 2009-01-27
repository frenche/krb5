/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <time.h>
#include <k5-int.h>
#include <kdb.h>
#include <kadm5/server_internal.h>
#include <kadm5/admin.h>
#include <adm_proto.h>
#include "kdb5_util.h"

extern krb5_keyblock master_keyblock; /* current mkey */
extern krb5_principal master_princ;
extern krb5_keylist_node *master_keylist;
extern krb5_data master_salt;
extern char *mkey_password;
extern char *progname;
extern int exit_status;
extern kadm5_config_params global_params;
extern krb5_context util_context;
extern time_t get_date(char *);

static char *strdate(krb5_timestamp when)
{
    struct tm *tm;
    static char out[40];

    time_t lcltim = when;
    tm = localtime(&lcltim);
    strftime(out, sizeof(out), "%a %b %d %H:%M:%S %Z %Y", tm);
    return out;
}

krb5_error_code
add_new_mkey(krb5_context context, krb5_db_entry *master_entry, krb5_keyblock *new_mkey, krb5_kvno *mkvno)
{
    krb5_error_code retval = 0;
    int old_key_data_count, i;
    krb5_kvno old_kvno, new_mkey_kvno;
    krb5_key_data tmp_key_data, *old_key_data;
    krb5_mkey_aux_node  *mkey_aux_data_head = NULL, **mkey_aux_data;
    krb5_keylist_node  *keylist_node;

    /* First save the old keydata */
    old_kvno = krb5_db_get_key_data_kvno(context, master_entry->n_key_data,
					 master_entry->key_data);
    old_key_data_count = master_entry->n_key_data;
    old_key_data = master_entry->key_data;

    /* alloc enough space to hold new and existing key_data */
    /*
     * The encrypted key is malloc'ed by krb5_dbekd_encrypt_key_data and
     * krb5_key_data key_data_contents is a pointer to this key.  Using some
     * logic from master_key_convert().
     */
    master_entry->key_data = (krb5_key_data *) malloc(sizeof(krb5_key_data) *
                                                     (old_key_data_count + 1));
    if (master_entry->key_data == NULL)
        return (ENOMEM);

    memset((char *) master_entry->key_data, 0,
           sizeof(krb5_key_data) * (old_key_data_count + 1));
    master_entry->n_key_data = old_key_data_count + 1;

    new_mkey_kvno = old_kvno + 1;
    /* deal with wrapping? */
    if (new_mkey_kvno == 0)
        new_mkey_kvno = 1; /* knvo must not be 0 as this is special value (IGNORE_VNO) */

    /* Note, mkey does not have salt */
    /* add new mkey encrypted with itself to mkey princ entry */
    if ((retval = krb5_dbekd_encrypt_key_data(context, new_mkey,
                                              new_mkey, NULL, 
                                              (int) new_mkey_kvno,
                                              &master_entry->key_data[0]))) {
        return (retval);
    }

    /*
     * Need to decrypt old keys with the current mkey which is in the global
     * master_keyblock and encrypt those keys with the latest mkey.  And while
     * the old keys are being decrypted, use those to create the
     * KRB5_TL_MKEY_AUX entries which store the latest mkey encrypted by one of
     * the older mkeys.
     *
     * The new mkey is followed by existing keys.
     *
     * First, set up for creating a krb5_mkey_aux_node list which will be used
     * to update the mkey aux data for the mkey princ entry.
     */
    mkey_aux_data_head = (krb5_mkey_aux_node *) malloc(sizeof(krb5_mkey_aux_node));
    if (mkey_aux_data_head == NULL) {
        retval = ENOMEM;
        goto clean_n_exit;
    }
    memset(mkey_aux_data_head, 0, sizeof(krb5_mkey_aux_node));
    mkey_aux_data = &mkey_aux_data_head;

    for (keylist_node = master_keylist, i = 1; keylist_node != NULL;
         keylist_node = keylist_node->next, i++) {

        /*
         * Create a list of krb5_mkey_aux_node nodes.  One node contains the new
         * mkey encrypted by an old mkey and the old mkey's kvno (one node per
         * old mkey).
         */
        if (*mkey_aux_data == NULL) {
            /* *mkey_aux_data points to next field of previous node */
            *mkey_aux_data = (krb5_mkey_aux_node *) malloc(sizeof(krb5_mkey_aux_node));
            if (*mkey_aux_data == NULL) {
                retval = ENOMEM;
                goto clean_n_exit;
            }
            memset(*mkey_aux_data, 0, sizeof(krb5_mkey_aux_node));
        }

        memset(&tmp_key_data, 0, sizeof(tmp_key_data));
        /* encrypt the new mkey with the older mkey */
        retval = krb5_dbekd_encrypt_key_data(context, &keylist_node->keyblock,
                                             new_mkey,
                                             NULL, /* no keysalt */
                                             (int) new_mkey_kvno,
                                             &tmp_key_data);
        if (retval)
            goto clean_n_exit;

        (*mkey_aux_data)->latest_mkey = tmp_key_data;
        (*mkey_aux_data)->mkey_kvno = keylist_node->kvno;
        mkey_aux_data = &((*mkey_aux_data)->next);

        /*
         * Store old key in master_entry keydata past the new mkey
         */
        retval = krb5_dbekd_encrypt_key_data(context, new_mkey,
                                             &keylist_node->keyblock,
                                             NULL, /* no keysalt */
                                             (int) keylist_node->kvno,
                                             &master_entry->key_data[i]);
        if (retval)
            goto clean_n_exit;
    }
    assert(i == old_key_data_count + 1);

    if ((retval = krb5_dbe_update_mkey_aux(context, master_entry,
                                           mkey_aux_data_head))) {
        goto clean_n_exit;
    }

    if (mkvno)
        *mkvno = new_mkey_kvno;

clean_n_exit:
    if (mkey_aux_data_head)
        krb5_dbe_free_mkey_aux_list(context, mkey_aux_data_head);
    return (retval);
}

void
kdb5_add_mkey(int argc, char *argv[])
{
    int optchar;
    krb5_error_code retval;
    char *mkey_fullname;
    char *pw_str = 0;
    unsigned int pw_size = 0;
    int do_stash = 0, nentries = 0;
    krb5_boolean more = 0;
    krb5_data pwd;
    krb5_kvno new_mkey_kvno;
    krb5_keyblock new_mkeyblock;
    krb5_enctype new_master_enctype = ENCTYPE_UNKNOWN;
    char *new_mkey_password;
    krb5_db_entry master_entry;
    krb5_timestamp now;

    /*
     * The command table entry for this command causes open_db_and_mkey() to be
     * called first to open the KDB and get the current mkey.
     */

    while ((optchar = getopt(argc, argv, "e:s")) != -1) {
        switch(optchar) {
        case 'e':
            if (krb5_string_to_enctype(optarg, &new_master_enctype)) {
                com_err(progname, EINVAL, ": %s is an invalid enctype", optarg);
                exit_status++;
                return;
            }
            break;
        case 's':
            do_stash++;
            break;
        case '?':
        default:
            usage();
            return;
        }
    }

    if (new_master_enctype == ENCTYPE_UNKNOWN)
        new_master_enctype = global_params.enctype;

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                                          global_params.mkey_name,
                                          global_params.realm,  
                                          &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry,
                                   &nentries, &more);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    printf("Creating new master key for master key principal '%s'\n",
        mkey_fullname);

    printf("You will be prompted for a new database Master Password.\n");
    printf("It is important that you NOT FORGET this password.\n");
    fflush(stdout);

    pw_size = 1024;
    pw_str = malloc(pw_size);
    if (pw_str == NULL) {
        com_err(progname, ENOMEM, "while creating new master key");
        exit_status++;
        return;
    }

    retval = krb5_read_password(util_context, KRB5_KDC_MKEY_1, KRB5_KDC_MKEY_2,
                                pw_str, &pw_size);
    if (retval) {
        com_err(progname, retval, "while reading new master key from keyboard");
        exit_status++;
        return;
    }
    new_mkey_password = pw_str;

    pwd.data = new_mkey_password;
    pwd.length = strlen(new_mkey_password);
    retval = krb5_principal2salt(util_context, master_princ, &master_salt);
    if (retval) {
        com_err(progname, retval, "while calculating master key salt");
        exit_status++;
        return;
    }

    retval = krb5_c_string_to_key(util_context, new_master_enctype, 
                                  &pwd, &master_salt, &new_mkeyblock);
    if (retval) {
        com_err(progname, retval, "while transforming master key from password");
        exit_status++;
        return;
    }

    retval = add_new_mkey(util_context, &master_entry, &new_mkeyblock, NULL);
    if (retval) {
        com_err(progname, retval, "adding new master key to master principal");
        exit_status++;
        return;
    }

    if ((retval = krb5_timeofday(util_context, &now))) {
        com_err(progname, retval, "while getting current time");
        exit_status++;
        return;
    }

    if ((retval = krb5_dbe_update_mod_princ_data(util_context, &master_entry,
                                                 now, master_princ))) {
        com_err(progname, retval, "while updating the master key principal modification time");
        exit_status++;
        return;
    }

    if ((retval = krb5_db_put_principal(util_context, &master_entry, &nentries))) {
        (void) krb5_db_fini(util_context);
        com_err(progname, retval, "while adding master key entry to the database");
        exit_status++;
        return;
    }

    if (do_stash) {
        retval = krb5_db_store_master_key(util_context,
                                          global_params.stash_file,
                                          master_princ,
                                          new_mkey_kvno,
                                          &new_mkeyblock,
                                          mkey_password);
        if (retval) {
            com_err(progname, errno, "while storing key");
            printf("Warning: couldn't stash master key.\n");
        }
    }
    /* clean up */
    (void) krb5_db_fini(util_context);
    zap((char *)master_keyblock.contents, master_keyblock.length);
    free(master_keyblock.contents);
    zap((char *)new_mkeyblock.contents, new_mkeyblock.length);
    free(new_mkeyblock.contents);
    if (pw_str) {
        zap(pw_str, pw_size);
        free(pw_str);
    }
    free(master_salt.data);
    free(mkey_fullname);

    return;
}

void
kdb5_use_mkey(int argc, char *argv[])
{
    krb5_error_code retval;
    char  *mkey_fullname;
    krb5_kvno  use_kvno;
    krb5_timestamp now, start_time;
    krb5_actkvno_node *actkvno_list, *new_actkvno_list_head, *new_actkvno,
                      *prev_actkvno, *cur_actkvno;
    krb5_db_entry master_entry;
    int   nentries = 0;
    krb5_boolean more = 0, found;
    krb5_keylist_node  *keylist_node;

    if (argc < 2 || argc > 3) {
        /* usage calls exit */
        usage();
    }

    use_kvno = atoi(argv[1]);
    if (use_kvno == 0) {
        com_err(progname, EINVAL, ": 0 is an invalid KVNO value.");
        exit_status++;
        return;
    } else {
        /* verify use_kvno is valid */
        for (keylist_node = master_keylist, found = FALSE; keylist_node != NULL;
             keylist_node = keylist_node->next) {
            if (use_kvno == keylist_node->kvno) {
                found = TRUE;
                break;
            }
        }
        if (!found) {
            com_err(progname, EINVAL, ": %d is an invalid KVNO value.", use_kvno);
            exit_status++;
            return;
        }
    }

    if ((retval = krb5_timeofday(util_context, &now))) {
        com_err(progname, retval, "while getting current time.");
        exit_status++;
        return;
    }

    if (argc == 3) {
        start_time = (krb5_timestamp) get_date(argv[2]);
    } else {
        start_time = now;
    }

    /*
     * Need to:
     *
     * 1. get mkey princ
     * 2. get krb5_actkvno_node list
     * 3. add use_kvno to actkvno list (sorted in right spot)
     * 4. update mkey princ's tl data
     * 5. put mkey princ.
     */

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                                          global_params.mkey_name,
                                          global_params.realm,  
                                          &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry, &nentries,
        &more);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_dbe_lookup_actkvno(util_context, &master_entry, &actkvno_list);
    if (retval != 0) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    /* alloc enough space to hold new and existing key_data */
    new_actkvno = (krb5_actkvno_node *) malloc(sizeof(krb5_actkvno_node));
    if (new_actkvno == NULL) {
        com_err(progname, ENOMEM, "while adding new master key");
        exit_status++;
        return;
    }
    memset(new_actkvno, 0, sizeof(krb5_actkvno_node));

    new_actkvno->act_kvno = use_kvno;
    new_actkvno->act_time = start_time;

    /*
     * determine which nodes to delete and where to insert new act kvno node
     */

    if (actkvno_list == NULL) {
        /* new actkvno is the list */
        new_actkvno_list_head = new_actkvno;
    } else {
        krb5_boolean inserted = FALSE, trimed = FALSE;

        for (prev_actkvno = NULL, cur_actkvno = actkvno_list;
             cur_actkvno != NULL;
             prev_actkvno = cur_actkvno, cur_actkvno = cur_actkvno->next) {

            if (!inserted) {
                if (new_actkvno->act_time < cur_actkvno->act_time) {
                    if (prev_actkvno) {
                        prev_actkvno->next = new_actkvno;
                        new_actkvno->next = cur_actkvno;
                    } else {
                        new_actkvno->next = actkvno_list;
                        actkvno_list = new_actkvno;
                    }
                    inserted = TRUE;
                } else if (cur_actkvno->next == NULL) {
                    /* end of line, just add new node to end of list */
                    cur_actkvno->next = new_actkvno;
                    inserted = TRUE;
                }
            }
            if (!trimed) {
                if (cur_actkvno->act_time > now) {
                    if (prev_actkvno) {
                        new_actkvno_list_head = prev_actkvno;
                    } else {
                        new_actkvno_list_head = actkvno_list;
                    }
                    trimed = TRUE;
                } else if (cur_actkvno->next == NULL) {
                    new_actkvno_list_head = cur_actkvno;
                    trimed = TRUE;
                }
            }
            if (trimed && inserted)
                break;
        }
    }

    if ((retval = krb5_dbe_update_actkvno(util_context, &master_entry,
                                          new_actkvno_list_head))) {
        com_err(progname, retval, "while updating actkvno data for master principal entry.");
        exit_status++;
        return;
    }

    if ((retval = krb5_dbe_update_mod_princ_data(util_context, &master_entry,
                now, master_princ))) {
        com_err(progname, retval, "while updating the master key principal modification time");
        exit_status++;
        return;
    }

    if ((retval = krb5_db_put_principal(util_context, &master_entry, &nentries))) {
        (void) krb5_db_fini(util_context);
        com_err(progname, retval, "while adding master key entry to the database");
        exit_status++;
        return;
    }

    /* clean up */
    (void) krb5_db_fini(util_context);
    free(mkey_fullname);
    krb5_dbe_free_actkvno_list(util_context, actkvno_list);
    return;
}

void
kdb5_list_mkeys(int argc, char *argv[])
{
    krb5_error_code retval;
    char  *mkey_fullname, *output_str = NULL, enctype[BUFSIZ];
    krb5_kvno  act_kvno;
    krb5_timestamp act_time;
    krb5_actkvno_node *actkvno_list = NULL, *cur_actkvno, *prev_actkvno;
    krb5_db_entry master_entry;
    int   nentries = 0;
    krb5_boolean more = 0;
    krb5_keylist_node  *cur_kb_node;
    krb5_keyblock *act_mkey;

    if (master_keylist == NULL) {
        com_err(progname, retval, "master keylist not initialized");
        exit_status++;
        return;
    }

    /* assemble & parse the master key name */
    if ((retval = krb5_db_setup_mkey_name(util_context,
                                          global_params.mkey_name,
                                          global_params.realm,  
                                          &mkey_fullname, &master_princ))) {
        com_err(progname, retval, "while setting up master key name");
        exit_status++;
        return;
    }

    retval = krb5_db_get_principal(util_context, master_princ, &master_entry, &nentries,
        &more);
    if (retval != 0) {
        com_err(progname, retval, "while getting master key principal %s", mkey_fullname);
        exit_status++;
        return;
    }

    retval = krb5_dbe_lookup_actkvno(util_context, &master_entry, &actkvno_list);
    if (retval != 0) {
        com_err(progname, retval, "while looking up active kvno list");
        exit_status++;
        return;
    }

    if (actkvno_list == NULL) {
        act_kvno = master_entry.key_data[0].key_data_kvno;
    } else {
        retval = krb5_dbe_find_act_mkey(util_context, master_keylist,
                                        actkvno_list, &act_kvno, &act_mkey);
        if (retval != 0) {
            com_err(progname, retval, "while setting up master key name");
            exit_status++;
            return;
        }
    }

    printf("Master keys for Principal: %s\n", mkey_fullname);

    for (cur_kb_node = master_keylist; cur_kb_node != NULL;
         cur_kb_node = cur_kb_node->next) {

        if ((retval = krb5_enctype_to_string(cur_kb_node->keyblock.enctype,
                                             enctype, sizeof(enctype)))) {
            com_err(progname, retval, "while getting enctype description");
            exit_status++;
            return;
        }

        if (actkvno_list != NULL) {
            act_time = 0;
            for (cur_actkvno = actkvno_list; cur_actkvno != NULL;
                 cur_actkvno = cur_actkvno->next) {
                if (cur_actkvno->act_kvno == cur_kb_node->kvno) {
                    act_time = cur_actkvno->act_time;
                    break;
                }
            }
        } else {
            /*
             * mkey princ doesn't have an active knvo list so assume the current
             * key is active now
             */
            if ((retval = krb5_timeofday(util_context, &act_time))) {
                com_err(progname, retval, "while getting current time");
                exit_status++;
                return;
            }
        }

        if (cur_kb_node->kvno == act_kvno) {
            /* * indicates kvno is currently active */
            retval = asprintf(&output_str, "KNVO: %d, Enctype: %s, Active on: %s *\n",
                              cur_kb_node->kvno, enctype, strdate(act_time));
        } else {
            if (act_time) {
                retval = asprintf(&output_str, "KNVO: %d, Enctype: %s, Active on: %s\n",
                                  cur_kb_node->kvno, enctype, strdate(act_time));
            } else {
                retval = asprintf(&output_str, "KNVO: %d, Enctype: %s, No activate time set\n",
                                  cur_kb_node->kvno, enctype);
            }
        }
        if (retval == -1) {
            com_err(progname, ENOMEM, "asprintf could not allocate enough memory to hold output");
            exit_status++;
            return;
        }
        printf("%s", output_str);
        free(output_str);
        output_str = NULL;
    }

    /* clean up */
    (void) krb5_db_fini(util_context);
    free(mkey_fullname);
    free(output_str);
    for (cur_actkvno = actkvno_list; cur_actkvno != NULL;) {
        prev_actkvno = cur_actkvno;
        cur_actkvno = cur_actkvno->next;
        free(prev_actkvno);
    }
    return;
}
