/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1990, 1991, 2016 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */
/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* KDC Database interface definitions */

/* This API is not considered as stable as the main krb5 API.
 *
 * - We may make arbitrary incompatible changes between feature
 *   releases (e.g. from 1.7 to 1.8).
 * - We will make some effort to avoid making incompatible changes for
 *   bugfix releases, but will make them if necessary.
 */

#ifndef KRB5_KDB5__
#define KRB5_KDB5__

#include <krb5.h>

/* This version will be incremented when incompatible changes are made to the
 * KDB API, and will be kept in sync with the libkdb major version. */
#define KRB5_KDB_API_VERSION 9

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL        0
/* #define KRB5_KDB_SALTTYPE_V4            1 */
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
/* #define KRB5_KDB_SALTTYPE_AFS3          5 */
#define KRB5_KDB_SALTTYPE_CERTHASH      6

/* Attributes */
#define KRB5_KDB_DISALLOW_POSTDATED     0x00000001
#define KRB5_KDB_DISALLOW_FORWARDABLE   0x00000002
#define KRB5_KDB_DISALLOW_TGT_BASED     0x00000004
#define KRB5_KDB_DISALLOW_RENEWABLE     0x00000008
#define KRB5_KDB_DISALLOW_PROXIABLE     0x00000010
#define KRB5_KDB_DISALLOW_DUP_SKEY      0x00000020
#define KRB5_KDB_DISALLOW_ALL_TIX       0x00000040
#define KRB5_KDB_REQUIRES_PRE_AUTH      0x00000080
#define KRB5_KDB_REQUIRES_HW_AUTH       0x00000100
#define KRB5_KDB_REQUIRES_PWCHANGE      0x00000200
#define KRB5_KDB_DISALLOW_SVR           0x00001000
#define KRB5_KDB_PWCHANGE_SERVICE       0x00002000
#define KRB5_KDB_SUPPORT_DESMD5         0x00004000
#define KRB5_KDB_NEW_PRINC              0x00008000
#define KRB5_KDB_OK_AS_DELEGATE         0x00100000
#define KRB5_KDB_OK_TO_AUTH_AS_DELEGATE 0x00200000 /* S4U2Self OK */
#define KRB5_KDB_NO_AUTH_DATA_REQUIRED  0x00400000
#define KRB5_KDB_LOCKDOWN_KEYS          0x00800000
#define KRB5_KDB_DELEGATION_NOT_ALLOWED 0x01000000

/* Creation flags */
#define KRB5_KDB_CREATE_BTREE           0x00000001
#define KRB5_KDB_CREATE_HASH            0x00000002

/* Private flag used to indicate principal is local TGS */
#define KRB5_KDB_TICKET_GRANTING_SERVICE        0x01000000
/* Private flag used to indicate xrealm relationship  is non-transitive */
#define KRB5_KDB_XREALM_NON_TRANSITIVE          0x02000000

/* Entry get flags */
/* Name canonicalization requested */
#define KRB5_KDB_FLAG_CANONICALIZE              0x00000010
/* Include authorization data generated by backend */
#define KRB5_KDB_FLAG_INCLUDE_PAC               0x00000020
/* Is AS-REQ (client referrals only) */
#define KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY     0x00000040
/* Map cross-realm principals */
#define KRB5_KDB_FLAG_MAP_PRINCIPALS            0x00000080
/* Protocol transition */
#define KRB5_KDB_FLAG_PROTOCOL_TRANSITION       0x00000100
/* Constrained delegation */
#define KRB5_KDB_FLAG_CONSTRAINED_DELEGATION    0x00000200
/* User-to-user */
#define KRB5_KDB_FLAG_USER_TO_USER              0x00000800
/* Cross-realm */
#define KRB5_KDB_FLAG_CROSS_REALM               0x00001000
/* Allow in-realm aliases */
#define KRB5_KDB_FLAG_ALIAS_OK                  0x00002000

#define KRB5_KDB_FLAGS_S4U                      ( KRB5_KDB_FLAG_PROTOCOL_TRANSITION | \
                                                  KRB5_KDB_FLAG_CONSTRAINED_DELEGATION )

/* KDB iteration flags */
#define KRB5_DB_ITER_WRITE      0x00000001
#define KRB5_DB_ITER_REV        0x00000002
#define KRB5_DB_ITER_RECURSE    0x00000004

/* String attribute names recognized by krb5 */
#define KRB5_KDB_SK_SESSION_ENCTYPES            "session_enctypes"
#define KRB5_KDB_SK_REQUIRE_AUTH                "require_auth"

#if !defined(_WIN32)

/*
 * Note --- these structures cannot be modified without changing the
 * database version number in libkdb.a, but should be expandable by
 * adding new tl_data types.
 */
typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;         /* NOT saved */
    krb5_int16            tl_data_type;
    krb5_ui_2             tl_data_length;
    krb5_octet          * tl_data_contents;
} krb5_tl_data;

/* String attributes (currently stored inside tl-data) map C string keys to
 * values.  They can be set via kadmin and consumed by KDC plugins. */
typedef struct krb5_string_attr_st {
    char *key;
    char *value;
} krb5_string_attr;

/*
 * If this ever changes up the version number and make the arrays be as
 * big as necessary.
 *
 * Currently the first type is the enctype and the second is the salt type.
 */
typedef struct _krb5_key_data {
    krb5_int16            key_data_ver;         /* Version */
    krb5_ui_2             key_data_kvno;        /* Key Version */
    krb5_int16            key_data_type[2];     /* Array of types */
    krb5_ui_2             key_data_length[2];   /* Array of lengths */
    krb5_octet          * key_data_contents[2]; /* Array of pointers */
} krb5_key_data;

#define KRB5_KDB_V1_KEY_DATA_ARRAY      2       /* # of array elements */

typedef struct _krb5_keysalt {
    krb5_int16            type;
    krb5_data             data;                 /* Length, data */
} krb5_keysalt;

/*
 * A principal database entry.  Extensions to this structure currently use the
 * tl_data list.  The e_data and e_length fields are not used by any calling
 * code except kdb5_util dump and load, which marshal and unmarshal the array
 * in the dump record.  KDB modules may use these fields internally as long as
 * they set e_length appropriately (non-zero if the data should be marshalled
 * across dump and load, zero if not) and handle null e_data values in
 * caller-constructed principal entries.
 */
typedef struct _krb5_db_entry_new {
    krb5_magic            magic;                /* NOT saved */
    krb5_ui_2             len;
    krb5_ui_4             mask;                 /* members currently changed/set */
    krb5_flags            attributes;
    krb5_deltat           max_life;
    krb5_deltat           max_renewable_life;
    krb5_timestamp        expiration;           /* When the client expires */
    krb5_timestamp        pw_expiration;        /* When its passwd expires */
    krb5_timestamp        last_success;         /* Last successful passwd */
    krb5_timestamp        last_failed;          /* Last failed passwd attempt */
    krb5_kvno             fail_auth_count;      /* # of failed passwd attempt */
    krb5_int16            n_tl_data;
    krb5_int16            n_key_data;
    krb5_ui_2             e_length;             /* Length of extra data */
    krb5_octet          * e_data;               /* Extra data to be saved */

    krb5_principal        princ;                /* Length, data */
    krb5_tl_data        * tl_data;              /* Linked list */

    /* key_data must be sorted by kvno in descending order. */
    krb5_key_data       * key_data;             /* Array */
} krb5_db_entry;

typedef struct _osa_policy_ent_t {
    int               version;
    char      *name;
    krb5_ui_4       pw_min_life;
    krb5_ui_4       pw_max_life;
    krb5_ui_4       pw_min_length;
    krb5_ui_4       pw_min_classes;
    krb5_ui_4       pw_history_num;
    krb5_ui_4       policy_refcnt;              /* no longer used */
    /* Only valid if version > 1 */
    krb5_ui_4       pw_max_fail;                /* pwdMaxFailure */
    krb5_ui_4       pw_failcnt_interval;        /* pwdFailureCountInterval */
    krb5_ui_4       pw_lockout_duration;        /* pwdLockoutDuration */
    /* Only valid if version > 2 */
    krb5_ui_4       attributes;
    krb5_ui_4       max_life;
    krb5_ui_4       max_renewable_life;
    char          * allowed_keysalts;
    krb5_int16      n_tl_data;
    krb5_tl_data  * tl_data;
} osa_policy_ent_rec, *osa_policy_ent_t;

typedef       void    (*osa_adb_iter_policy_func) (void *, osa_policy_ent_t);

typedef struct __krb5_key_salt_tuple {
    krb5_enctype        ks_enctype;
    krb5_int32          ks_salttype;
} krb5_key_salt_tuple;

#define KRB5_KDB_MAGIC_NUMBER           0xdbdbdbdb
#define KRB5_KDB_V1_BASE_LENGTH         38

#define KRB5_KDB_MAX_ALLOWED_KS_LEN     512

#define KRB5_TL_LAST_PWD_CHANGE         0x0001
#define KRB5_TL_MOD_PRINC               0x0002
#define KRB5_TL_KADM_DATA               0x0003
#define KRB5_TL_KADM5_E_DATA            0x0004
#define KRB5_TL_RB1_CHALLENGE           0x0005
#ifdef SECURID
#define KRB5_TL_SECURID_STATE           0x0006
#endif /* SECURID */
#define KRB5_TL_USER_CERTIFICATE        0x0007
#define KRB5_TL_MKVNO                   0x0008
#define KRB5_TL_ACTKVNO                 0x0009
#define KRB5_TL_MKEY_AUX                0x000a

/* String attributes may not always be represented in tl-data.  kadmin clients
 * must use the get_strings and set_string RPCs. */
#define KRB5_TL_STRING_ATTRS            0x000b

#define KRB5_TL_PAC_LOGON_INFO          0x0100 /* NDR encoded validation info */
#define KRB5_TL_SERVER_REFERRAL         0x0200 /* ASN.1 encoded ServerReferralInfo */
#define KRB5_TL_SVR_REFERRAL_DATA       0x0300 /* ASN.1 encoded PA-SVR-REFERRAL-DATA */
#define KRB5_TL_CONSTRAINED_DELEGATION_ACL 0x0400 /* Each entry is a permitted SPN */
#define KRB5_TL_LM_KEY                  0x0500 /* LM OWF */
#define KRB5_TL_X509_SUBJECT_ISSUER_NAME 0x0600 /* <I>IssuerDN<S>SubjectDN */
#define KRB5_TL_LAST_ADMIN_UNLOCK       0x0700 /* Timestamp of admin unlock */

#define KRB5_TL_DB_ARGS                 0x7fff

/* version number for KRB5_TL_ACTKVNO data */
#define KRB5_TL_ACTKVNO_VER     1

/* version number for KRB5_TL_MKEY_AUX data */
#define KRB5_TL_MKEY_AUX_VER    1

typedef struct _krb5_actkvno_node {
    struct _krb5_actkvno_node *next;
    krb5_kvno      act_kvno;
    krb5_timestamp act_time;
} krb5_actkvno_node;

typedef struct _krb5_mkey_aux_node {
    struct _krb5_mkey_aux_node *next;
    krb5_kvno        mkey_kvno; /* kvno of mkey protecting the latest_mkey */
    krb5_key_data    latest_mkey; /* most recent mkey */
} krb5_mkey_aux_node;

typedef struct _krb5_keylist_node {
    krb5_keyblock keyblock;
    krb5_kvno     kvno;
    struct _krb5_keylist_node *next;
} krb5_keylist_node;

/*
 * Determines the number of failed KDC requests before DISALLOW_ALL_TIX is set
 * on the principal.
 */
#define KRB5_MAX_FAIL_COUNT             5

/* XXX depends on knowledge of krb5_parse_name() formats */
#define KRB5_KDB_M_NAME         "K/M"   /* Kerberos/Master */

/* prompts used by default when reading the KDC password from the keyboard. */
#define KRB5_KDC_MKEY_1 "Enter KDC database master key"
#define KRB5_KDC_MKEY_2 "Re-enter KDC database master key to verify"


extern char *krb5_mkey_pwd_prompt1;
extern char *krb5_mkey_pwd_prompt2;

/*
 * These macros specify the encoding of data within the database.
 *
 * Data encoding is little-endian.
 */
#ifdef _KRB5_INT_H
#include "k5-platform.h"
#define krb5_kdb_decode_int16(cp, i16)          \
    *((krb5_int16 *) &(i16)) = load_16_le(cp)
#define krb5_kdb_decode_int32(cp, i32)          \
    *((krb5_int32 *) &(i32)) = load_32_le(cp)
#define krb5_kdb_encode_int16(i16, cp)  store_16_le(i16, cp)
#define krb5_kdb_encode_int32(i32, cp)  store_32_le(i32, cp)
#endif /* _KRB5_INT_H */

#define KRB5_KDB_OPEN_RW                0
#define KRB5_KDB_OPEN_RO                1

#ifndef KRB5_KDB_SRV_TYPE_KDC
#define KRB5_KDB_SRV_TYPE_KDC           0x0100
#endif

#ifndef KRB5_KDB_SRV_TYPE_ADMIN
#define KRB5_KDB_SRV_TYPE_ADMIN         0x0200
#endif

/* 0x0300 was KRB5_KDB_SRV_TYPE_PASSWD but it is no longer used. */

#ifndef KRB5_KDB_SRV_TYPE_OTHER
#define KRB5_KDB_SRV_TYPE_OTHER         0x0400
#endif

#define KRB5_KDB_OPT_SET_DB_NAME        0
#define KRB5_KDB_OPT_SET_LOCK_MODE      1

#define KRB5_DB_LOCKMODE_SHARED       0x0001
#define KRB5_DB_LOCKMODE_EXCLUSIVE    0x0002
#define KRB5_DB_LOCKMODE_PERMANENT    0x0008

/* libkdb.spec */
krb5_error_code krb5_db_setup_lib_handle(krb5_context kcontext);
krb5_error_code krb5_db_open( krb5_context kcontext, char **db_args, int mode );
krb5_error_code krb5_db_init  ( krb5_context kcontext );
krb5_error_code krb5_db_create ( krb5_context kcontext, char **db_args );
krb5_error_code krb5_db_inited  ( krb5_context kcontext );
krb5_error_code kdb5_db_create ( krb5_context kcontext, char **db_args );
krb5_error_code krb5_db_fini ( krb5_context kcontext );
const char * krb5_db_errcode2string ( krb5_context kcontext, long err_code );
krb5_error_code krb5_db_destroy ( krb5_context kcontext, char **db_args );
krb5_error_code krb5_db_promote ( krb5_context kcontext, char **db_args );
krb5_error_code krb5_db_get_age ( krb5_context kcontext, char *db_name, time_t *t );
krb5_error_code krb5_db_lock ( krb5_context kcontext, int lock_mode );
krb5_error_code krb5_db_unlock ( krb5_context kcontext );
krb5_error_code krb5_db_get_principal ( krb5_context kcontext,
                                        krb5_const_principal search_for,
                                        unsigned int flags,
                                        krb5_db_entry **entry );
void krb5_db_free_principal ( krb5_context kcontext, krb5_db_entry *entry );
krb5_error_code krb5_db_put_principal ( krb5_context kcontext,
                                        krb5_db_entry *entry );
krb5_error_code krb5_db_delete_principal ( krb5_context kcontext,
                                           krb5_principal search_for );
krb5_error_code krb5_db_rename_principal ( krb5_context kcontext,
                                           krb5_principal source,
                                           krb5_principal target );

/*
 * Iterate over principals in the KDB.  If the callback may write to the DB,
 * the caller must get an exclusive lock with krb5_db_lock before iterating,
 * and release it with krb5_db_unlock after iterating.
 */
krb5_error_code krb5_db_iterate ( krb5_context kcontext,
                                  char *match_entry,
                                  int (*func) (krb5_pointer, krb5_db_entry *),
                                  krb5_pointer func_arg, krb5_flags iterflags );


krb5_error_code krb5_db_store_master_key  ( krb5_context kcontext,
                                            char *keyfile,
                                            krb5_principal mname,
                                            krb5_kvno kvno,
                                            krb5_keyblock *key,
                                            char *master_pwd);
krb5_error_code krb5_db_store_master_key_list  ( krb5_context kcontext,
                                                 char *keyfile,
                                                 krb5_principal mname,
                                                 char *master_pwd);
krb5_error_code krb5_db_fetch_mkey  ( krb5_context   context,
                                      krb5_principal mname,
                                      krb5_enctype   etype,
                                      krb5_boolean   fromkeyboard,
                                      krb5_boolean   twice,
                                      char          *db_args,
                                      krb5_kvno     *kvno,
                                      krb5_data     *salt,
                                      krb5_keyblock *key);
krb5_error_code
krb5_db_fetch_mkey_list( krb5_context    context,
                         krb5_principal  mname,
                         const krb5_keyblock * mkey );

krb5_error_code
krb5_dbe_find_enctype( krb5_context     kcontext,
                       krb5_db_entry    *dbentp,
                       krb5_int32               ktype,
                       krb5_int32               stype,
                       krb5_int32               kvno,
                       krb5_key_data    **kdatap);


krb5_error_code krb5_dbe_search_enctype ( krb5_context kcontext,
                                          krb5_db_entry *dbentp,
                                          krb5_int32 *start,
                                          krb5_int32 ktype,
                                          krb5_int32 stype,
                                          krb5_int32 kvno,
                                          krb5_key_data **kdatap);

krb5_error_code
krb5_db_setup_mkey_name ( krb5_context context,
                          const char *keyname,
                          const char *realm,
                          char **fullname,
                          krb5_principal *principal);

/**
 * Decrypts the key given in @@a key_data. If @a mkey is specified, that
 * master key is used. If @a mkey is NULL, then all master keys are tried.
 */
krb5_error_code
krb5_dbe_decrypt_key_data( krb5_context         context,
                           const krb5_keyblock        * mkey,
                           const krb5_key_data        * key_data,
                           krb5_keyblock      * dbkey,
                           krb5_keysalt       * keysalt);

krb5_error_code
krb5_dbe_encrypt_key_data( krb5_context                 context,
                           const krb5_keyblock        * mkey,
                           const krb5_keyblock        * dbkey,
                           const krb5_keysalt         * keysalt,
                           int                          keyver,
                           krb5_key_data              * key_data);

krb5_error_code
krb5_dbe_fetch_act_key_list(krb5_context          context,
                            krb5_principal       princ,
                            krb5_actkvno_node  **act_key_list);

krb5_error_code
krb5_dbe_find_act_mkey( krb5_context          context,
                        krb5_actkvno_node   * act_mkey_list,
                        krb5_kvno           * act_kvno,
                        krb5_keyblock      ** act_mkey);

krb5_error_code
krb5_dbe_find_mkey( krb5_context         context,
                    krb5_db_entry      * entry,
                    krb5_keyblock      ** mkey);

/* Set *mkvno to mkvno in entry tl_data, or 0 if not present. */
krb5_error_code
krb5_dbe_lookup_mkvno( krb5_context    context,
                       krb5_db_entry * entry,
                       krb5_kvno     * mkvno);

krb5_keylist_node *
krb5_db_mkey_list_alias( krb5_context kcontext );

/* Set *mkvno to mkvno in entry tl_data, or minimum value from mkey_list. */
krb5_error_code
krb5_dbe_get_mkvno( krb5_context        context,
                    krb5_db_entry     * entry,
                    krb5_kvno         * mkvno);

krb5_error_code
krb5_dbe_lookup_mod_princ_data( krb5_context          context,
                                krb5_db_entry       * entry,
                                krb5_timestamp      * mod_time,
                                krb5_principal      * mod_princ);

krb5_error_code
krb5_dbe_lookup_mkey_aux( krb5_context         context,
                          krb5_db_entry      * entry,
                          krb5_mkey_aux_node ** mkey_aux_data_list);
krb5_error_code
krb5_dbe_update_mkvno( krb5_context    context,
                       krb5_db_entry * entry,
                       krb5_kvno       mkvno);

krb5_error_code
krb5_dbe_lookup_actkvno( krb5_context         context,
                         krb5_db_entry      * entry,
                         krb5_actkvno_node ** actkvno_list);

krb5_error_code
krb5_dbe_update_mkey_aux( krb5_context          context,
                          krb5_db_entry       * entry,
                          krb5_mkey_aux_node  * mkey_aux_data_list);

krb5_error_code
krb5_dbe_update_actkvno(krb5_context    context,
                        krb5_db_entry * entry,
                        const krb5_actkvno_node *actkvno_list);

krb5_error_code
krb5_dbe_update_last_pwd_change( krb5_context     context,
                                 krb5_db_entry  * entry,
                                 krb5_timestamp   stamp);

krb5_error_code
krb5_dbe_update_last_admin_unlock( krb5_context     context,
                                   krb5_db_entry  * entry,
                                   krb5_timestamp   stamp);

krb5_error_code
krb5_dbe_lookup_tl_data( krb5_context          context,
                         krb5_db_entry       * entry,
                         krb5_tl_data        * ret_tl_data);

krb5_error_code
krb5_dbe_create_key_data( krb5_context          context,
                          krb5_db_entry       * entry);


krb5_error_code
krb5_dbe_update_mod_princ_data( krb5_context          context,
                                krb5_db_entry       * entry,
                                krb5_timestamp        mod_date,
                                krb5_const_principal  mod_princ);

/*
 * These are wrappers around realloc() and free().  Applications and KDB
 * modules can use them when manipulating principal and policy entries to
 * ensure that they allocate and free memory in a manner compatible with the
 * library.  Using libkrb5 or libkbd5 functions to construct values (such as
 * krb5_copy_principal() to construct the princ field of a krb5_db_entry) is
 * also safe.  On Unix platforms, just using malloc() and free() is safe as
 * long as the application or module does not use a malloc replacement.
 */
void *krb5_db_alloc( krb5_context kcontext,
                     void *ptr,
                     size_t size );
void krb5_db_free( krb5_context kcontext,
                   void *ptr);


krb5_error_code
krb5_dbe_lookup_last_pwd_change( krb5_context          context,
                                 krb5_db_entry       * entry,
                                 krb5_timestamp      * stamp);

krb5_error_code
krb5_dbe_lookup_last_admin_unlock( krb5_context          context,
                                   krb5_db_entry       * entry,
                                   krb5_timestamp      * stamp);

/* Retrieve the set of string attributes in entry, in no particular order.
 * Free *strings_out with krb5_dbe_free_strings when done. */
krb5_error_code
krb5_dbe_get_strings(krb5_context context, krb5_db_entry *entry,
                     krb5_string_attr **strings_out, int *count_out);

/* Retrieve a single string attribute from entry, or NULL if there is no
 * attribute for key.  Free *value_out with krb5_dbe_free_string when done. */
krb5_error_code
krb5_dbe_get_string(krb5_context context, krb5_db_entry *entry,
                    const char *key, char **value_out);

/* Change or add a string attribute in entry, or delete it if value is NULL. */
krb5_error_code
krb5_dbe_set_string(krb5_context context, krb5_db_entry *entry,
                    const char *key, const char *value);

krb5_error_code
krb5_dbe_delete_tl_data( krb5_context    context,
                         krb5_db_entry * entry,
                         krb5_int16      tl_data_type);

krb5_error_code
krb5_db_update_tl_data(krb5_context          context,
                       krb5_int16          * n_tl_datap,
                       krb5_tl_data        **tl_datap,
                       krb5_tl_data        * new_tl_data);

krb5_error_code
krb5_dbe_update_tl_data( krb5_context          context,
                         krb5_db_entry       * entry,
                         krb5_tl_data        * new_tl_data);

/* Compute the salt for a key data entry given the corresponding principal. */
krb5_error_code
krb5_dbe_compute_salt(krb5_context context, const krb5_key_data *key,
                      krb5_const_principal princ, krb5_int16 *salttype_out,
                      krb5_data **salt_out);

/*
 * Modify the key data of entry to explicitly store salt values using the
 * KRB5_KDB_SALTTYPE_SPECIAL salt type.
 */
krb5_error_code
krb5_dbe_specialize_salt(krb5_context context, krb5_db_entry *entry);

krb5_error_code
krb5_dbe_cpw( krb5_context        kcontext,
              krb5_keyblock       * master_key,
              krb5_key_salt_tuple       * ks_tuple,
              int                         ks_tuple_count,
              char              * passwd,
              int                         new_kvno,
              krb5_boolean        keepold,
              krb5_db_entry     * db_entry);


krb5_error_code
krb5_dbe_ark( krb5_context        context,
              krb5_keyblock       * master_key,
              krb5_key_salt_tuple       * ks_tuple,
              int                         ks_tuple_count,
              krb5_db_entry     * db_entry);

krb5_error_code
krb5_dbe_crk( krb5_context        context,
              krb5_keyblock       * master_key,
              krb5_key_salt_tuple       * ks_tuple,
              int                         ks_tuple_count,
              krb5_boolean        keepold,
              krb5_db_entry     * db_entry);

krb5_error_code
krb5_dbe_apw( krb5_context        context,
              krb5_keyblock       * master_key,
              krb5_key_salt_tuple       * ks_tuple,
              int                         ks_tuple_count,
              char              * passwd,
              krb5_db_entry     * db_entry);

int
krb5_db_get_key_data_kvno( krb5_context    context,
                           int             count,
                           krb5_key_data * data);

krb5_error_code krb5_db_sign_authdata(krb5_context kcontext,
                                      unsigned int flags,
                                      krb5_const_principal client_princ,
                                      krb5_db_entry *client,
                                      krb5_db_entry *server,
                                      krb5_db_entry *krbtgt,
                                      krb5_keyblock *client_key,
                                      krb5_keyblock *server_key,
                                      krb5_keyblock *krbtgt_key,
                                      krb5_keyblock *session_key,
                                      krb5_timestamp authtime,
                                      krb5_authdata **tgt_auth_data,
                                      krb5_authdata ***signed_auth_data);

krb5_error_code krb5_db_check_transited_realms(krb5_context kcontext,
                                               const krb5_data *tr_contents,
                                               const krb5_data *client_realm,
                                               const krb5_data *server_realm);

krb5_error_code krb5_db_check_policy_as(krb5_context kcontext,
                                        krb5_kdc_req *request,
                                        krb5_db_entry *client,
                                        krb5_db_entry *server,
                                        krb5_timestamp kdc_time,
                                        const char **status,
                                        krb5_pa_data ***e_data);

krb5_error_code krb5_db_check_policy_tgs(krb5_context kcontext,
                                         krb5_kdc_req *request,
                                         krb5_db_entry *server,
                                         krb5_ticket *ticket,
                                         const char **status,
                                         krb5_pa_data ***e_data);

void krb5_db_audit_as_req(krb5_context kcontext, krb5_kdc_req *request,
                          const krb5_address *local_addr,
                          const krb5_address *remote_addr,
                          krb5_db_entry *client, krb5_db_entry *server,
                          krb5_timestamp authtime, krb5_error_code error_code);

void krb5_db_refresh_config(krb5_context kcontext);

krb5_error_code krb5_db_check_allowed_to_delegate(krb5_context kcontext,
                                                  krb5_const_principal client,
                                                  const krb5_db_entry *server,
                                                  krb5_const_principal proxy);

krb5_error_code krb5_db_get_s4u_x509_principal(krb5_context kcontext,
                                               const krb5_data *client_cert,
                                               krb5_const_principal in_princ,
                                               unsigned int flags,
                                               krb5_db_entry **entry);

/**
 * Sort an array of @a krb5_key_data keys in descending order by their kvno.
 * Key data order within a kvno is preserved.
 *
 * @param key_data
 *     The @a krb5_key_data array to sort.  This is sorted in place so the
 *     array will be modified.
 * @param key_data_length
 *     The length of @a key_data.
 */
void
krb5_dbe_sort_key_data(krb5_key_data *key_data, size_t key_data_length);

/* default functions. Should not be directly called */
/*
 *   Default functions prototype
 */

krb5_error_code
krb5_dbe_def_search_enctype( krb5_context kcontext,
                             krb5_db_entry *dbentp,
                             krb5_int32 *start,
                             krb5_int32 ktype,
                             krb5_int32 stype,
                             krb5_int32 kvno,
                             krb5_key_data **kdatap);

krb5_error_code
krb5_def_store_mkey_list( krb5_context context,
                          char *keyfile,
                          krb5_principal mname,
                          krb5_keylist_node *keylist,
                          char *master_pwd);

krb5_error_code
krb5_db_def_fetch_mkey( krb5_context   context,
                        krb5_principal mname,
                        krb5_keyblock *key,
                        krb5_kvno     *kvno,
                        char          *db_args);

krb5_error_code
krb5_def_fetch_mkey_list( krb5_context            context,
                          krb5_principal        mprinc,
                          const krb5_keyblock  *mkey,
                          krb5_keylist_node  **mkeys_list);

krb5_error_code
krb5_dbe_def_cpw( krb5_context    context,
                  krb5_keyblock       * master_key,
                  krb5_key_salt_tuple   * ks_tuple,
                  int                     ks_tuple_count,
                  char          * passwd,
                  int                     new_kvno,
                  krb5_boolean    keepold,
                  krb5_db_entry * db_entry);

krb5_error_code
krb5_dbe_def_decrypt_key_data( krb5_context             context,
                               const krb5_keyblock    * mkey,
                               const krb5_key_data    * key_data,
                               krb5_keyblock          * dbkey,
                               krb5_keysalt           * keysalt);

krb5_error_code
krb5_dbe_def_encrypt_key_data( krb5_context             context,
                               const krb5_keyblock    * mkey,
                               const krb5_keyblock    * dbkey,
                               const krb5_keysalt     * keysalt,
                               int                      keyver,
                               krb5_key_data          * key_data);

krb5_error_code
krb5_db_def_rename_principal( krb5_context kcontext,
                              krb5_const_principal source,
                              krb5_const_principal target);

krb5_error_code
krb5_db_create_policy( krb5_context kcontext,
                       osa_policy_ent_t policy);

krb5_error_code
krb5_db_get_policy ( krb5_context kcontext,
                     char *name,
                     osa_policy_ent_t *policy );

krb5_error_code
krb5_db_put_policy( krb5_context kcontext,
                    osa_policy_ent_t policy);

krb5_error_code
krb5_db_iter_policy( krb5_context kcontext,
                     char *match_entry,
                     osa_adb_iter_policy_func func,
                     void *data);

krb5_error_code
krb5_db_delete_policy( krb5_context kcontext,
                       char *policy);

void
krb5_db_free_policy( krb5_context kcontext,
                     osa_policy_ent_t policy);


krb5_error_code
krb5_db_set_context(krb5_context, void *db_context);

krb5_error_code
krb5_db_get_context(krb5_context, void **db_context);

void
krb5_dbe_free_key_data_contents(krb5_context, krb5_key_data *);

void
krb5_dbe_free_key_list(krb5_context, krb5_keylist_node *);

void
krb5_dbe_free_actkvno_list(krb5_context, krb5_actkvno_node *);

void
krb5_dbe_free_mkey_aux_list(krb5_context, krb5_mkey_aux_node *);

void
krb5_dbe_free_tl_data(krb5_context, krb5_tl_data *);

void
krb5_dbe_free_strings(krb5_context, krb5_string_attr *, int count);

void
krb5_dbe_free_string(krb5_context, char *);

/*
 * Register the KDB keytab type, allowing "KDB:" to be used as a keytab name.
 * For this type to work, the context used for keytab operations must have an
 * associated database handle (via krb5_db_open()).
 */
krb5_error_code krb5_db_register_keytab(krb5_context context);

#define KRB5_KDB_DEF_FLAGS      0

#define KDB_MAX_DB_NAME                 128
#define KDB_REALM_SECTION               "realms"
#define KDB_MODULE_POINTER              "database_module"
#define KDB_MODULE_DEF_SECTION          "dbdefaults"
#define KDB_MODULE_SECTION              "dbmodules"
#define KDB_LIB_POINTER                 "db_library"
#define KDB_DATABASE_CONF_FILE          DEFAULT_SECURE_PROFILE_PATH
#define KDB_DATABASE_ENV_PROF           KDC_PROFILE_ENV

#define KRB5_KDB_OPEN_RW                0
#define KRB5_KDB_OPEN_RO                1

#define KRB5_KDB_OPT_SET_DB_NAME        0
#define KRB5_KDB_OPT_SET_LOCK_MODE      1

/*
 * This number indicates the date of the last incompatible change to the DAL.
 * The maj_ver field of the module's vtable structure must match this version.
 */
#define KRB5_KDB_DAL_MAJOR_VERSION 7

/*
 * A krb5_context can hold one database object.  Modules should use
 * krb5_db_set_context and krb5_db_get_context to store state associated with
 * the database object.
 *
 * Some module functions are mandatory for KDC operation; others are optional
 * or apply only to administrative operations.  If a function is optional, a
 * module can leave the function pointer as NULL.  Alternatively, modules can
 * return KRB5_PLUGIN_OP_NOTSUPP when asked to perform an inapplicable action.
 *
 * Some module functions have default implementations which will call back into
 * the vtable interface.  Leave these functions as NULL to use the default
 * implementations.
 *
 * The documentation in these comments describes the DAL as it is currently
 * implemented and used, not as it should be.  So if anything seems off, that
 * probably means the current state of things is off.
 *
 * Modules must allocate memory for principal entries, policy entries, and
 * other structures using an allocator compatible with malloc() as seen by
 * libkdb5 and libkrb5.  Modules may link against libkdb5 and call
 * krb5_db_alloc() to be certain that the same malloc implementation is used.
 */

typedef struct _kdb_vftabl {
    short int maj_ver;
    short int min_ver;

    /*
     * Mandatory: Invoked after the module library is loaded, when the first DB
     * using the module is opened, across all contexts.
     */
    krb5_error_code (*init_library)(void);

    /*
     * Mandatory: Invoked before the module library is unloaded, after the last
     * DB using the module is closed, across all contexts.
     */
    krb5_error_code (*fini_library)(void);

    /*
     * Mandatory: Initialize a database object.  Profile settings should be
     * read from conf_section inside KDB_MODULE_SECTION.  db_args communicates
     * command-line arguments for module-specific flags.  mode will be one of
     * KRB5_KDB_OPEN_{RW,RO} or'd with one of
     * KRB5_KDB_SRV_TYPE_{KDC,ADMIN,PASSWD,OTHER}.
     */
    krb5_error_code (*init_module)(krb5_context kcontext, char *conf_section,
                                   char **db_args, int mode);

    /*
     * Mandatory: Finalize the database object contained in a context.  Free
     * any state contained in the db_context pointer and null it out.
     */
    krb5_error_code (*fini_module)(krb5_context kcontext);

    /*
     * Optional: Initialize a database object while creating the underlying
     * database.  conf_section and db_args have the same meaning as in
     * init_module.  This function may return an error if the database already
     * exists.  Used by kdb5_util create.
     *
     * If db_args contains the value "temporary", the module should create an
     * exclusively locked side copy of the database suitable for loading in a
     * propagation from master to replica.  This side copy will later be
     * promoted with promote_db, allowing complete updates of the DB with no
     * loss in read availability.  If the module cannot comply with this
     * architecture, it should return an error.
     */
    krb5_error_code (*create)(krb5_context kcontext, char *conf_section,
                              char **db_args);

    /*
     * Optional: Destroy a database.  conf_section and db_args have the same
     * meaning as in init_module.  Used by kdb5_util destroy.  In current
     * usage, the database is destroyed while open, so the module should handle
     * that.
     */
    krb5_error_code (*destroy)(krb5_context kcontext, char *conf_section,
                               char **db_args);

    /*
     * Deprecated: No longer used as of krb5 1.10; can be removed in the next
     * DAL revision.  Modules should leave as NULL.
     */
    krb5_error_code (*get_age)(krb5_context kcontext, char *db_name,
                               time_t *age);

    /*
     * Optional: Lock the database, with semantics depending on the mode
     * argument:
     *
     * KRB5_DB_LOCKMODE_SHARED: Lock may coexist with other shared locks.
     * KRB5_DB_LOCKMODE_EXCLUSIVE: Lock may not coexist with other locks.
     * KRB5_DB_LOCKMODE_PERMANENT: Exclusive lock surviving process exit.
     *
     * Used by the "kadmin lock" command, incremental propagation, and
     * kdb5_util dump.  Incremental propagation support requires shared locks
     * to operate.  kdb5_util dump will continue unlocked if the module returns
     * KRB5_PLUGIN_OP_NOTSUPP.
     */
    krb5_error_code (*lock)(krb5_context kcontext, int mode);

    /* Optional: Release a lock created with db_lock. */
    krb5_error_code (*unlock)(krb5_context kcontext);

    /*
     * Mandatory: Set *entry to an allocated entry for the principal
     * search_for.  If the principal is not found, return KRB5_KDB_NOENTRY.
     *
     * The meaning of flags are as follows:
     *
     * KRB5_KDB_FLAG_CANONICALIZE: Set by the KDC when looking up entries for
     *     an AS or TGS request with canonicalization requested.  Determines
     *     whether the module should return out-of-realm referrals.
     *
     * KRB5_KDB_FLAG_INCLUDE_PAC: Set by the KDC during an AS request when the
     *     client requested PAC information during padata, and during most TGS
     *     requests.  Indicates that the module should include PAC information
     *     when its sign_authdata method is invoked.
     *
     * KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY: Set by the KDC when looking up the
     *     client entry in an AS request.  Affects how the module should return
     *     out-of-realm referrals.
     *
     * KRB5_KDB_FLAG_MAP_PRINCIPALS: Set by the KDC when looking up the client
     *     entry during TGS requests, except for S4U TGS requests and requests
     *     where the server entry has the KRB5_KDB_NO_AUTH_DATA_REQUIRED
     *     attribute.  Indicates that the module should map foreign principals
     *     to local principals if it supports doing so.
     *
     * KRB5_KDB_FLAG_PROTOCOL_TRANSITION: Set by the KDC when looking up the
     *     client entry during an S4U2Self TGS request.  This affects the PAC
     *     information which should be included when authorization data is
     *     generated; see the Microsoft S4U specification for details.
     *
     * KRB5_KDB_FLAG_CONSTRAINED_DELEGATION: Set by the KDC when looking up the
     *     client entry during an S4U2Proxy TGS request.  Also affects PAC
     *     generation.
     *
     * KRB5_KDB_FLAG_CROSS_REALM: Set by the KDC when looking up a client entry
     *     during a TGS request, if the client principal is not part of the
     *     realm being served.
     *
     * KRB5_KDB_FLAG_ALIAS_OK: Set by the KDC for server principal lookups and
     *     for AS request client principal lookups with canonicalization
     *     requested; also set by the admin interface.  Determines whether the
     *     module should return in-realm aliases.
     *
     * A module can return in-realm aliases if KRB5_KDB_FLAG_ALIAS_OK is set,
     * or if search_for->type is KRB5_NT_ENTERPRISE_PRINCIPAL.  To return an
     * in-realm alias, fill in a different value for entries->princ than the
     * one requested.
     *
     * A module can return out-of-realm referrals if KRB5_KDB_FLAG_CANONICALIZE
     * is set.  For AS request clients (KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY is
     * also set), the module should do so by simply filling in an out-of-realm
     * name in entries->princ and setting all other fields to NULL.  Otherwise,
     * the module should return the entry for the cross-realm TGS of the
     * referred-to realm.  For TGS referals, the module can also include
     * tl-data of type KRB5_TL_SERVER_REFERRAL containing ASN.1-encoded Windows
     * referral data as documented in draft-ietf-krb-wg-kerberos-referrals-11
     * appendix A; this will be returned to the client as encrypted padata.
     */
    krb5_error_code (*get_principal)(krb5_context kcontext,
                                     krb5_const_principal search_for,
                                     unsigned int flags,
                                     krb5_db_entry **entry);

    /*
     * Optional: Create or modify a principal entry.  db_args communicates
     * command-line arguments for module-specific flags.
     *
     * The mask field of an entry indicates the changed fields.  Mask values
     * are defined in kadmin's admin.h header.  If KADM5_PRINCIPAL is set in
     * the mask, the entry is new; otherwise it already exists.  All fields of
     * an entry are expected to contain correct values, regardless of whether
     * they are specified in the mask, so it is acceptable for a module to
     * ignore the mask and update the entire entry.
     */
    krb5_error_code (*put_principal)(krb5_context kcontext,
                                     krb5_db_entry *entry, char **db_args);

    /*
     * Optional: Delete the entry for the principal search_for.  If the
     * principal did not exist, return KRB5_KDB_NOENTRY.
     */
    krb5_error_code (*delete_principal)(krb5_context kcontext,
                                        krb5_const_principal search_for);

    /*
     * Optional with default: Rename a principal.  If the source principal does
     * not exist, return KRB5_KDB_NOENTRY.  If the target exists, return an
     * error.
     *
     * NOTE: If the module chooses to implement a custom function for renaming
     * a principal instead of using the default, then rename operations will
     * fail if iprop logging is enabled.
     */
    krb5_error_code (*rename_principal)(krb5_context kcontext,
                                        krb5_const_principal source,
                                        krb5_const_principal target);

    /*
     * Optional: For each principal entry in the database, invoke func with the
     * argments func_arg and the entry data.  If match_entry is specified, the
     * module may narrow the iteration to principal names matching that regular
     * expression; a module may alternatively ignore match_entry.
     */
    krb5_error_code (*iterate)(krb5_context kcontext,
                               char *match_entry,
                               int (*func)(krb5_pointer, krb5_db_entry *),
                               krb5_pointer func_arg, krb5_flags iterflags);

    /*
     * Optional: Create a password policy entry.  Return an error if the policy
     * already exists.
     */
    krb5_error_code (*create_policy)(krb5_context kcontext,
                                     osa_policy_ent_t policy);

    /*
     * Optional: Set *policy to the policy entry of the specified name.  If the
     * entry does not exist, return KRB5_KDB_NOENTRY.
     */
    krb5_error_code (*get_policy)(krb5_context kcontext, char *name,
                                  osa_policy_ent_t *policy);

    /*
     * Optional: Modify an existing password policy entry to match the values
     * in policy.  Return an error if the policy does not already exist.
     */
    krb5_error_code (*put_policy)(krb5_context kcontext,
                                  osa_policy_ent_t policy);

    /*
     * Optional: For each password policy entry in the database, invoke func
     * with the argments data and the entry data.  If match_entry is specified,
     * the module may narrow the iteration to policy names matching that
     * regular expression; a module may alternatively ignore match_entry.
     */
    krb5_error_code (*iter_policy)(krb5_context kcontext, char *match_entry,
                                   osa_adb_iter_policy_func func,
                                   void *data);

    /*
     * Optional: Delete the password policy entry with the name policy.  Return
     * an error if the entry does not exist.
     */
    krb5_error_code (*delete_policy)(krb5_context kcontext, char *policy);

    /*
     * Optional with default: Retrieve a master keyblock from the stash file
     * db_args, filling in *key and *kvno.  mname is the name of the master
     * principal for the realm.
     *
     * The default implementation reads the master keyblock from a keytab or
     * old-format stash file.
     */
    krb5_error_code (*fetch_master_key)(krb5_context kcontext,
                                        krb5_principal mname,
                                        krb5_keyblock *key, krb5_kvno *kvno,
                                        char *db_args);

    /*
     * Optional with default: Given a keyblock for some version of the
     * database's master key, fetch the decrypted master key values from the
     * database and store the list into *mkeys_list.  The caller will free
     * *mkeys_list using a libkdb5 function which uses the standard free()
     * function, so the module must not use a custom allocator.
     *
     * The caller may not know the version number of the master key it has, in
     * which case it will pass IGNORE_VNO.
     *
     * The default implementation ignores kvno and tries the key against the
     * current master key data and all KRB5_TL_MKEY_AUX values, which contain
     * copies of the master keys encrypted with old master keys.
     */
    krb5_error_code (*fetch_master_key_list)(krb5_context kcontext,
                                             krb5_principal mname,
                                             const krb5_keyblock *key,
                                             krb5_keylist_node **mkeys_list);

    /*
     * Optional with default: Save a list of master keyblocks, obtained from
     * fetch_master_key_list, into the stash file db_arg.  The caller will set
     * master_pwd to NULL, so the module should just ignore it.  mname is the
     * name of the master principal for the realm.
     *
     * The default implementation saves the list of master keys in a
     * keytab-format file.
     */
    krb5_error_code (*store_master_key_list)(krb5_context kcontext,
                                             char *db_arg,
                                             krb5_principal mname,
                                             krb5_keylist_node *keylist,
                                             char *master_pwd);

    /*
     * Optional with default: Starting at position *start, scan the key data of
     * a database entry for a key matching the enctype ktype, the salt type
     * stype, and the version kvno.  Store the resulting key into *kdatap and
     * set *start to the position after the key found.  If ktype is negative,
     * match any enctype.  If stype is negative, match any salt type.  If kvno
     * is zero or negative, find the most recent key version satisfying the
     * other constraints.
     */
    krb5_error_code (*dbe_search_enctype)(krb5_context kcontext,
                                          krb5_db_entry *dbentp,
                                          krb5_int32 *start, krb5_int32 ktype,
                                          krb5_int32 stype, krb5_int32 kvno,
                                          krb5_key_data **kdatap);


    /*
     * Optional with default: Change the key data for db_entry to include keys
     * derived from the password passwd in each of the specified key-salt
     * types, at version new_kvno.  Discard the old key data if keepold is not
     * set.
     *
     * The default implementation uses the keyblock master_key to encrypt each
     * new key, via the function encrypt_key_data.
     */
    krb5_error_code (*change_pwd)(krb5_context context,
                                  krb5_keyblock *master_key,
                                  krb5_key_salt_tuple *ks_tuple,
                                  int ks_tuple_count, char *passwd,
                                  int new_kvno, krb5_boolean keepold,
                                  krb5_db_entry *db_entry);

    /*
     * Optional: Promote a temporary database to be the live one.  context must
     * be initialized with an exclusively locked database created with the
     * "temporary" db_arg.  On success, the database object contained in
     * context will be finalized.
     *
     * This method is used by kdb5_util load to replace the live database with
     * minimal loss of read availability.
     */
    krb5_error_code (*promote_db)(krb5_context context, char *conf_section,
                                  char **db_args);

    /*
     * Optional with default: Decrypt the key in key_data with master keyblock
     * mkey, placing the result into dbkey.  Copy the salt from key_data, if
     * any, into keysalt.  Either dbkey or keysalt may be left unmodified on
     * successful return if key_data does not contain key or salt information.
     *
     * The default implementation expects the encrypted key (in krb5_c_encrypt
     * format) to be stored in key_data_contents[0], with length given by
     * key_data_length[0].  If key_data_ver is 2, it expects the salt to be
     * stored, unencrypted, in key_data_contents[1], with length given by
     * key_data_length[1].
     */
    krb5_error_code (*decrypt_key_data)(krb5_context kcontext,
                                        const krb5_keyblock *mkey,
                                        const krb5_key_data *key_data,
                                        krb5_keyblock *dbkey,
                                        krb5_keysalt *keysalt);

    /*
     * Optional with default: Encrypt dbkey with master keyblock mkey, placing
     * the result into key_data along with keysalt.
     *
     * The default implementation stores the encrypted key (in krb5_c_encrypt
     * format) in key_data_contents[0] and the length in key_data_length[0].
     * If keysalt is specified, it sets key_data_ver to 2, and stores the salt
     * in key_data_contents[1] and its length in key_data_length[1].  If
     * keysalt is not specified, key_data_ver is set to 1.
     */
    krb5_error_code (*encrypt_key_data)(krb5_context kcontext,
                                        const krb5_keyblock *mkey,
                                        const krb5_keyblock *dbkey,
                                        const krb5_keysalt *keysalt,
                                        int keyver, krb5_key_data *key_data);

    /*
     * Optional: Generate signed authorization data, such as a Windows PAC, for
     * the ticket to be returned to the client.  Place the signed authorization
     * data, if any, in *signed_auth_data.  This function will be invoked for
     * an AS request if the client included padata requesting a PAC.  This
     * function will be invoked for a TGS request if there is authorization
     * data in the TGT, if the client is from another realm, or if the TGS
     * request is an S4U2Self or S4U2Proxy request.  This function will not be
     * invoked during TGS requests if the server principal has the
     * no_auth_data_required attribute set.  Input parameters are:
     *
     *   flags: The flags used to look up the client principal.
     *
     *   client_princ: For S4U2Self and S4U2Proxy TGS requests, the client
     *     principal requested by the service; for regular TGS requests, the
     *     possibly-canonicalized client principal.
     *
     *   client: The DB entry of the client.  For S4U2Self, this will be the DB
     *     entry for the client principal requested by the service).
     *
     *   server: The DB entry of the service principal, or of a cross-realm
     *     krbtgt principal in case of referral.
     *
     *   krbtgt: For TGS requests, the DB entry of the server of the ticket in
     *     the PA-TGS-REQ padata; this is usually a local or cross-realm krbtgt
     *     principal, but not always.  For AS requests, the DB entry of the
     *     service principal; this is usually a local krbtgt principal, but not
     *     always.
     *
     *   client_key: The reply key for the KDC request, before any FAST armor
     *     is applied.  For AS requests, this may be the client's long-term key
     *     or a key chosen by a preauth mechanism.  For TGS requests, this may
     *     be the subkey found in the AP-REQ or the session key of the TGT.
     *
     *   server_key: The server key used to encrypt the returned ticket.
     *
     *   krbtgt_key: For TGS requests, the key used to decrypt the ticket in
     *     the PA-TGS-REQ padata.  For AS requests, the server key used to
     *     encrypt the returned ticket.
     *
     *   session_key: The session key of the ticket being granted to the
     *     requestor.
     *
     *   authtime: The timestamp of the original client authentication time.
     *     For AS requests, this is the current time.  For TGS requests, this
     *     is the authtime of the subject ticket (TGT or S4U2Proxy evidence
     *     ticket).
     *
     *   tgt_auth_data: For TGS requests, the authorization data present in the
     *     subject ticket.  For AS requests, NULL.
     */
    krb5_error_code (*sign_authdata)(krb5_context kcontext,
                                     unsigned int flags,
                                     krb5_const_principal client_princ,
                                     krb5_db_entry *client,
                                     krb5_db_entry *server,
                                     krb5_db_entry *krbtgt,
                                     krb5_keyblock *client_key,
                                     krb5_keyblock *server_key,
                                     krb5_keyblock *krbtgt_key,
                                     krb5_keyblock *session_key,
                                     krb5_timestamp authtime,
                                     krb5_authdata **tgt_auth_data,
                                     krb5_authdata ***signed_auth_data);

    /*
     * Optional: Perform a policy check on a cross-realm ticket's transited
     * field.  Return 0 if the check authoritatively succeeds,
     * KRB5_PLUGIN_NO_HANDLE to use the core transited-checking mechanisms, or
     * another error (other than KRB5_PLUGIN_OP_NOTSUPP) if the check fails.
     */
    krb5_error_code (*check_transited_realms)(krb5_context kcontext,
                                              const krb5_data *tr_contents,
                                              const krb5_data *client_realm,
                                              const krb5_data *server_realm);

    /*
     * Optional: Perform a policy check on an AS request, in addition to the
     * standard policy checks.  Return 0 if the AS request is allowed.  If the
     * AS request is not allowed:
     *   - Place a short string literal into *status.
     *   - If desired, place data into e_data.  Any data placed here will be
     *     freed by the caller using the standard free function.
     *   - Return an appropriate error (such as KRB5KDC_ERR_POLICY).
     */
    krb5_error_code (*check_policy_as)(krb5_context kcontext,
                                       krb5_kdc_req *request,
                                       krb5_db_entry *client,
                                       krb5_db_entry *server,
                                       krb5_timestamp kdc_time,
                                       const char **status,
                                       krb5_pa_data ***e_data);

    /*
     * Optional: Perform a policy check on a TGS request, in addition to the
     * standard policy checks.  Return 0 if the TGS request is allowed.  If the
     * TGS request is not allowed:
     *   - Place a short string literal into *status.
     *   - If desired, place data into e_data.  Any data placed here will be
     *     freed by the caller using the standard free function.
     *   - Return an appropriate error (such as KRB5KDC_ERR_POLICY).
     * The input parameter ticket contains the TGT used in the TGS request.
     */
    krb5_error_code (*check_policy_tgs)(krb5_context kcontext,
                                        krb5_kdc_req *request,
                                        krb5_db_entry *server,
                                        krb5_ticket *ticket,
                                        const char **status,
                                        krb5_pa_data ***e_data);

    /*
     * Optional: This method informs the module of a successful or unsuccessful
     * AS request.
     */
    void (*audit_as_req)(krb5_context kcontext, krb5_kdc_req *request,
                         const krb5_address *local_addr,
                         const krb5_address *remote_addr,
                         krb5_db_entry *client, krb5_db_entry *server,
                         krb5_timestamp authtime, krb5_error_code error_code);

    /* Note: there is currently no method for auditing TGS requests. */

    /*
     * Optional: This method informs the module of a request to reload
     * configuration or other state (that is, the KDC received a SIGHUP).
     */
    void (*refresh_config)(krb5_context kcontext);

    /*
     * Optional: Perform a policy check on server being allowed to obtain
     * tickets from client to proxy.  (Note that proxy is the target of the
     * delegation, not the delegating service; the term "proxy" is from the
     * viewpoint of the delegating service asking another service to perform
     * some of its work in the authentication context of the client.  This
     * terminology comes from the Microsoft S4U protocol documentation.)
     * Return 0 if policy allows it, or an appropriate error (such as
     * KRB5KDC_ERR_POLICY) if not.  If this method is not implemented, all
     * S4U2Proxy delegation requests will be rejected.
     */
    krb5_error_code (*check_allowed_to_delegate)(krb5_context context,
                                                 krb5_const_principal client,
                                                 const krb5_db_entry *server,
                                                 krb5_const_principal proxy);

    /*
     * Optional: Free the e_data pointer of a database entry.  If this method
     * is not implemented, the e_data pointer in principal entries will be
     * freed with free() as seen by libkdb5.
     */
    void (*free_principal_e_data)(krb5_context kcontext, krb5_octet *e_data);

    /* End of minor version 0. */

    /*
     * Optional: get a principal entry for S4U2Self based on X509 certificate.
     *
     * If flags include KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY, princ->realm
     * indicates the request realm, but the data components should be ignored.
     * The module can return an out-of-realm client referral as it would for
     * get_principal().
     *
     * If flags does not include KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY, princ is
     * from PA-S4U-X509-USER.  If it contains data components (and not just a
     * realm), the module should verify that it is the same as the lookup
     * result for client_cert.  The module should not return a referral.
     */
    krb5_error_code (*get_s4u_x509_principal)(krb5_context kcontext,
                                              const krb5_data *client_cert,
                                              krb5_const_principal princ,
                                              unsigned int flags,
                                              krb5_db_entry **entry_out);

    /* End of minor version 1 for major version 7. */
} kdb_vftabl;

#endif /* !defined(_WIN32) */

#endif /* KRB5_KDB5__ */
