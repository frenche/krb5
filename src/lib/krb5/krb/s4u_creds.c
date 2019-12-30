/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/s4u_creds.c */
/*
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

#include "k5-int.h"
#include "int-proto.h"
#include "fast.h"


/*
 * Make AS requests with the canonicalize flag set, stopping when we get a
 * message indicating which realm the client principal is in.  Set *client_out
 * to a copy of client with the canonical realm.  If subject_cert is non-null,
 * include PA_S4U_X509_USER pa-data with the subject certificate each request.
 * (See [MS-SFU] 3.1.5.1.1.1 and 3.1.5.1.1.2.)
 */

static krb5_error_code
identify_realm(krb5_context context, krb5_principal client,
               const krb5_data *subject_cert, krb5_principal *realm)
{
    krb5_error_code ret;
    krb5_get_init_creds_opt *opts = NULL;
    krb5_init_creds_context ctx = NULL;
    int use_master = 0;

    *realm = NULL;

    ret = krb5_get_init_creds_opt_alloc(context, &opts);
    if (ret)
        goto cleanup;
    krb5_get_init_creds_opt_set_tkt_life(opts, 15);
    krb5_get_init_creds_opt_set_renew_life(opts, 0);
    krb5_get_init_creds_opt_set_forwardable(opts, 0);
    krb5_get_init_creds_opt_set_proxiable(opts, 0);
    krb5_get_init_creds_opt_set_canonicalize(opts, 1);
    krb5_get_init_creds_opt_set_identify_realm(opts, 1);
    krb5_get_init_creds_opt_set_id_cert(opts, subject_cert);

    ret = krb5_init_creds_init(context, client, NULL, NULL, 0, opts, &ctx);
    if (ret)
        goto cleanup;

    ret = k5_init_creds_get(context, ctx, &use_master);
    if (ret)
        goto cleanup;

    ret = krb5_init_creds_get_req_client_realm(context, ctx, realm);

cleanup:
    krb5_get_init_creds_opt_free(context, opts);
    krb5_init_creds_free(context, ctx);
    return ret;
}

static krb5_error_code
s4u_identify_realm(krb5_context context,
                   krb5_creds *in_creds,
                   krb5_data *subject_cert,
                   krb5_principal *realm)
{
    krb5_principal_data client;
    krb5_data empty_name = empty_data();

    *realm = NULL;

    if (in_creds->client == NULL && subject_cert == NULL) {
        return EINVAL;
    }

    if (in_creds->client != NULL &&
        in_creds->client->type != KRB5_NT_ENTERPRISE_PRINCIPAL) {
        int anonymous;

        anonymous = krb5_principal_compare(context, in_creds->client,
                                           krb5_anonymous_principal());

        return krb5_copy_principal(context,
                                   anonymous ? in_creds->server
                                   : in_creds->client,
                                   realm);
    }

    if (in_creds->client != NULL) {
        client = *in_creds->client;
        client.realm = in_creds->server->realm;

        /* Don't send subject_cert if we have an enterprise principal. */
        return identify_realm(context, &client, NULL, realm);
    }

    client.magic = KV5M_PRINCIPAL;
    client.realm = in_creds->server->realm;

    /*
     * Windows clients send the certificate subject as the client name.
     * However, Windows KDC seem to be happy with an empty string as long as
     * the name-type is NT-X500-PRINCIPAL.
     */
    client.data = &empty_name;
    client.length = 1;
    client.type = KRB5_NT_X500_PRINCIPAL;

    return identify_realm(context, &client, subject_cert, realm);
}

static krb5_error_code
s4u_identify_user(krb5_context context,
                  krb5_creds *in_creds,
                  krb5_data *subject_cert,
                  krb5_principal *canon_user)
{
    krb5_error_code code;
    krb5_principal realm;

    code = s4u_identify_realm(context, in_creds, subject_cert, &realm);
    if (code)
        return code;

    if (in_creds->client == NULL) {
        *canon_user = realm;
        return 0;
    }

    code = krb5_copy_principal(context, in_creds->client, canon_user);
    if (code) {
        krb5_free_principal(context, realm);
        return code;
    }

    krb5_free_data_contents(context, &(*canon_user)->realm);
    (*canon_user)->realm = realm->realm;
    realm->realm = empty_data();
    krb5_free_principal(context, realm);

    return 0;
}

/* Unparse princ and re-parse it as an enterprise principal. */
static krb5_error_code
convert_to_enterprise(krb5_context context, krb5_principal princ,
                      krb5_principal *eprinc_out)
{
    krb5_error_code code;
    char *str;

    *eprinc_out = NULL;
    code = krb5_unparse_name(context, princ, &str);
    if (code != 0)
        return code;
    code = krb5_parse_name_flags(context, str,
                                 KRB5_PRINCIPAL_PARSE_ENTERPRISE |
                                 KRB5_PRINCIPAL_PARSE_IGNORE_REALM,
                                 eprinc_out);
    krb5_free_unparsed_name(context, str);
    return code;
}

static krb5_error_code
krb5_get_self_cred_from_kdc(krb5_context context,
                            krb5_flags options,
                            krb5_ccache ccache,
                            krb5_creds *in_creds,
                            krb5_principal impersonate,
                            krb5_data *subject_cert,
                            krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds *out = NULL;
    krb5_tkt_creds_context ctx = NULL;

    code = krb5_tkt_creds_init(context, ccache, in_creds, options, &ctx); 
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_set_impersonate(context, ctx, impersonate);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_set_impersonate_cert(context, ctx, subject_cert);
    if (code)
        goto cleanup;

    code = krb5_tkt_creds_get(context, ctx);
    if (code)
        goto cleanup;

    /* Allocate a container. */
    out = k5alloc(sizeof(krb5_creds), &code);
    if (out == NULL)
        goto cleanup;

    code = krb5_tkt_creds_get_creds(context, ctx, out);
    if (code) {
        free(out);
        goto cleanup;
    }

    *out_creds = out;   

cleanup:
    krb5_tkt_creds_free(context, ctx);
    return code;
}

krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_user(krb5_context context, krb5_flags options,
                              krb5_ccache ccache, krb5_creds *in_creds,
                              krb5_data *subject_cert,
                              krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds s4u_creds, *reply = NULL;
    krb5_principal canon = NULL;
    krb5_principal server = NULL;
    krb5_principal enterprise_server = NULL;

    *out_creds = NULL;

    if (in_creds->client != NULL) {
        /* Uncanonicalised check */
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED,
                                    ccache, in_creds, out_creds);
        if (code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
            goto cleanup;

        if ((options & KRB5_GC_CACHED) && !(options & KRB5_GC_CANONICALIZE))
            goto cleanup;
    }

    code = s4u_identify_user(context, in_creds, subject_cert, &canon);
    if (code != 0)
        goto cleanup;

    if (in_creds->client != NULL &&
        in_creds->client->type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        /* Post-canonicalisation check for enterprise principals */
        krb5_creds mcreds = *in_creds;
        mcreds.client = canon;
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED,
                                    ccache, &mcreds, &reply);
        if ((code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
            || (options & KRB5_GC_CACHED))
            goto cleanup;
    }

    server = in_creds->server;
    s4u_creds = *in_creds;
    s4u_creds.client = server;

    if (!krb5_realm_compare(context, s4u_creds.server, canon)) {
        code = convert_to_enterprise(context, s4u_creds.server,
                                     &enterprise_server);
        if (code)
            goto cleanup;

        krb5_free_data_contents(context, &enterprise_server->realm);
        code = krb5int_copy_data_contents(context, &canon->realm,
                                          &enterprise_server->realm);
        if (code)
            goto cleanup;

        s4u_creds.server = enterprise_server;
    }

    /* XXX: TEMP */
    options |= KRB5_GC_CANONICALIZE;

    code = krb5_get_self_cred_from_kdc(context, options | KRB5_GC_NO_STORE,
                                       ccache, &s4u_creds,
                                       canon, subject_cert, &reply);
    if (code != 0)
        goto cleanup;

    if (enterprise_server != NULL) {
        krb5_free_principal(context, reply->server);
        reply->server = NULL;

        code = krb5_copy_principal(context, server, &reply->server);
        if (code != 0)
            goto cleanup;
    }

    /* If we canonicalized the client name or discovered it using subject_cert,
     * check if we had cached credentials and return them if found. */
    if (in_creds->client == NULL ||
        !krb5_principal_compare(context, canon, reply->client)) {
        krb5_creds *old_creds;
        krb5_creds mcreds = *in_creds;
        mcreds.client = reply->client;
        code = krb5_get_credentials(context, options | KRB5_GC_CACHED, ccache,
                                    &mcreds, &old_creds);
        if (code == 0) {
            krb5_free_creds(context, reply);
            reply = old_creds;
            options |= KRB5_GC_NO_STORE;
        } else if (code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE) {
            goto cleanup;
        }
        code = 0;
    }

    if ((options & KRB5_GC_NO_STORE) == 0) {
        code = krb5_cc_store_cred(context, ccache, reply);
        if (code != 0)
            goto cleanup;
    }

    *out_creds = reply;
    reply = NULL;

cleanup:
    krb5_free_creds(context, reply);
    krb5_free_principal(context, canon);
    krb5_free_principal(context, enterprise_server);

    return code;
}

/*
 * Exported API for constrained delegation (S4U2Proxy).
 *
 * This is preferable to using krb5_get_credentials directly because
 * it can perform some additional checks.
 */
krb5_error_code KRB5_CALLCONV
krb5_get_credentials_for_proxy(krb5_context context,
                               krb5_flags options,
                               krb5_ccache ccache,
                               krb5_creds *in_creds,
                               krb5_ticket *evidence_tkt,
                               krb5_creds **out_creds)
{
    krb5_error_code code;
    krb5_creds mcreds;
    krb5_creds *ncreds = NULL;
    krb5_flags fields;
    krb5_data *evidence_tkt_data = NULL;
    krb5_creds s4u_creds;

    *out_creds = NULL;

    if (in_creds == NULL || in_creds->client == NULL || evidence_tkt == NULL) {
        code = EINVAL;
        goto cleanup;
    }

    /*
     * Caller should have set in_creds->client to match evidence
     * ticket client.  If we can, verify it before issuing the request.
     */
    if (evidence_tkt->enc_part2 != NULL &&
        !krb5_principal_compare(context, evidence_tkt->enc_part2->client,
                                in_creds->client)) {
        code = EINVAL;
        goto cleanup;
    }

    code = krb5int_construct_matching_creds(context, options, in_creds,
                                            &mcreds, &fields);
    if (code != 0)
        goto cleanup;

    ncreds = calloc(1, sizeof(*ncreds));
    if (ncreds == NULL) {
        code = ENOMEM;
        goto cleanup;
    }
    ncreds->magic = KV5M_CRED;

    code = krb5_cc_retrieve_cred(context, ccache, fields, &mcreds, ncreds);
    if (code != 0) {
        free(ncreds);
        ncreds = in_creds;
    } else {
        *out_creds = ncreds;
    }

    if ((code != KRB5_CC_NOTFOUND && code != KRB5_CC_NOT_KTYPE)
        || options & KRB5_GC_CACHED)
        goto cleanup;

    code = encode_krb5_ticket(evidence_tkt, &evidence_tkt_data);
    if (code != 0)
        goto cleanup;

    s4u_creds = *in_creds;
    s4u_creds.client = evidence_tkt->server;
    s4u_creds.second_ticket = *evidence_tkt_data;

    code = krb5_get_credentials(context,
                                options | KRB5_GC_CONSTRAINED_DELEGATION,
                                ccache, &s4u_creds, out_creds);
    if (code != 0)
        goto cleanup;

    /*
     * Check client name because we couldn't compare that inside
     * krb5_get_credentials() (enc_part2 is unavailable in clear)
     */
    if (!krb5_principal_compare(context, in_creds->client,
                                (*out_creds)->client)) {
        code = KRB5_KDCREP_MODIFIED;
        goto cleanup;
    }

cleanup:
    if (*out_creds != NULL && code != 0) {
        krb5_free_creds(context, *out_creds);
        *out_creds = NULL;
    }
    if (evidence_tkt_data != NULL)
        krb5_free_data(context, evidence_tkt_data);

    return code;
}
