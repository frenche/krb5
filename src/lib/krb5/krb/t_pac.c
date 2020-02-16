/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "k5-int.h"
#include "t_pac.h"

#if !defined(__cplusplus) && (__GNUC__ > 2)
static void err(krb5_context ctx, krb5_error_code code, const char *fmt, ...)
    __attribute__((__format__(__printf__, 3, 0)));
#endif

static void
err(krb5_context ctx, krb5_error_code code, const char *fmt, ...)
{
    va_list ap;
    char *msg;
    const char *errmsg = NULL;

    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0)
        exit(1);
    va_end(ap);
    if (ctx && code)
        errmsg = krb5_get_error_message(ctx, code);
    if (errmsg)
        fprintf(stderr, "t_pac: %s: %s\n", msg, errmsg);
    else
        fprintf(stderr, "t_pac: %s\n", msg);
    exit(1);
}

static krb5_error_code
check_marshalled(krb5_data data, krb5_data marshalled)
{
    if (marshalled.length < data.length)
        return ERANGE;

    return memcmp(marshalled.data, data.data, data.length);
}

static void
check_pac(krb5_context context, const struct pac_and_info *p,
          const krb5_keyblock *server_key, const krb5_keyblock *kdc_key)
{
    krb5_error_code ret;
    krb5_principal princ;
    krb5_data data, marshalled;
    krb5_pac pac;

    if (p->is_enterprise) {
        ret = krb5_parse_name_flags(context, p->principal,
                                    KRB5_PRINCIPAL_PARSE_ENTERPRISE, &princ);
        if (ret)
            err(context, ret, "krb5_parse_name_flags");
    } else {
        ret = krb5_parse_name(context, p->principal, &princ);
        if (ret)
            err(context, ret, "krb5_parse_name");
    }

    ret = krb5_pac_parse(context, p->data, p->length, &pac);
    if (ret)
        err(context, ret, "[pac: %s] krb5_pac_parse", p->pac_name);

    ret = krb5_pac_verify_ext(context, pac, p->authtime, princ, server_key,
                              kdc_key, p->is_xrealm);
    if (ret)
        err(context, ret, "[pac: %s] krb5_pac_verify_ext", p->pac_name);

    /* If we don't have the KDC key (S4U cases),
     * skip the KDC signature when verifying. */
    if (kdc_key != NULL) {
        ret = krb5_pac_sign_ext(context, pac, p->authtime, princ, server_key,
                                kdc_key, p->is_xrealm, &data);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_sign_ext", p->pac_name);

        krb5_pac_free(context, pac);

        ret = krb5_pac_parse(context, data.data, data.length, &pac);
        krb5_free_data_contents(context, &data);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_parse 2", p->pac_name);

        ret = krb5_pac_verify_ext(context, pac, p->authtime, princ, server_key,
                                  kdc_key, p->is_xrealm);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_verify_ext 2", p->pac_name);
    }

    /* make a copy and try to reproduce it */
    {
        uint32_t *list;
        size_t len, i;
        krb5_pac pac2;

        ret = krb5_pac_init(context, &pac2);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_init", p->pac_name);

        /* our two user buffer plus the three "system" buffers */
        ret = krb5_pac_get_types(context, pac, &len, &list);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_get_types", p->pac_name);

        for (i = 0; i < len; i++) {
            /* skip server_cksum, privsvr_cksum, and logon_name */
            if (list[i] == 6 || list[i] == 7 || list[i] == 10)
                continue;

            ret = krb5_pac_get_buffer(context, pac, list[i], &data);
            if (ret)
                err(context, ret, "[pac: %s] krb5_pac_get_buffer", p->pac_name);

            if (list[i] == 1) {
                struct kerb_validation_info logon_info;

                ret = krb5_pac_get_logon_info(context, pac, &logon_info);
                if (ret)
                    err(context, ret, "krb5_pac_get_logon_info");

                ret = krb5_marshal_pac_logon_info(context, logon_info, &marshalled);
                if (ret)
                    err(context, ret, "krb5_marshal_pac_logon_info");

                //free_pac_logon_info(context, logon_info);

                ret = check_marshalled(data, marshalled);
                if (ret)
                    err(context, ret, "marshal mismatch");

                if (p->type_length != data.length) {
                    err(context, 0, "[pac: %s] type 1 have wrong length: %lu",
                        p->pac_name, (unsigned long)data.length);
                }
            } else if (list[i] == 11) {
                struct delegation_info deleg_info;

                ret = krb5_pac_get_delegation_info(context, pac, &deleg_info);
                if (ret)
                    err(context, ret, "krb5_pac_get_delegation_info");

                ret = krb5_marshal_pac_delegation_info(context, deleg_info, &marshalled);
                if (ret)
                    err(context, ret, "krb5_marshal_pac_delegation_info");

                //free_pac_delegation_info(context, deleg_info);

                ret = check_marshalled(data, marshalled);
                if (ret)
                    err(context, ret, "Marshalled length too short");

            } else if (list[i] == 12) {
                struct upn_dns_info upn_info;

                ret = krb5_pac_get_upn_dns_info(context, pac, &upn_info);
                if (ret)
                    err(context, ret, "krb5_pac_get_upn_dns_info");

                ret = krb5_marshal_pac_upn_dns_info(context, upn_info, &marshalled);
                if (ret)
                    err(context, ret, "krb5_marshal_pac_upn_dns_info");

                //free_pac_upn_dns_info(context, upn_info);

                ret = check_marshalled(data, marshalled);
                if (ret)
                    err(context, ret, "Marshalled length too short");

            } else {
                err(context, 0, "[pac: %s] unknown type %lu",
                    p->pac_name, (unsigned long)list[i]);
            }

            krb5_free_data_contents(context, &marshalled);

            ret = krb5_pac_add_buffer(context, pac2, list[i], &data);
            if (ret)
                err(context, ret, "[pac: %s] krb5_pac_add_buffer", p->pac_name);
            krb5_free_data_contents(context, &data);
        }
        free(list);

        if (kdc_key == NULL)
            kdc_key = server_key;

        ret = krb5_pac_sign_ext(context, pac2, p->authtime, princ, server_key,
                                kdc_key, p->is_xrealm, &data);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_sign_ext 4", p->pac_name);

        krb5_pac_free(context, pac2);

        ret = krb5_pac_parse(context, data.data, data.length, &pac2);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_parse 4", p->pac_name);

        ret = krb5_pac_verify_ext(context, pac2, p->authtime, princ, server_key,
                                  kdc_key, p->is_xrealm);
        if (ret)
            err(context, ret, "[pac: %s] krb5_pac_verify_ext 4", p->pac_name);

        krb5_free_data_contents(context, &data);

        krb5_free_principal(context, princ);
        krb5_pac_free(context, pac2);
    }

    krb5_pac_free(context, pac);
}

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_pac pac;
    krb5_data data;
    krb5_principal p;

    ret = krb5_init_context(&context);
    if (ret)
        err(NULL, 0, "krb5_init_contex");

    ret = krb5_set_default_realm(context, "WIN2K3.THINKER.LOCAL");
    if (ret)
        err(context, ret, "krb5_set_default_realm");

    ret = krb5_parse_name(context, user, &p);
    if (ret)
        err(context, ret, "krb5_parse_name");

    /* Check a pre-saved PAC. */
    check_pac(context, &reg_pac, &member_keyblock, &kdc_keyblock);

    /* Check S4U2Self PACs. */
    {
        const struct pac_and_info *pi;

        for (pi = s4u_pacs; pi->data != NULL; pi++) {
            check_pac(context, pi,
                      pi->is_xrealm ? &s4u_tgt_srv_key : &s4u_srv_key, NULL);
        }
    }

    /* Check S4U2Proxy PACs. */
    {
        const struct pac_and_info *pi;

        ret = krb5_set_default_realm(context, "ACME.COM");
        if (ret)
             err(context, ret, "krb5_set_default_realm");

        for (pi = s4u2p_pacs; pi->data != NULL; pi++) {
            check_pac(context, pi, pi->is_xrealm ? &s4u2p_xrealm_srv_key :
                      &s4u2p_local_srv_key, NULL);
        }
    }

    /*
     * Test empty free
     */

    ret = krb5_pac_init(context, &pac);
    if (ret)
        err(context, ret, "krb5_pac_init");
    krb5_pac_free(context, pac);

    /*
     * Test add remove buffer
     */

    ret = krb5_pac_init(context, &pac);
    if (ret)
        err(context, ret, "krb5_pac_init");

    {
        const krb5_data cdata = { 0, 2, "\x00\x01" } ;

        ret = krb5_pac_add_buffer(context, pac, 1, &cdata);
        if (ret)
            err(context, ret, "krb5_pac_add_buffer");
    }
    {
        ret = krb5_pac_get_buffer(context, pac, 1, &data);
        if (ret)
            err(context, ret, "krb5_pac_get_buffer");
        if (data.length != 2 || memcmp(data.data, "\x00\x01", 2) != 0)
            err(context, 0, "krb5_pac_get_buffer data not the same");
        krb5_free_data_contents(context, &data);
    }

    {
        const krb5_data cdata = { 0, 2, "\x02\x00" } ;

        ret = krb5_pac_add_buffer(context, pac, 2, &cdata);
        if (ret)
            err(context, ret, "krb5_pac_add_buffer");
    }
    {
        ret = krb5_pac_get_buffer(context, pac, 1, &data);
        if (ret)
            err(context, ret, "krb5_pac_get_buffer");
        if (data.length != 2 || memcmp(data.data, "\x00\x01", 2) != 0)
            err(context, 0, "krb5_pac_get_buffer data not the same");
        krb5_free_data_contents(context, &data);
        /* */
        ret = krb5_pac_get_buffer(context, pac, 2, &data);
        if (ret)
            err(context, ret, "krb5_pac_get_buffer");
        if (data.length != 2 || memcmp(data.data, "\x02\x00", 2) != 0)
            err(context, 0, "krb5_pac_get_buffer data not the same");
        krb5_free_data_contents(context, &data);
    }

    ret = krb5_pac_sign(context, pac, authtime, p,
                        &member_keyblock, &kdc_keyblock, &data);
    if (ret)
        err(context, ret, "krb5_pac_sign");

    krb5_pac_free(context, pac);

    ret = krb5_pac_parse(context, data.data, data.length, &pac);
    krb5_free_data_contents(context, &data);
    if (ret)
        err(context, ret, "krb5_pac_parse 3");

    ret = krb5_pac_verify(context, pac, authtime, p,
                          &member_keyblock, &kdc_keyblock);
    if (ret)
        err(context, ret, "krb5_pac_verify 3");

    {
        uint32_t *list;
        size_t len;

        /* our two user buffer plus the three "system" buffers */
        ret = krb5_pac_get_types(context, pac, &len, &list);
        if (ret)
            err(context, ret, "krb5_pac_get_types");
        if (len != 5)
            err(context, 0, "list wrong length");
        free(list);
    }

    {
        krb5_principal ep, np;

        ret = krb5_parse_name_flags(context, user,
                                    KRB5_PRINCIPAL_PARSE_ENTERPRISE, &ep);
        if (ret)
            err(context, ret, "krb5_parse_name_flags");

        ret = krb5_copy_principal(context, ep, &np);
        if (ret)
            err(context, ret, "krb5_copy_principal");
        np->type = KRB5_NT_MS_PRINCIPAL;

        /* Try to verify as enterprise. */
        ret = krb5_pac_verify(context, pac, authtime, ep, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        ret = krb5_pac_sign(context, pac, authtime, ep, &member_keyblock,
                            &kdc_keyblock, &data);
        if (!ret)
            err(context, ret, "krb5_pac_sign should have failed");

        /* Try to verify with realm. */
        ret = krb5_pac_verify_ext(context, pac, authtime, p, &member_keyblock,
                                  &kdc_keyblock, TRUE);
        if (!ret)
            err(context, ret, "krb5_pac_verify_ext with realm should fail");

        /* Currently we can't re-sign the PAC with realm (although that could
         * be useful), only sign a new one. */
        ret = krb5_pac_sign_ext(context, pac, authtime, p, &member_keyblock,
                                &kdc_keyblock, TRUE, &data);
        if (!ret)
            err(context, ret, "krb5_pac_sign_ext with realm should fail");

        krb5_pac_free(context, pac);

        /* Test enterprise. */
        ret = krb5_pac_init(context, &pac);
        if (ret)
            err(context, ret, "krb5_pac_init");

        ret = krb5_pac_sign(context, pac, authtime, ep, &member_keyblock,
                            &kdc_keyblock, &data);
        if (ret)
            err(context, ret, "krb5_pac_sign enterprise failed");

        krb5_pac_free(context, pac);

        ret = krb5_pac_parse(context, data.data, data.length, &pac);
        krb5_free_data_contents(context, &data);
        if (ret)
            err(context, ret, "krb5_pac_parse failed");

        ret = krb5_pac_verify(context, pac, authtime, ep, &member_keyblock,
                              &kdc_keyblock);
        if (ret)
            err(context, ret, "krb5_pac_verify enterprise failed");

        /* Also verify enterprise as KRB5_NT_MS_PRINCIPAL. */
        ret = krb5_pac_verify(context, pac, authtime, np, &member_keyblock,
                              &kdc_keyblock);
        if (ret)
            err(context, ret, "krb5_pac_verify enterprise as nt-ms failed");

        ret = krb5_pac_verify(context, pac, authtime, p, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        krb5_pac_free(context, pac);

        /* Test nt-ms-principal. */
        ret = krb5_pac_init(context, &pac);
        if (ret)
            err(context, ret, "krb5_pac_init");

        ret = krb5_pac_sign(context, pac, authtime, np, &member_keyblock,
                            &kdc_keyblock, &data);
        if (ret)
            err(context, ret, "krb5_pac_sign enterprise failed");

        krb5_pac_free(context, pac);

        ret = krb5_pac_parse(context, data.data, data.length, &pac);
        krb5_free_data_contents(context, &data);
        if (ret)
            err(context, ret, "krb5_pac_parse failed");

        ret = krb5_pac_verify(context, pac, authtime, np, &member_keyblock,
                              &kdc_keyblock);
        if (ret)
            err(context, ret, "krb5_pac_verify enterprise failed");

        /* Also verify as enterprise principal. */
        ret = krb5_pac_verify(context, pac, authtime, ep, &member_keyblock,
                              &kdc_keyblock);
        if (ret)
            err(context, ret, "krb5_pac_verify nt-ms as enterprise failed");

        ret = krb5_pac_verify(context, pac, authtime, p, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        krb5_pac_free(context, pac);

        /* Test with realm. */
        ret = krb5_pac_init(context, &pac);
        if (ret)
            err(context, ret, "krb5_pac_init");

        ret = krb5_pac_sign_ext(context, pac, authtime, p, &member_keyblock,
                                &kdc_keyblock, TRUE, &data);
        if (ret)
            err(context, ret, "krb5_pac_sign_ext with realm failed");

        krb5_pac_free(context, pac);

        ret = krb5_pac_parse(context, data.data, data.length, &pac);
        krb5_free_data_contents(context, &data);
        if (ret)
            err(context, ret, "krb5_pac_parse failed");

        ret = krb5_pac_verify_ext(context, pac, authtime, p, &member_keyblock,
                                  &kdc_keyblock, TRUE);
        if (ret)
            err(context, ret, "krb5_pac_verify_ext with realm failed");

        ret = krb5_pac_verify(context, pac, authtime, p, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        krb5_pac_free(context, pac);

        /* Test enterprise with realm. */
        ret = krb5_pac_init(context, &pac);
        if (ret)
            err(context, ret, "krb5_pac_init");

        ret = krb5_pac_sign_ext(context, pac, authtime, ep, &member_keyblock,
                                &kdc_keyblock, TRUE, &data);
        if (ret)
            err(context, ret, "krb5_pac_sign_ext ent with realm failed");

        krb5_pac_free(context, pac);

        ret = krb5_pac_parse(context, data.data, data.length, &pac);
        krb5_free_data_contents(context, &data);
        if (ret)
            err(context, ret, "krb5_pac_parse failed");

        ret = krb5_pac_verify_ext(context, pac, authtime, ep, &member_keyblock,
                                  &kdc_keyblock, TRUE);
        if (ret)
            err(context, ret, "krb5_pac_verify_ext ent with realm failed");

        ret = krb5_pac_verify(context, pac, authtime, p, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        ret = krb5_pac_verify(context, pac, authtime, ep, &member_keyblock,
                              &kdc_keyblock);
        if (!ret)
            err(context, ret, "krb5_pac_verify should have failed");

        ret = krb5_pac_verify_ext(context, pac, authtime, p, &member_keyblock,
                                  &kdc_keyblock, TRUE);
        if (!ret)
            err(context, ret, "krb5_pac_verify_ext should have failed");

        krb5_free_principal(context, ep);
        krb5_free_principal(context, np);
    }

    krb5_pac_free(context, pac);

    krb5_free_principal(context, p);
    krb5_free_context(context);

    return 0;
}
