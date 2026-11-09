/* Shared in-process engine plumbing for the xquic harnesses: null I/O callbacks, an HTTP/3
 * context whose request callback drains headers+body (so the QPACK/H3 decode paths run). */
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"

static void
hc_null_log(xqc_log_level_t lvl, const void *buf, size_t count, void *user_data)
{
    (void) lvl; (void) buf; (void) count; (void) user_data;
}

static void
hc_null_timer(xqc_msec_t wake_after, void *engine_user_data)
{
    (void) wake_after; (void) engine_user_data;
}

/* The no-op versions of the callbacks xquic documents as REQUIRED (it calls them unconditionally). */
static void hc_save_token(const unsigned char *t, uint32_t n, void *u) { (void) t; (void) n; (void) u; }
static void hc_save_string(const char *d, size_t n, void *u) { (void) d; (void) n; (void) u; }
static void hc_update_cid(xqc_connection_t *c, const xqc_cid_t *r, const xqc_cid_t *n, void *u)
{
    (void) c; (void) r; (void) n; (void) u;
}
static int
hc_cert_verify(const unsigned char *certs[], const size_t cert_len[], size_t certs_len, void *u)
{
    (void) certs; (void) cert_len; (void) certs_len; (void) u;
    return 0;
}
static int
hc_server_accept(xqc_engine_t *e, xqc_connection_t *c, const xqc_cid_t *cid, void *u)
{
    (void) e; (void) c; (void) cid; (void) u;
    return 0;
}
static void
hc_server_refuse(xqc_engine_t *e, xqc_connection_t *c, const xqc_cid_t *cid, void *u)
{
    (void) e; (void) c; (void) cid; (void) u;
}
static void
hc_fill_required_cbs(xqc_transport_callbacks_t *t)
{
    t->save_token = hc_save_token;
    t->save_session_cb = hc_save_string;
    t->save_tp_cb = hc_save_string;
    t->cert_verify_cb = hc_cert_verify;
    t->conn_update_cid_notify = hc_update_cid;
    t->server_accept = hc_server_accept;
    t->server_refuse = hc_server_refuse;
}

static int
hc_h3_req_create(xqc_h3_request_t *req, void *user_data)
{
    (void) req; (void) user_data;
    return 0;
}

static int
hc_h3_req_close(xqc_h3_request_t *req, void *user_data)
{
    (void) req; (void) user_data;
    return 0;
}

static int
hc_h3_req_read(xqc_h3_request_t *req, xqc_request_notify_flag_t flag, void *user_data)
{
    uint8_t fin = 0;
    unsigned char buf[4096];
    (void) user_data;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        xqc_h3_request_recv_headers(req, &fin);
    }
    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        ssize_t n;
        do {
            n = xqc_h3_request_recv_body(req, buf, sizeof(buf), &fin);
        } while (n > 0 && !fin);
    }
    if (flag & XQC_REQ_NOTIFY_READ_TRAILER) {
        xqc_h3_request_recv_headers(req, &fin);
    }
    return 0;
}

static int
hc_h3_req_write(xqc_h3_request_t *req, void *user_data)
{
    (void) req; (void) user_data;
    return 0;
}

static xqc_h3_callbacks_t
hc_h3_callbacks(void)
{
    xqc_h3_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.h3r_cbs.h3_request_create_notify = hc_h3_req_create;
    cbs.h3r_cbs.h3_request_close_notify = hc_h3_req_close;
    cbs.h3r_cbs.h3_request_read_notify = hc_h3_req_read;
    cbs.h3r_cbs.h3_request_write_notify = hc_h3_req_write;
    return cbs;
}

#endif
