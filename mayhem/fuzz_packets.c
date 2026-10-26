/* Fuzz the whole receive path of an xquic server with a real in-process client.
 *
 * First input byte, bits 0-1 pick the scenario:
 *   0  the rest is a raw UDP datagram sent to a fresh server (header parsing, version
 *      negotiation, retry, stateless reset, initial decryption failures, ...)
 *   1  the client's genuine first Initial reaches the server, then the rest is used as the frames
 *      of a correctly protected Initial packet from the client
 *   2  one round trip later: the rest is the frames of a protected Handshake packet
 *   3  after the handshake completed: the rest is the frames of a protected 1-RTT packet
 * bit 2 selects HTTP/3 (0) or the bare "transport" application protocol (1) on both ends.
 * Frames are protected with the client's real keys through xquic's own packet encryption, so
 * the fuzzed bytes reach xqc_process_frames(), HTTP/3 and QPACK on the server.
 */
#include "harness_common.h"
#include "harness_cert.h"
#include <sys/time.h>
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_parser.h"

static xqc_usec_t
now_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (xqc_usec_t) tv.tv_sec * 1000000 + tv.tv_usec;
}

#define MAX_QUEUED   32
#define MAX_FRAMES   1300
#define MAX_ROUNDS   12

typedef struct {
    unsigned char  *buf[MAX_QUEUED];
    size_t          len[MAX_QUEUED];
    int             n;
} dgram_queue_t;

static dgram_queue_t g_client_out, g_server_out;
static xqc_cid_t g_server_cid;
static int g_server_cid_set;

static void
queue_push(dgram_queue_t *q, const unsigned char *buf, size_t len)
{
    if (q->n >= MAX_QUEUED) {
        return;
    }
    q->buf[q->n] = malloc(len);
    if (q->buf[q->n] == NULL) {
        return;
    }
    memcpy(q->buf[q->n], buf, len);
    q->len[q->n++] = len;
}

static void
queue_clear(dgram_queue_t *q)
{
    for (int i = 0; i < q->n; i++) {
        free(q->buf[i]);
    }
    q->n = 0;
}

static ssize_t
client_write(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    (void) peer_addr; (void) peer_addrlen; (void) conn_user_data;
    queue_push(&g_client_out, buf, size);
    return size;
}

static ssize_t
server_write(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    (void) peer_addr; (void) peer_addrlen; (void) conn_user_data;
    queue_push(&g_server_out, buf, size);
    return size;
}

static int
server_h3_conn_create(xqc_h3_conn_t *h3c, const xqc_cid_t *cid, void *user_data)
{
    (void) h3c; (void) user_data;
    g_server_cid = *cid;
    g_server_cid_set = 1;
    return 0;
}

static int
server_transport_conn_create(xqc_connection_t *conn, const xqc_cid_t *cid, void *user_data,
    void *proto_data)
{
    (void) conn; (void) user_data; (void) proto_data;
    g_server_cid = *cid;
    g_server_cid_set = 1;
    return 0;
}

static char *
write_tmp(const char *content, char *name_tpl)
{
    const char *dir = getenv("TMPDIR");
    snprintf(name_tpl, 256, "%s/xqfuzz-XXXXXX", (dir && *dir) ? dir : "/tmp");
    int fd = mkstemp(name_tpl);
    if (fd < 0) {
        return NULL;
    }
    size_t len = strlen(content);
    ssize_t w = write(fd, content, len);
    close(fd);
    return (w == (ssize_t) len) ? name_tpl : NULL;
}

static xqc_engine_t *
create_engine(xqc_engine_type_t type, int use_h3, xqc_transport_callbacks_t *tcbs)
{
    xqc_engine_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    char key_path[256], cert_path[256];
    key_path[0] = cert_path[0] = '\0';
    if (type == XQC_ENGINE_SERVER) {
        if (write_tmp(HC_KEY_PEM, key_path) == NULL || write_tmp(HC_CERT_PEM, cert_path) == NULL) {
            if (key_path[0]) { unlink(key_path); }
            return NULL;
        }
        ssl_cfg.private_key_file = key_path;
        ssl_cfg.cert_file = cert_path;
    }

    xqc_engine_callback_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.log_callbacks.xqc_log_write_err = hc_null_log;
    cbs.set_event_timer = hc_null_timer;

    /* The server default sizes its connection hash tables for 1M buckets; that costs ~50 ms per
     * engine, so ask for small tables. Zero fields keep their defaults. */
    xqc_config_t small_cfg;
    memset(&small_cfg, 0, sizeof(small_cfg));
    small_cfg.conns_hash_bucket_size = 1024;
    small_cfg.conns_active_pq_capacity = 128;
    small_cfg.conns_wakeup_pq_capacity = 128;

    xqc_engine_t *engine = xqc_engine_create(type, &small_cfg, &ssl_cfg, &cbs, tcbs, NULL);
    if (key_path[0]) { unlink(key_path); }
    if (cert_path[0]) { unlink(cert_path); }
    if (engine == NULL) {
        return NULL;
    }

    if (use_h3) {
        xqc_h3_callbacks_t h3_cbs = hc_h3_callbacks();
        if (type == XQC_ENGINE_SERVER) {
            h3_cbs.h3c_cbs.h3_conn_create_notify = server_h3_conn_create;
        }
        if (xqc_h3_ctx_init(engine, &h3_cbs) != XQC_OK) {
            xqc_engine_destroy(engine);
            return NULL;
        }
    } else {
        xqc_app_proto_callbacks_t cbs_t;
        memset(&cbs_t, 0, sizeof(cbs_t));
        if (type == XQC_ENGINE_SERVER) {
            cbs_t.conn_cbs.conn_create_notify = server_transport_conn_create;
        }
        xqc_engine_register_alpn(engine, "transport", 9, &cbs_t, NULL);
    }
    return engine;
}

static struct sockaddr_in g_cli_addr, g_srv_addr;

static void
deliver(xqc_engine_t *to, dgram_queue_t *q, struct sockaddr_in *local, struct sockaddr_in *peer)
{
    dgram_queue_t snapshot = *q;
    q->n = 0;
    for (int i = 0; i < snapshot.n; i++) {
        xqc_engine_packet_process(to, snapshot.buf[i], snapshot.len[i],
                                  (struct sockaddr *) local, sizeof(*local),
                                  (struct sockaddr *) peer, sizeof(*peer), now_us(), NULL);
        free(snapshot.buf[i]);
    }
    xqc_engine_finish_recv(to);
}

static int
handshake_done(xqc_connection_t *c)
{
    return c != NULL && c->conn_state >= XQC_CONN_STATE_ESTABED;
}

/* One flight in each direction; returns when both ends consider the handshake done. */
static void
pump(xqc_engine_t *cli, xqc_engine_t *srv, xqc_connection_t *cconn, int rounds, int until_done)
{
    for (int i = 0; i < rounds; i++) {
        deliver(srv, &g_client_out, &g_srv_addr, &g_cli_addr);
        xqc_engine_main_logic(srv);
        deliver(cli, &g_server_out, &g_cli_addr, &g_srv_addr);
        xqc_engine_main_logic(cli);
        if (until_done && handshake_done(cconn) && g_client_out.n == 0 && g_server_out.n == 0) {
            break;
        }
    }
}

static void
send_protected(xqc_engine_t *srv, xqc_connection_t *cconn, xqc_pkt_type_t type,
    const uint8_t *frames, size_t frames_len)
{
    xqc_packet_out_t *po = xqc_packet_out_create(2048);
    if (po == NULL) {
        return;
    }

    xqc_cid_t *dcid = &cconn->dcid_set.current_dcid;
    xqc_cid_t *scid = &cconn->scid_set.user_scid;
    po->po_pkt.pkt_type = type;
    po->po_pkt.pkt_num = 1000;
    po->po_path_id = 0;

    ssize_t hdr;
    if (type == XQC_PTYPE_SHORT_HEADER) {
        hdr = xqc_gen_short_packet_header(po, dcid->cid_buf, dcid->cid_len, XQC_PKTNO_BITS, 1000, 0);
    } else {
        hdr = xqc_gen_long_packet_header(po, dcid->cid_buf, dcid->cid_len,
                                         scid->cid_buf, scid->cid_len, NULL, 0,
                                         XQC_VERSION_V1, XQC_PKTNO_BITS);
    }
    if (hdr <= 0) {
        xqc_packet_out_destroy(po);
        return;
    }

    /* Pad so header protection has a sample and Initials reach the 1200-byte minimum. */
    size_t min_total = (type == XQC_PTYPE_INIT) ? 1200 - 16 : 48;
    size_t payload_len = frames_len;
    if ((size_t) hdr + payload_len < min_total) {
        payload_len = min_total - hdr;
    }
    if ((size_t) hdr + payload_len > 1400) {
        payload_len = 1400 - hdr;
    }
    memset(po->po_buf + hdr, 0, payload_len);
    memcpy(po->po_buf + hdr, frames, frames_len < payload_len ? frames_len : payload_len);
    po->po_used_size = hdr + payload_len;

    unsigned char enc[2048];
    size_t enc_len = 0;
    if (xqc_packet_encrypt_buf(cconn, po, enc, sizeof(enc), &enc_len) == XQC_OK) {
        xqc_engine_packet_process(srv, enc, enc_len,
                                  (struct sockaddr *) &g_srv_addr, sizeof(g_srv_addr),
                                  (struct sockaddr *) &g_cli_addr, sizeof(g_cli_addr),
                                  now_us(), NULL);
        xqc_engine_finish_recv(srv);
        xqc_engine_main_logic(srv);
    }
    xqc_packet_out_destroy(po);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return -1;
    }

    uint8_t mode = data[0];
    const uint8_t *body = data + 1;
    size_t body_len = size - 1;
    int scenario = mode & 3;
    int use_h3 = !(mode & 4);

    memset(&g_cli_addr, 0, sizeof(g_cli_addr));
    memset(&g_srv_addr, 0, sizeof(g_srv_addr));
    g_cli_addr.sin_family = g_srv_addr.sin_family = AF_INET;
    g_cli_addr.sin_addr.s_addr = htonl(0x7f000001);
    g_srv_addr.sin_addr.s_addr = htonl(0x7f000001);
    g_cli_addr.sin_port = htons(40000);
    g_srv_addr.sin_port = htons(4433);
    g_server_cid_set = 0;

    xqc_transport_callbacks_t stcbs, ctcbs;
    memset(&stcbs, 0, sizeof(stcbs));
    memset(&ctcbs, 0, sizeof(ctcbs));
    hc_fill_required_cbs(&stcbs);
    hc_fill_required_cbs(&ctcbs);
    stcbs.write_socket = server_write;
    ctcbs.write_socket = client_write;

    xqc_engine_t *srv = create_engine(XQC_ENGINE_SERVER, use_h3, &stcbs);
    if (srv == NULL) {
        return 0;
    }

    if (scenario == 0) {
        xqc_engine_packet_process(srv, body, body_len,
                                  (struct sockaddr *) &g_srv_addr, sizeof(g_srv_addr),
                                  (struct sockaddr *) &g_cli_addr, sizeof(g_cli_addr),
                                  now_us(), NULL);
        xqc_engine_finish_recv(srv);
        xqc_engine_main_logic(srv);
        goto out_server;
    }

    xqc_engine_t *cli = create_engine(XQC_ENGINE_CLIENT, use_h3, &ctcbs);
    if (cli == NULL) {
        goto out_server;
    }

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl;
    memset(&conn_ssl, 0, sizeof(conn_ssl));

    const xqc_cid_t *ccid;
    if (use_h3) {
        ccid = xqc_h3_connect(cli, &settings, NULL, 0, "test.xquic.com", 0, &conn_ssl,
                              (struct sockaddr *) &g_srv_addr, sizeof(g_srv_addr), NULL);
    } else {
        ccid = xqc_connect(cli, &settings, NULL, 0, "test.xquic.com", 0, &conn_ssl,
                           (struct sockaddr *) &g_srv_addr, sizeof(g_srv_addr), "transport", NULL);
    }
    xqc_connection_t *cconn = ccid ? xqc_engine_conns_hash_find(cli, ccid, 's') : NULL;
    if (cconn == NULL) {
        goto out_client;
    }

    xqc_pkt_type_t type = XQC_PTYPE_INIT;
    if (scenario == 1) {
        /* only the client's first Initial reaches the server: it now holds the Initial keys */
        deliver(srv, &g_client_out, &g_srv_addr, &g_cli_addr);
        xqc_engine_main_logic(srv);
        queue_clear(&g_server_out);

    } else if (scenario == 2) {
        pump(cli, srv, cconn, 1, 0);
        type = XQC_PTYPE_HSK;

    } else {
        pump(cli, srv, cconn, MAX_ROUNDS, 1);
        type = XQC_PTYPE_SHORT_HEADER;
    }

    if (body_len > MAX_FRAMES) {
        body_len = MAX_FRAMES;
    }
    send_protected(srv, cconn, type, body, body_len);

out_client:
    xqc_engine_destroy(cli);
out_server:
    xqc_engine_destroy(srv);
    queue_clear(&g_client_out);
    queue_clear(&g_server_out);
    return 0;
}
