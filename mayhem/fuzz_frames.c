/* Fuzz the QUIC frame processor: the input is a packet payload (a sequence of frames) handed to
 * xqc_process_frames() on a fresh connection. The first byte selects the packet type, the
 * connection role/state and the application protocol (HTTP/3 or raw "transport"). */
#include "harness_common.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_in.h"

static ssize_t
write_socket(const unsigned char *buf, size_t size, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *conn_user_data)
{
    (void) buf; (void) peer_addr; (void) peer_addrlen; (void) conn_user_data;
    return size;
}

static xqc_engine_t *
create_client_engine(void)
{
    xqc_engine_ssl_config_t ssl_cfg;
    memset(&ssl_cfg, 0, sizeof(ssl_cfg));
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups = XQC_TLS_GROUPS;

    xqc_engine_callback_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.log_callbacks.xqc_log_write_err = hc_null_log;
    cbs.set_event_timer = hc_null_timer;

    xqc_transport_callbacks_t tcbs;
    memset(&tcbs, 0, sizeof(tcbs));
    hc_fill_required_cbs(&tcbs);
    tcbs.write_socket = write_socket;

    xqc_engine_t *engine = xqc_engine_create(XQC_ENGINE_CLIENT, NULL, &ssl_cfg, &cbs, &tcbs, NULL);
    if (engine == NULL) {
        return NULL;
    }

    xqc_h3_callbacks_t h3_cbs = hc_h3_callbacks();
    if (xqc_h3_ctx_init(engine, &h3_cbs) != XQC_OK) {
        xqc_engine_destroy(engine);
        return NULL;
    }

    xqc_app_proto_callbacks_t transport_cbs;
    memset(&transport_cbs, 0, sizeof(transport_cbs));
    xqc_engine_register_alpn(engine, "transport", 9, &transport_cbs, NULL);
    return engine;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) {
        return -1;
    }

    uint8_t mode = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    xqc_engine_t *engine = create_client_engine();
    if (engine == NULL) {
        return 0;
    }

    xqc_conn_settings_t settings;
    memset(&settings, 0, sizeof(settings));
    settings.proto_version = XQC_VERSION_V1;
    xqc_conn_ssl_config_t conn_ssl;
    memset(&conn_ssl, 0, sizeof(conn_ssl));

    const xqc_cid_t *cid;
    if (mode & 0x08) {
        cid = xqc_connect(engine, &settings, NULL, 0, "", 0, &conn_ssl, NULL, 0, "transport", NULL);
    } else {
        cid = xqc_h3_connect(engine, &settings, NULL, 0, "", 0, &conn_ssl, NULL, 0, NULL);
    }
    xqc_connection_t *conn = cid ? xqc_engine_conns_hash_find(engine, cid, 's') : NULL;
    if (conn == NULL) {
        xqc_engine_destroy(engine);
        return 0;
    }

    static const xqc_pkt_type_t pkt_types[4] = {
        XQC_PTYPE_INIT, XQC_PTYPE_0RTT, XQC_PTYPE_HSK, XQC_PTYPE_SHORT_HEADER
    };

    if (mode & 0x04) {
        conn->conn_state = XQC_CONN_STATE_ESTABED;
        conn->conn_flag |= XQC_CONN_FLAG_HANDSHAKE_COMPLETED | XQC_CONN_FLAG_HANDSHAKE_CONFIRMED
                           | XQC_CONN_FLAG_CAN_SEND_1RTT;
    }
    if (mode & 0x10) {
        conn->conn_type = XQC_CONN_TYPE_SERVER;
    }

    unsigned char *buf = malloc(payload_len);
    if (buf == NULL) {
        xqc_engine_destroy(engine);
        return 0;
    }
    memcpy(buf, payload, payload_len);

    xqc_packet_in_t pi;
    memset(&pi, 0, sizeof(pi));
    pi.pi_pkt.pkt_type = pkt_types[mode & 3];
    pi.pi_pkt.pkt_num = 1;
    pi.pos = buf;
    pi.last = buf + payload_len;
    xqc_process_frames(conn, &pi);

    free(buf);
    xqc_engine_destroy(engine);
    return 0;
}
