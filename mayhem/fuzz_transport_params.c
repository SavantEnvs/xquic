/* Fuzz QUIC transport-parameter decoding (peer's TLS extension) and the stored 0-RTT text form. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <xquic/xquic.h>
#include "src/transport/xqc_transport_params.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return -1;
    }

    uint8_t mode = data[0];
    const uint8_t *in = data + 1;
    size_t in_len = size - 1;

    xqc_transport_params_t params;
    memset(&params, 0, sizeof(params));

    if (mode & 0x80) {
        char *text = malloc(in_len + 1);
        if (text == NULL) {
            return 0;
        }
        memcpy(text, in, in_len);
        text[in_len] = '\0';
        xqc_read_transport_params(text, in_len, &params);
        free(text);
        return 0;
    }

    xqc_transport_params_type_t type = (mode & 1) ? XQC_TP_TYPE_ENCRYPTED_EXTENSIONS
                                                  : XQC_TP_TYPE_CLIENT_HELLO;
    if (xqc_decode_transport_params(&params, type, in, in_len) != XQC_OK) {
        return 0;
    }

    uint8_t out[XQC_MAX_TRANSPORT_PARAM_BUF_LEN];
    size_t out_len = 0;
    xqc_encode_transport_params(&params, type, out, sizeof(out), &out_len);

    char text[1024];
    xqc_write_transport_params(text, sizeof(text), &params);
    return 0;
}
