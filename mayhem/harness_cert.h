/* Throwaway self-signed P-256 test identity for the in-process server (never used outside fuzzing). */
#ifndef MAYHEM_HARNESS_CERT_H
#define MAYHEM_HARNESS_CERT_H

static const char HC_KEY_PEM[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIPL1kUaX0MbMaQ0h/BYh3bob0XM/KVuFdqQEE7379u8RoAoGCCqGSM49\n"
    "AwEHoUQDQgAEqO6jFXfXvVX/rNpSXd/a86dvU7ep/YHLlocgO+7F60v8oWFaPt8s\n"
    "9JusqOcpZ19jR/c5JKa4lCn6WoiJFW4/zQ==\n"
    "-----END EC PRIVATE KEY-----\n";

static const char HC_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBijCCAS+gAwIBAgIUUrLK3d3RqlNSSiDp0OJFUCPUUHIwCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOdGVzdC54cXVpYy5jb20wIBcNMjYxMDI2MTcwMTM5WhgPMjEy\n"
    "NjEwMDIxNzAxMzlaMBkxFzAVBgNVBAMMDnRlc3QueHF1aWMuY29tMFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEqO6jFXfXvVX/rNpSXd/a86dvU7ep/YHLlocgO+7F\n"
    "60v8oWFaPt8s9JusqOcpZ19jR/c5JKa4lCn6WoiJFW4/zaNTMFEwHQYDVR0OBBYE\n"
    "FGON9458GHDsSkSTWw1mYgn8rUnqMB8GA1UdIwQYMBaAFGON9458GHDsSkSTWw1m\n"
    "Ygn8rUnqMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALzZUIcy\n"
    "wVj2dS0D2hyZwhOv+A+SDFTZ/mga6jknAZo1AiEAypiMYkcHdkKDapEoS0B0SGRI\n"
    "M8a17YqnnGeZS/tVIUs=\n"
    "-----END CERTIFICATE-----\n";

#endif
