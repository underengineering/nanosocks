#ifndef NANOSOCKS_PROTOCOL_H
#define NANOSOCKS_PROTOCOL_H

#include <stdint.h>

enum Socks5AuthMethod {
    AUTH_METHOD_NO_AUTH   = 0x00,
    AUTH_METHOD_USER_PASS = 0x02,
};

enum Socks5Command {
    SOCKS5_CMD_TCP_STREAM = 0x01,
    SOCKS5_CMD_TCP_ASSOC  = 0x02,
    SOCKS5_CMD_UDP_ASSOC  = 0x03
};

enum Socks5AddressType {
    SOCKS5_ADDR_IPV4   = 0x01,
    SOCKS5_ADDR_DOMAIN = 0x03,
    SOCKS5_ADDR_IPV6   = 0x04,
};

enum Socks5Status {
    SOCKS5_STATUS_REQUEST_GRANTED        = 0x00,
    SOCKS5_STATUS_GENERAL_FAILURE        = 0x01,
    SOCKS5_STATUS_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS5_STATUS_NETWORK_UNREACHABLE    = 0x03,
    SOCKS5_STATUS_HOST_UNREACHABLE       = 0x04,
    SOCKS5_STATUS_CONNECTION_REFUSED     = 0x05,
    SOCKS5_STATUS_TTL_EXPIRED            = 0x06,
    SOCKS5_STATUS_COMMAND_NOT_SUPPORTED  = 0x07,
    SOCKS5_STATUS_ADDRESS_NOT_SUPPORTED  = 0x08,
};

struct Socks5ConnRequestHeader {
    uint8_t version;
    uint8_t command;
    uint8_t reserved;
    uint8_t address_type;
};

#endif
