//
//  server.h
//  Simple DNS server
//
//  Created by Eugeny Volobuev on 09.08.13.
//  Copyright (c) 2013 Eugeny Volobuev. All rights reserved.
//

#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <stdbool.h>

#define OPTIONS "h:p:c:?"
#define HOST "127.0.0.1"
#define PORT 8053
#define HEADER_LENGTH 12
#define IPADDR_LENGTH 4

typedef struct label {
    char *label;
    struct label *next;
} dns_labels_t;

typedef struct {
    unsigned char qr:1;
    unsigned char opcode:4;
    unsigned char aa:1;
    unsigned char tc:1;
    unsigned char rd:1;
    unsigned char ra:1;
    unsigned char z:3;
    unsigned char rcode:4;
} dns_flags_t;

typedef struct {
    unsigned short id;
    union {
        dns_flags_t flags_s;
        unsigned short flags;
    } flags;
    unsigned short qdcount, ancount, nscount, arcount;
} dns_header_t;

typedef struct {
    dns_labels_t *label;
    unsigned short qtype, qclass;
} dns_question_t;

typedef struct {
    char *cptr;
    dns_labels_t *label;
    unsigned short rtype, rclass;
    unsigned int ttl;
    unsigned short rdlength;
    char *rdata;
    bool use_compression;
} dns_record_t;

typedef struct {
    dns_header_t header;
    dns_question_t *questions;
    dns_record_t *answers;
} dns_packet_t;

typedef struct {
    dns_labels_t *label;
    char *addr;
} name_t;

typedef struct {
    char *host;
    char *config;
    unsigned int port;
    name_t *names;
    size_t names_count;
} opts_t;

#endif
