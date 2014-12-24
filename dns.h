#ifndef DNS_H_
#define DNS_H_

#include <stdbool.h>

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

extern dns_labels_t *make_label(char *domain);
extern char *label_to_string(dns_labels_t *label, size_t *llen);
extern void copy_label(dns_labels_t *src, dns_labels_t *dst);
extern dns_labels_t *reverse_label(dns_labels_t *label);
extern bool compare_labels(dns_labels_t *l1, dns_labels_t *l2);
extern char *pack_label(dns_labels_t *label, size_t *llen);
extern char *pack_header(dns_header_t *header);
extern char *pack_question(dns_question_t *question, size_t *len);
extern char *pack_record(dns_record_t *record, size_t *rlen);
extern char *pack_response(dns_packet_t *packet, size_t *rlen);
extern void unpack_header(char *buf, dns_header_t *header);
extern void unpack_question(char *buf, dns_question_t* question);
extern void unpack_request(char *buf, dns_packet_t *packet);
extern char *encode_ip_address(char *addr);
extern void make_reply(dns_question_t *question, char *addr, bool use_compression, dns_record_t *answer);

#endif
