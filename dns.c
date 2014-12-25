#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "dns.h"
#include "utils.h"

dns_labels_t *make_label(char *domain)
{
    dns_labels_t *root = malloc(sizeof(dns_labels_t));
    dns_labels_t *current = root;
    dns_labels_t *last = NULL;
    char *buf = malloc(strlen(domain));
    strcpy(buf, domain);
    char *pch = strtok(buf, ".");
    while (pch != NULL) {
        size_t token_len = strlen(pch);
        current->label = malloc(token_len);
        memcpy(current->label, pch, token_len);
        pch = strtok(NULL, ".");
        last = current;
        current->next = malloc(sizeof(dns_labels_t));
        current = current->next;
    }
    free(last->next);
    last->next = NULL;
    return root;
}

char *label_to_string(dns_labels_t *label, size_t *llen)
{
    char *result = NULL;
    size_t total_len = 0;

    dns_labels_t *elem = label;
    while (elem) {
        size_t label_len = strlen(elem->label);
        char *current = malloc(label_len + 1);
        strcpy(current, elem->label);
        current[label_len] = '.';

        total_len += label_len + 1;
        if (!result)
            result = malloc(total_len);
        else
            result = realloc(result, total_len);
        strcat(result, current);
        elem = elem->next;
    }

    result[total_len - 1] = 0;

    if (llen)
        *llen = total_len;

    return result;
}

void copy_label(dns_labels_t *src, dns_labels_t *dst)
{
    dns_labels_t *ptr = src;
    dns_labels_t *cur = dst, *last;
    while (ptr) {
        memcpy(cur, ptr, sizeof(dns_labels_t));
        last = cur;
        cur->next = malloc(sizeof(dns_labels_t));
        cur = cur->next;
        ptr = ptr->next;
    }
    free(last->next);
    last->next = NULL;
}

dns_labels_t *reverse_label(dns_labels_t *label)
{
    dns_labels_t *root = NULL;
    while (label) {
        dns_labels_t *next = label->next;
        label->next = root;
        root = label;
        label = next;
    }
    return root;
}

bool compare_labels(dns_labels_t *l1, dns_labels_t *l2)
{
    if (l1 == l2)
        return true;

    size_t label_size = sizeof(dns_labels_t);
    dns_labels_t *l1_ = malloc(label_size);
    dns_labels_t *l2_ = malloc(label_size);
    copy_label(l1, l1_);
    copy_label(l2, l2_);
    dns_labels_t *c1 = reverse_label(l1_);
    dns_labels_t *c2 = reverse_label(l2_);

    bool result = false;

    while (c1 != c2) {
        if (c1 && !(strcmp(c1->label, "*"))) {
            result = true;
            break;
        }

        if (c2 && !(strcmp(c2->label, "*"))) {
            result = true;
            break;
        }

        if (c1 && c2) {
            if (!strcmp(c1->label, c2->label)) {
                c1 = c1->next;
                c2 = c2->next;
                continue;
            } else {
                result = false;
                break;
            }
        } else if (!c1 && !c2) {
            result = true;
            break;
        }

        break;
    }

    free(l1_);
    free(l2_);
    return result;
}

char *pack_label(dns_labels_t *label, size_t *llen)
{
    char *result = NULL;
    size_t total_len = 0;

    dns_labels_t *elem = label;
    while (elem) {
        size_t label_len = strlen(elem->label);
        char *current = malloc(label_len + 1);
        *current = label_len;
        strcpy(current + 1, elem->label);

        total_len += label_len + 1;
        if (!result)
            result = malloc(total_len);
        else
            result = realloc(result, total_len);
        strcat(result, current);
        elem = elem->next;
    }

    *llen = total_len + 1;

    return result;
}

char *pack_header(dns_header_t *header)
{
    size_t header_len = sizeof(dns_header_t);
    char *buf = malloc(header_len);
    char *start = buf;

    buf = write_uint16(buf, &header->id, true);
    buf = write_uint16(buf, (unsigned short *)&header->flags, true);
    buf = write_uint16(buf, &header->qdcount, true);
    buf = write_uint16(buf, &header->ancount, true);
    buf = write_uint16(buf, &header->nscount, true);
    buf = write_uint16(buf, &header->arcount, true);

#ifdef DEBUG
    puts("output header");
    dump_buffer(start, header_len);
#endif

    return start;
}

char *pack_question(dns_question_t *question, size_t *len)
{
    size_t question_len = sizeof(dns_question_t);
    char *buf = malloc(question_len);
    char *start = buf;

    size_t domain_rec_len;
    char *domain = pack_label(question->label, &domain_rec_len);
    memcpy(buf, domain, domain_rec_len);
    buf += domain_rec_len;

    buf = write_uint16(buf, &question->qtype, true);
    buf = write_uint16(buf, &question->qclass, true);

    *len = buf - start;

    return start;
}

char *pack_record(dns_record_t *record, size_t *rlen)
{
    size_t record_len = sizeof(dns_record_t);
    char *buf = malloc(record_len);
    char *start = buf;

    if (record->use_compression) {
        memcpy(buf, record->cptr, 2);
        buf += 2;
    } else {
        size_t domain_rec_len;
        char *domain = pack_label(record->label, &domain_rec_len);
        memcpy(buf, domain, domain_rec_len);
        buf += domain_rec_len;
    }

    buf = write_uint16(buf, &record->rtype, true);
    buf = write_uint16(buf, &record->rclass, true);
    buf = write_uint32(buf, &record->ttl, true);
    buf = write_uint16(buf, &record->rdlength, true);
    memcpy(buf, record->rdata, record->rdlength);
    buf += record->rdlength;

    *rlen = buf - start;

#ifdef DEBUG
    puts("output record");
    dump_buffer(start, *rlen);
#endif

    return start;
}

char *pack_response(dns_packet_t *packet, size_t *rlen)
{
    size_t header_len = sizeof(dns_header_t);
    size_t question_len = sizeof(dns_question_t);
    size_t answer_len = sizeof(dns_record_t);

    char *buf = malloc(
            header_len + \
            packet->header.qdcount * question_len + \
            packet->header.ancount * answer_len);

    char *start = buf;
    memcpy(buf, pack_header(&packet->header), header_len);
    buf += header_len;

    for (int i = 0; i < packet->header.qdcount; i++) {
        size_t question_len;
        char *question = pack_question(&packet->questions[i], &question_len);
        memcpy(buf, question, question_len);
        buf += question_len;
        free(question);
    }

    for (int i = 0; i < packet->header.ancount; i++) {
        size_t record_len;
        char *record = pack_record(&packet->answers[i], &record_len);
        memcpy(buf, record, record_len);
        buf += record_len;
        free(record);
    }

    *rlen = buf - start;

    return start;
}

void unpack_header(char *buf, dns_header_t *header)
{
    size_t header_len = sizeof(dns_header_t);
    char *buf_ = malloc(header_len);
    memcpy((void *)buf_, buf, header_len);

#ifdef DEBUG
    puts("input header");
    dump_buffer(buf_, header_len);
#endif

    buf_ = read_uint16(buf_, &header->id, true);
    buf_ = read_uint16(buf_, (unsigned short *)&header->flags, true);
    buf_ = read_uint16(buf_, &header->qdcount, true);
    buf_ = read_uint16(buf_, &header->ancount, true);
    buf_ = read_uint16(buf_, &header->nscount, true);
    buf_ = read_uint16(buf_, &header->arcount, true);
}

void unpack_question(char *buf, dns_question_t* question)
{
    char *qdata = buf;
    question->label = malloc(sizeof(dns_labels_t));
    dns_labels_t *elem = question->label;
    dns_labels_t *last = NULL;
    size_t label_len;
    while ((label_len = *qdata++) != 0) {

        elem->label = malloc(label_len);
        memcpy(elem->label, qdata, label_len);
        qdata += label_len;

        last = elem;
        elem->next = malloc(sizeof(dns_labels_t));
        elem = elem->next;
    }
    free(last->next);
    last->next = NULL;
    qdata = read_uint16(qdata, &question->qtype, true);
    qdata = read_uint16(qdata, &question->qclass, true);
}

void unpack_request(char *buf, dns_packet_t *packet)
{
    dns_header_t header;
    unpack_header(buf, &header);
    packet->header = header;

    char *qdata = buf + sizeof(dns_header_t);
    packet->questions = calloc(packet->header.qdcount, sizeof(dns_question_t));
    dns_question_t *questions = packet->questions;
    for (int i = 0; i < packet->header.qdcount; i++) {
        dns_question_t question;
        unpack_question(qdata, &question);
        questions[i] = question;
#ifdef DEBUG
        printf("query for: %s\n", label_to_string(question->label, NULL));
#endif
    }
    packet->answers = NULL;
}

char *encode_ip_address(char *addr)
{
    char *ip = malloc(IPADDR_LENGTH);
    char *addr_ = strdup(addr);

    char* oct = strtok(addr_, ".");
    *ip++ = atoi(oct);

    while (oct != NULL) {
        *ip++ = atoi(oct);
        oct = strtok(NULL, ".");
    }

    ip -= IPADDR_LENGTH;

    free(addr_);
    return ip;
}

void make_reply(dns_question_t *question, char *addr, bool use_compression, dns_record_t *answer)
{
    answer->use_compression = use_compression;
    if (use_compression) {
        answer->cptr = "\xc0\x0c";
    } else {
        answer->label = question->label;
    }
    answer->rtype = question->qtype;
    answer->rclass = question->qclass;
    answer->ttl = 86400;
    answer->rdlength = 4;
    answer->rdata = encode_ip_address(addr);
}
