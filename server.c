//
//  server.c
//  Simple DNS server
//
//  Created by Eugeny Volobuev on 05.08.13.
//  Copyright (c) 2013 Eugeny Volobuev. All rights reserved.
//

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <uv.h>
#include <jansson.h>

#include "server.h"
#include "utils.h"

uv_loop_t *loop;
uv_udp_t server;

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


dns_labels_t *copy_label(dns_labels_t *label)
{
    dns_labels_t *ptr = label;
    dns_labels_t *start = malloc(sizeof(dns_labels_t)), *cur = start, *last;
    while (ptr) {
        memcpy(cur, ptr, sizeof(dns_labels_t));
        last = cur;
        cur->next = malloc(sizeof(dns_labels_t));
        cur = cur->next;
        ptr = ptr->next;
    }
    free(last->next);
    last->next = NULL;
    return start;
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

    dns_labels_t *l1_ = reverse_label(copy_label(l1)), *l2_ = reverse_label(copy_label(l2));

    while (l1_ != l2_) {
        if ((l1_ && !l2) || (!l1_ && l2))
            return false;

        if (strcmp(l1_->label, l2_->label) == 0) {
            l1_ = l1_->next;
            l2_ = l2_->next;
        } else if (strcmp(l1_->label, "*") == 0 ||
                   strcmp(l2_->label, "*") == 0) {
            return true;
        } else
            return false;
    }
    return false;
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

    if (!record->use_compression) {
        size_t domain_rec_len;
        char *domain = pack_label(record->label, &domain_rec_len);
        memcpy(buf, domain, domain_rec_len);
        buf += domain_rec_len;
    } else {
        memcpy(buf, record->cptr, 2);
        buf += 2;
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

uv_buf_t pack_response(dns_packet_t *packet)
{
    size_t len = sizeof(*packet);
    char *buf_ = malloc(len);
    char *start = buf_;

    size_t header_len = sizeof(packet->header);
    memcpy(buf_, pack_header(&packet->header), header_len);
    buf_ += header_len;

    for (int i = 0; i < packet->header.qdcount; i++) {
        size_t question_len;
        char *question = pack_question(&packet->questions[i], &question_len);
        memcpy(buf_, question, question_len);
        buf_ += question_len;
    }

    for (int i = 0; i < packet->header.ancount; i++) {
        size_t record_len;
        char *record = pack_record(&packet->answers[i], &record_len);
        memcpy(buf_, record, record_len);
        buf_ += record_len;
    }

    uv_buf_t buf;
    len = buf_ - start;
    buf.base = malloc(len);
    buf.len = len;
    memcpy(buf.base, start, len);
    return buf;
}

dns_header_t unpack_header(uv_buf_t buf, size_t *hlen)
{
    dns_header_t header;
    size_t header_len = sizeof(dns_header_t);
    char *buf_ = malloc(header_len);
    memcpy((void *)buf_, buf.base, header_len);

#ifdef DEBUG
    puts("input header");
    dump_buffer(buf_, header_len);
#endif

    buf_ = read_uint16(buf_, &header.id, true);
    buf_ = read_uint16(buf_, (unsigned short *)&header.flags, true);
    buf_ = read_uint16(buf_, &header.qdcount, true);
    buf_ = read_uint16(buf_, &header.ancount, true);
    buf_ = read_uint16(buf_, &header.nscount, true);
    buf_ = read_uint16(buf_, &header.arcount, true);

    *hlen = HEADER_LENGTH;

    return header;
}

dns_question_t *unpack_question(char *buf, size_t *qlen)
{
    char *qdata = buf;

    dns_question_t *question = malloc(sizeof(dns_question_t));
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

    *qlen = qdata - buf;

    return question;
}

dns_packet_t *unpack_request(uv_buf_t buf)
{
    dns_packet_t *packet = malloc(sizeof(dns_packet_t));
    size_t header_len;
    packet->header = unpack_header(buf, &header_len);

    char *qdata = buf.base + header_len;
    packet->questions = calloc(packet->header.qdcount, sizeof(dns_question_t));
    dns_question_t *questions = packet->questions;
    for (int i = 0; i < packet->header.qdcount; i++) {
        size_t question_len;
        dns_question_t *question = unpack_question(qdata, &question_len);

#ifdef DEBUG
        printf("query for: %s\n", label_to_string(question->label, NULL));
#endif

        memcpy(questions, question, question_len);
        questions += question_len;
    }
    return packet;
}

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

char *make_rdata(char *addr)
{
    char *ip = malloc(IPADDR_LENGTH);

    char *addr_ = malloc(strlen(addr));
    strcpy(addr_, addr);

    char* oct = strtok(addr_, ".");
    *ip++ = atoi(oct);

    while (oct != NULL) {
        *ip++ = atoi(oct);
        oct = strtok(NULL, ".");
    }

    ip -= IPADDR_LENGTH;

    return ip;
}

dns_record_t *make_answer(dns_question_t *question, char *addr, bool use_compression)
{
    dns_record_t *answer = malloc(sizeof(dns_record_t));

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
    answer->rdata = make_rdata(addr);

    return answer;
}

void process_packet(dns_packet_t *packet, opts_t *config)
{
    int answers_count = 0;
    for (int i = 0; i < packet->header.qdcount; i++) {
        dns_question_t *question = &packet->questions[i];
        for (int j = 0; j < config->names_count; j++) {
            name_t *name = &config->names[j];
            if (compare_labels(name->label, question->label)) {
                answers_count++;
                if (!packet->answers) {
                    packet->answers = calloc(answers_count, sizeof(dns_record_t));
                } else {
                    packet->answers = realloc(packet->answers, answers_count * sizeof(dns_record_t));
                }
                packet->answers[answers_count - 1] = *make_answer(question, name->addr, true);
            }
        }
    }

    packet->header.ancount = answers_count;
    packet->header.flags.flags = (0x81 << 8) | 0x80;

    //    packet->header.flags.flags_s.qr = 1;
    //    packet->header.flags.flags_s.aa = 1;
    //    packet->header.flags.flags_s.ra = 1;

}

void on_read(uv_udp_t* handle, ssize_t nread, uv_buf_t buf, struct sockaddr* addr, unsigned flags)
{
    if (nread < 0) {
        fputs("on_read error", stderr);
        uv_close((uv_handle_t *)handle, NULL);
        free(buf.base);
        return;
    }

    if (nread == 0) {
        free(buf.base);
        return;
    }

    // show client ip
    struct sockaddr_in sin = *(struct sockaddr_in *)addr;
    printf("data from <%s:%d>\n", inet_ntoa(sin.sin_addr), sin.sin_port);

    // process request
    dns_packet_t *packet = unpack_request(buf);
    process_packet(packet, handle->data);
    uv_buf_t response = pack_response(packet);
    free(packet);

    uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
    uv_udp_send(send_req, handle, &response, 1, sin, NULL);

    free(buf.base);
}

uv_buf_t alloc_buffer(uv_handle_t *handle, size_t suggested_size)
{
    return uv_buf_init(malloc(suggested_size), (unsigned int)suggested_size);
}

void load_config(char *filename, opts_t *options)
{
    json_t *config = json_load_file(filename, 0, NULL);
    if (json_is_object(config)) {
        json_t *host = json_object_get(config, "host");
        if (json_is_string(host)) {
            char *host_str = (char *)json_string_value(host);
            options->host = malloc(strlen(host_str));
            strcpy(options->host, host_str);
        }

        json_t *port = json_object_get(config, "port");
        if (json_is_integer(port)) {
            options->port = (int)json_integer_value(port);
        }

        json_t *names = json_object_get(config, "names");
        if (json_is_object(names)) {
            options->names = calloc(json_object_size(names), sizeof(name_t));
            char *key;
            json_t *value;
            int i = 0;
            json_object_foreach(names, key, value) {
                options->names[i].label = make_label(key);
                char *addr = json_string_value(value);
                size_t addr_len = strlen(addr);
                options->names[i].addr = malloc(addr_len);
                strcpy(options->names[i].addr, addr);
                i++;
            }
            options->names_count = i;
        }
    }
}

void parse_options(int argc, char * const *argv, char *getopt_opts, opts_t *options)
{
    int opt = getopt(argc, (char * const *)argv, OPTIONS);
    while (opt != -1) {
        switch (opt) {
            case 'h':
                options->host = malloc(strlen(optarg));
                strcpy(options->host, optarg);
                break;
            case 'p':
                options->port = atoi(optarg);
                break;
            case 'c':
                options->config = malloc(strlen(optarg));
                strcpy(options->config, optarg);
                break;
            case '?':
                printf("usage: %s [-h 127.0.0.1] [-p 8053] [-c config.json]\n", argv[0]);
                exit(0);
                break;
        }
        opt = getopt(argc, (char * const *)argv, OPTIONS);
    }
}

int main(int argc, const char *argv[])
{
    opts_t *config;
    config = malloc(sizeof(opts_t));
    config->host = HOST;
    config->port = PORT;
    config->names_count = 0;

    parse_options(argc, (char * const *)argv, OPTIONS, config);

    if (config->config) {
        load_config(config->config, config);
    }

    loop = uv_default_loop();
    int err;

    err = uv_udp_init(loop, &server);
    if (err) {
        fputs("can't create socket", stderr);
        return 1;
    }

    server.data = config;

    struct sockaddr_in bind_addr = uv_ip4_addr(config->host, config->port);
    err = uv_udp_bind(&server, bind_addr, 0);
    if (err) {
        fputs("can't bind socket", stderr);
        return 1;
    }

    err = uv_udp_recv_start(&server, alloc_buffer, on_read);
    if (err) {
        fprintf(stderr, "can't listen: %s\n", uv_err_name(err));
        return 1;
    }

    fprintf(stdout, "listening<%d> on: %s:%d\n", getpid(), config->host, config->port);

    return uv_run(loop, UV_RUN_DEFAULT);
}
