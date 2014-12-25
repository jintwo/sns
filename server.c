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

uv_loop_t *loop;
uv_udp_t server;

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
                dns_record_t *answer = malloc(sizeof(dns_record_t));
                make_reply(question, name->addr, false, answer);
//                make_reply(question, name->addr, true, answer);
                packet->answers[answers_count - 1] = *answer;
                free(answer);
            }
        }
    }

    packet->header.ancount = answers_count;
    packet->header.flags.flags = (0x81 << 8) | 0x80;

    //    packet->header.flags.flags_s.qr = 1;
    //    packet->header.flags.flags_s.aa = 1;
    //    packet->header.flags.flags_s.ra = 1;

}

uv_buf_t pack_response_to_uv_buf(dns_packet_t *packet)
{
    size_t len;
    char *response_buf = pack_response(packet, &len);

    uv_buf_t buf;
    buf.base = malloc(len);
    buf.len = len;
    memcpy(buf.base, response_buf, len);

    free(response_buf);
    return buf;
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

    struct sockaddr_in sin = *(struct sockaddr_in *)addr;
    printf("data from <%s:%d>\n", inet_ntoa(sin.sin_addr), sin.sin_port);

    dns_packet_t packet;
    unpack_request(buf.base, &packet);
    process_packet(&packet, handle->data);
    uv_buf_t response = pack_response_to_uv_buf(&packet);
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
