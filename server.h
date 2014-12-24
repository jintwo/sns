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

#include "dns.h"

#define OPTIONS "h:p:c:?"
#define HOST "127.0.0.1"
#define PORT 8053

typedef struct {
    char *host;
    char *config;
    unsigned int port;
    name_t *names;
    size_t names_count;
} opts_t;

#endif
