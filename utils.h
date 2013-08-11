//
//  utils.h
//  Simple DNS server
//
//  Created by Eugeny Volobuev on 09.08.13.
//  Copyright (c) 2013 Eugeny Volobuev. All rights reserved.
//

#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#import <stdbool.h>

extern void *read_uint8(void *buffer, unsigned char *value);
extern void *read_uint16(void *buffer, unsigned short *value, bool order_hl);
extern void *write_uint8(void *buffer, unsigned char *value);
extern void *write_uint16(void *buffer, unsigned short *value, bool order_hl);
extern void *write_uint32(void *buffer, unsigned int *value, bool order_hl);
extern void dump_buffer(void *buffer, size_t len);

#endif
