//
//  utils.c
//  Simple DNS server
//
//  Created by Eugeny Volobuev on 09.08.13.
//  Copyright (c) 2013 Eugeny Volobuev. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void *read_uint8(void *buffer, unsigned char *value)
{
    *value = *(unsigned char *)buffer++;
    return buffer;
}

void *read_uint16(void *buffer, unsigned short *value, bool order_hl)
{
    unsigned char hi, lo;
    if (order_hl) {
        buffer = read_uint8(buffer, &hi);
        buffer = read_uint8(buffer, &lo);
    } else {
        buffer = read_uint8(buffer, &lo);
        buffer = read_uint8(buffer, &hi);
    }
    *value = (hi << 8) | lo;
    return buffer;
}

void *write_uint8(void *buffer, unsigned char *value)
{
    *(unsigned char *)buffer = *value;
    buffer++;
    return buffer;
}

void *write_uint16(void *buffer, unsigned short *value, bool order_hl)
{
    unsigned char hi = (*value >> 8) & 0xff;
    unsigned char lo = (*value & 0xff);
    if (order_hl) {
        buffer = write_uint8(buffer, &hi);
        buffer = write_uint8(buffer, &lo);
    } else {
        buffer = write_uint8(buffer, &lo);
        buffer = write_uint8(buffer, &hi);
    }
    return buffer;
}

void *write_uint32(void *buffer, unsigned int *value, bool order_hl)
{
    unsigned short hi = (*value >> 16) & 0xffff;
    unsigned short lo = (*value & 0xffff);
    if (order_hl) {
        buffer = write_uint16(buffer, &hi, order_hl);
        buffer = write_uint16(buffer, &lo, order_hl);
    } else {
        buffer = write_uint16(buffer, &lo, order_hl);
        buffer = write_uint16(buffer, &hi, order_hl);
    }
    return buffer;
}

void dump_buffer(void *buffer, size_t len)
{
    const char *ptr = buffer;
    printf("dump_buffer: ");
    for (int i = 0; i < len; i++) {
        printf("0x%hhx ", *ptr++);
    }
    printf("\n");
}