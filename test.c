//
//  test.c
//  Simple DNS server
//
//  Created by Eugeny Volobuev on 09.08.13.
//  Copyright (c) 2013 Eugeny Volobuev. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "utils.h"

void test_read_uint8()
{
    unsigned char buf = 128;
    unsigned char val = 0;
    read_uint8(&buf, &val);
    assert(val == 128);
}

void test_read_uint16_lh()
{
    short buf = 512;
    unsigned short val = 0;
    read_uint16(&buf, &val, false);
    assert(val == 512);
}

void test_read_uint16_hl()
{
    short buf = htons(512);
    unsigned short val = 0;
    read_uint16(&buf, &val, true);
    assert(val == 512);
}

void test_write_uint8()
{
    unsigned char buf;
    unsigned char *start = &buf;
    unsigned char val = 0x80;
    write_uint8(&buf, &val);
    assert(*start == 0x80);
}

void test_write_uint16_lh()
{
    unsigned short buf;
    unsigned short *start = &buf;
    unsigned short val = 512;
    write_uint16(&buf, &val, false);
    assert(*start == 512);
}

void test_write_uint16_hl()
{
    unsigned short buf;
    unsigned short *start = &buf;
    unsigned short val = htons(512);
    write_uint16(&buf, &val, true);
    assert(*start == 512);
}

int main(int argc, const char *argv[])
{
    test_read_uint8();
    test_read_uint16_lh();
    test_read_uint16_hl();
    test_write_uint8();
    test_write_uint16_lh();
    test_write_uint16_hl();
    fprintf(stdout, "all tests sucessfully completed");
}