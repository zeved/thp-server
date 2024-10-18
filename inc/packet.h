/*
 *
 * Copyright (c) 2022 Zevedei Ionut
 *  
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *  
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.*
 *
 */

#ifndef _PACKET_H
#define _PACKET_H

#include "types.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void packet_make(uint8_t type, uint8_t *data, uint8_t size, uint8_t *output);
uint8_t packet_parse(packet_t *packet, connection_t * connection);
void packet_dump(const uint8_t *packet_ptr, uint16_t length);
uint16_t packet_send(int socket, uint8_t *packet_ptr, uint16_t length);
void make_query_packet_response(packet_t *packet, server_t *server);
void make_ack_packet(packet_t *packet, server_t *server);
void make_query_ident_packet(packet_t *packet, identity_t *identity, server_t *server);
void make_close_packet(packet_t *packet, server_t *server);

#endif