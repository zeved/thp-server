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

#ifndef _TYPES_H
#define _TYPES_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#define SIGNATURE "\xC0\xFF\xEE\xC0\xFF\xEE\x00\x00"

#define IDENTITY_STR_LEN        33


typedef struct {
  uint8_t identity_str[IDENTITY_STR_LEN];
  uint8_t ipv4[INET_ADDRSTRLEN];
  uint16_t port;
} identity_t;

#define MAX_PACKET_DATA_SIZE  sizeof(identity_t) * 10

#define MAX_PACKET_SIZE       MAX_PACKET_DATA_SIZE + 64 

// identify to the server
#define PACKET_TYPE_IDENT       0
// ask server for a list of identities
#define PACKET_TYPE_QUERY       1
// ask server for details on a specific identity
#define PACKET_TYPE_QUERY_IDENT 2
// close connection
#define PACKET_TYPE_CLOSE       3
// invalid packet
#define PACKET_TYPE_INVALID     4
// acknowledged packet
#define PACKET_TYPE_ACK         5

#define MAX_CONNECTIONS         10
#define TIMEOUT                 60

#define INVALID_RESULT          0xff

typedef struct {
  uint8_t signature[8];
  uint8_t type;
  uint8_t data[MAX_PACKET_DATA_SIZE];
  uint8_t reserved[64];
} packet_t;

typedef struct {
  pthread_t thread;
  int socket;
  struct sockaddr_in address;
  uint8_t ip_address[INET_ADDRSTRLEN];
  uint8_t bad_packets_number;
  void *server_ptr;
  void *identity_ptr;
  struct timeval time;
} connection_t;

typedef struct {
  bool accepts_connections;
  pthread_t thread;
  int socket;
  struct sockaddr_in address;
  socklen_t address_sz;
  connection_t connections[10];
  identity_t identities[10];
  uint8_t connections_number;
} server_t;

#endif