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

#include "inc/connection.h"
#include "inc/packet.h"
#include "inc/server.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

void *connection_thread(void *param) {
  if (param == NULL) {
    fprintf(stderr, "[connection]: received null pointer; aborting thread\n");
    pthread_exit(NULL);
  }
  else {
    connection_t *connection = (connection_t *)param;

    fprintf(stdout, "[connection]: started thread 0x%08lx\n", connection->thread);
    
    gettimeofday(&connection->time, NULL);

    uint8_t packet_buffer[MAX_PACKET_SIZE];
    memset(packet_buffer, 0, MAX_PACKET_SIZE);
    size_t bytes_read = 0;

    fprintf(stdout, "[connection]: packet size: %ld\n", MAX_PACKET_SIZE);

    while ((bytes_read = recv(connection->socket, packet_buffer, MAX_PACKET_SIZE, 0)) != -1) {
      struct timeval new_time, delta;
      gettimeofday(&new_time, NULL);
      timersub(&new_time, &connection->time, &delta);
      
      if (bytes_read == MAX_PACKET_SIZE) {
        packet_buffer[MAX_PACKET_SIZE - 1] = 0;
        packet_t *packet = (packet_t *) packet_buffer;

        uint8_t packet_type = packet_parse(packet, connection);

        if (packet_type == PACKET_TYPE_CLOSE) {
          goto exit;
        }
      }
      else if (bytes_read == 0 && delta.tv_sec > TIMEOUT) {
        fprintf(stdout, "[connection]: no packets for %d seconds or connection killed\n", TIMEOUT);
        goto exit;
      }
      else {
        memset(packet_buffer, 0, MAX_PACKET_SIZE);
      }
    }

    if (bytes_read == -1) {
      perror("recv()");
    }

exit:
    memset(packet_buffer, 0xff, MAX_PACKET_SIZE);
    fprintf(stdout, "[connection]: exiting thread 0x%08lx, closing connection as well\n", connection->thread);
    close_connection(connection);

    pthread_exit(NULL);
  }
  return NULL;
}

void close_connection(connection_t *connection) {
  if (connection != NULL) {
    close(connection->socket);
    shutdown(connection->socket, SHUT_RDWR);
    connection->address.sin_addr.s_addr = 0;
    memset(connection->ip_address, 0, INET_ADDRSTRLEN);
    remove_identity(connection->identity_ptr, connection->server_ptr);
    ((server_t *)(connection->server_ptr))->connections_number--;
    fprintf(stdout, "[server]: connections %d\n", ((server_t *)(connection->server_ptr))->connections_number);
    connection->server_ptr = NULL;
    free(connection);
  }
}