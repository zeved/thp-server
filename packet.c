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

#include "inc/packet.h"
#include "inc/connection.h"
#include "inc/server.h"
#include <unistd.h>

void packet_make(uint8_t type, uint8_t *data, uint8_t size, uint8_t *output) {
  if (data != NULL) {
    if (size > MAX_PACKET_DATA_SIZE) {
      fprintf(stderr, "[packet]: packet data size %d > %ld\n", size, MAX_PACKET_DATA_SIZE);
      return;
    }

    if (output != NULL) {
      memset(output, 0, MAX_PACKET_SIZE);

      packet_t *packet = (packet_t *) calloc(1, sizeof(packet_t));

      if (packet == NULL) {
        fprintf(stderr, "[packet]: failed allocating %ld bytes\n", sizeof(packet_t));
        return;
      }

      memcpy(packet->signature, SIGNATURE, 8);
      packet->type = type;

      memset(packet->reserved, 0x41, 64);
      memcpy(packet->data, data, size);

      memcpy(output, packet, MAX_PACKET_SIZE);

      free(packet);
    }
    else {
      fprintf(stderr, "[packet]: null pointer received for destination;\n");
    }
  }
  else {
    fprintf(stderr, "[error]: null pointer received for data\n");
  }
}

// TODO: fix this shit.
void packet_dump(const uint8_t *packet_buff, uint16_t length) {
  uint8_t byte;
  uint16_t i = 0, j = 0, offset = 0;

  for (i = 0; i < length; i++) {
    if (i % 16 == 0) {
      printf("0x%04x -> ", offset);
    }
    byte = packet_buff[i];
    printf("%02x ", packet_buff[i]);
    if (((i % 16) == 15) || (i == length - 1)) {
      for (j = 0; j < 15 - (i % 16) - 1; j++) {
        printf("   ");
      }
      printf("| ");
      for (j = (i - (i % 16)); j <= i; j++) {
        byte = packet_buff[j];
        if ((byte > 32) && (byte < 127)) {
          printf("%c", byte);
        }
        else {
          printf(".");
        }
      }
      printf("\n");
      offset += 16;
    }
  }
}

uint16_t packet_send(int socket, uint8_t *packet_buff, uint16_t length) {
  int bytes_sent = 0, bytes_remaining = length;
  uint8_t *orig_ptr = packet_buff;

  while (bytes_remaining > 0) {
    bytes_sent = send(socket, packet_buff, bytes_remaining, 0);

    if (bytes_sent == -1) {
      fprintf(stderr, "[packet]: failed sending data to socket\n");
      perror("send()");
      return 0;
    }

    bytes_remaining -= bytes_sent;
    packet_buff += bytes_sent;
  }

  fprintf(stdout, "[packet]: sent packet type %d, %d bytes out of %u\n", *(orig_ptr + 8), bytes_sent, length);

  return bytes_sent;
}

uint8_t packet_parse(packet_t *packet, connection_t *connection) {
  if (connection == NULL || packet == NULL) {
    fprintf(stderr, "[packet]: received null pointer in packet_parse)_\n");
      return INVALID_RESULT;
  }
  else {
    uint8_t ret;
    packet_t *response_packet = (packet_t *) calloc(1, sizeof(packet_t));
    identity_t *identity = NULL;

    if (response_packet == NULL) {
      fprintf(stderr, "[packet]: failed allocating %ld bytes for packet struct\n", sizeof(packet_t));
      return INVALID_RESULT;
    }

    response_packet->type = PACKET_TYPE_INVALID;
    memset(response_packet->data, 0, sizeof(response_packet->data));

    if (memcmp(packet->signature, SIGNATURE, 8) != 0) {
      fprintf(stderr, "[packet]: received bad packet signature; ignoring\n");
      connection->bad_packets_number++;
      return INVALID_RESULT;
    } 

    if (connection->bad_packets_number >= 10) {
      fprintf(stderr, "[packet]: connection sent 10 bad packets -> shutting down\n");
      close_connection(connection);
      return INVALID_RESULT;
    }

    switch (packet->type) {
      case PACKET_TYPE_IDENT: {
        identity_t *identity = (identity_t *) calloc(1, sizeof(identity_t));
        if (identity == NULL) {
          fprintf(stderr, "[packet]: failed allocating %ld bytes for identity struct\n", sizeof(identity_t));
        }
        else {
          memcpy(identity->identity_str, packet->data, IDENTITY_STR_LEN);
          inet_ntop(connection->address.sin_family, &(connection->address.sin_addr), identity->ipv4, INET_ADDRSTRLEN);

          identity->port = htons(connection->address.sin_port);

          fprintf(stdout, "[packet]: got IDENT packet with:\n");
          fprintf(stdout, "          identity str: %s\n", identity->identity_str);
          fprintf(stdout, "          IP: %s\n", identity->ipv4);
          fprintf(stdout, "          port: %d\n", identity->port);

          uint8_t index = add_identity(identity, connection->server_ptr, true);

          if (index != 0xff) {
            connection->identity_ptr = &((server_t *)connection->server_ptr)->identities[index];
          }
          else {
            fprintf(stdout, "[packet]: identity %s already exists with index %d\n", identity->identity_str, index);
          }

          free(identity);

          make_ack_packet(response_packet, connection->server_ptr);
          ret = packet->type;
        }

        break;
      }

      case PACKET_TYPE_QUERY:
        fprintf(stdout, "[packet]: got QUERY packet; sending all identities\n");
        make_query_packet_response(response_packet, connection->server_ptr);
        ret = packet->type;
        break;

      case PACKET_TYPE_QUERY_IDENT:
        identity = (identity_t *) calloc(1, sizeof(identity_t));
        // check for null ptr
        memcpy(identity->identity_str, packet->data, IDENTITY_STR_LEN);
        fprintf(stdout, "[packet]: got QUERY_IDENT packet; looking up identity %s\n", identity->identity_str);

        uint8_t index = identity_exists(identity, connection->server_ptr);
        fprintf(stdout, "[packet]: found identity on index %d\n", index);

        make_query_ident_packet(response_packet, identity, connection->server_ptr);
        ret = PACKET_TYPE_QUERY_IDENT;

        break;

        // check for null ptr 

        // TODO: implement.

      case PACKET_TYPE_CLOSE:
        fprintf(stdout, "[packet]: got CLOSE packet\n");
        make_close_packet(response_packet, connection->server_ptr);
        break;


      default:
        connection->bad_packets_number++;
        fprintf(stderr, "[packet]: invalid packet type %d; ignoring\n", packet->type);
        ret = PACKET_TYPE_INVALID;
    }

    // packet_dump((const uint8_t *) packet, MAX_PACKET_SIZE);
    if (response_packet->type != PACKET_TYPE_INVALID) {
      packet_send(connection->socket, (uint8_t *) response_packet, sizeof(packet_t));
    }

    free(response_packet);

    return ret;
  }

  return PACKET_TYPE_INVALID;
}

void make_query_packet_response(packet_t *packet, server_t *server) {
  if (packet == NULL || server == NULL) {
    fprintf(stderr, "[paclet]: received null pointer in make_query_packet_response()\n");
    return;
  }

  memcpy(packet->signature, SIGNATURE, 8);
  packet->type = PACKET_TYPE_QUERY;
  
  uint8_t j = 0;
  for (uint16_t i = 0; i < server->connections_number; i += 32) {
    if (server->identities[j].port != 0) {
      memcpy(packet->data + i, server->identities[j++].identity_str, IDENTITY_STR_LEN);
    }
  }
}

void make_ack_packet(packet_t *packet, server_t *server) {
  if (packet == NULL || server == NULL) {
    fprintf(stderr, "[paclet]: received null pointer in make_ack_packet()\n");
    return;
  }

  memcpy(packet->signature, SIGNATURE, 8);
  packet->type = PACKET_TYPE_ACK;
}

void make_query_ident_packet(packet_t *packet, identity_t *identity, server_t *server) {
  if (packet == NULL || server == NULL || identity == NULL) {
    fprintf(stderr, "[paclet]: received null pointer in make_ack_packet()\n");
    return;
  }

  memcpy(packet->signature, SIGNATURE, 8);
  packet->type = PACKET_TYPE_QUERY_IDENT;

  uint8_t index = 0xff;

  if ((index = identity_exists(identity, server)) != 0xff) {
    memcpy(packet->data, server->identities[index].identity_str, IDENTITY_STR_LEN - 1);
    memcpy(packet->data + IDENTITY_STR_LEN - 1, server->identities[index].ipv4, INET_ADDRSTRLEN);
    // a << 8 + b
    memcpy((packet->data + IDENTITY_STR_LEN - 1 + INET_ADDRSTRLEN), &server->identities[index].port, 2);
  }
  else {
    packet->data[0] = 0xff;
  }
}

void make_close_packet(packet_t *packet, server_t *server) {
    if (packet == NULL || server == NULL) {
    fprintf(stderr, "[paclet]: received null pointer in make_close_packet()\n");
    return;
  }

  memcpy(packet->signature, SIGNATURE, 8);
  packet->type = PACKET_TYPE_CLOSE;
}
