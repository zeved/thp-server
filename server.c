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

#include "inc/server.h"
#include "inc/connection.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/**
 * @brief initialize server
 *
 * @param server pointer to server_t struct (must be allocated beforehand)
 * @param port port number to bind on
 * @param max_connections maximum connections the server will accept
 * @return true - server initialized and thread exited
 * @return false - something went wrong
 */
bool server_init(server_t *server, uint16_t port, uint8_t max_connections) {
  fprintf(stdout, "[server]: initializing\n");

  if (server == NULL) {
    fprintf(stderr, "[server]: received NULL pointer for server struct\n");
    return false;
  }

  server->socket = socket(PF_INET, SOCK_STREAM, 0);

  if (server->socket == -1) {
    fprintf(stderr, "[server]: could not create socket\n");
    perror("socket()");
    free(server);
    return false;
  }

  int yes = 1;

  if (setsockopt(
    server->socket,
    SOL_SOCKET,
    SO_REUSEADDR,
    &yes,
    sizeof(int)
  ) == -1) {
    fprintf(stderr, "[server]: could not set socket options\n");
    perror("setsockopt()");
    return false;
  }

  server->address_sz = sizeof(struct sockaddr_in);

  server->address.sin_family = AF_INET;
  server->address.sin_addr.s_addr = INADDR_ANY;
  server->address.sin_port = htons(port);
  memset(&(server->address.sin_zero), 0x00, 8);

  int result = bind(server->socket, (struct sockaddr *) &server->address, server->address_sz);

  if (result == -1) {
    fprintf(stderr, "[server]: failed binding to port %d\n", port);
    perror("bind()");
    return false;
  }

  fprintf(stdout, "[server]: bound to IP %s on port %d\n", inet_ntoa(server->address.sin_addr), port);

  result = listen(server->socket, max_connections);

  if (result == -1) {
    fprintf(stderr, "[server]: listening failed\n");
    perror("listen()");
    return false;
  }

  result = 0;

  server->accepts_connections = true;

  result = pthread_create(&server->thread, NULL, server_thread, server);

  if (result) {
    fprintf(stderr, "[server]: failed creating server thread\n");
    perror("pthread_create()");
    return false;
  }


  pthread_join(server->thread, NULL);

  close(server->socket);
  shutdown(server->socket, SHUT_RDWR);

  return true;
}

/**
 * @brief server thread
 *
 * @param param pointer to server_t struct
 * @return void* - NULL
 */
void *server_thread(void *param) {
  fprintf(stdout, "[server]: thread started\n\n\b");

  if (param == NULL) {
    fprintf(stderr, "[server]: received NULL server ptr\n");
    return NULL;
  }

  server_t *server = (server_t *) param;

  while (server->accepts_connections) {
    if (server->connections_number < MAX_CONNECTIONS) {
      connection_t *connection = (connection_t *) calloc(1, sizeof(connection_t));

      if (connection == NULL) {
        fprintf(stderr, "[server]: failed allocating %ld bytes for connection\n", sizeof(connection_t));
        perror("calloc()");
        continue;
      }

      connection->server_ptr = server;

      socklen_t size = sizeof(connection->address);
      connection->socket = accept(server->socket, (struct sockaddr *) &connection->address, &size);

      if (connection->socket == -1) {
        fprintf(stderr, "[server]: failed accepting connection\n");
        perror("accept()");
        free(connection);
        continue;
      }

      inet_ntop(AF_INET, &connection->address.sin_addr, (char *)connection->ip_address, INET_ADDRSTRLEN);

      server->connections_number++;

      fprintf(stdout, "[server]: connection from %s:%d; spawning thread\n\b", connection->ip_address, connection->address.sin_port);
      fprintf(stdout, "[server]: connections: %d\n", server->connections_number);

      int result = pthread_create(&connection->thread, NULL, connection_thread, connection);
      if (result != 0) {
        fprintf(stderr, "[server]: failed creating thread for connection!\n");
        perror("pthread_create()");
        
        close_connection(connection);
      }
    }
    // else {
    //   fprintf(stdout, "[server]: server already has 10 connections; waiting for a free slot\n");
    // }
  }

  shutdown(server->socket, SHUT_RDWR);
  free(server);

  pthread_exit(NULL);

  return NULL;
}

/**
 * @brief checks if an identity exists in the server's list
 *
 * @param identity pointer to identity_t struct
 * @param server pointer to server_t struct
 * @return uint8_t - index or 0xff if not found
 */
uint8_t identity_exists(identity_t *identity, server_t *server) {
  if (identity == NULL || server == NULL) {
    fprintf(stderr, "[server]: identity_exists() received null pointer\n");
    return 0xff;
  }

  for (uint8_t i = 0; i < server->connections_number; i++) {
    if (server->identities[i].port == 0) {
      continue;
    }
    if (memcmp(server->identities[i].identity_str, identity->identity_str, IDENTITY_STR_LEN) == 0) {
      return i;
    }
  }

  return 0xff;
}

/**
 * @brief add an identity to the server's list
 *
 * @param identity pointer to identity_t
 * @param server pointer to server_t
 * @param replace replace identity if found
 * @return uint8_t - index or 0xff if error
 */
uint8_t add_identity(identity_t *identity, server_t *server, bool replace) {
  if (identity == NULL || server == NULL) {
    fprintf(stderr, "[server]: identity_exists() received null pointer\n");
    return 0xff;
  }

  if (server->connections_number < MAX_CONNECTIONS) {
    identity_t *slot;
    uint8_t index = identity_exists(identity, server);
    if (index != 0xff) {
      if (replace) {
        slot = &server->identities[index];
        memcpy(server->identities[index].ipv4, identity->ipv4, INET_ADDRSTRLEN);
        server->identities[index].port = identity->port;
        return index;
      }
    }
    else {
      bool added = false;
      // look for an empty slot then add it there
      uint8_t i;
      for (i = 0; i < MAX_CONNECTIONS; i++) {
        if (server->identities[i].identity_str[0] == 0) {
          slot = &server->identities[i];
          memcpy(slot->identity_str, identity->identity_str, IDENTITY_STR_LEN);
          memcpy(slot->ipv4, identity->ipv4, INET_ADDRSTRLEN);
          slot->port = identity->port;
          added = true;
          break;
        }
      }

      if (!added) {
        fprintf(stderr, "[server]: bug: this should not happen; connections_number %d < MAX_CONNECTIONS but no free slots\n", server->connections_number);
      }

      return i;
    }
  }
  else {
    fprintf(stderr, "[server]: server already has 10 connections\n");
  }
  return 0xff;
}

/**
 * @brief remove identity from server's list
 *
 * @param identity pointer to identity_t
 * @param server pointer to server_t
 * @return uint8_t - index or 0xff if error / not found
 */
uint8_t remove_identity(identity_t *identity, server_t *server) {
  if (identity == NULL || server == NULL) {
    fprintf(stderr, "[server]: identity_exists() received null pointer\n");
    return 0xff;
  }

  uint8_t index = identity_exists(identity, server);
  if (index != 0xff) {
    identity_t *identity = &server->identities[index];
    memset(identity->identity_str, 0x00, IDENTITY_STR_LEN);
    memset(identity->ipv4, 0x00, INET_ADDRSTRLEN);
    identity->port = 0;
  }

  return index;
}

/**
 * @brief print the hex identity string
 *
 * @param identity pointer to identity_t
 */

void print_identity_str(identity_t *identity) {
  if (identity == NULL) {
    fprintf(stderr, "[server]: received null pointer in print_identity_str()\n");
  }
  else {
    for (uint8_t i = 0; i < 32; i++) {
      fprintf(stdout, "%x", identity->identity_str[i]);
    }
    fprintf(stdout, "\n");
  }
}

