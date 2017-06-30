/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HYPERVISOR_PARSER_H_
#define HYPERVISOR_PARSER_H_

#include <sys/types.h>

/* Parser Errors */
enum {
   PARSER_ERROR_NOMEM = 1,
   PARSER_ERROR_UNEXP_QUOTE,    /* Unexpected quote in a word */
   PARSER_ERROR_UNEXP_EOL,      /* Unexpected end of line */
};

/* Parser states */
enum {
   PARSER_STATE_DONE,
   PARSER_STATE_SKIP,
   PARSER_STATE_BLANK,
   PARSER_STATE_STRING,
   PARSER_STATE_QUOTED_STRING,
};

/* Token */
typedef struct parser_token parser_token_t;
struct parser_token {
   char *value;
   struct parser_token *next;
};

/* Parser context */
typedef struct parser_context parser_context_t;
struct parser_context {
   /* Token list */
   parser_token_t *tok_head,*tok_last;
   int tok_count;

   /* Temporary token */
   char *tmp_tok;
   size_t tmp_tot_len,tmp_cur_len;

   /* Parser state and error */
   int state,error;

   /* Number of consumed chars */
   size_t consumed_len;
};

/* Get a description given an error code */
char *parser_strerror(parser_context_t *ctx);

/* Dump a token list */
void parser_dump_tokens(parser_context_t *ctx);

/* Map a token list to an array */
char **parser_map_array(parser_context_t *ctx);

/* Initialize parser context */
void parser_context_init(parser_context_t *ctx);

/* Free memory used by a parser context */
void parser_context_free(parser_context_t *ctx);

/* Send a buffer to the tokenizer */
int parser_scan_buffer(parser_context_t *ctx,char *buf,size_t buf_size);

/* Tokenize a string */
int parser_tokenize(char *str,struct parser_token **tokens,int *tok_count);

#endif /* !HYPERVISOR_PARSER_H_ */
