#include "tree_sitter/parser.h"

enum TokenType {
  _IF,
  _FC,
  _TE,
};

void *tree_sitter_selinux_external_scanner_create() {
  return NULL;
}

void tree_sitter_selinux_external_scanner_destroy(void *payload) {}

unsigned tree_sitter_selinux_external_scanner_serialize(void *payload, char *buffer) {
  return 0;
}

void tree_sitter_selinux_external_scanner_deserialize(void *payload, const char *buffer, unsigned length) {}

bool tree_sitter_selinux_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols) {
  if (valid_symbols[_IF]) {
    lexer->result_symbol = _IF;
    return true;
  }

  if (valid_symbols[_FC]) {
    lexer->result_symbol = _FC;
    return true;
  }

  if (valid_symbols[_TE]) {
    lexer->result_symbol = _TE;
    return true;
  }

  return false;
}
