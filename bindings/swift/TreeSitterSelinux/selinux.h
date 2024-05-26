#ifndef TREE_SITTER_SELINUX_H_
#define TREE_SITTER_SELINUX_H_

typedef struct TSLanguage TSLanguage;

#ifdef __cplusplus
extern "C" {
#endif

const TSLanguage *tree_sitter_selinux(void);

#ifdef __cplusplus
}
#endif

#endif // TREE_SITTER_SELINUX_H_
