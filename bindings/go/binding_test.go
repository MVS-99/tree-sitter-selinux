package tree_sitter_selinux_test

import (
	"testing"

	tree_sitter "github.com/smacker/go-tree-sitter"
	"github.com/tree-sitter/tree-sitter-selinux"
)

func TestCanLoadGrammar(t *testing.T) {
	language := tree_sitter.NewLanguage(tree_sitter_selinux.Language())
	if language == nil {
		t.Errorf("Error loading Selinux grammar")
	}
}
