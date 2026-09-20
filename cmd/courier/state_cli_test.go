package main

import (
	"reflect"
	"testing"
)

func TestSplitStateFlags(t *testing.T) {
	specs := map[string]bool{"title": true, "body": true, "escalate": false}
	cases := []struct {
		name     string
		args     []string
		wantPos  []string
		wantFlag map[string]string
	}{
		{
			name:     "documented form: flags after peer",
			args:     []string{"lane", "--title", "Agenda", "--body", "milk"},
			wantPos:  []string{"lane"},
			wantFlag: map[string]string{"title": "Agenda", "body": "milk"},
		},
		{
			name:     "flags before peer",
			args:     []string{"--title", "Agenda", "lane"},
			wantPos:  []string{"lane"},
			wantFlag: map[string]string{"title": "Agenda"},
		},
		{
			name:     "equals form and boolean flag",
			args:     []string{"lane", "--title=Agenda", "--escalate"},
			wantPos:  []string{"lane"},
			wantFlag: map[string]string{"title": "Agenda", "escalate": "true"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, flags, err := splitStateFlags(tc.args, specs)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pos, tc.wantPos) {
				t.Errorf("pos = %v, want %v", pos, tc.wantPos)
			}
			if !reflect.DeepEqual(flags, tc.wantFlag) {
				t.Errorf("flags = %v, want %v", flags, tc.wantFlag)
			}
		})
	}
}

func TestSplitStateFlagsErrors(t *testing.T) {
	specs := map[string]bool{"title": true, "escalate": false}
	for _, args := range [][]string{
		{"lane", "--bogus"},
		{"lane", "--title"},
		{"lane", "--escalate=yes"},
		{"lane", "-x"},
	} {
		if _, _, err := splitStateFlags(args, specs); err == nil {
			t.Errorf("args %v: want error, got nil", args)
		}
	}
}
