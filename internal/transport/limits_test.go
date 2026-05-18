package transport

import "testing"

func TestDimsInBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rows uint16
		cols uint16
		want bool
	}{
		// Happy path.
		{"typical 80x24", 24, 80, true},
		{"iPad portrait approx", 50, 80, true},
		{"iPad landscape approx", 30, 120, true},

		// Floor.
		{"min boundary", MinPTYRows, MinPTYCols, true},
		{"zero rows", 0, 80, false},
		{"zero cols", 24, 0, false},
		{"both zero", 0, 0, false},
		{"one by one", 1, 1, false},
		{"under-floor rows", MinPTYRows - 1, 80, false},
		{"under-floor cols", 24, MinPTYCols - 1, false},

		// Ceiling.
		{"max boundary", MaxPTYRows, MaxPTYCols, true},
		{"over-ceiling rows", MaxPTYRows + 1, 80, false},
		{"over-ceiling cols", 24, MaxPTYCols + 1, false},
		{"u16 max", 65535, 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dimsInBounds(tc.rows, tc.cols); got != tc.want {
				t.Fatalf("dimsInBounds(%d, %d) = %v, want %v",
					tc.rows, tc.cols, got, tc.want)
			}
		})
	}
}
