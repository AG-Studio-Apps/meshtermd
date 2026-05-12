package main

import (
	"testing"
	"time"
)

func TestDecideUnderline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mode string
		rtt  time.Duration
		want bool
	}{
		{"always low rtt", predictModeAlways, 10 * time.Millisecond, true},
		{"always high rtt", predictModeAlways, 500 * time.Millisecond, true},
		{"always zero rtt", predictModeAlways, 0, true},
		{"never low rtt", predictModeNever, 10 * time.Millisecond, false},
		{"never high rtt", predictModeNever, 500 * time.Millisecond, false},
		{"adaptive below threshold", predictModeAdaptive, 50 * time.Millisecond, false},
		{"adaptive at threshold", predictModeAdaptive, adaptivePredictUnderlineRTT, false},
		{"adaptive just above threshold", predictModeAdaptive, adaptivePredictUnderlineRTT + time.Millisecond, true},
		{"adaptive far above threshold", predictModeAdaptive, 500 * time.Millisecond, true},
		{"adaptive zero rtt", predictModeAdaptive, 0, false},
		{"unknown mode falls back to false", "garbage", 500 * time.Millisecond, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := decideUnderline(tc.mode, tc.rtt); got != tc.want {
				t.Errorf("decideUnderline(%q, %v) = %v, want %v",
					tc.mode, tc.rtt, got, tc.want)
			}
		})
	}
}
