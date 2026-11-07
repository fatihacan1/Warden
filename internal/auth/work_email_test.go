package auth

import "testing"

func TestBlockedWorkEmail(t *testing.T) {
	cases := []struct {
		name, email    string
		extra, allowed []string
		blocked        bool
	}{
		{"exact", "a@gmail.com", nil, nil, true},
		{"subdomain", "a@mail.gmail.com", nil, nil, true},
		{"case and whitespace", "  A@GMAIL.COM  ", nil, nil, true},
		{"boundary", "a@notgmail.com", nil, nil, false},
		{"company", "a@example.com", nil, nil, false},
		{"extra", "a@sub.example.com", []string{" Example.COM "}, nil, true},
		{"allowed wins", "a@sub.gmail.com", []string{"gmail.com"}, []string{" GMAIL.COM "}, false},
		{"missing email", "", nil, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockedWorkEmail(tc.email, tc.extra, tc.allowed); got != tc.blocked {
				t.Fatalf("got %v, want %v", got, tc.blocked)
			}
		})
	}
}
