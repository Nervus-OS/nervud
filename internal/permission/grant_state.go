package permission

// GrantState is the system-owned runtime decision for a USER_CONSENT
// permission. Install eligibility and runtime consent remain separate facts.
type GrantState uint8

const (
	GrantStateNotRequested GrantState = iota
	GrantStateGranted
	GrantStateDenied
	GrantStateDeniedPermanent
)

func (s GrantState) valid() bool {
	return s == GrantStateNotRequested || s == GrantStateGranted ||
		s == GrantStateDenied || s == GrantStateDeniedPermanent
}
