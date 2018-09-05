package cookie

type Verifier interface {
	Verify(*Payload) error
}
