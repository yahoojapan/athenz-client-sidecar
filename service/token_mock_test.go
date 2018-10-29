package service

import (
	"time"

	"github.com/yahoo/athenz/libs/go/zmssvctoken"
)

type mockTokenBuilder struct {
	valueFunc valueFunc // mock function of zmssvctoken.TokenBuilder.Value()
}

type valueFunc func() (string, error)

type mockToken struct {
	valueFunc valueFunc
}

// NewMockTokenBuilder create a mock object of zmssvctoken.TokenBuilder
func NewMockTokenBuilder() zmssvctoken.TokenBuilder {
	return &mockTokenBuilder{}
}

// NewMockToken create a mock object of zmssvctoken.Token
func NewMockToken() zmssvctoken.Token {
	return &mockToken{}
}

// SetExpiration return a mock value of zmssvctoken.TokenBuilder.SetExpiration() function
func (mt *mockTokenBuilder) SetExpiration(t time.Duration) {
	//TODO some mocking
}

// SetHostname return a mock value of zmssvctoken.TokenBuilder.SetHostname() function
func (mt *mockTokenBuilder) SetHostname(h string) {
	//TODO some mocking
}

// SetIPAddress return a mock value of zmssvctoken.TokenBuilder.SetIPAddress() function
func (mt *mockTokenBuilder) SetIPAddress(ip string) {
	//TODO some mocking
}

// SetKeyService return a mock value of zmssvctoken.TokenBuilder.SetKeyService() function
func (mt *mockTokenBuilder) SetKeyService(keyService string) {
	//TODO some mocking
}

// Token return a mock object of zmssvctoken.Token.
func (mt *mockTokenBuilder) Token() zmssvctoken.Token {
	t := &mockToken{}
	t.valueFunc = mt.valueFunc
	return t
}

// Value return a mock value of zmssvctoken.TokenBuilder.Value() function.
// Example:
// tb := NewMockTokenBuilder()
// tb.(*mockTokenBuilder).valueFunc = func() (string, error) {
//	 // mock function logic
// }
func (mt *mockToken) Value() (string, error) {
	return mt.valueFunc()
}
