package message

import (
	"encoding/hex"
	"testing"
)

func TestReadSearchRequestWithExtensibleMatchFilter(t *testing.T) {
	raw := "3081f30201026381ed040e44433d636c2c44433d6c6f63616c0a01020a010002010002011e010100a0819ba318040e6f626a65637443617465676f72790406706572736f6ea313040b6f626a656374436c617373040475736572a231a92f8116312e322e3834302e3131333535362e312e342e3830338212757365724163636f756e74436f6e74726f6c830132a33704086d656d6265724f66042b434e3d61636c2e6b38732d73746167652e757365722c4f553d41434c2c44433d636c2c44433d6c6f63616c302e0402646e040e73414d4163636f756e744e616d6504046d61696c0412757365724163636f756e74436f6e74726f6c"

	data, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := ReadLDAPMessage(NewBytes(0, data))
	if err != nil {
		t.Fatal(err)
	}

	req, ok := msg.ProtocolOp().(SearchRequest)
	if !ok {
		t.Fatalf("unexpected protocol op type: %T", msg.ProtocolOp())
	}

	got := req.FilterString()
	want := "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=CN=acl.k8s-stage.user,OU=ACL,DC=cl,DC=local))"

	if got != want {
		t.Fatalf("filter mismatch\ngot:  %s\nwant: %s", got, want)
	}
}
