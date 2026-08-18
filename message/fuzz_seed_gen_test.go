package message

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestGenerateFuzzCorpus programmatically constructs valid LDAP messages of
// every protocol op type (and every filter variant), serializes them via
// Write(), and saves them as Go fuzz corpus entries.  The fuzzers then start
// from these structurally valid messages and mutate them, reaching deep parser
// code paths that random bytes almost never hit.
//
// Run with:  go test -run TestGenerateFuzzCorpus ./message/
func TestGenerateFuzzCorpus(t *testing.T) {
	messages := buildSeedMessages()

	for _, dir := range []string{
		"testdata/fuzz/FuzzReadLDAPMessage",
		"testdata/fuzz/FuzzRoundTrip",
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, sm := range messages {
		written, err := sm.msg.Write()
		if err != nil {
			t.Fatalf("Write failed for %s: %v", sm.name, err)
		}

		// Verify it round-trips.
		b := Bytes{offset: 0, bytes: written.getBytes()}
		_, err = ReadLDAPMessage(&b)
		if err != nil {
			t.Fatalf("ReadLDAPMessage failed for %s: %v", sm.name, err)
		}

		// Write corpus entry to both fuzz targets.
		for _, dir := range []string{
			"testdata/fuzz/FuzzReadLDAPMessage",
			"testdata/fuzz/FuzzRoundTrip",
		} {
			writeSeedFile(t, filepath.Join(dir, "gen_"+sm.name), written.getBytes())
		}
	}

	// Write malformed/edge-case inputs that can't be produced by Write().
	// These only go to FuzzReadLDAPMessage (they are intentionally invalid,
	// so FuzzRoundTrip would just skip them).
	edgeCases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"zero_length_seq", []byte{0x30, 0x00}},
		{"indefinite_length", []byte{0x30, 0x80}},
		{"huge_length", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}},
		{"truncated_seq", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
	}
	for _, ec := range edgeCases {
		writeSeedFile(t, filepath.Join("testdata/fuzz/FuzzReadLDAPMessage", "gen_edge_"+ec.name), ec.data)
	}

	t.Logf("Generated %d seed corpus entries + %d edge cases", len(messages), len(edgeCases))
}

type seedMessage struct {
	name string
	msg  LDAPMessage
}

func writeSeedFile(t *testing.T, path string, data []byte) {
	t.Helper()
	var b strings.Builder
	b.WriteString("go test fuzz v1\n[]byte(\"")
	for _, c := range data {
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteString("\")\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ldapdnPtr(s string) *LDAPDN           { d := LDAPDN(s); return &d }
func octetPtr(s string) *OCTETSTRING        { o := OCTETSTRING(s); return &o }
func oidPtr(s string) *LDAPOID              { o := LDAPOID(s); return &o }

func resultOK() LDAPResult {
	return LDAPResult{
		resultCode:        ResultCodeSuccess,
		matchedDN:         "",
		diagnosticMessage: "",
	}
}

func resultWithReferral() LDAPResult {
	ref := Referral([]URI{"ldap://other.example.com/dc=example,dc=com"})
	return LDAPResult{
		resultCode:        ResultCodeReferral,
		matchedDN:         "dc=example,dc=com",
		diagnosticMessage: "referral",
		referral:          ref.Pointer(),
	}
}

// --- Filters ---

func filterPresent() Filter {
	return FilterPresent("objectClass")
}

func filterEquality() Filter {
	return FilterEqualityMatch(AttributeValueAssertion{
		attributeDesc:  "cn",
		assertionValue: "admin",
	})
}

func filterSubstringInitial() Filter {
	return FilterSubstrings(SubstringFilter{
		type_:      "cn",
		substrings: []Substring{SubstringInitial("adm")},
	})
}

func filterSubstringAny() Filter {
	return FilterSubstrings(SubstringFilter{
		type_:      "cn",
		substrings: []Substring{SubstringAny("mid")},
	})
}

func filterSubstringFinal() Filter {
	return FilterSubstrings(SubstringFilter{
		type_:      "cn",
		substrings: []Substring{SubstringFinal("in")},
	})
}

func filterSubstringAll() Filter {
	return FilterSubstrings(SubstringFilter{
		type_: "cn",
		substrings: []Substring{
			SubstringInitial("a"),
			SubstringAny("b"),
			SubstringAny("c"),
			SubstringFinal("d"),
		},
	})
}

func filterGE() Filter {
	return FilterGreaterOrEqual(AttributeValueAssertion{
		attributeDesc:  "uidNumber",
		assertionValue: "1000",
	})
}

func filterLE() Filter {
	return FilterLessOrEqual(AttributeValueAssertion{
		attributeDesc:  "uidNumber",
		assertionValue: "9999",
	})
}

func filterApprox() Filter {
	return FilterApproxMatch(AttributeValueAssertion{
		attributeDesc:  "cn",
		assertionValue: "jon",
	})
}

func filterExtensibleFull() Filter {
	mr := MatchingRuleId("1.2.840.113556.1.4.803")
	ad := AttributeDescription("sAMAccountType")
	return FilterExtensibleMatch(MatchingRuleAssertion{
		matchingRule: mr.Pointer(),
		type_:        &ad,
		matchValue:   "805306368",
		dnAttributes: true,
	})
}

func filterExtensibleMinimal() Filter {
	return FilterExtensibleMatch(MatchingRuleAssertion{
		matchValue:   "test",
		dnAttributes: false,
	})
}

func filterAnd() Filter {
	return FilterAnd([]Filter{filterPresent(), filterEquality()})
}

func filterOr() Filter {
	return FilterOr([]Filter{filterGE(), filterLE()})
}

func filterNot() Filter {
	return FilterNot{filterPresent()}
}

func filterDeep() Filter {
	return FilterAnd([]Filter{
		FilterOr([]Filter{
			filterEquality(),
			FilterNot{filterApprox()},
		}),
		filterPresent(),
		filterExtensibleFull(),
	})
}

// --- Search requests with various filters ---

func searchRequest(filter Filter) SearchRequest {
	return SearchRequest{
		baseObject:   "dc=example,dc=com",
		scope:        ENUMERATED(2),
		derefAliases: ENUMERATED(0),
		sizeLimit:    100,
		timeLimit:    30,
		typesOnly:    false,
		filter:       filter,
		attributes:   AttributeSelection{"cn", "mail", "uid"},
	}
}

// --- Controls ---

func controlSimple() Controls {
	return Controls{
		Control{
			controlType: "1.2.840.113556.1.4.319",
			criticality: true,
			controlValue: octetPtr("\x30\x05\x02\x01\x05\x04\x00"),
		},
	}
}

func controlNoCritNoval() Controls {
	return Controls{
		Control{
			controlType: "2.16.840.1.113730.3.4.2",
			criticality: false,
		},
	}
}

func buildSeedMessages() []seedMessage {
	var seeds []seedMessage
	id := MessageID(0)

	add := func(name string, op ProtocolOp, controls *Controls) {
		id++
		seeds = append(seeds, seedMessage{
			name: name,
			msg: LDAPMessage{
				messageID:  id,
				protocolOp: op,
				controls:   controls,
			},
		})
	}

	// --- BindRequest ---
	add("bind_simple", BindRequest{
		version:        3,
		name:           "cn=admin,dc=example,dc=com",
		authentication: OCTETSTRING("secret"),
	}, nil)

	creds := OCTETSTRING("sasl-data")
	add("bind_sasl", BindRequest{
		version: 3,
		name:    "",
		authentication: SaslCredentials{
			mechanism:   "GSSAPI",
			credentials: &creds,
		},
	}, nil)

	add("bind_sasl_no_creds", BindRequest{
		version: 3,
		name:    "",
		authentication: SaslCredentials{
			mechanism: "EXTERNAL",
		},
	}, nil)

	// --- BindResponse ---
	add("bind_response_ok", BindResponse{
		LDAPResult: resultOK(),
	}, nil)

	add("bind_response_sasl_creds", BindResponse{
		LDAPResult:      resultOK(),
		serverSaslCreds: octetPtr("server-sasl-data"),
	}, nil)

	add("bind_response_referral", BindResponse{
		LDAPResult: resultWithReferral(),
	}, nil)

	// --- UnbindRequest ---
	add("unbind", UnbindRequest{}, nil)

	// --- SearchRequest with every filter type ---
	filterSeeds := []struct {
		name   string
		filter Filter
	}{
		{"present", filterPresent()},
		{"equality", filterEquality()},
		{"substr_initial", filterSubstringInitial()},
		{"substr_any", filterSubstringAny()},
		{"substr_final", filterSubstringFinal()},
		{"substr_all", filterSubstringAll()},
		{"ge", filterGE()},
		{"le", filterLE()},
		{"approx", filterApprox()},
		{"extensible_full", filterExtensibleFull()},
		{"extensible_minimal", filterExtensibleMinimal()},
		{"and", filterAnd()},
		{"or", filterOr()},
		{"not", filterNot()},
		{"deep_nested", filterDeep()},
	}
	for _, fs := range filterSeeds {
		add("search_"+fs.name, searchRequest(fs.filter), nil)
	}

	// Search with empty attributes list
	sr := searchRequest(filterPresent())
	sr.attributes = AttributeSelection{}
	add("search_no_attrs", sr, nil)

	// Search with typesOnly=true
	sr = searchRequest(filterPresent())
	sr.typesOnly = true
	add("search_types_only", sr, nil)

	// --- SearchResultEntry ---
	add("search_result_entry", SearchResultEntry{
		objectName: "cn=admin,dc=example,dc=com",
		attributes: PartialAttributeList{
			{type_: "cn", vals: []AttributeValue{"admin"}},
			{type_: "mail", vals: []AttributeValue{"admin@example.com"}},
			{type_: "objectClass", vals: []AttributeValue{"top", "person", "inetOrgPerson"}},
		},
	}, nil)

	add("search_result_entry_empty_vals", SearchResultEntry{
		objectName: "cn=test,dc=example,dc=com",
		attributes: PartialAttributeList{
			{type_: "cn", vals: []AttributeValue{}},
		},
	}, nil)

	// --- SearchResultDone ---
	add("search_result_done_ok", SearchResultDone(resultOK()), nil)
	add("search_result_done_referral", SearchResultDone(resultWithReferral()), nil)

	// --- SearchResultReference ---
	add("search_result_reference", SearchResultReference([]URI{
		"ldap://host1.example.com/dc=example,dc=com",
		"ldap://host2.example.com/dc=example,dc=com",
	}), nil)

	// --- ModifyRequest ---
	add("modify_add", ModifyRequest{
		object: "cn=test,dc=example,dc=com",
		changes: []ModifyRequestChange{
			{
				operation: ModifyRequestChangeOperationAdd,
				modification: PartialAttribute{
					type_: "mail",
					vals:  []AttributeValue{"test@example.com"},
				},
			},
		},
	}, nil)

	add("modify_delete_replace", ModifyRequest{
		object: "cn=test,dc=example,dc=com",
		changes: []ModifyRequestChange{
			{
				operation: ModifyRequestChangeOperationDelete,
				modification: PartialAttribute{
					type_: "mail",
					vals:  []AttributeValue{},
				},
			},
			{
				operation: ModifyRequestChangeOperationReplace,
				modification: PartialAttribute{
					type_: "description",
					vals:  []AttributeValue{"new description"},
				},
			},
		},
	}, nil)

	// --- ModifyResponse ---
	add("modify_response", ModifyResponse(resultOK()), nil)

	// --- AddRequest ---
	add("add_request", AddRequest{
		entry: "cn=new,dc=example,dc=com",
		attributes: AttributeList{
			Attribute{type_: "objectClass", vals: []AttributeValue{"top", "person"}},
			Attribute{type_: "cn", vals: []AttributeValue{"new"}},
			Attribute{type_: "sn", vals: []AttributeValue{"user"}},
		},
	}, nil)

	// --- AddResponse ---
	add("add_response", AddResponse(resultOK()), nil)

	// --- DelRequest ---
	add("del_request", DelRequest("cn=old,dc=example,dc=com"), nil)

	// --- DelResponse ---
	add("del_response", DelResponse(resultOK()), nil)

	// --- ModifyDNRequest ---
	add("moddn_basic", ModifyDNRequest{
		entry:        "cn=old,dc=example,dc=com",
		newrdn:       "cn=new",
		deleteoldrdn: true,
	}, nil)

	add("moddn_new_superior", ModifyDNRequest{
		entry:        "cn=user,ou=old,dc=example,dc=com",
		newrdn:       "cn=user",
		deleteoldrdn: false,
		newSuperior:  ldapdnPtr("ou=new,dc=example,dc=com"),
	}, nil)

	// --- ModifyDNResponse ---
	add("moddn_response", ModifyDNResponse(resultOK()), nil)

	// --- CompareRequest ---
	add("compare_request", CompareRequest{
		entry: "cn=test,dc=example,dc=com",
		ava: AttributeValueAssertion{
			attributeDesc:  "userPassword",
			assertionValue: "secret",
		},
	}, nil)

	// --- CompareResponse ---
	add("compare_response_true", CompareResponse(LDAPResult{
		resultCode:        ResultCodeCompareTrue,
		matchedDN:         "",
		diagnosticMessage: "",
	}), nil)

	add("compare_response_false", CompareResponse(LDAPResult{
		resultCode:        ResultCodeCompareFalse,
		matchedDN:         "",
		diagnosticMessage: "",
	}), nil)

	// --- AbandonRequest ---
	add("abandon", AbandonRequest(42), nil)

	// --- ExtendedRequest ---
	add("extended_request_name_only", ExtendedRequest{
		requestName: "1.3.6.1.4.1.1466.20037",
	}, nil)

	add("extended_request_with_value", ExtendedRequest{
		requestName:  "1.3.6.1.4.1.4203.1.11.1",
		requestValue: octetPtr("extended-payload"),
	}, nil)

	// --- ExtendedResponse ---
	add("extended_response_minimal", ExtendedResponse{
		LDAPResult: resultOK(),
	}, nil)

	add("extended_response_full", ExtendedResponse{
		LDAPResult:    resultOK(),
		responseName:  oidPtr("1.3.6.1.4.1.1466.20037"),
		responseValue: octetPtr("response-data"),
	}, nil)

	// --- IntermediateResponse ---
	add("intermediate_response_empty", IntermediateResponse{}, nil)

	add("intermediate_response_name", IntermediateResponse{
		responseName: oidPtr("1.3.6.1.4.1.4203.1.9.2"),
	}, nil)

	add("intermediate_response_full", IntermediateResponse{
		responseName:  oidPtr("1.3.6.1.4.1.4203.1.9.2"),
		responseValue: octetPtr("sync-data"),
	}, nil)

	// --- Messages with controls ---
	add("search_with_control", searchRequest(filterPresent()), controlSimple().Pointer())
	add("bind_with_control", BindRequest{
		version:        3,
		name:           "cn=admin,dc=example,dc=com",
		authentication: OCTETSTRING("secret"),
	}, controlNoCritNoval().Pointer())

	// --- Boundary message IDs ---
	for _, mid := range []MessageID{0, 1, 127, 128, 255, 256, 32767, 32768} {
		seeds = append(seeds, seedMessage{
			name: "msgid_" + strconv.Itoa(int(mid)),
			msg: LDAPMessage{
				messageID: mid,
				protocolOp: BindRequest{
					version:        3,
					name:           "",
					authentication: OCTETSTRING(""),
				},
			},
		})
	}

	return seeds
}

