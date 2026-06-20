package dnsrecon

import "testing"

func TestClassifyDNSResponseRejectsNXDOMAINAsMissing(t *testing.T) {
	response := testDNSResponse(257, 0xABCE, 3, nil)
	if got := classifyDNSResponse(response, 257, 0xABCE); got != caaUnknown {
		t.Fatalf("NXDOMAIN must be inconclusive, got %v", got)
	}
}

func TestClassifyDNSResponseValidatesTransactionID(t *testing.T) {
	response := testDNSResponse(257, 0xBEEF, 0, nil)
	if got := classifyDNSResponse(response, 257, 0xABCE); got != caaUnknown {
		t.Fatalf("mismatched transaction ID must be inconclusive, got %v", got)
	}
}

func TestClassifyDNSResponseConfirmsEmptyAnswer(t *testing.T) {
	response := testDNSResponse(257, 0xABCE, 0, nil)
	if got := classifyDNSResponse(response, 257, 0xABCE); got != caaMissing {
		t.Fatalf("validated NOERROR empty answer should be missing, got %v", got)
	}
}

func TestClassifyDNSResponseRequiresRequestedRecordType(t *testing.T) {
	cnameOnly := testDNSResponse(257, 0xABCE, 0, []uint16{5})
	if got := classifyDNSResponse(cnameOnly, 257, 0xABCE); got != caaUnknown {
		t.Fatalf("CNAME-only answer must be inconclusive, got %v", got)
	}

	caa := testDNSResponse(257, 0xABCE, 0, []uint16{257})
	if got := classifyDNSResponse(caa, 257, 0xABCE); got != caaPresent {
		t.Fatalf("CAA answer should be present, got %v", got)
	}
}

func testDNSResponse(qtype, id uint16, rcode byte, answerTypes []uint16) []byte {
	question := append(encodeDNSName("example.com"), byte(qtype>>8), byte(qtype), 0x00, 0x01)
	response := []byte{
		byte(id >> 8), byte(id),
		0x81, rcode & 0x0F,
		0x00, 0x01,
		byte(len(answerTypes) >> 8), byte(len(answerTypes)),
		0x00, 0x00,
		0x00, 0x00,
	}
	response = append(response, question...)
	for _, recordType := range answerTypes {
		response = append(response,
			0xC0, 0x0C,
			byte(recordType>>8), byte(recordType),
			0x00, 0x01,
			0x00, 0x00, 0x00, 0x3C,
			0x00, 0x01,
			0x00,
		)
	}
	return response
}
