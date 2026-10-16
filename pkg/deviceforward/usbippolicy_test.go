package deviceforward

import (
	"encoding/binary"
	"testing"
)

func opCommon(code uint16) []byte {
	b := make([]byte, opCommonSize)
	binary.BigEndian.PutUint16(b[0:2], usbipVersion)
	binary.BigEndian.PutUint16(b[2:4], code)
	return b
}

func importReq(busid string) []byte {
	b := make([]byte, opReqImportSize)
	copy(b, opCommon(opReqImport))
	copy(b[opCommonSize:], []byte(busid))
	return b
}

func TestParseUSBIPRequest(t *testing.T) {
	// Import for "3-1".
	req, n, ok, err := parseUSBIPRequest(importReq("3-1"))
	if err != nil || !ok {
		t.Fatalf("parse import: ok=%v err=%v", ok, err)
	}
	if req.Code != opReqImport || req.BusID != "3-1" || n != opReqImportSize {
		t.Fatalf("got code=%#x busid=%q n=%d", req.Code, req.BusID, n)
	}

	// Devlist.
	req, n, ok, err = parseUSBIPRequest(opCommon(opReqDevlist))
	if err != nil || !ok || req.Code != opReqDevlist || n != opCommonSize {
		t.Fatalf("devlist: req=%+v n=%d ok=%v err=%v", req, n, ok, err)
	}

	// Partial import: header present, busid missing → need more.
	_, _, ok, err = parseUSBIPRequest(opCommon(opReqImport))
	if ok || err != nil {
		t.Fatalf("partial import should want more bytes: ok=%v err=%v", ok, err)
	}

	// Wrong version.
	bad := importReq("3-1")
	binary.BigEndian.PutUint16(bad[0:2], 0x0200)
	if _, _, _, err := parseUSBIPRequest(bad); err == nil {
		t.Fatal("expected a version error")
	}

	// Unknown code.
	if _, _, _, err := parseUSBIPRequest(opCommon(0x1234)); err == nil {
		t.Fatal("expected an unknown-code error")
	}
}
