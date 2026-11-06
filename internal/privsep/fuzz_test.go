package privsep

import "testing"

func FuzzPacketDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not-gob"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPacket {
			t.Skip()
		}
		_, _ = decodePacket(data)
	})
}
