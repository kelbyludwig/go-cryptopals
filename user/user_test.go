package user

import "testing"
import "github.com/kelbyludwig/cryptopals/xor"
import "github.com/kelbyludwig/cryptopals/aes"

func TestAdmin(t *testing.T) {
    u := Decode("user=kelby&uid=2&role=admin")
    if !u.IsAdmin(){
        t.Errorf("Admin: Should have returned true!")
    }
}

func TestNotAdmin(t *testing.T) {
    u := Decode("user=kelby&uid=2&role=user")
    if u.IsAdmin(){
        t.Errorf("Admin: Should have returned false!")
    }
}

//Test for set 2 challenge 13
func TestECBCutAndPaste(t *testing.T) {
    key := aes.RandBytes(16)
    oracle := func(in string) []byte { return ProfileFor(key, in) }
    //This payload will give me an padded admin block.
    payload1 := "kelbyXXXXXadmin\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
    //This payload will give me a ct with "role=" at a block border.
    payload2 := "kelbyXXXXXXXX"
    ct1 := oracle(payload1)
    ct2 := oracle(payload2)
    new_ct := append(ct2[:32], ct1[16:32]...)
    if !CTIsAdmin(key, new_ct) {
        t.Errorf("ECBCutAndPaste: Failed to create admin profile")
    }

}

func TestComment(t *testing.T) {
    key, iv, ct := EncryptComment("KELBY")
    if DecryptComment(key, iv, ct) {
        t.Errorf("Comment: False admin positive.")
    }
}

func TestCBCBitflip(t *testing.T) {
    as := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    admin := xor.Xor([]byte(";admin=true;\x00\x00\x00\x00"), []byte("AAAAAAAAAAAAAAAA"))
    key, iv, ct := EncryptComment(string(as))
    modblock := xor.Xor(ct[32:48], admin)
    ctpre := ct[:32]
    ctpost := ct[48:]
    newct := append(ctpre, modblock...)
    newct = append(newct, ctpost...)
    if !DecryptComment(key, iv, newct){
        t.Errorf("CBCBitflip: Failed to create admin block!")
    }

}
