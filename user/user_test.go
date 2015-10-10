package user

import "testing"

func TestAdmin(t *testing.T) {
    u := Decode("user=kelby&uid=2&role=admin")
    if !u.IsAdmin(){
        t.Errorf("Admin: Should have returned true!")
    }
    t.Log(u.Encode())
}

func TestNotAdmin(t *testing.T) {
    u := Decode("user=kelby&uid=2&role=user")
    if u.IsAdmin(){
        t.Errorf("Admin: Should have returned false!")
    }
}
