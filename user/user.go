package user

import "github.com/kelbyludwig/cryptopals/aes"
import "strings"

type User struct {
    role string
    uid string
    email string
}

func (u *User) IsAdmin() bool {
    //padding screws this up. not a big deal tho. simulate padding removal
    if strings.Contains(u.role,"admin") {
        return true
    } else {
        return false
    }
}

func (u *User) Encode() string {
    var result string
    result = "email=" + u.email + "&"
    result += "uid=" + u.uid + "&"
    result += "role=" + u.role
    return result
}

func Decode(input string) User {
    m := ParseKV(input)
    return CreateUser(m)
}

func ParseKV(kv string) map[string]string {
    kvs := strings.Split(kv, "&")
    look := make(map[string]string)
    for _,s := range kvs {
        arr := strings.Split(s, "=")
        //Get rid of pesky hackers who use & in their email!
        enc_key := strings.Split(arr[0], "&")[0]
        enc_val := strings.Split(arr[1], "&")[0]
        look[enc_key] = enc_val
    }
    return look
}

func CreateUser(kvs map[string]string) User {
    return User{role:kvs["role"], uid:kvs["uid"], email:kvs["email"]}
}

func ProfileFor(key []byte, profile string) []byte {
    u := User{role:"user", uid:"17", email:profile}
    ue := []byte(u.Encode())
    return aes.ECBEncrypt(key, aes.Pad(ue, 16))
}

func CTIsAdmin(key []byte, ct []byte) bool {
   profile := DecryptCookie(key, ct)
   u := Decode(profile)
   return u.IsAdmin()
}

func DecryptCookie(key []byte, ct []byte) string {
    return string(aes.ECBDecrypt(key, ct))
}

//For simplicity sake, return key and iv too.
func EncryptComment(comment string) (key, iv, ciphertext []byte) {
    pre := []byte("comment1=cooking%20MCs;userdata=")
    //Eat illegal characters
    comment = strings.Split(comment, ";")[0]
    comment = strings.Split(comment, "=")[0]
    combytes := []byte(comment)
    post := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
    plaintext := append(pre, combytes...)
    plaintext = append(plaintext, post...)
    plaintext = aes.Pad(plaintext, 16)
    key = aes.RandBytes(16)
    iv = aes.RandBytes(16)
    ciphertext = aes.CBCEncrypt(key, iv, plaintext)
    return
}

func DecryptComment(key, iv, ciphertext []byte) bool {
    plaintext := aes.CBCDecrypt(key, iv, ciphertext)
    if strings.Contains(string(plaintext), ";admin=true;") {
         return true
    } else {
         return false
    }
}
