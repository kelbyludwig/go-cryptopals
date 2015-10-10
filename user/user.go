package user

import "strings"
import "html"

type User struct {
    role string
    uid string
    email string
}

func (u *User) IsAdmin() bool {
    if u.role == "admin" {
        return true
    } else {
        return false
    }
}

func (u *User) Encode() string {
    var result string
    result = "email=" + u.email + "&"
    result += "uid=" + u.uid + "&"
    result += "role" + u.role
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
        enc_key := html.EscapeString(arr[0])
        enc_val := html.EscapeString(arr[1])
        look[enc_key] = enc_val
    }
    return look
}

func CreateUser(kvs map[string]string) User {
    return User{role:kvs["role"], uid:kvs["uid"], email:kvs["email"]}
}
