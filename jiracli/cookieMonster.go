package jiracli

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"os/exec"
	"os/user"

	// called indirectly by database/sql
	_ "github.com/mattn/go-sqlite3"
)

var (
	salt       = "saltysalt"
	iv         = "                "
	length     = 16
	password   = ""
	iterations = 1003
)

func decryptValue(encryptedValue []byte) string {
	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, length, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	decrypted := make([]byte, len(encryptedValue))
	cbc := cipher.NewCBCDecrypter(block, []byte(iv))
	cbc.CryptBlocks(decrypted, encryptedValue)

	plainText, err := aesStripPadding(decrypted)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return ""
	}
	return string(plainText)
}

// In the padding scheme the last <padding length> bytes
// have a value equal to the padding length, always in (1,16]
func aesStripPadding(data []byte) ([]byte, error) {
	if len(data)%length != 0 {
		return nil, fmt.Errorf("decrypted data block length is not a multiple of %d", length)
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > 16 {
		return nil, fmt.Errorf("invalid last block padding length: %d", paddingLen)
	}
	return data[:len(data)-paddingLen], nil
}

func getPassword() string {
	parts := strings.Fields("security find-generic-password -wga Chrome")
	cmd := parts[0]
	parts = parts[1:]

	out, err := exec.Command(cmd, parts...).Output()
	if err != nil {
		log.Fatal("error finding password ", err)
	}
	pass := strings.Trim(string(out), "\n")
	// log.Warningf("password: %s\n", pass)
	return pass
}

func GetCookies(domain string, keys []string) (cookies []*http.Cookie) {
	password = getPassword()
	usr, _ := user.Current()
	twoDays, _ := time.ParseDuration("48h")
	expires := time.Now().Add(twoDays)
	cookiesFile := fmt.Sprintf("%s/Library/Application Support/Google/Chrome/Default/Cookies", usr.HomeDir)
	cookieSet := make(map[string]struct{}, len(cookies))
	for _, s := range keys {
		cookieSet[s] = struct{}{}
	}
	isKeyAllowed := func(key string) bool {
		_, ok := cookieSet[key]
		return ok
	}

	db, err := sql.Open("sqlite3", cookiesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT name, value, host_key, encrypted_value, path, is_secure, is_httponly FROM cookies WHERE host_key like ?", fmt.Sprintf("%%%s%%", domain))
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()
	for rows.Next() {
		var name, value, hostKey, path string
		var encryptedValue []byte
		var isSecure, isHttponly bool

		rows.Scan(&name, &value, &hostKey, &encryptedValue, &path, &isSecure, &isHttponly)

		if isKeyAllowed(name) {
			cookies = append(cookies, &http.Cookie{
				Name:       name,
				Value:      decryptValue(encryptedValue[3:]),
				Path:       path,
				Domain:     hostKey,
				Expires:    expires,
				RawExpires: "",
				MaxAge:     0,
				Secure:     isSecure,
				HttpOnly:   false,
				SameSite:   0,
				Raw:        "",
				Unparsed:   nil,
			})
		}
	}
	return
}
