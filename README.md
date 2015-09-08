# aescrypt
AES 128 pkcs5 padding encrypt

Example:
```go
package main()

import (
	"github.com/coseyo/aescrypt"
	"fmt"
)
func main() {
	key := []byte("fefasef52458g456f8h7t8j4ghj9s68ry5ghtut")
	origtext := []byte("3eceef209806decbbb2f4e47d2da6607ce96270f0003473bda")

	encrytext, err := aescrypt.Encrypt(origtext, key)
	if err != nil {
		fmt.Println(err)
	}
	//	fmt.Println(aescrypt.UrlSafeBase64Encode(encrytext))
	decrytext, err := aescrypt.Decrypt(encrytext, key)
	if err != nil {
		fmt.Println(err)
	}
	//	fmt.Println(string(decrytext))
	if string(origtext) != string(decrytext) {
		fmt.Println(err)
	}
}

```
