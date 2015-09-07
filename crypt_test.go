package aescrypt

import "testing"

func TestAesCrypt(t *testing.T) {

	key := []byte(toMD5("fefasef52458g456f8h7t8j4ghj9s68ry5ghtut"))
	origtext := []byte("3eceef209806decbbb2f4e47d2da6607ce96270f0003473bda")

	encrytext, err := AesEncrypt(origtext, key)
	if err != nil {
		t.Error(err)
	}
	//	fmt.Println(UrlSafeBase64Encode(encrytext))
	decrytext, err := AesDecrypt(encrytext, key)
	if err != nil {
		t.Error(err)
	}
	//	fmt.Println(string(decrytext))
	if string(origtext) != string(decrytext) {
		t.Error(err)
	}
}
