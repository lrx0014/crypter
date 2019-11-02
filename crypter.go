package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	data := flag.String("data", "", "input a string data")
	mode := flag.String("mode", "", "the mode can only be \"encode\" or \"decode\"")
	key := flag.String("key", "!@#lrx00", "optional: Specify the key used for encryption and decryption")
	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(0)
	}

	if *data == "" {
		flag.Usage()
		os.Exit(-1)
	}

	if *mode == "encode" {
		enData, _ := DesCBCEncrypt(*data, []byte(*key))
		fmt.Printf("Src: %s\n", *data)
		fmt.Printf("Encrypted: %s\n", enData)
	} else if *mode == "decode" {
		deData, _ := DesCBCDecrypt(*data, []byte(*key))
		fmt.Printf("Src: %s\n", *data)
		fmt.Printf("Decrypted: %s\n", deData)
	} else {
		flag.Usage()
		os.Exit(-1)
	}
}

func DesCBCEncrypt(origDataStr string, key []byte) (string, error) {
	origData := []byte(origDataStr)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	encodeString := base64.StdEncoding.EncodeToString(crypted)
	return encodeString, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DesCBCDecrypt(crypted string, key []byte) (string, error) {
	cryptedBytes, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		log.Fatalln(err)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	//origData := make([]byte, len(crypted))
	origData := cryptedBytes
	blockMode.CryptBlocks(origData, cryptedBytes)
	//origData = PKCS5UnPadding(origData)

	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
