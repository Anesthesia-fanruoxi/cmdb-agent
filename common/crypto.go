package common

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// DecryptAndDecompress 解密并解压数据
func DecryptAndDecompress(data string, salt string) ([]byte, error) {
	// 使用agent配置中的salt作为密钥
	key := []byte(salt)

	// 1. Base64解码
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("base64解码失败: %v", err)
	}

	// 2. AES-GCM解密
	if len(encryptedData) < 12 {
		return nil, fmt.Errorf("加密数据长度不足")
	}
	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建GCM失败: %v", err)
	}

	compressedData, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM解密失败: %v", err)
	}

	// 3. gzip解压缩
	reader := bytes.NewReader(compressedData)
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("创建gzip reader失败: %v", err)
	}
	defer func(gzipReader *gzip.Reader) {
		err := gzipReader.Close()
		if err != nil {

		}
	}(gzipReader)

	return io.ReadAll(gzipReader)
}

// CompressAndEncrypt 压缩并加密数据
func CompressAndEncrypt(data []byte, salt string) (string, error) {
	// 压缩数据
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)

	_, err := gzipWriter.Write(data)
	if err != nil {
		return "", fmt.Errorf("压缩数据失败: %v", err)
	}

	// 关闭gzip写入器以确保所有数据都被写入
	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("关闭gzip写入器失败: %v", err)
	}

	compressedData := compressedBuf.Bytes()

	// 创建AES加密器
	block, err := aes.NewCipher([]byte(salt))
	if err != nil {
		return "", fmt.Errorf("创建AES加密器失败: %v", err)
	}

	// 创建GCM模式加密器
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建GCM失败: %v", err)
	}

	// 创建12字节的nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成nonce失败: %v", err)
	}

	// 加密数据
	ciphertext := aesgcm.Seal(nil, nonce, compressedData, nil)

	// 将nonce和密文组合
	result := append(nonce, ciphertext...)

	// 将结果转换为base64编码
	return base64.StdEncoding.EncodeToString(result), nil
}

// pkcs7Pad 对数据进行PKCS#7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}
