package abstratriumvault

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

const baseUrl = "http://localhost:8080"

func TestHappy_123123123123_RealIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "123.123.123.123")
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("def", body)
}

func TestHappy_127001_RealIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=def"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "127.0.0.1")
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("2", body)
}

func TestHappy_123123123123_RealIP_SecondToken(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=ghi"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "123.123.123.123")
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("jkl", body)
}

func TestHappy_123123123123_testaddr(t *testing.T) {
	assert := assert.New(t)

	path := "/?testaddr=123.123.123.123&keyname=abc"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("def", body)
}

func TestHappy_WrongIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "123.123.123.124") // <<< wrong IP
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1000", body)
}

func TestHappy_WrongKey(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=ZZZ" // <<< wrong key

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "123.123.123.123")
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusForbidden, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1001", body)
}

func TestHappy_NoKey(t *testing.T) {
	assert := assert.New(t)

	path := "/" // <<< no key

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Real-IP", "123.123.123.123")
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusForbidden, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1001", body)
}

func TestHappy_NoIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	var client = &http.Client{}
    var req, _ = http.NewRequest("GET", baseUrl + path, nil)
	// <<< no header or query parameter with IP
    var resp, err = client.Do(req)

	assert.Nil(err)
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1000", body)
}

