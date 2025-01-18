package abstratriumvault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const baseUrl = "http://localhost:8080"

func TestHappy_123123123123_ForwardedFor(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "123.123.123.123")
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("def", body)
}

func TestHappy_127001_ForwardedFor(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=def"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "127.0.0.1")
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("2", body)
}

func TestHappy_123123123123_ForwardedFor_SecondToken(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=ghi"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "123.123.123.123")
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("jkl", body)
}

func TestHappy_WrongIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "123.123.123.124") // <<< wrong IP
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1000", body)
}

func TestHappy_WrongKey(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=ZZZ" // <<< wrong key

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "123.123.123.123")
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusForbidden, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1001", body)
}

func TestHappy_NoKey(t *testing.T) {
	assert := assert.New(t)

	path := "/" // <<< no key

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", "123.123.123.123")
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusForbidden, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1001", body)
}

func TestHappy_NoIP(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=abc"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
	// <<< no header or query parameter with IP
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("E1000", body)
}

func TestHappy_124124124124_Forwarded(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=mno"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("Forwarded", `for="124.124.124.124";proto=https`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("pqr", body)
}

func TestHappy_ipv6_Forwarded(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=stu"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("Forwarded", `for="2a02:0110:68a5:0000:0000:c24:0000:0001";proto=https`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)
	assert.Equal("vwy", body)
}

func Test_124124124124_DoubleForwarded(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=mno"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("Forwarded", `123.123.123.123,for="124.124.124.124";proto=https`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)

	matches, err := regexp.MatchString("forwarded header '123.123.123.123,for=.* does not match expected pattern", body)
	assert.Nil(err)
	assert.True(matches, body)
}

func Test_124124124124_TripleForwarded(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=mno"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("Forwarded", `123.123.123.123,125.125.125.125,for="124.124.124.124";proto=https`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)

	matches, err := regexp.MatchString("forwarded header '123.123.123.123,125.125.125.125,for=.* does not match expected pattern", body)
	assert.Nil(err)
	assert.True(matches, body)
}

func Test_123123123123_DoubleForwardedFor(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=mno"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", `125.125.125.125,124.124.124.124`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)

	matches, err := regexp.MatchString("x-forwarded-for header '125.125.125.125,124.124.124.124' does not match expected pattern", body)
	assert.Nil(err)
	assert.True(matches, body)
}

func Test_ipv6_DoubleForwardedFor(t *testing.T) {
	assert := assert.New(t)

	path := "/?keyname=mno"

	req := httptest.NewRequest("GET", baseUrl + path, nil)
    req.Header.Add("X-Forwarded-For", `125.125.125.125,2a02:0110:68a5:0000:0000:c24:0000:0001`)
	w := httptest.NewRecorder()

	// when
	VaultMain(w, req)

	// then
	resp := w.Result()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)
	defer resp.Body.Close()
	bytes, _ := io.ReadAll(resp.Body)
	body := string(bytes)

	matches, err := regexp.MatchString("x-forwarded-for header '125.125.125.125,2a02:0110:68a5:0000:0000:c24:0000:0001' does not match expected pattern", body)
	assert.Nil(err)
	assert.True(matches, body)
}
