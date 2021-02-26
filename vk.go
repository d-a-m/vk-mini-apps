package vk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"sort"
	"strings"
)

// CheckSign проверяет подпись параметров, пришедших с клиента
func CheckSign(fullUrl string, clientSecret string) (bool, error) {
	u, err := url.Parse(fullUrl)
	if err != nil {
		return false, err
	}

	queryParams, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false, err
	}

	// Собираем только VK параметры
	signParams := make(map[string]string)
	keys := []string{}
	for k, p := range queryParams {
		if strings.Contains(k, "vk_") {
			signParams[k] = p[0]
			keys = append(keys, k)
		}
	}

	// Сортируем ключи мапы
	sort.Strings(keys)

	// Формируем строку вида "param_name1=value&param_name2=value"
	strParams := ""
	for _, key := range keys {
		strParams += key + "=" + signParams[key] + "&"
	}
	strParams = strings.TrimRight(strParams, "&")

	// Хешируем
	h := hmac.New(sha256.New, []byte(clientSecret))
	h.Write([]byte(strParams))

	res := base64.StdEncoding.EncodeToString(h.Sum(nil))
	res = strings.ReplaceAll(res, "+", "-")
	res = strings.ReplaceAll(res, "/", "_")
	res = strings.TrimRight(res, "=")

	if v, ok := queryParams["sign"]; !ok {
		return false, errors.New("sign is empty")
	} else {
		return res == v[0], nil
	}
}
