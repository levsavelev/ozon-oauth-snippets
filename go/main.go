// Package main - компактный модуль авторизации Ozon (OAuth2) для внешних
// разработчиков коробочных решений.
//
// Что он даёт вместо голого HTTP:
//   - кэширует access_token и продлевает его по refresh_token, когда срок
//     жизни подходит к концу (за 60 сек до expires_in);
//   - сам подставляет заголовок Authorization: Bearer;
//   - переживает защиту серверов Ozon (testcookie): 302/307-редиректы с
//     сохранением тела запроса и Cookie;
//   - при 401/403 пере-получает токен и повторяет запрос ОДИН раз.
//
// ВАЖНО про безопасность секрета:
//   - client_secret НЕЛЬЗЯ передавать и хранить на клиентской стороне
//     (в браузере или мобильном приложении) - он оттуда будет украден.
//   - Этот модуль рассчитан на СЕРВЕРНУЮ часть: для authorization_code
//     client_secret и redirect_uri живут на сервере, а код, полученный в
//     браузере продавца, передаётся на сервер по защищённому каналу.
//   - HTTPS с проверкой сертификата включён всегда, InsecureSkipVerify
//     в боевом коде отключать нельзя.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	tokenURL        = "https://xapi.ozon.ru/oauth/token"
	refreshLeeway   = 60 * time.Second // продлеваем токен за 60 сек до истечения
	testcookieLimit = 3                // максимум редиректов testcookie, чтобы не зациклиться
)

// Transport - http.Client, настроенный под защиту Ozon testcookie.
//
// Зачем своя логика редиректов: дефолтный http.Client на 302/303 может
// сменить POST на GET и потерять тело запроса. testcookie отвечает редиректом
// 302/307 c Location и Set-Cookie, и клиент обязан повторить ЗАПРОС С ТЕМ ЖЕ
// ТЕЛОМ по новому пути, подставив Cookie. Поэтому мы пере-создаём запрос
// через req.GetBody (чтобы тело можно было прочитать повторно), сохраняем
// метод, и ограничиваем число переходов, чтобы не зациклиться.
// Cookie-журнал (cookiejar) держит куки автоматически для всех запросов к узлу.
func NewTransport() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= testcookieLimit {
				return errors.New("слишком много редиректов (testcookie зациклился)")
			}
			// req идёт от http.Client уже с новым путём из Location, но нужно
			// вернуть ему прежний метод и перечитываемое тело.
			prev := via[len(via)-1]
			req.Method = prev.Method
			if prev.GetBody != nil {
				body, err := prev.GetBody()
				if err != nil {
					return err
				}
				req.Body = body
			}
			return nil
		},
	}, nil
}

// Token - ответ Ozon на запрос токена.
type Token struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"` // секунды до истечения access_token
	RefreshToken string   `json:"refresh_token"`
	Scope        []string `json:"scope"`
	// служебные, не из ответа
	issuedAt time.Time
}

// Valid - токен ещё не истёк с запасом refreshLeeway.
func (t *Token) Valid() bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	return time.Now().Before(t.issuedAt.Add(time.Duration(t.ExpiresIn)*time.Second - refreshLeeway))
}

// AuthClient - авторизованный клиент Ozon API.
type AuthClient struct {
	client       *http.Client
	mu           sync.Mutex // защищает token: простой, но честный кэш
	token        *Token
	refresh      func(ctx context.Context) (*Token, error) // стратегия получения токена
	clientID     string
	clientSecret string
	redirectURI  string
}

// GetToken - возвращает валидный токен из кэша или запрашивает новый.
func (a *AuthClient) GetToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token.Valid() {
		return a.token.AccessToken, nil
	}
	tok, err := a.refresh(ctx)
	if err != nil {
		return "", err
	}
	if tok != nil {
		tok.issuedAt = time.Now()
		a.token = tok
	}
	if a.token == nil || a.token.AccessToken == "" {
		return "", errors.New("сервер не вернул access_token")
	}
	return a.token.AccessToken, nil
}

// Request - запрос к Ozon API с Autoin Bearer-токеном.
// При 401/403 пере-получает токен и повторяет запрос ОДИН раз.
func (a *AuthClient) Request(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	tok, err := a.GetToken(ctx)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, path, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, err
		}
		if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && attempt == 0 {
			resp.Body.Close()
			// старый токен мог протухнуть: сбрасываем кэш и пере-получаем
			a.mu.Lock()
			a.token = nil
			a.mu.Unlock()
			tok, err = a.GetToken(ctx)
			if err != nil {
				return nil, err
			}
			continue
		}
		return resp, nil
	}
}

// requestToken - низкоуровневый POST на tokenURL с параметрами.
func (a *AuthClient) requestToken(ctx context.Context, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var tok Token
		if err := json.Unmarshal(data, &tok); err != nil {
			return nil, err
		}
		// при обновлении сервер может не вернуть новый refresh_token -
		// сохраняем прежний
		if tok.RefreshToken == "" && a.token != nil {
			tok.RefreshToken = a.token.RefreshToken
		}
		tok.issuedAt = time.Now()
		return &tok, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("ошибка авторизации Ozon: %d %s", resp.StatusCode, string(data))
	default:
		return nil, fmt.Errorf("неожиданный код от Ozon: %d %s", resp.StatusCode, string(data))
	}
}

// ---------- Фабрика 1: client_credentials (сервисные/машинные интеграции,
// в т.ч. Delivery API) ----------

// NewClientCredentials - клиент для сервисной интеграции.
// scope - массив разрешений (например ["delivery:read"]).
func NewClientCredentials(clientID, clientSecret string, scope []string) (*AuthClient, error) {
	hc, err := NewTransport()
	if err != nil {
		return nil, err
	}
	a := &AuthClient{client: hc}
	a.refresh = func(ctx context.Context) (*Token, error) {
		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
		form.Set("scope", strings.Join(scope, " "))
		form.Set("grant_type", "client_credentials")
		return a.requestToken(ctx, form)
	}
	return a, nil
}

// ---------- Фабрика 2: authorization_code (приложения от имени продавца) ----------
// Первый вызов требует code и redirect_uri; далее токен продлевается по
// refresh_token (актуально при access_type=offline), пока не истечёт refresh.
func NewAuthorizationCode(clientID, clientSecret, redirectURI string) (*AuthClient, error) {
	hc, err := NewTransport()
	if err != nil {
		return nil, err
	}
	a := &AuthClient{client: hc, clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI}
	a.refresh = func(ctx context.Context) (*Token, error) {
		form := url.Values{}
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
		form.Set("redirect_uri", redirectURI)
		// если уже есть refresh_token - продлеваем по нему
		if a.token != nil && a.token.RefreshToken != "" {
			form.Set("refresh_token", a.token.RefreshToken)
			form.Set("grant_type", "refresh_token")
			return a.requestToken(ctx, form)
		}
		return nil, errors.New("нет refresh_token: нужна повторная авторизация (получите новый code)")
	}
	return a, nil
}

// ExchangeCode - первый обмен authorization_code на токен. Вызывается один раз
// после того, как продавец авторизовался в браузере и сервер получил code.
func (a *AuthClient) ExchangeCode(ctx context.Context, code string) error {
	form := url.Values{}
	form.Set("client_id", a.clientID)
	form.Set("client_secret", a.clientSecret)
	form.Set("redirect_uri", a.redirectURI)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	tok, err := a.requestToken(ctx, form)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.token = tok
	a.mu.Unlock()
	return nil
}

func main() {
	// ---------- Пример использования ----------
	ctx := context.Background()

	// 1. Получаем клиент (client_credentials, как для Delivery API).
	client, err := NewClientCredentials(
		"ваш_client_id",
		"ваш_client_secret", // ТОЛЬКО на сервере, не на клиенте
		[]string{"delivery:read"},
	)
	if err != nil {
		panic(err)
	}

	// 2. Реальный запрос к API - токен подставится сам.
	resp, err := client.Request(ctx, http.MethodGet,
		"https://api-seller.ozon.ru/v1/product/list", nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("статус:", resp.StatusCode)

	// 3. Автопродление: следующий вызов GetToken (когда expires_in подойдёт
	//    к концу) сам сделает refresh по refresh_token, ничего не придётся
	//    делать вручную.
	time.Sleep(70 * time.Second) // демонстрация: переждать expires_in
	tok, _ := client.GetToken(ctx)
	fmt.Println("обновлённый токен:", tok[:8]+"...")
}
