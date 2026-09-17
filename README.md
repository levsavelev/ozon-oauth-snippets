# Ozon OAuth сниппеты (PHP + Go)

Готовые модули авторизации для доступа к **Ozon API** (Seller API / Delivery API) внешним приложениям. Сниппеты позволяют не писать обвязку вокруг `/oauth/token` с нуля: достаточно подключить файл и работать с API, не думая о токенах и редиректах.

> Эти сниппеты - независимый пример интеграции и не являются официальным клиентом Ozon. Используются на свой страх и риск. Продуктовый контур и правила публикации приложений см. на [dev.ozon.ru](https://dev.ozon.ru).

---

## Содержимое

| Код | Файл | Способы авторизации |
| --- | --- | --- |
| PHP | [`php/ozon-auth.php`](php/ozon-auth.php) | `client_credentials`, `authorization_code` |
| Go | [`go/main.go`](go/main.go) | `client_credentials`, `authorization_code` |

---

## Возможности (общие для обоих языков)

- **Получение токена** по `client_credentials` (сервисные/машинные интеграции, в т.ч. Delivery API) и `authorization_code` (приложения от имени продавца).
- **Кэш токена** - повторные вызовы не дёргают `/oauth/token`, пока токен жив.
- **Автопродление по `refresh_token`** - за 60 секунд до истечения `expires_in` клиент сам обновляет токен.
- **Автоподстановка заголовка** `Authorization: Bearer <token>`.
- **Повтор запроса при 401/403** - после переполучения токена запрос выполняется один раз заново.
- **Поддержка защиты от DDoS (testcookie)** - корректно обрабатываются редиректы 302/307 с сохранением тела запроса и Cookie.

### Важно про безопасность

`client_secret` **нельзя передавать и хранить на клиентской стороне** (в браузере или мобильном приложении) - оно оттуда будет украдено. Модули рассчитаны **исключительно на серверную часть**: для `authorization_code` секрет и `redirect_uri` живут на сервере, а продавец в браузере проходит через страницу авторизации Ozon и возвращается с `authorization_code`.

---

## PHP

Требования: **PHP >= 7.0**, расширение **cURL**.

```php
<?php
require 'ozon-auth.php';

$transport = new Transport(sys_get_temp_dir() . '/ozon_jar.txt');
$transport->apiKey = 'ваш-client-id';          // Api-Key = client_id

$auth = new AuthClient(
    $transport,
    ozon_client_credentials_token_factory(
        'ваш-client-id',
        'ваш-client-secret',   // только на сервере!
        ['api.delivery.read']  // scope
    ),
    sys_get_temp_dir() . '/ozon_token_cache.json'
);

// Токен подставится автоматически
$resp = $auth->request('POST', '/v3/product/list', ['filter' => [], 'limit' => 10]);
var_dump($resp['status'], $resp['body']);
```

Для схемы `authorization_code` используйте фабрику `ozon_authorization_code_token_factory()`. Пример - в комментариях внизу файла.

---

## Go

Модуль собран в одном файле с `package main`. Требований к внешним зависимостям нет - только стандартная библиотека.

```go
package main

import (
	"context"
	"fmt"
	"net/http"
)

func main() {
	client, err := NewClientCredentials(
		"ваш_client_id",
		"ваш_client_secret", // только на сервере!
		[]string{"delivery:read"},
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	resp, err := client.Request(ctx, http.MethodGet,
		"https://api-seller.ozon.ru/v1/product/list", nil)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("статус:", resp.StatusCode)
}
```

Для `authorization_code`:

```go
client, _ := NewAuthorizationCode("client_id", "client_secret", "https://your-app.ru/oauth/callback")
// первый обмен code продавца
client.ExchangeCode(ctx, "CODE_FROM_SELLER")
// далее токен продлевается автоматически по refresh_token
resp, _ := client.Request(ctx, http.MethodGet, "/v1/posting/fbs/list", nil)
```

---

## Как это работает

1. Клиент запрашивает токен у `https://xapi.ozon.ru/oauth/token`.
2. Модуль кэширует токен и автоматически продлевает по `refresh_token`.
3. Все последующие запросы к API идут с заголовком `Authorization: Bearer <token>`.
4. При 401/403 модуль переполучает токен и повторяет запрос один раз.

---

## Лицензия

[MIT](LICENSE)
