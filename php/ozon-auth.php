<?php

/**
 * =============================================================================
 *  Модуль авторизации и обращения к Ozon API (Seller API / Delivery API)
 * =============================================================================
 *
 *  Что делает этот модуль вместо «голого» HTTP:
 *  1. Получает валидный OAuth-токен (из кэша или запрашивает заново).
 *  2. Автоматически продлевает токен по refresh_token, когда срок жизни
 *     подходит к концу (за 60 секунд до expires_in).
 *  3. Выполняет реальные запросы к API с заголовком Authorization: Bearer,
 *     а при ответах 401/403 сам переполучает токен и повторяет запрос ОДИН раз.
 *
 *  ⚠️ ВАЖНО ПРО СЕКРЕТ (обязательно к прочтению разработчиком):
 *  client_secret НЕЛЬЗЯ передавать и хранить на клиентской стороне —
 *  в браузере или мобильном приложении. Иначе секрет будет виден каждому,
 *  кто откроет DevTools или распакует приложение, и любой сможет выдавать
 *  себя за вашу интеграцию.
 *  Этот модуль рассчитан ИСКЛЮЧИТЕЛЬНО на серверную часть (бэкенд).
 *  Для схемы authorization_code client_secret и redirect_uri живут только
 *  на сервере; в приложении (браузер/мобилка) выполняется только переход
 *  продавца на страницу авторизации Ozon с получением authorization_code.
 *
 *  Структура файла:
 *    Transport  ->  AuthClient  ->  две фабрики токенов (фабрики функций).
 *
 *  Требования к окружению: PHP >= 7.0, расширение cURL.
 * =============================================================================
 */


/**
 * =============================================================================
 *  Transport — тонкая обёртка над cURL.
 * =============================================================================
 *
 *  Зачем она нужна: серверы Ozon защищены модулем testcookie (защита от DDoS).
 *  Он может перехватить HTTP-запрос и ответить РЕДИРЕКТОМ с кодом 302 ИЛИ 307,
 *  добавив заголовки Location и Set-Cookie. Клиент обязан:
 *    - повторить запрос с тем же ТЕЛОМ по пути из Location;
 *    - приложить Cookie из Set-Cookie;
 *    - сохранить эту Cookie и использовать её для последующих запросов.
 *
 *  ЛОВУШКА (главная): при ответе 302 многие HTTP-клиенты конвертируют
 *  POST в GET и ТЕРЯЮТ тело запроса. Чтобы этого не случилось, для cURL
 *  обязательно выставляем CURLOPT_POSTREDIR => CURL_REDIR_POST_ALL —
 *  тогда при редиректе сохраняются и метод POST, и тело запроса.
 *  Без этого токен-запрос (POST) «превратится» в пустой GET, и авторизация
 *  молча сломается.
 */
class Transport
{
    /** Общий файл cookie-jar: в него пишутся и из него читаются Cookie. */
    private $cookieFile;

    /**
     * @param string $cookieFile путь к файлу cookie-jar (должен быть перезаписываем).
     */
    public function __construct($cookieFile)
    {
        $this->cookieFile = $cookieFile;
    }

    /**
     * Выполнить HTTP-запрос с телом JSON.
     *
     * @param string            $method   HTTP-метод: GET / POST / PUT / PATCH / DELETE.
     * @param string            $url      Полный URL, включая endpoint.
     * @param array|null        $jsonBody Тело как массив (будет закодировано в JSON),
     *                                    или null, если тела нет.
     * @param array             $headers  Дополнительные заголовки (напр. Authorization).
     *
     * @return array  ['status' => int, 'body' => array]  — HTTP-код и JSON-ответ.
     *
     * @throws RuntimeException  При сетевой ошибке cURL или невалидном JSON в ответе.
     */
    public function request($method, $url, $jsonBody = null, $headers = [])
    {
        $ch = curl_init($url);

        // Разрешаем следовать редиректам testcookie (302/307).
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        // ГЛАВНАЯ ЛОВУШКА: сохраняем метод POST и тело при редиректе.
        curl_setopt($ch, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
        // Не выходим из-под контроля количества переходов (страховка от зацикливания).
        curl_setopt($ch, CURLOPT_MAXREDIRS, 2);

        // Cookie-jar: один и тот же файл и для записи, и для чтения,
        // чтобы Cookie сохранялись и подхватывались на всю сессию.
        curl_setopt($ch, CURLOPT_COOKIEJAR, $this->cookieFile);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $this->cookieFile);

        // Возвращаем результат как строку, не выводим напрямую.
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        // Метод и тело.
        // ВАЖНО: SSL-верификацию в боевом коде НЕ отключаем (безопасность TLS).
        $body = null;
        if ($jsonBody !== null) {
            $body = json_encode($jsonBody, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }

        switch (strtoupper($method)) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                if ($body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                }
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                if ($body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                }
                break;
            case 'PATCH':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
                if ($body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if ($body !== null) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                }
                break;
        }

        // Заголовки: по умолчанию отправляем JSON (Content-Type, Accept) и
        // межсервисный заголовок Api-Key (обязателен для Seller/Delivery API).
        // Content-Length cURL выставит сам, т.к. мы передаём тело через CURLOPT_POSTFIELDS.
        $allHeaders = array_merge([
            'Content-Type: application/json',
            'Accept: application/json',
            'Api-Key: ' . $this->apiKey,
        ], $headers);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $allHeaders);

        // 5-секундный таймаут на соединение и на передачу данных.
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $raw = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . $err);
        }
        curl_close($ch);

        $decoded = json_decode($raw, true);
        // Ответ может быть не-JSON (например, пустое тело или HTML), поэтому
        // в теле отдаём декодированный массив, а сырую строку сохраняем как есть.
        return [
            'status' => $status,
            'body'   => is_array($decoded) ? $decoded : [],
            'raw'    => $raw,
        ];
    }

    /** client_secret / токен не лежат в Transport — здесь только Api-Key. */
    public $apiKey = '';
}


/**
 * =============================================================================
 *  AuthClient — получение и продление токена + авторизованные запросы.
 * =============================================================================
 *
 *  Отвечает за:
 *    - кэш токена (можно в памяти объекта или в файле);
 *    - продление по refresh_token за 60 сек до истечения expires_in;
 *    - подстановку Authorization: Bearer <token> в запросы;
 *    - повтор запроса один раз при 401/403 (после переполучения токена).
 */
class AuthClient
{
    const TOKEN_URL = 'https://xapi.ozon.ru/oauth/token';

    /** Точка входа Ozon Seller API. Delivery API — отдельный базовый URL. */
    const SELLER_API_BASE = 'https://api-seller.ozon.ru';

    private $transport;

    /** Фабрика (callable), которая запрашивает/продлевает токен у Ozon. */
    private $tokenFactory;

    /** Запас времени (сек) до истечения, при котором токен считается «просроченным». */
    private $refreshAheadSec = 60;

    /** Кэш токена: ['access_token'=>..., 'expires_at'=>..., 'refresh_token'=>...] */
    private $cache = null;

    /** Путь файла кэша (кэш можно хранить на диске долго-живущего процесса). */
    private $cacheFile = null;

    /**
     * @param Transport $transport    Экземпляр Transport с настроенным Api-Key.
     * @param callable  $tokenFactory callable, возвращающий массив с полями токена.
     * @param string|null $cacheFile  путь к файлу кэша, либо null для памяти.
     */
    public function __construct(Transport $transport, callable $tokenFactory, $cacheFile = null)
    {
        $this->transport = $transport;
        $this->tokenFactory = $tokenFactory;
        $this->cacheFile = $cacheFile;
        $this->loadCache();
    }

    /** Загрузить кэш из файла, если он задан и существует. */
    private function loadCache()
    {
        if ($this->cacheFile && is_file($this->cacheFile)) {
            $data = json_decode(file_get_contents($this->cacheFile), true);
            if (is_array($data)) {
                $this->cache = $data;
            }
        }
    }

    /** Сохранить кэш в файл, если он задан. */
    private function saveCache()
    {
        if ($this->cacheFile !== null) {
            file_put_contents($this->cacheFile, json_encode($this->cache));
        }
    }

    /**
     * Вернуть валидный (неистёкший) access_token, при необходимости
     * получив новый или продлив по refresh_token.
     *
     * @param bool $force обновить токен принудительно (используется при 401/403).
     *
     * @return string access_token.
     */
    public function getToken($force = false)
    {
        $now = time();

        // Токен валиден и не близок к истечению — отдаём из кэша.
        if (!$force
            && $this->cache
            && isset($this->cache['access_token'], $this->cache['expires_at'])
            && $this->cache['expires_at'] > ($now + $this->refreshAheadSec))
        {
            return $this->cache['access_token'];
        }

        // Если есть refresh_token — сначала пробуем продлить (экономнее и надёжнее).
        if (isset($this->cache['refresh_token'])) {
            try {
                $newToken = $this->refreshToken($this->cache['refresh_token']);
                $this->storeToken($newToken);
                return $newToken['access_token'];
            } catch (Exception $e) {
                // invalid_refresh_token — токен недействителен (продавец отозвал доступ
                // или токен истёк). Нужна повторная авторизация: запрашиваем новый.
                // Логируем и продолжаем как при первом получении.
                // (Здесь можно пробросить исключение, если требуется ручное действие.)
            }
        }

        // Первичное получение токена через фабрику.
        $token = call_user_func($this->tokenFactory);
        $this->storeToken($token);
        return $token['access_token'];
    }

    /** Сохранить поля токена в кэш и на диск. */
    private function storeToken(array $token)
    {
        $this->cache = [
            'access_token'  => $token['access_token'],
            'refresh_token' => isset($token['refresh_token']) ? $token['refresh_token'] : null,
            // expires_at = now + expires_in, с небольшим запасом (минус 5 сек).
            'expires_at'    => time() + (int) $token['expires_in'] - 5,
            'scope'         => isset($token['scope']) ? $token['scope'] : null,
        ];
        $this->saveCache();
    }

    /**
     * Продлить токен по refresh_token: POST на /oauth/token
     * с grant_type=refresh_token.
     */
    private function refreshToken($refreshToken)
    {
        $payload = [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
        ];
        $resp = $this->transport->request('POST', self::TOKEN_URL, $payload);
        if ($resp['status'] >= 400) {
            // 400/401/403 — недействительный refresh_token.
            throw new RuntimeException('Refresh failed, status=' . $resp['status']
                . ' body=' . $resp['raw']);
        }
        return $resp['body'];
    }

    /**
     * Выполнить запрос к Ozon API с автозаголовком Authorization: Bearer.
     * При 401/403 переполучает токен и повторяет запрос ОДИН раз.
     *
     * @param string     $method HTTP-метод.
     * @param string     $path   Путь относительно базового URL, например
     *                           '/v2/product/list'. Можно передать полный URL.
     * @param array|null $body   Тело запроса (массив) или null.
     *
     * @return array  ['status' => int, 'body' => array]  ответ API.
     */
    public function request($method, $path, $body = null)
    {
        // Полный ли это URL, или относительный путь к Seller API.
        $url = (strpos($path, 'http') === 0) ? $path : self::SELLER_API_BASE . $path;

        // Автоподстановка Bearer-токена.
        $headers = ['Authorization: Bearer ' . $this->getToken()];

        $resp = $this->transport->request($method, $url, $body, $headers);

        // 401/403: невалидный/истёкший токен или не хватает прав.
        // Принудительно обновляем токен и повторяем запрос один раз.
        if (in_array($resp['status'], [401, 403], true)) {
            $headers = ['Authorization: Bearer ' . $this->getToken(true)];
            return $this->transport->request($method, $url, $body, $headers);
        }

        return $resp;
    }
}


/**
 * =============================================================================
 *  ФАБРИКА 1: client_credentials (сервисные/машинные интеграции, в т.ч. Delivery API).
 * =============================================================================
 *  Возвращает callable-фабрику, которую принимает AuthClient.
 *
 *  @param string $clientId
 *  @param string $clientSecret  См. предупреждение в шапке файла про секрет.
 *  @param array  $scope         Массив запрашиваемых scope, например
 *                               ['api.delivery.read', 'api.delivery.write'].
 */
function ozon_client_credentials_token_factory($clientId, $clientSecret, array $scope)
{
    return function () use ($clientId, $clientSecret, $scope) {
        // Подготавливаем транспорт локально, чтобы фабрика была самодостаточной.
        $transport = new Transport(sys_get_temp_dir() . '/ozon_client_credentials_jar.txt');
        $transport->apiKey = $clientId; // для client_credentials Api-Key совпадает с client_id

        $payload = [
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'grant_type'    => 'client_credentials',
            'scope'         => implode(' ', $scope), // Ozon принимает scope строкой
        ];
        $resp = $transport->request('POST', AuthClient::TOKEN_URL, $payload);
        if ($resp['status'] >= 400) {
            throw new RuntimeException('client_credentials failed, status=' . $resp['status']
                . ' body=' . $resp['raw']);
        }
        return $resp['body'];
    };
}


/**
 * =============================================================================
 *  ФАБРИКА 2: authorization_code (приложения от имени продавца).
 * =============================================================================
 *  redirect_uri и client_secret живут только на сервере. Продавец в браузере
 *  проходит авторизацию Ozon и возвращается с authorization_code;
 *  сервер обменивает этот code на токены.
 *
 *  Если access_type=offline, Ozon выдаёт refresh_token — тогда действует
 *  автопродление в AuthClient.getToken().
 *
 *  @param string $clientId
 *  @param string $clientSecret  См. предупреждение в шапке — секрет только на сервере.
 *  @param string $code          authorization_code от продавца.
 *  @param string $redirectUri   redirect_uri, заданный при регистрации приложения.
 *  @param bool   $offline       запросить refresh_token (access_type=offline).
 */
function ozon_authorization_code_token_factory($clientId, $clientSecret, $code, $redirectUri, $offline = true)
{
    return function () use ($clientId, $clientSecret, $code, $redirectUri, $offline) {
        $transport = new Transport(sys_get_temp_dir() . '/ozon_authcode_jar.txt');
        $transport->apiKey = $clientId;

        $payload = [
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => $redirectUri,
        ];
        if ($offline) {
            $payload['access_type'] = 'offline';
        }
        $resp = $transport->request('POST', AuthClient::TOKEN_URL, $payload);
        if ($resp['status'] >= 400) {
            throw new RuntimeException('authorization_code failed, status=' . $resp['status']
                . ' body=' . $resp['raw']);
        }
        return $resp['body'];
    };
}


/* =========================== ПРИМЕР ИСПОЛЬЗОВАНИЯ =========================== */

/*
// --- 1. client_credentials: получаем токен и делаем запрос к Seller API ---------
$transport = new Transport(sys_get_temp_dir() . '/ozon_jar.txt');
$transport->apiKey = 'your-client-id';            // Api-Key = client_id

$auth = new AuthClient(
    $transport,
    ozon_client_credentials_token_factory(
        'your-client-id',
        'your-client-secret',   // ⚠️ только на сервере!
        ['api.delivery.read']   // scope
    ),
    sys_get_temp_dir() . '/ozon_token_cache.json' // кэш токена на диске
);

// Запрос к API: токен подставится автоматически.
$resp = $auth->request('POST', '/v3/product/list', ['filter' => [], 'limit' => 10]);
var_dump($resp['status'], $resp['body']);


// --- 2. Автопродление: демонстрация -------------------------------------------
// Первый вызов — токен получен и закэширован.
$t1 = $auth->getToken();
// При следующем вызове фабрика не дёргается: токен берётся из кэша, пока он жив
// (не ближе 60 сек до expires_in).
$t2 = $auth->getToken();
// Когда expires_at приблизится к концу (за 60 сек), AuthClient сам вызовет
// refresh_token-обмен и вернёт новый токен — без участия вызывающего кода.
$t3 = $auth->getToken();
// $t1 === $t2 (кэш), $t3 — новый токен (если $t1 был близок к истечению).


// --- 3. authorization_code: обмен code продавца на токены ----------------------
$auth2 = new AuthClient(
    $transport,
    ozon_authorization_code_token_factory(
        'your-client-id',
        'your-client-secret',   // ⚠️ только на сервере!
        'CODE_FROM_SELLER',     // authorization_code, полученный после входа продавца
        'https://your-app.ru/oauth/callback', // redirect_uri из настроек приложения
        true                     // offline=true -> будет refresh_token и автопродление
    ),
    sys_get_temp_dir() . '/ozon_token_cache2.json'
);
$resp = $auth2->request('GET', '/v1/posting/fbs/list', ['dir' => 'ASC', 'limit' => 10]);
var_dump($resp['status'], $resp['body']);
*/
