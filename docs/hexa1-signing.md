# Схема подписи HEXA1 — полный разбор

Всё восстановлено статическим анализом официального APK `com.xiaomi.superhexa`.
Ничего не подбиралось перебором.

## 1. Карта классов

| Класс | Роль |
|---|---|
| `com.superhexa.supervision.library.net.retrofit.CredentialCalculator` | сборка строки credential |
| `com.superhexa.supervision.library.base.basecommon.tools.d0` | HMAC-SHA256 |
| `com.superhexa.supervision.library.base.basecommon.tools.ExtensionsKt` | hex-кодирование (`%02x`) |
| `com.superhexa.supervision.library.net.retrofit.interceptor.b` | установка заголовка `Authorization` |
| `m7.a` | источник `passToken` |

## 2. `CredentialCalculator`

### Поля

```
a : String                  // passToken
b : String                  // postParameter (тело/параметры)
c : HttpType                // Get | Post
d : String                  // serviceToken
```

### Конструктор по умолчанию

Синтетический конструктор подставляет `serviceToken`:

```
const-string v4, "f7b364516e739c2ac60f1114e88f6afc"
```

То есть `serviceToken = f7b364516e739c2ac60f1114e88f6afc`.

### `b(String) -> String` — MD5

```smali
const-string v2, "MD5"
invoke-static v2, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
...
invoke-virtual v2, v3, Ljava/security/MessageDigest;->digest([B)[B
const/4 v3, 1
invoke-direct v0, v3, v2, Ljava/math/BigInteger;-><init>(I [B)V
const/16 v2, 16
invoke-virtual v0, v2, Ljava/math/BigInteger;->toString(I)Ljava/lang/String;
...
const/16 v3, 32
const/16 v0, 48
invoke-static v2, v3, v0, Lkotlin/text/m;->U3(Ljava/lang/String; I C)Ljava/lang/String;
```

Смысл: `md5(input)` → `BigInteger(1, digest).toString(16)` → `padStart(32, '0')`.
`BigInteger.toString(16)` отбрасывает ведущие нули, поэтому нужен `padStart`.

### `c(String, String) -> String` — текст + HMAC

Формирование текста:

| Условие | Формат |
|---|---|
| GET и `postParameter` пуст | `nonce=%s&timestamp=%s` |
| GET и `postParameter` не пуст | `%s&nonce=%s&timestamp=%s` |
| POST и `postParameter` пуст | `nonce=%s&timestamp=%s` |
| POST и `postParameter` не пуст | `data=%s&nonce=%s&timestamp=%s` |

Формирование ключа:

```smali
iget-object v8, v6, ...->a Ljava/lang/String;     // passToken
invoke-interface v8, Ljava/lang/CharSequence;->length()I
if-nez v8, +005h
iget-object v6, v6, ...->d Ljava/lang/String;      // только serviceToken
goto +14h
iget-object v8, v6, ...->d Ljava/lang/String;      // serviceToken
iget-object v6, v6, ...->a Ljava/lang/String;      // passToken
new-instance v0, Ljava/lang/StringBuilder;
... append(serviceToken) ... append(passToken) ...
```

То есть:

```
key = passToken.isEmpty() ? serviceToken : serviceToken + passToken
```

Далее:

```smali
new-instance v8, Lcom/superhexa/supervision/library/base/basecommon/tools/d0;
invoke-direct v8, ...-><init>()V
invoke-virtual v8, v6, v7, ...->a(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;
```

`d0.a(key, text)` → подпись.

### `a() -> String` — сборка заголовка

```smali
invoke-static Ljava/lang/System;->currentTimeMillis()J        // ts
...
new-instance v2, Lkotlin/ranges/l;
const/4 v3, 0
const/16 v4, 10000
invoke-direct v2, v3, v4, Lkotlin/ranges/l;-><init>(I I)V     // range 0..10000
...
invoke-static v2, v3, Lkotlin/ranges/s;->g1(...)I             // random in range
int-to-long v2, v2
add-long/2addr v2, v0                                         // ts + rand
invoke-static v2, v3, Ljava/lang/String;->valueOf(J)Ljava/lang/String;
invoke-direct v5, v2, ...->b(Ljava/lang/String;)Ljava/lang/String;   // nonce = md5(ts+rand)
...
invoke-direct v5, v2, v0, ...->c(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String; // signature
...
const-string v0, "HEXA1-HMAC-SHA256 nonce=%s, timestamp=%s, signature=%s"
invoke-static v0, v5, Ljava/lang/String;->format(Ljava/lang/String; [Ljava/lang/Object;)Ljava/lang/String;
```

Итог: `nonce = md5(ts + random(0..10000))`, `timestamp = ts`.

## 3. `tools.d0.a(String token, String text)`

```smali
const-string v4, "HmacSHA256"
invoke-static v4, Ljavax/crypto/Mac;->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;
...
new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
invoke-virtual v5, v2, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B
invoke-direct v1, v5, v4, Ljavax/crypto/spec/SecretKeySpec;-><init>([B Ljava/lang/String;)V
invoke-virtual v0, v1, Ljavax/crypto/Mac;->init(Ljava/security/Key;)V
invoke-virtual v6, v2, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B
invoke-virtual v0, v4, Ljavax/crypto/Mac;->doFinal([B)[B
invoke-static v4, ...ExtensionsKt;->j([B)Ljava/lang/String;
```

`HmacSHA256(key = token, data = text)` → hex.

## 4. `ExtensionsKt.j(byte[])` — hex

```smali
sget-object v7, ...ExtensionsKt$toHex$1;->INSTANCE
const-string v2, ""
invoke-static/range ... Lkotlin/collections/j;->Gh(...)Ljava/lang/String;
```

Лямбда `toHex$1.invoke(B)`:

```smali
const-string v1, "%02x"
invoke-static v1, v0, Ljava/lang/String;->format(Ljava/lang/String; [Ljava/lang/Object;)Ljava/lang/String;
```

То есть hex в **нижнем** регистре, байты склеены без разделителей.

## 5. `interceptor.b` — куда кладётся результат

```smali
const-string v10, "Authorization"
invoke-virtual v3, v10, Lokhttp3/a0;->i(Ljava/lang/String;)Ljava/lang/String;
...
invoke-direct v1, v0, v3, v4, ...->b(Ljava/lang/String; Lokhttp3/a0; Lokhttp3/t;)Ljava/lang/String;
...
invoke-virtual v12, v1, v0, Lokhttp3/a0$a;->n(Ljava/lang/String; Ljava/lang/String;)Lokhttp3/a0$a;
```

Смысл: если `Authorization` пуст — построить credential и добавить его
в заголовок `Authorization`.

Дополнительные заголовки (`a`):

```smali
"Content-Type"   -> "application/json"
"X-Request-ID"   -> c()
"X-Mobile-Id"    -> tools.b.c()
"Accept-Language"-> R.string.hexaLanguage
"X-App-Version"  -> "Android:" + versionName
```

`X-Request-ID` (`c()`):

```smali
"App_Android_" + currentTimeMillis + "_" + Random(30)
-> hashCode() -> String.valueOf
```

## 6. Откуда берётся `passToken`

`m7.a.i(host)`:

```smali
config.b.c(host)  -> device.eco.mi.com | device-eco.test.mi.com
config.b.b(host)  -> asp.mi.com
config.b.d(host)  -> host contains "fds.api.xiaomi.com"

если любой true  -> f()  = AccountInfo.miWearServiceToken
иначе           -> AccountInfo.passToken (или "" если аккаунта нет)
```

Для локального IP очков ни одно условие не выполняется → берётся
`AccountInfo.passToken`.

## 7. Итоговый алгоритм

```python
ts = now_ms()
r  = random(0, 10000)
nonce = md5(str(ts + r)).hexdigest().rjust(32, "0")

if body == "":
    text = f"nonce={nonce}&timestamp={ts}"
elif method == "GET":
    text = f"{body}&nonce={nonce}&timestamp={ts}"
else:
    text = f"data={body}&nonce={nonce}&timestamp={ts}"

key = SERVICE_TOKEN if pass_token == "" else SERVICE_TOKEN + pass_token
signature = hmac_sha256_hex(key, text)

header = f"HEXA1-HMAC-SHA256 nonce={nonce}, timestamp={ts}, signature={signature}"
```

Реализация: [`../tools/hexa_sign.py`](../tools/hexa_sign.py).

## 8. Тестовый вектор

Детерминированный прогон (`ts=1700000000000`, `rand=1234`, пустой passToken, GET без тела):

```
nonce     = d797018352a2731345a285fd3e0c055d
timestamp = 1700000000000
text      = nonce=d797018352a2731345a285fd3e0c055d&timestamp=1700000000000
key       = f7b364516e739c2ac60f1114e88f6afc
signature = 797b76fc2ed4379460f076ff4cab71044add4387a49f3e5b739eccbb87a9c2d7
```

Проверка:

```bash
python tools/hexa_sign.py --ts 1700000000000 --rand 1234
```

## 9. Ограничения

- Схема подтверждена статически; поведение устройства не проверялось.
- Неизвестно, требуется ли для локального API `passToken` или SV bind-ключи.
- `serviceToken` — публичная константа из APK, а не пользовательский секрет.
- Реальные `passToken` нельзя коммитить: они дают доступ к аккаунту.
