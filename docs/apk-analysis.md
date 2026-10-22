# Анализ APK приложения Xiaomi Glasses

## 1. Что за приложение

| Параметр | Значение |
|---|---|
| Package | `com.xiaomi.superhexa` |
| Название | Xiaomi Glasses / 小米眼镜 |
| Разработчик | Beijing Xiaomi Mobile Software Co., Ltd. |
| Версия (APKPure) | 3.1.0i |
| Официальный APK | 402 681 690 байт |
| Last-Modified | 12 Feb 2026 03:51:38 GMT |
| SHA-256 | `CFB86B4A886015EF75297646609C41FBD0E5A0069F8D68610EC6282F3EA68A00` |

Официальная страница загрузки:

```
https://cnbj1.fds.api.xiaomi.com/camera-glasses-fds/andriod/andriod_download.html
```

Она содержит JS-редирект на прямую ссылку:

```
https://cnbj1.fds.api.xiaomi.com/camera-glasses-fds/andriod/eco-andriod-glass.apk
```

> Примечание: в APKPure лежит XAPK-вариант 103.3 МБ с другим SHA-256
> (`f51233ad...`) — это другая упаковка (split APK), не идентичная официальному файлу.

## 2. Скачивание

```bash
curl -L --retry 2 -o glasses.apk \
  "https://cnbj1.fds.api.xiaomi.com/camera-glasses-fds/andriod/eco-andriod-glass.apk"
sha256sum glasses.apk
```

Проверка размера (HEAD):

```bash
curl -I "https://cnbj1.fds.api.xiaomi.com/camera-glasses-fds/andriod/eco-andriod-glass.apk"
# Content-Length: 402681690
```

## 3. Структура архива

APK — обычный ZIP. Наблюдения по официальному файлу:

| Метрика | Значение |
|---|---|
| Записей в архиве | **4768** |
| DEX-файлов | **17** (`classes.dex` … `classes17.dex`) |
| Крупнейшая библиотека | `libarcsoft_facialrestoration.so` — 65 237 904 байт |
| Прочее | ArcSoft-библиотеки (supernight, HDR, портреты), `libeffect.so`, `libttvesdk.so` (Volcengine) |
| Ресурсы | `assets/EffectResource/ILAModels.bundle/*` — ML-модели эффектов |
| H5 | `assets/dist/` — React-фронтенд |

Крупнейшие файлы:

```
65 237 904  lib/arm64-v8a/libarcsoft_facialrestoration.so
37 580 672  lib/arm64-v8a/libarcsoft_supernight.so
33 507 056  lib/arm64-v8a/libeffect.so
18 825 184  lib/arm64-v8a/libarcsoft_portrait_distortion_correction.so
15 543 112  lib/arm64-v8a/libarcsoft_high_dynamic_range.so
15 362 576  lib/arm64-v8a/libttvesdk.so
13 196 900  classes.dex
 9 989 386  assets/EffectResource/ILAModels.bundle/algo_ctvh0k4lqblbyyl59puvs_v1_0_model
 9 869 960  classes11.dex
```

## 4. Что искать в строках DEX

Скрипт `tools/apk_scan.py` извлекает:

- все URL (`https?://...`) — в официальном APK их **468** (по dex-файлам);
- хосты и их частоту;
- пути `/v1/...` — **79** уникальных;
- строки, связанные с подписью и OTA.

Пример запуска:

```bash
python tools/apk_scan.py glasses.apk
python tools/apk_scan.py glasses.apk --json > report.json
```

### Найденные хосты (верх списка)

```
44  github.com
27  logback.qos.ch
22  watch.iot.mi.com
14  www.xiaomi.com
14  apmplus.volces.com
12  qr.alipay.com
12  account.xiaomi.com
10  cdn.eco.mi.com
 8  i-preview.xiaomixiaoai.com
 7  i.xiaomixiaoai.com
 7  xiaomixiaoai.com (ASR/NLP)
```

### Главная находка

```
http://%s:8080/v1/ota/uploadOtaFile/
http://%s:8080/v1/ota/checkOtaStatus/
http://%s:8080/v1/ota_package
```

Шаблон `http://%s:8080` встречается 13 раз, `http://{host}:8080` — 5 раз.
Это локальный HTTP-сервер очков.

## 5. Инструменты

### Вариант A: androguard (чистый Python, без Java)

```bash
python -m pip install androguard
```

Работа с DEX:

```python
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

d = DEX(open("classes5.dex", "rb").read())
dx = Analysis()
dx.add(d)

for c in dx.get_classes():
    for m in c.get_methods():
        code = m.get_method().get_code()
        ...
```

Практические замечания:

- `androguard.misc.AnalyzeDex()` в версии 4.1.4 может возвращать не 2 значения —
  надёжнее использовать `DEX` + `Analysis` напрямую;
- логи androguard очень шумные: отключайте `logging` и `loguru`:

  ```python
  import logging
  logging.disable(logging.CRITICAL)
  from loguru import logger
  logger.remove()
  ```

- на Windows консоль cp1251 падает на не-ASCII строках — запускайте с
  `PYTHONIOENCODING=utf-8` и перенаправляйте вывод в файл.

### Вариант B: jadx (читаемый Java)

Требует Java 11+. Даёт более читаемый результат, но на 400-МБ APK с 17 dex
работает долго и требует много памяти.

```bash
jadx -d out glasses.apk
```

## 6. Как нашли схему подписи

1. Поиск строки `HEXA1-HMAC-SHA256` по dex → `classes5.dex`.
2. Поиск `HmacSHA256` → `classes4.dex` (класс `tools.d0`).
3. Дизассемблирование `CredentialCalculator` (методы `a`, `b`, `c`).
4. Дизассемблирование `tools.d0.a(String, String)` → HMAC-SHA256.
5. Дизассемблирование `ExtensionsKt.j(byte[])` → hex `%02x`.
6. Поиск интерцептора, который ставит заголовок → `interceptor.b`, заголовок
   **`Authorization`**.

Подробный разбор: [`hexa1-signing.md`](hexa1-signing.md).

## 7. Побочные находки

| Строка | Смысл |
|---|---|
| `VE_APP_SECRET`, `clientSecret`, `signSecret` | OAuth/подпись облачных запросов |
| `MiWearOTADownloadHelper` | загрузчик OTA из SDK miwear |
| `OTA_LOG checkFileByCheckSum fileCheckSum=%s serverCheckSum=%s` | проверка контрольной суммы OTA |
| `fileMd5`, `md5sum` | поля метаданных файлов |
| `WEAR_DETECTION_SENSITIVITY GET:` | чтение чувствительности датчика ношения |
| `ItemWearDetection(wearSensitivity=...)` | модель настройки |
| `deviceWearSensitivityTitle1/2/3` | три уровня чувствительности |
| `ve_camera_fps_max` (default 30) | фича-флаг FPS |
| `HEXA1-HMAC-SHA256` | схема подписи |
| `HMAC-SHA256 Credential=` | другая схема (вероятно, для другого сервиса) |

## 8. Ограничения анализа

- Статический анализ не показывает, какие проверки выполняет **само устройство**.
- Наличие эндпоинта не означает, что он доступен без авторизации.
- Формат OTA-пакета по APK не восстанавливается: файл тянется с сервера,
  а не лежит в APK.
