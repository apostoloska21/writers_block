# Безбедна автентикација (Flask) + RBAC/JIT + HTTPS (PKI)

## Опис
Овој репозиториум содржи Flask веб-апликација („Writer’s Block“) која демонстрира практична имплементација на безбедна корисничка автентикација, контрола на пристап со улоги (RBAC) и привремени дозволи (JIT), како и пристап преку HTTPS со локално генерирани сертификати (PKI).

## Функционалности
### 1) Регистрација и автентикација
- Регистрација со валидација на email и лозинка (policy за сложеност).
- Хеширање на лозинки со SHA-256 + уникатен salt по корисник.
- Email верификација преку 6-цифрен код (валиден 10 минути).
- 2-step login: по username/password се праќа верификациски код на email и се логира по внесување код.

### 2) Сесии и безбедносни поставки
- Управување со сесии преку Flask-Login.
- Cookie заштита: Secure, HttpOnly и SameSite.
- Ограничување на траење на сесија.

### 3) RBAC (Role-Based Access Control)
- Систем на улоги:
  - ORG_ADMIN (администратор)
  - EMPLOYEE (организациска улога)
  - DB_READER / DB_WRITER (ресурсни улоги)
- Заштитени рути според улога (пример: admin панели, организациски ресурси, ресурсни акции).

### 4) JIT (Just-In-Time) дозволи
- Доделување на DB_WRITER како привремена улога (пр. 1 час).
- Автоматска проверка за истечени улоги и испраќање нотификации (до корисник и администратор).

### 5) HTTPS и сертификати (PKI)
- Локално генерирана PKI структура:
  - Root CA (FINKI CA)
  - Intermediate CA (IB CA)
  - Lab CA
  - Server сертификат за `localhost` со `subjectAltName=DNS:localhost,IP:127.0.0.1`
- Import на CA сертификат во macOS Keychain и поставување “Always Trust” за да нема browser warning при `https://localhost:8443`.

## Технологии
- Python, Flask
- PostgreSQL, SQLAlchemy
- Flask-Login (sessions)
- Flask-Mail (email верификација/нотификации)
- OpenSSL (сертификати)
- HTML/Jinja2 templates
- XSS


