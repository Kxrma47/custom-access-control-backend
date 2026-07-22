Repository name: custom-access-control-backend
Название репозитория: custom-access-control-backend

Access Control Backend
======================

English
-------

This project is a Python backend application with a custom authentication
and authorization system. It implements user registration, login, logout,
profile management, soft account deletion, token-based sessions,
database-backed roles, protected resources, and editable access rules.

The application does not rely on built-in authentication or authorization
features from a web framework. Password hashing, bearer-token creation,
session storage, user identification, role lookup, and permission checks are
implemented directly in the project code.


Project Structure
-----------------

access_app/
  auth.py          Password hashing and signed bearer-token helpers.
  api.py           HTTP routes and request handling.
  database.py      SQLite schema creation and seed data.
  permissions.py   Role and permission decision logic.
  settings.py      Runtime configuration.
  __main__.py      Server entry point.

tests/
  test_auth.py         Password and token tests.
  test_api.py          End-to-end HTTP API tests.
  test_permissions.py  Authorization rule tests.

scripts/
  demo.py          Runs a short local API demonstration.

data/
  app.sqlite3      Local SQLite database, created automatically.


Requirements
------------

Python 3.11 or newer.

No third-party runtime packages are required. The application uses only the
Python standard library.


How To Run
----------

From the project folder:

  python3 -m access_app

By default, the server runs at:

  http://127.0.0.1:8000

The database is created automatically at:

  data/app.sqlite3


Environment Variables
---------------------

ACCESS_APP_DB
  SQLite database path.

ACCESS_APP_SECRET
  Secret key used to sign bearer tokens.

ACCESS_APP_TOKEN_TTL
  Token lifetime in seconds.

ACCESS_APP_HOST
  Server host. Default: 127.0.0.1.

ACCESS_APP_PORT
  Server port. Default: 8000.


Seeded Accounts
---------------

Role       Email                 Password
admin      admin@example.com     AdminPass123!
manager    manager@example.com   ManagerPass123!
user       user@example.com      UserPass123!


API Endpoints
-------------

GET     /health
  Public health check.

POST    /auth/register
  Registers a new active user and assigns the default user role.

POST    /auth/login
  Authenticates by email and password, creates a session, and returns a
  bearer token.

POST    /auth/logout
  Revokes the current session.

GET     /me
  Returns the current authenticated user's profile.

PATCH   /me
  Updates the current authenticated user's profile.

DELETE  /me
  Soft-deletes the current account by setting is_active to false and revokes
  active sessions.

GET     /access/roles
  Lists roles. Admin only.

GET     /access/elements
  Lists protected business elements. Admin only.

GET     /access/rules
  Lists access rules. Admin only.

POST    /access/rules
  Creates or replaces an access rule. Admin only.

PATCH   /access/rules/{id}
  Updates selected permission fields for an access rule. Admin only.

DELETE  /access/rules/{id}
  Deletes an access rule. Admin only.

GET     /business/orders
POST    /business/orders
GET     /business/products
POST    /business/products
GET     /business/reports
  Mock business resources protected by authorization rules.


Authentication Behavior
-----------------------

After login, the API returns a bearer token. Protected endpoints expect:

  Authorization: Bearer <token>

If the request does not contain a valid token, the API returns:

  401 Authentication required.

Logout revokes the current session. Soft deletion also revokes all active
sessions for the deleted account and blocks future login attempts.


Authorization Model
-------------------

The authorization system is stored in database tables:

users
  Stores profile fields, email, password hash, activity status, and timestamps.

roles
  Stores available roles: admin, manager, and user.

user_roles
  Connects users to one or more roles.

business_elements
  Stores protected resource categories: orders, products, reports, and
  access_rules.

access_rules
  Stores permissions for each role and protected resource.

sessions
  Stores issued tokens, expiration timestamps, and revocation timestamps.


Access Rule Fields
------------------

read_permission
read_all_permission
create_permission
update_permission
update_all_permission
delete_permission
delete_all_permission

Fields ending in _all_permission grant access to all objects of that resource.
Fields without _all_permission grant access only to objects owned by the
current user. Mock business objects include owner_id values, so this rule can
be demonstrated without creating additional business tables.


Error Handling
--------------

401 Unauthorized
  Returned when the API cannot identify a logged-in user.

403 Forbidden
  Returned when the user is authenticated but the access rule does not allow
  the requested action.

404 Not Found
  Returned for unknown routes or unknown protected business elements.


Example Requests
----------------

Login:

  curl -s http://127.0.0.1:8000/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@example.com","password":"AdminPass123!"}'

Use the returned token:

  curl -s http://127.0.0.1:8000/access/rules \
    -H "Authorization: Bearer $TOKEN"

Create or replace a rule:

  curl -s http://127.0.0.1:8000/access/rules \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
      "role": "user",
      "element": "reports",
      "permissions": {
        "read_permission": true,
        "read_all_permission": true,
        "create_permission": false,
        "update_permission": false,
        "update_all_permission": false,
        "delete_permission": false,
        "delete_all_permission": false
      }
    }'


Testing
-------

Run the full test suite:

  python3 -m unittest discover -s tests -v

Run the demonstration script:

  python3 scripts/demo.py

The tests cover password hashing, token validation, invalid token rejection,
expired token rejection, session revocation, soft deletion, admin-only access
rule management, 401 responses, 403 responses, and successful protected
resource access.


Verified Output
---------------

Test command:

  python3 -m unittest discover -s tests -v

Result:

  Ran 9 tests
  OK

Demo command:

  python3 scripts/demo.py

Result:

  GET /health -> 200 {'status': 'ok'}
  GET /business/orders without token -> 401 {'error': 'Authentication required.'}
  POST /auth/login user@example.com -> 200 token_type=Bearer
  GET /business/orders as user -> 200 scope=own ids=[1, 3]
  GET /business/reports as user -> 403 {'error': 'Forbidden.'}
  POST /auth/login admin@example.com -> 200 token_type=Bearer
  POST /access/rules as admin -> 200 role=user element=reports
  GET /business/reports as user after rule change -> 200 scope=all


Русский
-------

Этот проект представляет собой backend-приложение на Python с собственной
системой аутентификации и авторизации. В нем реализованы регистрация
пользователя, вход, выход, управление профилем, мягкое удаление аккаунта,
сессии на основе bearer-токенов, роли в базе данных, защищенные ресурсы и
редактируемые правила доступа.

Приложение не использует готовую систему аутентификации или авторизации
какого-либо web-фреймворка. Хеширование паролей, создание bearer-токенов,
хранение сессий, определение текущего пользователя, получение ролей и
проверка прав доступа реализованы в коде проекта.


Структура проекта
-----------------

access_app/
  auth.py          Хеширование паролей и работа с подписанными токенами.
  api.py           HTTP-маршруты и обработка запросов.
  database.py      Создание схемы SQLite и тестовые данные.
  permissions.py   Логика ролей и правил доступа.
  settings.py      Настройки запуска.
  __main__.py      Точка входа для запуска сервера.

tests/
  test_auth.py         Тесты паролей и токенов.
  test_api.py          Сквозные HTTP-тесты API.
  test_permissions.py  Тесты правил авторизации.

scripts/
  demo.py          Короткая демонстрация работы API.

data/
  app.sqlite3      Локальная SQLite-база, создается автоматически.


Требования
----------

Python 3.11 или новее.

Сторонние runtime-зависимости не требуются. Приложение использует только
стандартную библиотеку Python.


Запуск
------

Из папки проекта:

  python3 -m access_app

По умолчанию сервер запускается по адресу:

  http://127.0.0.1:8000

База данных создается автоматически по пути:

  data/app.sqlite3


Переменные окружения
--------------------

ACCESS_APP_DB
  Путь к SQLite-базе данных.

ACCESS_APP_SECRET
  Секретный ключ для подписи bearer-токенов.

ACCESS_APP_TOKEN_TTL
  Время жизни токена в секундах.

ACCESS_APP_HOST
  Хост сервера. По умолчанию: 127.0.0.1.

ACCESS_APP_PORT
  Порт сервера. По умолчанию: 8000.


Тестовые аккаунты
-----------------

Роль       Email                 Пароль
admin      admin@example.com     AdminPass123!
manager    manager@example.com   ManagerPass123!
user       user@example.com      UserPass123!


API
---

GET     /health
  Публичная проверка состояния сервера.

POST    /auth/register
  Регистрирует нового активного пользователя и назначает роль user.

POST    /auth/login
  Проверяет email и пароль, создает сессию и возвращает bearer-токен.

POST    /auth/logout
  Отзывает текущую сессию.

GET     /me
  Возвращает профиль текущего авторизованного пользователя.

PATCH   /me
  Обновляет профиль текущего авторизованного пользователя.

DELETE  /me
  Выполняет мягкое удаление аккаунта: устанавливает is_active=false и
  отзывает активные сессии.

GET     /access/roles
  Возвращает список ролей. Только для администратора.

GET     /access/elements
  Возвращает список защищенных бизнес-элементов. Только для администратора.

GET     /access/rules
  Возвращает список правил доступа. Только для администратора.

POST    /access/rules
  Создает или заменяет правило доступа. Только для администратора.

PATCH   /access/rules/{id}
  Обновляет выбранные поля правила доступа. Только для администратора.

DELETE  /access/rules/{id}
  Удаляет правило доступа. Только для администратора.

GET     /business/orders
POST    /business/orders
GET     /business/products
POST    /business/products
GET     /business/reports
  Вымышленные бизнес-ресурсы, защищенные правилами авторизации.


Поведение аутентификации
------------------------

После login API возвращает bearer-токен. Для защищенных endpoints нужно
передавать заголовок:

  Authorization: Bearer <token>

Если в запросе нет валидного токена, API возвращает:

  401 Authentication required.

Logout отзывает текущую сессию. Мягкое удаление аккаунта также отзывает все
активные сессии пользователя и запрещает повторный вход.


Модель авторизации
------------------

Система авторизации хранится в таблицах базы данных:

users
  Профиль пользователя, email, хеш пароля, статус активности и timestamps.

roles
  Доступные роли: admin, manager и user.

user_roles
  Связь пользователей с одной или несколькими ролями.

business_elements
  Категории защищенных ресурсов: orders, products, reports и access_rules.

access_rules
  Права доступа каждой роли к каждому защищенному ресурсу.

sessions
  Выданные токены, время истечения и время отзыва сессии.


Поля правил доступа
-------------------

read_permission
read_all_permission
create_permission
update_permission
update_all_permission
delete_permission
delete_all_permission

Поля с окончанием _all_permission дают доступ ко всем объектам ресурса.
Поля без _all_permission дают доступ только к объектам, владельцем которых
является текущий пользователь. Вымышленные бизнес-объекты содержат owner_id,
поэтому это правило демонстрируется без создания дополнительных таблиц.


Обработка ошибок
----------------

401 Unauthorized
  Возвращается, если API не может определить залогиненного пользователя.

403 Forbidden
  Возвращается, если пользователь определен, но правило доступа не разрешает
  запрошенное действие.

404 Not Found
  Возвращается для неизвестных маршрутов или неизвестных бизнес-элементов.


Примеры запросов
----------------

Вход:

  curl -s http://127.0.0.1:8000/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@example.com","password":"AdminPass123!"}'

Использование полученного токена:

  curl -s http://127.0.0.1:8000/access/rules \
    -H "Authorization: Bearer $TOKEN"

Создание или замена правила:

  curl -s http://127.0.0.1:8000/access/rules \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
      "role": "user",
      "element": "reports",
      "permissions": {
        "read_permission": true,
        "read_all_permission": true,
        "create_permission": false,
        "update_permission": false,
        "update_all_permission": false,
        "delete_permission": false,
        "delete_all_permission": false
      }
    }'


Тестирование
------------

Запуск полного набора тестов:

  python3 -m unittest discover -s tests -v

Запуск демонстрационного скрипта:

  python3 scripts/demo.py

Тесты проверяют хеширование пароля, валидацию токена, отклонение неверного
токена, отклонение истекшего токена, отзыв сессии, мягкое удаление аккаунта,
административное управление правилами, ответы 401, ответы 403 и успешный
доступ к защищенным ресурсам.


Проверенный вывод
-----------------

Команда тестов:

  python3 -m unittest discover -s tests -v

Результат:

  Ran 9 tests
  OK

Команда демонстрации:

  python3 scripts/demo.py

Результат:

  GET /health -> 200 {'status': 'ok'}
  GET /business/orders without token -> 401 {'error': 'Authentication required.'}
  POST /auth/login user@example.com -> 200 token_type=Bearer
  GET /business/orders as user -> 200 scope=own ids=[1, 3]
  GET /business/reports as user -> 403 {'error': 'Forbidden.'}
  POST /auth/login admin@example.com -> 200 token_type=Bearer
  POST /access/rules as admin -> 200 role=user element=reports
  GET /business/reports as user after rule change -> 200 scope=all
