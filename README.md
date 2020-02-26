# Spring Boot Gatekeeper Starter

## Введение
Данный Spring Boot Starter предназначен для упрощения взаимодействия с сервером авторизации на клиентской части в рамках Code Flow протокола OpenID Connect , подробнее: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.  
Он поддерживат автоматическую работу с токенами (обмен, проверка, обновление), имеет функционал отзыва токенов и упрощенную конфигурацию (по сравнению, например, с Spring Security).

## Конфигурация
Ссылка для redirect_uri всегда имеет следующий вид: `http(s)://{gateway-address}/openid/authorize/{client_id}`  
Префикс для всех настроек: gatekeeper.

### Endpoints
#### error-page-uri
Ссылка на страницу - куда будет выполнена переадресация в случае ошибки (например, ID Token имеет неправильную подпись)
#### authorization-page-uri
Ссылка на страницу аторизации  
спецификация: https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint
#### token-endpoint-uri
Ссылка на endpoint для обработки code и обмена токенов  
спецификация: https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
#### introspection-endpoint-uri
Ссылка на endpoint для проверки access токенов  
спецификация: https://tools.ietf.org/html/rfc7662#section-2
#### revocation-endpoint-uri
Ссылка на endpoint для отзыва токенов  
спецификация: https://tools.ietf.org/html/rfc7009#section-2

### OpenID Connect Clients
#### clients 
Список клиентов
#### id
Идентификатор клиента (client_id), должен быть равен route id в настройках Spring Cloud Gateway для которого необходим Code Flow
#### scope
Дополнительный scope клиента (можно не указывать, если требуется только openid, этот scope добавляется автоматичеки для всех клиентов) 
#### password
Пароль клиента для обращения к API token/introspection/revocation (client_secret)
#### secret
Secret для валидации ID Token по алгоритму HS256
#### default-page-uri
Ссылка на страницу - куда будет выполнена переадресация в случае потери/отсутсвия первоначального запроса к Gateway
#### default-page-uri-priority
Принимает значения true или false. Если флаг активен, то после успешной аутентификации клиент получит редирект на default-page-uri

### Пример yml конфигурации
Описание конфигурации Spring Cloud Gateway: https://cloud.spring.io/spring-cloud-gateway/reference/html/#gateway-request-predicates-factories
```yml
spring:
  cloud:
    gateway:
      routes:
        - id: test-app
          uri: http://web-application.com/
          predicates:
            - Path=/web-app/**
          filters:
            - StripPrefix=1

gatekeeper:
  error-page-uri: "https://authorization-server/error"
  authorization-page-uri: "https://authorization-server/login"
  token-endpoint-uri: "https://authorization-server/openid/token"
  introspection-endpoint-uri: "https://authorization-server/openid/check_token"
  revocation-endpoint-uri: "https://authorization-server/openid/logout"
  clients:
    - id: test-app
      scope: profile
      password: A4aympy2hkiohobesqugbprkp
      secret: T1x23hldjancmr3zooy7dlp8evkfkciz81c+y2z99oo=
      default-page-uri: "https://gateway/web-app/main"
``` 
