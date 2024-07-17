keycloakHost = "http://localhost:8080"
baseUrl = '{}/auth/realms/Flask_Realm/protocol/openid-connect/'.format(keycloakHost)

authEndpoint = baseUrl + "auth"
callbackEndpoint = baseUrl + "callback"
tokenEndpoint = baseUrl + "token"
logoutEndpoint = baseUrl + "logged_out"
local = "http://localhost:8080/"
