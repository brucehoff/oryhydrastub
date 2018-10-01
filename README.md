# oryhydrastub

This is a test implementation of the services required to make Ory Hydra work.  See https://www.ory.sh/docs/guides/master/hydra


To run the end-to-end test:

(1) start up Ory Hydra and the stubbed out auth service:

```
docker-compose up
```
(2) Register the client ID and secret:

```
docker run --rm -it \
  -e HYDRA_ADMIN_URL=http://10.0.0.87:9001 \
  oryd/hydra:v1.0.0-beta.9 \
  clients create --skip-tls-verify \
    --id demo-client-id \
    --secret demo-client-secret \
    --grant-types authorization_code,refresh_token,client_credentials,implicit \
    --response-types token,code,id_token \
    --scope openid,offline,demo.scope \
    --callbacks http://127.0.0.1:9010/callback
```
(3) Start the client app:

```
docker run --rm -it \
  -p 9010:9010 \
  oryd/hydra:v1.0.0-beta.9 \
  token user --skip-tls-verify \
    --port 9010 \
    --auth-url http://10.0.0.87:9000/oauth2/auth \
    --token-url http://10.0.0.87:9000/oauth2/token \
    --client-id demo-client-id  \
    --client-secret demo-client-secret \
    --scope openid,offline,demo.scope
```

Note:  This demo currently does not use TLS, does not use a Docker network to connect the containers, and uses only an in-memory database.  For more info on this demo, see: 

[The authentication and consent flow](https://www.ory.sh/docs/guides/latest/hydra/3-overview/1-oauth2#authenticating-users-and-requesting-consent)

[The system set-up instructions](https://www.ory.sh/docs/guides/master/hydra/4-install/)

[The javascript implementation of what we have stubbed out here in Java](https://github.com/ory/hydra-login-consent-node)

[The source code for the server](https://github.com/ory/hydra)

