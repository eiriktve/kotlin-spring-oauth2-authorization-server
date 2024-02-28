# Spring Boot Authorization Server

Authorization server to handle OAuth2.1 management, leveraging Spring's Authorization Server framework.

This application is designed to be used as an OAuth Authorization server supporting the *client credentials* 
grant type/flow. The idea is to have this as the authorization manager for *clients* (such as APIs or 
automated jobs) that want to interact with different *resource servers*, and for resource servers to be able
to verify access tokens provided by said clients. 


## Features
- Spring Authorization server
- Device Authorization with Oauth2.1 
- Client Credential grant

## Technologies
- Kotlin with JDK 17
- Spring 3
- Spring Authorization Server
- Spring Security
- Postgresql for storing the registered client repository and authorizations 

## Usage
The server automatically persists a valid client upon startup which you can use to either retrieve registered clients
or to register new clients.

To get an access token you need to do a request to ```{server}:{port}/oauth2/token```  
The request should be on this format (choose the scopes you need):

````text
POST /oauth2/token HTTP/1.1
Authorization: Basic <base64-encoded-credentials>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=client.create
````

Credentials should be base64 encoded as <**client-id**>:<**client-secret**>  
Can be done in bash like this: ```echo -n "client-id:client-secret" | base64```

A valid response will look like this:
````text
{
    "access_token": "eyJraWQiOiI5ZDM2ZmJhMi01ZGIxLTQ4MzctODM2YS0zODkyYWUzZDhmMjciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdGFja2NhbmFyeS1jbGllbnQiLCJhdWQiOiJzdGFja2NhbmFyeS1jbGllbnQiLCJuYmYiOjE3MDkxNTU0NjEsInNjb3BlIjpbIm1lc3NhZ2VzLnJlYWQiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNzA5MTU3MjYxLCJpYXQiOjE3MDkxNTU0NjEsImp0aSI6ImZmNmUyNjMwLTY2Y2QtNGU0Ny1hY2VhLWMzYTk1NTEzOGZjYiJ9.iTUZ1kuAD5f-Zw0BKjodrmRTocq1iQkxoqSMnjNGd_Abo48w_gtYxgHtV1AQ5FUU-C-ZBYNUQtPlauwgAjU0kT2dh83Bb6fAMd-n0zhml7YPNuN11VYTaOH36WxF8q2JTN68yoUITgkTwljOoTTQw58wAGNSSkqic4dzAUTIxUwNDJzEXByrezgPQO7O53EDBril8cLwFRMLPYW_3s0FRkQH1vXc1G2ltPEvfpaZXwnn4ArxSAMVQKXhxjPMxL5yWhKHbRkdj1kJmpAc2qvx0cBtwRnbxlhyisxR8myZS2Fea-Cje5QqJGQACfj8TV8KbVBogYky3t48uuP1UVGuMQ",
    "scope": "messages.read",
    "token_type": "Bearer",
    "expires_in": 1799
}
````

You can import an example request for the default registered client [here](postman/Authorization server.postman_collection.json)

## Database
The Spring Oauth component *RegisteredClientRepository* depends on the table definitions described in 
"classpath:org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql" and 
therefore must be defined in the database schema you're using. These are used to store clients and authorizations (i.e., token information).

The updated table definitions can be found here:
https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql

and here: https://github.com/spring-projects/spring-authorization-server/blob/main/oauth2-authorization-server/src/main/resources/org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql

As for the schema version for this application, we're using this:
````sql
CREATE TABLE oauth2_registered_client (
        id varchar(100) NOT NULL,
        client_id varchar(100) NOT NULL,
        client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
        client_secret varchar(200) DEFAULT NULL,
        client_secret_expires_at timestamp DEFAULT NULL,
        client_name varchar(200) NOT NULL,
        client_authentication_methods varchar(1000) NOT NULL,
        authorization_grant_types varchar(1000) NOT NULL,
        redirect_uris varchar(1000) DEFAULT NULL,
        post_logout_redirect_uris varchar(1000) DEFAULT NULL,
        scopes varchar(1000) NOT NULL,
        client_settings varchar(2000) NOT NULL,
        token_settings varchar(2000) NOT NULL,
        PRIMARY KEY (id)
);
````

````sql
CREATE TABLE oauth2_authorization (
      id varchar(100) NOT NULL,
      registered_client_id varchar(100) NOT NULL,
      principal_name varchar(200) NOT NULL,
      authorization_grant_type varchar(100) NOT NULL,
      authorized_scopes varchar(1000) DEFAULT NULL,
      attributes text DEFAULT NULL,
      state varchar(500) DEFAULT NULL,
      authorization_code_value text DEFAULT NULL,
      authorization_code_issued_at timestamp DEFAULT NULL,
      authorization_code_expires_at timestamp DEFAULT NULL,
      authorization_code_metadata text DEFAULT NULL,
      access_token_value text DEFAULT NULL,
      access_token_issued_at timestamp DEFAULT NULL,
      access_token_expires_at timestamp DEFAULT NULL,
      access_token_metadata text DEFAULT NULL,
      access_token_type varchar(100) DEFAULT NULL,
      access_token_scopes varchar(1000) DEFAULT NULL,
      oidc_id_token_value text DEFAULT NULL,
      oidc_id_token_issued_at timestamp DEFAULT NULL,
      oidc_id_token_expires_at timestamp DEFAULT NULL,
      oidc_id_token_metadata text DEFAULT NULL,
      refresh_token_value text DEFAULT NULL,
      refresh_token_issued_at timestamp DEFAULT NULL,
      refresh_token_expires_at timestamp DEFAULT NULL,
      refresh_token_metadata text DEFAULT NULL,
      user_code_value text DEFAULT NULL,
      user_code_issued_at timestamp DEFAULT NULL,
      user_code_expires_at timestamp DEFAULT NULL,
      user_code_metadata text DEFAULT NULL,
      device_code_value text DEFAULT NULL,
      device_code_issued_at timestamp DEFAULT NULL,
      device_code_expires_at timestamp DEFAULT NULL,
      device_code_metadata text DEFAULT NULL,
      PRIMARY KEY (id)
);
````