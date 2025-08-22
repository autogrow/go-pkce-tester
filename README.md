# OAuth2 PKCE Flow tester

This is a web interface that runs locally and helps to test and understand PKCE.  It acts as an OAuth2
client and runs the PKCE flow against a remote authorization server.  At each step the payloads and
responses can be inspected and the fields are explained in a handy table.

## Building

Run `go build ./cmd/oauthsrv`. ez.

## Usage

Run `./oauthsrv` and navigate to http://localhost:8080.

You can also specify the port it runs on with `-port 1234`.

Some applications will only callback to an SSL server, so we can use `-ssl` to make it run with SSL. By
default it runs on port 443 but you can change it with `-port 8443` so you don't need root access. Remember
to update your callback/redirect URI accordingly.  The cert and key are hard coded in the binary so you
will have to accept an "unsafe" certificate.

The config is stored in `./cfg.yml`.  You can make changes to the file or from the web interface.  Token
responses are also stored in `./tokens.yml` so you can view your previous responses in the web interface.

If your app uses refresh tokens, you can also request a new access token on these old responses using the
"Request Token" button and it will do the refresh token flow for you.

## AI Slop Warning

Much of this app was generated with claude haiku 3.5, so it's not the prettiest code and has HTML embedded
in the main file but I wanted everything in one file and one binary.

Tests?  Who needs tests... 😆
