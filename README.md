# Nimbus

A small web proxy with cookie sessions, in the style of Rammerhead. No dependencies.

## Run it

Needs Node 18.14 or newer.

    node server.js

Then open http://127.0.0.1:8080

## Settings (environment variables)

- `PORT`: default 8080
- `HOST`: default 127.0.0.1 (this computer only). Use `0.0.0.0` to allow other devices.
- `PASSWORD`: if set, starting a session requires it. Set this if the server is on the internet.
- `ALLOW_PRIVATE=1`: lets the proxy reach localhost and home-network addresses. Off by default.

Example: `HOST=0.0.0.0 PASSWORD=pick-something node server.js`

## How it works

- Each session has an ID. Cookies that sites set go into that session on the server. Your browser never stores them.
- Sessions live in memory, so they disappear when the server restarts. Idle sessions are deleted after 3 days.
- Pages are rewritten so links, images, styles, forms, fetch and XHR all go back through the proxy.
- Only a fixed set of request headers is forwarded, so your IP address (X-Forwarded-For) and browser cookies are not passed on.

## Limits

- No WebSockets, service workers, or Google sign-in. Heavy web apps (YouTube, Discord, Netflix) will not work.
- localStorage is shared by all sites in a browser, since they all sit on the proxy's address. Sites do not get their own storage.
- All sites in one session share one origin, so a site you visit could in theory reach other sites you are logged into in the same session. Use it for everyday browsing, not banking, and use a new session for anything sensitive.
- If you run this on a remote server, the server owner (you) can see the traffic. Nothing here is encrypted between the proxy and you unless you put HTTPS in front of it.
