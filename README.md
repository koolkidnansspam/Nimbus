# Nimbus

A small web proxy with cookie sessions, in the style of Rammerhead. One dependency (`ws`, for WebSockets).

## Run it

Needs Node 18.14 or newer.

    npm install
    node server.js

Then open http://127.0.0.1:8080

## Settings (environment variables)

- `PORT`: default 8080
- `HOST`: default 127.0.0.1 (this computer only). Use `0.0.0.0` to allow other devices.
- `PASSWORD`: if set, starting a session requires it. Set this if the server is on the internet.
- `ALLOW_PRIVATE=1`: lets the proxy reach localhost and home-network addresses. Off by default.
- `SEARCH_URL`: search engine used when you type words instead of an address. Default `https://html.duckduckgo.com/html/?q=` (your words are added on the end). Example: `SEARCH_URL=https://www.bing.com/search?q=`
- `YOUTUBE_FRONTEND`: address of an Invidious or Piped site. Turns on YouTube support (see below).
- `DEBUG=1`: logs each request (site, path, status) and WebSocket events, and shows what a site says when it refuses you (403). For troubleshooting. Off by default because it records what you browse.
  - Mac/Linux: `DEBUG=1 node server.js`
  - Windows (cmd): `set DEBUG=1&& node server.js`
  - Windows (PowerShell): `$env:DEBUG=1; node server.js`

Example: `HOST=0.0.0.0 PASSWORD=pick-something node server.js`

## How it works

- Each session has an ID. Cookies that sites set go into that session on the server. Your browser never stores them.
- Sessions live in memory, so they disappear when the server restarts. Idle sessions are deleted after 3 days.
- Pages are rewritten so links, images, styles, forms, fetch, XHR and WebSockets all go back through the proxy.
- Only a fixed set of request headers is forwarded, so your IP address (X-Forwarded-For) and browser cookies are not passed on.

## YouTube (optional)

YouTube's own site needs scripts Nimbus cannot run, so it will not load directly. Instead, point Nimbus at an Invidious or Piped site. These are open-source YouTube front ends that work as ordinary web pages:

    YOUTUBE_FRONTEND=https://your-instance.example node server.js

After that, YouTube links open there, through the proxy: watch pages, youtu.be links, shorts, search and channels. Typing `youtube.com` in the address bar works too. YouTube's scripts, images and other files are left alone.

- Public instances often go down or get blocked by YouTube. Check that the instance plays a video in a normal browser tab before you use it. The Invidious and Piped projects each keep a list of public instances.
- Running your own instance is the reliable option.
- This was tested with a stand-in server, not real YouTube.

## Site fixes

Some sites check which address they are running on. `SITE_PATCHES` in `server.js` holds small edits for these. Right now it has one, for Pokemon Showdown. If a fix stops working after the site updates, run with `DEBUG=1` and look for `SITE PATCH DID NOT MATCH`.

## Limits

- No service workers or Google sign-in. Heavy web apps (YouTube, Discord, Netflix) will not work. WebSocket apps such as browser games may work; it depends on the site.
- Pages that add HTML with scripts (innerHTML) can load a few items straight from the site instead of through the proxy.
- localStorage is shared by all sites in a browser, since they all sit on the proxy's address. Sites do not get their own storage.
- All sites in one session share one origin, so a site you visit could in theory reach other sites you are logged into in the same session. Use it for everyday browsing, not banking, and use a new session for anything sensitive.
- If you run this on a remote server, the server owner (you) can see the traffic. Nothing here is encrypted between the proxy and you unless you put HTTPS in front of it.
