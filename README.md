# adns-enroll

A small web app in front of [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
that gives the people you approve their own DNS-over-HTTPS address, such as
`https://dns.example.com/dns-query/3f9c…`, and a page that shows it with a Copy
button, so nobody has to remember a long ClientID.

- A person signs in with [Pawl](https://github.com/Kleavox/Pawl). The first
  sign-in is a request: they are thanked and wait, and nothing more is shown.
- An admin approves or rejects. On approval the app makes a random 128-bit
  ClientID, adds it to AdGuard as a client and to **Allowed clients**. One
  address per account; every device of theirs uses it.
- Only the admin makes a **New address** (the old one stops at once) or
  **Revokes** an account.
- Every 10 minutes, and on start, the app checks AdGuard against its own list
  and repairs what drifted. Every 6 hours, and on start, it asks Pawl which
  approved accounts still exist; an account Pawl no longer knows (deleted, or
  disconnected from this app) stops working, and comes back as it was when
  that person signs in again. When Pawl cannot be asked, nothing changes.

It only touches what it made: entries in Allowed clients and clients it did
not create are never changed. AdGuard's API is called on the private network
only; it never needs to face the internet.

AdGuard reads an empty Allowed clients list as "everyone". When removing a
device would leave the list empty, the app puts `192.0.2.1` there instead, a
documentation address no client can have (RFC 5737), so AdGuard keeps
answering nobody. The next approved device takes its place.

## What it reads from AdGuard

The address is AdGuard's own: every page and card asks **Settings →
Encryption settings** for the server name and the HTTPS port (`:port` is added
unless it is 443), so a change there shows at once. With encryption off, or
AdGuard not answering, no address is shown, only why; the ClientID still is.
The Android Private DNS hostname, `<ClientID>.<server name>`, is offered only
when DNS-over-TLS is on port 853 and the certificate covers `*.<server name>`
(the name also needs a wildcard DNS record). The note that the person running
the server can see the names looked up shows while AdGuard's query log is on,
or when that setting cannot be read.

## How it runs

One container, Go standard library only, pages rendered on the server. Data
is one JSON file in `/data`. The container runs as a non-root user and works
with a read-only root filesystem.

Sign-in is OpenID Connect with Pawl (authorization code, PKCE, a client
secret). The app checks Pawl's ES256 ID token itself and keeps its own
12-hour session cookie. An account is Pawl's `sub` for this app; the email is
only shown. Put nothing in front of the app's Web address: no Cloudflare
Access.

The app also answers Pawl's card, `GET /.well-known/pawl/card`, so the cabinet
shows the request's state: waiting, the DNS address and ClientID with Copy,
or no access. **Detail** opens this app. Pawl only relays what the app writes.
The card holds at most 70 characters per value; an address longer than that
(a server name and port over 19 characters) is left off the card and shown on
the page.

## Configuration

| Variable | Meaning |
| --- | --- |
| `ADGUARD_URL` | AdGuard Home base URL, e.g. `http://host.docker.internal:3000` |
| `ADGUARD_USERNAME`, `ADGUARD_PASSWORD` | an AdGuard user for this app |
| `PAWL_ISSUER` | Pawl's address, e.g. `https://paw.example.com` |
| `PAWL_CLIENT_ID`, `PAWL_CLIENT_SECRET` | from registering this app in Pawl |
| `PUBLIC_ORIGIN` | this app's own address, e.g. `https://enroll.example.com` |
| `ADMIN_SUBJECTS` | comma-separated Pawl subjects of the admins |
| `DATA_DIR` | data directory, default `/data` |
| `LISTEN` | listen address, default `:8080` |

Without one of the four Pawl settings the app starts, answers `/healthz`, and
every page says which one is missing. Without `ADMIN_SUBJECTS` nobody is admin,
and the page shows the signed-in person their own subject to put there.
Sessions are sealed with a key derived from the client secret, so a new secret
signs everyone out.

`ADMIN_EMAILS`, `ACCESS_TEAM`, `ACCESS_AUD` and, since 0.1.3, `DOH_HOST` are no
longer read; the log says so, and why, when they are still set.

## Registering in Pawl

In `paw.` sign in as the admin, then **Account → Registered apps → New app**:
the app's title, its address (`PUBLIC_ORIGIN`), who may see it, the return
address `PUBLIC_ORIGIN/auth/callback`, and **Shows a card on the cabinet**.
Pawl shows the ClientID and the secret once; put them in the settings above.

## From devices to accounts

Before 0.1.2 the app kept devices, signed in through Access. On start it turns
them into one account per owner email, approved, keeping their ClientIDs, so
no address stops working. That account has no Pawl subject yet. When the owner
of that email signs in with Pawl, their request shows **Link to the old
account** next to Approve; linking gives them the addresses they had. The app
never links on its own: an email match is the admin's call.

## AdGuard user

Give the app its own AdGuard user, so its password can be changed without
touching yours. Make a bcrypt hash (the command asks for the password, so it
stays out of your shell history):

```sh
htpasswd -nB enroll
```

Add it under `users:` in `AdGuardHome.yaml` and restart AdGuard Home:

```yaml
users:
  - name: admin
    password: $2y$10$…
  - name: enroll
    password: $2y$05$…
```

## Compose

```yaml
services:
  enroll:
    image: ghcr.io/kleavox/adns-enroll:0.1.3
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    extra_hosts:
      - host.docker.internal:host-gateway
    environment:
      ADGUARD_URL: http://host.docker.internal:3000
      ADGUARD_USERNAME: enroll
      ADGUARD_PASSWORD: ${ADGUARD_PASSWORD}
      PAWL_ISSUER: https://paw.example.com
      PAWL_CLIENT_ID: ${PAWL_CLIENT_ID}
      PAWL_CLIENT_SECRET: ${PAWL_CLIENT_SECRET}
      PUBLIC_ORIGIN: https://enroll.example.com
      ADMIN_SUBJECTS: ${ADMIN_SUBJECTS}
    volumes:
      - data:/data

volumes:
  data:
```

The app must reach AdGuard's web port on the host and Pawl's public address,
and nothing else. With
[Krynodes](https://github.com/Kleavox/Krynodes) that is a Contained stack with
**Reach this server on** `3000/tcp`, published through its **Web address**.

## Development

```sh
gofmt -l .
go vet ./...
go test ./...
```

Releases come from `VERSION`. A push to `main` that changes the code checks
whether the tag `v<VERSION>` exists; if not, it tests, builds and pushes
`ghcr.io/kleavox/adns-enroll:<VERSION>` and `:latest` for linux/amd64 and
linux/arm64, then tags the commit and publishes a GitHub release. Without a
bumped `VERSION` nothing is released.
