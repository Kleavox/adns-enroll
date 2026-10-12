# adns-enroll

A small web app in front of [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
that gives the people you approve their own DNS-over-HTTPS address, such as
`https://dns.example.com/dns-query/3f9c…`, and a page that shows it with a Copy
button, so nobody has to remember a long ClientID.

- A person signs in, asks for a device ("Phone") and waits.
- An admin approves or rejects. On approval the app makes a random 128-bit
  ClientID, adds it to AdGuard as a client and to **Allowed clients**.
- The person sees the address, can make a **New address** (the old one stops at
  once) or **Remove** the device. An admin can **Revoke** any device.
- Every 10 minutes, and on start, the app checks AdGuard against its own list
  and repairs what drifted.

It only touches what it made: entries in Allowed clients and clients it did
not create are never changed. AdGuard's API is called on the private network
only; it never needs to face the internet.

## How it runs

One container, Go standard library only, pages rendered on the server. Data
is one JSON file in `/data`. The container runs as a non-root user and works
with a read-only root filesystem.

Sign-in comes from the front door. Today that is Cloudflare Access: the app
verifies the `Cf-Access-Jwt-Assertion` token itself (signature, issuer,
audience, expiry) against your team's keys and answers 401 without a valid
one.

## Configuration

| Variable | Meaning |
| --- | --- |
| `ADGUARD_URL` | AdGuard Home base URL, e.g. `http://host.docker.internal:3000` |
| `ADGUARD_USERNAME`, `ADGUARD_PASSWORD` | an AdGuard user for this app |
| `DOH_HOST` | host shown in the address, e.g. `dns.example.com` |
| `ADMIN_EMAILS` | comma-separated admin emails |
| `ACCESS_TEAM` | Cloudflare Access team domain, e.g. `yourteam.cloudflareaccess.com` |
| `ACCESS_AUD` | the AUD tag of the Access application in front of this app |
| `DATA_DIR` | data directory, default `/data` |
| `LISTEN` | listen address, default `:8080` |

Without `ACCESS_TEAM` or `ACCESS_AUD` the app starts, answers `/healthz`, and
every page says which of the two is missing. That lets you deploy first and
copy the AUD once the Access application exists.

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
    image: ghcr.io/kleavox/adns-enroll:0.1.0
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
      DOH_HOST: dns.example.com
      ADMIN_EMAILS: ${ADMIN_EMAILS}
      ACCESS_TEAM: yourteam.cloudflareaccess.com
      ACCESS_AUD: ${ACCESS_AUD}
    volumes:
      - data:/data

volumes:
  data:
```

The app must reach AdGuard's web port on the host and nothing else. With
[Krynodes](https://github.com/Kleavox/Krynodes) that is a Contained stack with
**Reach this server on** `3000/tcp`, published through its **Web address**.

## Development

```sh
gofmt -l .
go vet ./...
go test ./...
```

Releases: a `vX.Y.Z` tag builds `ghcr.io/kleavox/adns-enroll:X.Y.Z` and
`:latest` for linux/amd64 and linux/arm64.
