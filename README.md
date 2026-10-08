# letsencrypt-cert-generator-fabric
A Harper Application for handling HTTP letsencrypt challenges for fabric bring your own domain. 
This was added to your cluster to support completing the challenge and getting certs issued for your domain.
This application will renew your certificates for you.
If you no longer wish to use your own certificates, you can unbind your domain from your cluster in [Fabric Studio](https://fabric.harper.fast)

Requires Harper 5.0.2 or later.

## How it works

Each bound domain is a record in the `ChallengeCertificate` table. One node in the cluster (the first entry in
`hdb_nodes`) requests certificates from Let's Encrypt using the HTTP-01 challenge, which every node answers at
`/.well-known/acme-challenge/<token>`.

- A new domain gets its first attempt after a short delay, so the application can finish deploying to every node.
- A failed attempt is retried with exponential backoff (2 minutes, doubling, up to every 6 hours) until it succeeds
  or the domain is unbound. Restarts do not interrupt this: the schedule is stored on the record and every record is
  rechecked each minute.
- Certificates are renewed once a third of their lifetime remains (60 days into a 90-day certificate).

Useful fields on a `ChallengeCertificate` record:

| Field            | Meaning                                               |
| ---------------- | ----------------------------------------------------- |
| `issueDate`      | When the current certificate was issued and installed |
| `renewalDate`    | When it will be renewed                               |
| `failedAttempts` | Consecutive failed attempts since the last success    |
| `nextAttemptAt`  | When the next attempt is scheduled                    |
| `lastError`      | Why the last attempt failed                           |
| `inProgress`     | Whether an attempt is running (informational)         |

## Development

```bash
npm install
npm test
npm run format:check
```

Set `ACME_DIRECTORY_URL` to request certificates from a different ACME server, such as
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/) or a local
[Pebble](https://github.com/letsencrypt/pebble) server. It defaults to Let's Encrypt production.