# Design notes

## Certificate work is derived from schedule fields, never from a flag

`lib/certificateManager.js` decides whether a domain needs a certificate attempt from the schedule
fields alone — `issueDate`, `renewalDate`, `nextAttemptAt` and `failedAttempts` (`nextStep`).
`inProgress` is written for visibility but never read as a gate, because a process that stops
mid-attempt (restart, redeploy, crash) cannot clear it.
Duplicate attempts within a worker are prevented by an in-memory set, which disappears with the
worker. A rolling restart briefly runs the old and new worker 0 side by side (on Linux Harper starts
the replacement before shutting the old one down), so two attempts on one domain can overlap there;
their challenge writes can collide and fail one attempt, which the normal retry recovers.

The subscription only makes new records start promptly. The recurring scan is what guarantees
progress: it revisits every record, including ones written while the subscription was not running.

A record is marked issued only after `add_certificate` succeeds, and a certificate that was issued but
failed to install is kept in memory and installed on the next attempt rather than requested again
(Let's Encrypt allows 5 duplicate certificates per week).
