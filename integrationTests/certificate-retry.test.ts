/**
 * Integration tests for the certificate manager's request and retry handling on a real Harper instance.
 *
 * The component is pointed at a local stand-in CA that rejects every request, so every certificate attempt
 * fails as soon as it reads the ACME directory. (A CA that cannot be reached at all is retried by acme-client
 * for over a minute per attempt.) That exercises, against Harper's real table, subscription and leader lookup:
 *  - a new domain ({ domain } only, as Fabric binds it) being picked up and attempted,
 *  - a failed attempt recording failedAttempts, nextAttemptAt (2 minutes out), lastError, and clearing
 *    inProgress and the challenge,
 *  - a record left inProgress by an interrupted attempt still being retried,
 *  - an issued domain not due for renewal being left alone.
 *
 * Issuance against a real CA is not covered: it needs a CA that can reach this node over HTTP.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';
import {
	getChallengeCertificate,
	issuedFields,
	startHarperWithComponent,
	upsertChallengeCertificates,
	waitFor,
	type ChallengeCertificateRecord,
} from './helpers.ts';

const RETRY_BASE_DELAY_MS = 2 * 60 * 1000;
/**
 * The subscription usually starts an attempt within a second, but the event for a domain's own scheduling write
 * can arrive while that domain is still in flight and be dropped. The scan, every minute, then picks it up.
 */
const ATTEMPT_TIMEOUT_MS = 90_000;

function assertFirstFailureRecorded(record: ChallengeCertificateRecord, attemptStartedAt: number) {
	strictEqual(record.failedAttempts, 1);
	strictEqual(record.inProgress, false);
	strictEqual(record.challengeToken ?? null, null, 'the challenge should be cleared');
	strictEqual(record.challengeContent ?? null, null, 'the challenge should be cleared');
	strictEqual(record.issueDate ?? null, null, 'a failed attempt must not mark the domain issued');
	ok(record.lastError, 'lastError should say why the attempt failed');
	const nextAttemptAt = new Date(record.nextAttemptAt!).getTime();
	ok(
		nextAttemptAt >= attemptStartedAt + RETRY_BASE_DELAY_MS && nextAttemptAt <= Date.now() + RETRY_BASE_DELAY_MS,
		`nextAttemptAt should be 2 minutes after the failure, got ${new Date(nextAttemptAt).toISOString()}`
	);
}

suite('Certificate requests against a CA that rejects them', (ctx: ContextWithHarper) => {
	let directoryRequests = 0;
	const rejectingCA = createServer((req, res) => {
		directoryRequests++;
		res.writeHead(403, { 'Content-Type': 'application/problem+json' });
		res.end(
			JSON.stringify({ type: 'urn:ietf:params:acme:error:unauthorized', detail: 'test CA rejects every request' })
		);
	});
	let directoryUrl: string;

	before(async () => {
		rejectingCA.listen(0, '127.0.0.1');
		await once(rejectingCA, 'listening');
		directoryUrl = `http://127.0.0.1:${(rejectingCA.address() as AddressInfo).port}/directory`;
		await startHarperWithComponent(ctx, { ACME_DIRECTORY_URL: directoryUrl });
	});

	after(async () => {
		await teardownHarper(ctx);
		rejectingCA.close();
	});

	test('a newly bound domain is attempted and its failure scheduled for retry', async () => {
		const domain = 'new-domain.example.com';
		const attemptStartedAt = Date.now();
		const { status, body } = await upsertChallengeCertificates(ctx, [{ domain }]);
		strictEqual(status, 200, `upsert should succeed, got ${status}: ${JSON.stringify(body)}`);

		const record = await waitFor(
			`${domain} to record a failed attempt`,
			() => getChallengeCertificate(ctx, domain),
			(record) => Boolean(record?.failedAttempts),
			{ timeoutMs: ATTEMPT_TIMEOUT_MS }
		);
		assertFirstFailureRecorded(record!, attemptStartedAt);
		ok(directoryRequests > 0, 'the component should have requested the configured ACME directory');
		strictEqual(record!.lastError, `Attempting to read ACME directory returned error 403: ${directoryUrl}`);
	});

	test('a record left inProgress by an interrupted attempt is retried', async () => {
		// v1.0.0 skipped such records forever; now only the schedule fields decide.
		const domain = 'stuck.example.com';
		const attemptStartedAt = Date.now();
		await upsertChallengeCertificates(ctx, [
			{ domain, inProgress: true, challengeToken: 'stale-token', challengeContent: 'stale-token.keyauth' },
		]);

		const record = await waitFor(
			`${domain} to record a failed attempt`,
			() => getChallengeCertificate(ctx, domain),
			(record) => Boolean(record?.failedAttempts),
			{ timeoutMs: ATTEMPT_TIMEOUT_MS }
		);
		assertFirstFailureRecorded(record!, attemptStartedAt);
	});

	test('an issued domain that is not due for renewal is left alone', async () => {
		const domain = 'issued.example.com';
		const issued = issuedFields();
		await upsertChallengeCertificates(ctx, [{ domain, ...issued }]);
		// Give the subscription time to see the write; a probe domain written afterward shows it has caught up.
		const probe = 'issued-probe.example.com';
		await upsertChallengeCertificates(ctx, [{ domain: probe }]);
		await waitFor(
			`${probe} to record a failed attempt`,
			() => getChallengeCertificate(ctx, probe),
			(record) => Boolean(record?.failedAttempts),
			{ timeoutMs: ATTEMPT_TIMEOUT_MS }
		);

		const record = await getChallengeCertificate(ctx, domain);
		ok(record, `${domain} should still exist`);
		strictEqual(record.failedAttempts ?? null, null, 'no attempt should have been made');
		strictEqual(record.nextAttemptAt ?? null, null, 'no attempt should have been scheduled');
		strictEqual(new Date(record.renewalDate!).getTime(), issued.renewalDate);
	});
});
