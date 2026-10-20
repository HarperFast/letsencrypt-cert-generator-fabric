/**
 * Certificate attempts and retries on a real Harper: its table, subscription and leader lookup.
 *
 * The component is pointed at a stand-in CA that rejects every request, so each attempt fails at the ACME
 * directory read. A CA that cannot be reached at all is retried by acme-client for over a minute per attempt.
 * Issuance is not covered: it needs a CA that can reach this node over HTTP.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';
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

function waitForFailedAttempt(ctx: ContextWithHarper, domain: string) {
	return waitFor(
		`${domain} to record a failed attempt`,
		() => getChallengeCertificate(ctx, domain),
		(record) => Boolean(record?.failedAttempts),
		{ timeoutMs: ATTEMPT_TIMEOUT_MS }
	);
}

suite('Certificate requests against a CA that rejects them', (ctx: ContextWithHarper) => {
	let directoryRequests = 0;
	const rejectingCA = createServer((_request, response) => {
		directoryRequests++;
		response.writeHead(403, { 'Content-Type': 'application/problem+json' });
		response.end(
			JSON.stringify({ type: 'urn:ietf:params:acme:error:unauthorized', detail: 'test CA rejects every request' })
		);
	});
	// A failed startup or teardown must not leave the server holding the test process open.
	rejectingCA.unref();
	let directoryUrl: string;

	before(async () => {
		rejectingCA.listen(0, '127.0.0.1');
		await once(rejectingCA, 'listening');
		directoryUrl = `http://127.0.0.1:${(rejectingCA.address() as AddressInfo).port}/directory`;
		await startHarperWithComponent(ctx, { ACME_DIRECTORY_URL: directoryUrl });
	});

	after(async () => {
		try {
			await teardownHarper(ctx);
		} finally {
			rejectingCA.close();
		}
	});

	test('a newly bound domain is attempted, and not again before its retry is due', async () => {
		const domain = 'new-domain.example.com';
		const attemptStartedAt = Date.now();
		const { status, body } = await upsertChallengeCertificates(ctx, [{ domain }]);
		strictEqual(status, 200, `upsert should succeed, got ${status}: ${JSON.stringify(body)}`);

		const record = await waitForFailedAttempt(ctx, domain);
		assertFirstFailureRecorded(record!, attemptStartedAt);
		ok(directoryRequests > 0, 'the component should have requested the configured ACME directory');
		strictEqual(record!.lastError, `Attempting to read ACME directory returned error 403: ${directoryUrl}`);

		// The failure write reaches the subscription too; it must not start another attempt.
		const requestsAfterFailure = directoryRequests;
		await sleep(3000);
		strictEqual(directoryRequests, requestsAfterFailure, 'no request should reach the CA before nextAttemptAt');
		strictEqual((await getChallengeCertificate(ctx, domain))?.failedAttempts, 1);
	});

	test('a record left inProgress by an interrupted attempt is retried', async () => {
		const domain = 'stuck.example.com';
		const attemptStartedAt = Date.now();
		await upsertChallengeCertificates(ctx, [
			{ domain, inProgress: true, challengeToken: 'stale-token', challengeContent: 'stale-token.keyauth' },
		]);

		assertFirstFailureRecorded((await waitForFailedAttempt(ctx, domain))!, attemptStartedAt);
	});

	test('an issued domain that is not due for renewal is left alone', async () => {
		const domain = 'issued.example.com';
		const issued = issuedFields();
		await upsertChallengeCertificates(ctx, [{ domain, ...issued }]);
		// Once a domain written afterward has been attempted, the subscription has seen this write.
		const probe = 'issued-probe.example.com';
		await upsertChallengeCertificates(ctx, [{ domain: probe }]);
		await waitForFailedAttempt(ctx, probe);

		const record = await getChallengeCertificate(ctx, domain);
		ok(record, `${domain} should still exist`);
		strictEqual(record.inProgress ?? null, null, 'no attempt should have started');
		strictEqual(record.failedAttempts ?? null, null, 'no attempt should have been made');
		strictEqual(record.nextAttemptAt ?? null, null, 'no attempt should have been scheduled');
		strictEqual(new Date(record.renewalDate!).getTime(), issued.renewalDate);
	});
});
