/**
 * acme-client 5.4.0 reports a final error without an HTTP response as a TypeError; lastError must show the
 * network error instead (lib/acmeNetworkErrors.js).
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, match } from 'node:assert/strict';
import { teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';
import {
	UNREACHABLE_ACME_DIRECTORY,
	getChallengeCertificate,
	startHarperWithComponent,
	upsertChallengeCertificates,
	waitFor,
} from './helpers.ts';

// acme-client's five retries wait 75s in all, after up to a minute for the scan to pick the domain up.
const FAILURE_TIMEOUT_MS = 180_000;

suite('Certificate requests against a CA that cannot be reached', (ctx: ContextWithHarper) => {
	before(async () => {
		await startHarperWithComponent(ctx);
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('the failed attempt records the connection error', async () => {
		const domain = 'unreachable-ca.example.com';
		await upsertChallengeCertificates(ctx, [{ domain }]);

		const record = await waitFor(
			`${domain} to record a failed attempt`,
			() => getChallengeCertificate(ctx, domain),
			(record) => Boolean(record?.failedAttempts),
			{ timeoutMs: FAILURE_TIMEOUT_MS, intervalMs: 1000 }
		);
		strictEqual(record!.failedAttempts, 1);
		match(record!.lastError!, new RegExp(`^ACME request to ${UNREACHABLE_ACME_DIRECTORY} failed: .*ECONNREFUSED`));
	});
});
