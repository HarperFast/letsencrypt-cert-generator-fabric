/**
 * Integration tests for the ChallengeCertificate table and the ACME HTTP-01 challenge middleware.
 *
 * Covers:
 *  - Harper startup with this component loaded, and the ChallengeCertificate schema it creates.
 *  - ChallengeCertificate records via the Operations API. The table is not REST-exported (no @export in
 *    schema.graphql), so it is reached only through the Operations API and the component itself.
 *  - The middleware serving a stored challenge at /.well-known/acme-challenge/<token> without authentication,
 *    and passing every other request through, including challenge URLs for unknown tokens.
 *
 * Records here are seeded as already issued (see issuedFields) so the certificate manager leaves them alone;
 * certificate attempts are covered by certificate-retry.test.ts.
 */
import { suite, test, before, after } from 'node:test';
import { deepStrictEqual, strictEqual, ok } from 'node:assert/strict';
import { teardownHarper, type ContextWithHarper } from '@harperfast/integration-testing';
import {
	anonFetch,
	authFetch,
	getChallengeCertificate,
	issuedFields,
	op,
	startHarperWithComponent,
	upsertChallengeCertificates,
	waitFor,
} from './helpers.ts';

suite('Harper startup', (ctx: ContextWithHarper) => {
	before(async () => {
		await startHarperWithComponent(ctx);
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('Harper starts successfully with the component loaded', async () => {
		const res = await authFetch(ctx, '/');
		ok([200, 400, 404].includes(res.status), `Harper should be reachable, got HTTP ${res.status}`);
	});

	test('ChallengeCertificate table is created with every schema attribute', async () => {
		const { status, body } = await op<{ attributes: { attribute: string }[] }>(ctx, {
			operation: 'describe_table',
			database: 'data',
			table: 'ChallengeCertificate',
		});
		strictEqual(status, 200, `describe_table should succeed, got ${status}: ${JSON.stringify(body)}`);
		const attributes = body.attributes.map(({ attribute }) => attribute);
		for (const attribute of [
			'domain',
			'issueDate',
			'renewalDate',
			'challengeToken',
			'challengeContent',
			'inProgress',
			'failedAttempts',
			'nextAttemptAt',
			'lastError',
		]) {
			ok(attributes.includes(attribute), `expected attribute ${attribute}, got ${attributes.join(', ')}`);
		}
	});

	test('ChallengeCertificate is not exposed over REST', async () => {
		const res = await authFetch(ctx, '/ChallengeCertificate/');
		strictEqual(res.status, 404, `ChallengeCertificate should not be REST-exported, got HTTP ${res.status}`);
	});
});

suite('ChallengeCertificate table via Operations API', (ctx: ContextWithHarper) => {
	before(async () => {
		await startHarperWithComponent(ctx);
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('upsert then search_by_id round-trips a record', async () => {
		const domain = 'roundtrip.example.com';
		const { status, body } = await upsertChallengeCertificates(ctx, [
			{ domain, challengeToken: 'abc123token', challengeContent: 'abc123token.keyauth-content', ...issuedFields() },
		]);
		strictEqual(status, 200, `upsert should succeed, got ${status}: ${JSON.stringify(body)}`);

		const record = await getChallengeCertificate(ctx, domain);
		ok(record, `${domain} should be found`);
		strictEqual(record.domain, domain);
		strictEqual(record.challengeToken, 'abc123token');
		strictEqual(record.challengeContent, 'abc123token.keyauth-content');
	});

	test('upsert merges into an existing record instead of replacing it', async () => {
		// Fabric re-binds a domain by upserting just { domain }; that must not wipe an issued certificate's schedule.
		const domain = 'rebind.example.com';
		const issued = issuedFields();
		await upsertChallengeCertificates(ctx, [{ domain, ...issued }]);
		await upsertChallengeCertificates(ctx, [{ domain }]);

		const record = await getChallengeCertificate(ctx, domain);
		ok(record, `${domain} should be found`);
		strictEqual(new Date(record.issueDate!).getTime(), issued.issueDate);
		strictEqual(new Date(record.renewalDate!).getTime(), issued.renewalDate);
	});

	test('search_by_conditions finds records by challengeToken', async () => {
		const domain = 'search.example.com';
		await upsertChallengeCertificates(ctx, [
			{ domain, challengeToken: 'searchable-token', challengeContent: 'searchable-token.keyauth', ...issuedFields() },
		]);

		const { status, body } = await op<{ domain: string }[]>(ctx, {
			operation: 'search_by_conditions',
			database: 'data',
			table: 'ChallengeCertificate',
			get_attributes: ['domain'],
			conditions: [{ search_attribute: 'challengeToken', search_type: 'equals', search_value: 'searchable-token' }],
		});
		strictEqual(status, 200, `search should succeed, got ${status}: ${JSON.stringify(body)}`);
		deepStrictEqual(body, [{ domain }]);
	});
});

suite('ACME HTTP-01 challenge middleware', (ctx: ContextWithHarper) => {
	const DOMAIN = 'middleware-test.example.com';
	const TOKEN = 'challenge-token-xyz';
	const KEY_AUTH = 'challenge-token-xyz.AAAA_key_authorization_content';

	before(async () => {
		await startHarperWithComponent(ctx);
		const { status, body } = await upsertChallengeCertificates(ctx, [
			{ domain: DOMAIN, challengeToken: TOKEN, challengeContent: KEY_AUTH, ...issuedFields() },
		]);
		strictEqual(status, 200, `seeding the challenge should succeed, got ${status}: ${JSON.stringify(body)}`);
	});

	after(async () => {
		await teardownHarper(ctx);
	});

	test('serves the challenge content at /.well-known/acme-challenge/<token>', async () => {
		// The middleware falls through until the component's table has loaded, so allow it a moment.
		const res = await waitFor(
			'the challenge to be served',
			() => anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}`),
			(res) => res.status === 200,
			{ timeoutMs: 5000 }
		);
		strictEqual(await res.text(), KEY_AUTH, 'middleware should return the key authorization');
	});

	test('ignores a query string on the challenge URL', async () => {
		const res = await anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}?cache-bust=1`);
		strictEqual(res.status, 200, `got HTTP ${res.status}`);
		strictEqual(await res.text(), KEY_AUTH);
	});

	test('passes through a challenge URL for an unknown token', async () => {
		const res = await anonFetch(ctx, '/.well-known/acme-challenge/nonexistent-token-xyz');
		strictEqual(res.status, 404, `unknown token should pass through and return 404, got HTTP ${res.status}`);
		ok(!(await res.text()).includes(KEY_AUTH), 'an unknown token must not be answered with another challenge');
	});

	test('passes through non-challenge URLs', async () => {
		const res = await anonFetch(ctx, '/some/other/path');
		strictEqual(res.status, 404, `non-challenge request should pass through, got HTTP ${res.status}`);
	});

	test('passes through challenge paths without exactly one token segment', async () => {
		for (const path of [
			'/.well-known/acme-challenge',
			'/.well-known/acme-challenge/',
			`/.well-known/acme-challenge/${TOKEN}/extra`,
		]) {
			const res = await anonFetch(ctx, path);
			strictEqual(res.status, 404, `${path} should pass through, got HTTP ${res.status}`);
		}
	});
});
