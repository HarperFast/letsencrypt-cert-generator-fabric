/**
 * The ChallengeCertificate table and the ACME HTTP-01 challenge middleware on a real Harper.
 *
 * Records are seeded as issued (issuedFields) so the certificate manager leaves them alone; attempts are
 * covered by certificate-retry.test.ts. The table is not REST-exported, so it is reached through the
 * Operations API.
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
		const response = await authFetch(ctx, '/');
		ok([200, 400, 404].includes(response.status), `Harper should be reachable, got HTTP ${response.status}`);
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

	test('requests without credentials are not authorized', async () => {
		// The middleware tests rely on this: a loopback request must not be treated as the superuser.
		const response = await fetch(ctx.harper.operationsAPIURL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ operation: 'describe_all' }),
		});
		strictEqual(response.status, 401, `an anonymous operation should be refused, got HTTP ${response.status}`);
	});

	test('ChallengeCertificate is not exposed over REST', async () => {
		const response = await authFetch(ctx, '/ChallengeCertificate/');
		strictEqual(response.status, 404, `ChallengeCertificate should not be REST-exported, got HTTP ${response.status}`);
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
		const { status, text } = await waitFor(
			'the challenge to be served',
			async () => {
				const response = await anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}`);
				return { status: response.status, text: await response.text() };
			},
			(result) => result.status === 200,
			{ timeoutMs: 5000 }
		);
		strictEqual(status, 200);
		strictEqual(text, KEY_AUTH, 'middleware should return the key authorization');
	});

	test('ignores a query string on the challenge URL', async () => {
		const response = await anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}?cache-bust=1`);
		strictEqual(response.status, 200, `got HTTP ${response.status}`);
		strictEqual(await response.text(), KEY_AUTH);
	});

	test('passes through a challenge URL for an unknown token', async () => {
		const response = await anonFetch(ctx, '/.well-known/acme-challenge/nonexistent-token-xyz');
		strictEqual(response.status, 404, `unknown token should pass through and return 404, got HTTP ${response.status}`);
		ok(!(await response.text()).includes(KEY_AUTH), 'an unknown token must not be answered with another challenge');
	});

	test('passes through non-challenge URLs', async () => {
		const response = await anonFetch(ctx, '/some/other/path');
		strictEqual(response.status, 404, `non-challenge request should pass through, got HTTP ${response.status}`);
	});

	test('passes through challenge paths without exactly one token segment', async () => {
		for (const path of [
			'/.well-known/acme-challenge',
			'/.well-known/acme-challenge/',
			`/.well-known/acme-challenge/${TOKEN}/extra`,
		]) {
			const response = await anonFetch(ctx, path);
			strictEqual(response.status, 404, `${path} should pass through, got HTTP ${response.status}`);
		}
	});
});
