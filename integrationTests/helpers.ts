import { ok } from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupHarperWithFixture, type ContextWithHarper } from '@harperfast/integration-testing';

const FIXTURE_PATH = fileURLToPath(new URL('../', import.meta.url));

// Nothing listens on port 1, so no suite can reach Let's Encrypt even if a record it writes is attempted.
export const UNREACHABLE_ACME_DIRECTORY = 'http://127.0.0.1:1/directory';

/**
 * harper's `exports` map only exposes ".", so neither `harper/dist/bin/harper.js` (the harness' own lookup) nor
 * `harper/package.json` can be resolved. Find the package root from its main entry and take the CLI from its `bin`.
 */
function resolveHarperBin(): string {
	const require = createRequire(import.meta.url);
	let directory = dirname(require.resolve('harper'));
	while (true) {
		const packageJsonPath = join(directory, 'package.json');
		if (existsSync(packageJsonPath)) {
			const { name, bin } = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
			if (name === 'harper') {
				const binPath = resolve(directory, typeof bin === 'string' ? bin : bin.harper);
				ok(existsSync(binPath), `harper's bin entry ${binPath} does not exist`);
				return binPath;
			}
		}
		const parent = dirname(directory);
		ok(parent !== directory, 'Could not find the root of the installed harper package');
		directory = parent;
	}
}

// The harness reads HARPER_INTEGRATION_TEST_INSTALL_SCRIPT itself, e.g. to run against @harperfast/harper-pro.
const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT ? undefined : resolveHarperBin();

export function startHarperWithComponent(ctx: ContextWithHarper, env: Record<string, string> = {}) {
	return setupHarperWithFixture(ctx, FIXTURE_PATH, {
		harperBinPath,
		// By default Harper treats loopback requests as the superuser, which would hide a challenge URL that needs auth.
		config: { authentication: { authorizeLocal: false } },
		env: { ACME_DIRECTORY_URL: UNREACHABLE_ACME_DIRECTORY, ...env },
	});
}

function basicAuth(ctx: ContextWithHarper): string {
	const { username, password } = ctx.harper.admin;
	return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
}

export async function runOperation<T = unknown>(
	ctx: ContextWithHarper,
	operation: Record<string, unknown>
): Promise<{ status: number; body: T }> {
	const response = await fetch(ctx.harper.operationsAPIURL, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'Authorization': basicAuth(ctx) },
		body: JSON.stringify(operation),
	});
	const text = await response.text();
	try {
		return { status: response.status, body: JSON.parse(text) as T };
	} catch {
		throw new Error(`${operation.operation} returned HTTP ${response.status} with a non-JSON body: ${text}`);
	}
}

export function anonFetch(ctx: ContextWithHarper, path: string): Promise<Response> {
	return fetch(`${ctx.harper.httpURL}${path}`);
}

export function authFetch(ctx: ContextWithHarper, path: string): Promise<Response> {
	return fetch(`${ctx.harper.httpURL}${path}`, { headers: { Authorization: basicAuth(ctx) } });
}

export interface ChallengeCertificateRecord {
	domain: string;
	issueDate?: number | string | null;
	renewalDate?: number | string | null;
	challengeToken?: string | null;
	challengeContent?: string | null;
	inProgress?: boolean | null;
	failedAttempts?: number | null;
	nextAttemptAt?: number | string | null;
	lastError?: string | null;
}

export async function upsertChallengeCertificates(ctx: ContextWithHarper, records: ChallengeCertificateRecord[]) {
	return runOperation(ctx, { operation: 'upsert', database: 'data', table: 'ChallengeCertificate', records });
}

export async function getChallengeCertificate(
	ctx: ContextWithHarper,
	domain: string
): Promise<ChallengeCertificateRecord | undefined> {
	const { status, body } = await runOperation<ChallengeCertificateRecord[]>(ctx, {
		operation: 'search_by_id',
		database: 'data',
		table: 'ChallengeCertificate',
		ids: [domain],
		get_attributes: ['*'],
	});
	ok(status === 200, `search_by_id failed with ${status}: ${JSON.stringify(body)}`);
	return body[0];
}

/** Without these a record is a new certificate request, which the certificate manager attempts. */
export function issuedFields() {
	const DAY = 24 * 60 * 60 * 1000;
	return { issueDate: Date.now(), renewalDate: Date.now() + 60 * DAY };
}

export async function waitFor<T>(
	description: string,
	read: () => Promise<T>,
	isDone: (value: T) => boolean,
	{ timeoutMs = 30_000, intervalMs = 250 } = {}
): Promise<T> {
	const deadline = Date.now() + timeoutMs;
	let value = await read();
	while (!isDone(value)) {
		ok(
			Date.now() < deadline,
			`Timed out after ${timeoutMs}ms waiting for ${description}; last saw ${JSON.stringify(value)}`
		);
		await new Promise((resolveDelay) => setTimeout(resolveDelay, intervalMs));
		value = await read();
	}
	return value;
}
