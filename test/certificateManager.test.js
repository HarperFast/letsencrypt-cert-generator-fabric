import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as acme from 'acme-client';
import {
	CHALLENGE_PUBLISH_DELAY_MS,
	DEPLOYMENT_DELAY_PER_NODE_MS,
	RETRY_BASE_DELAY_MS,
	RETRY_MAX_DELAY_MS,
	challengeTokenFromUrl,
	createCertificateManager,
	nextStep,
	renewalDateFor,
	retryDelay,
} from '../lib/certificateManager.js';

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const T0 = Date.parse('2026-10-07T00:00:00Z');
const DOMAIN = 'shop.example.com';
const DIRECTORY_URL = 'https://ca.test/directory';

describe('nextStep', () => {
	it('schedules a domain that has never been attempted', () => {
		assert.equal(nextStep({ domain: DOMAIN }, T0), 'schedule');
	});

	it('does not let a leftover inProgress flag block a domain', () => {
		assert.equal(nextStep({ domain: DOMAIN, inProgress: true }, T0), 'schedule');
		assert.equal(nextStep({ domain: DOMAIN, inProgress: true, nextAttemptAt: new Date(T0) }, T0), 'attempt');
	});

	it('waits for nextAttemptAt', () => {
		assert.equal(nextStep({ domain: DOMAIN, nextAttemptAt: new Date(T0 + 1) }, T0), 'none');
		assert.equal(nextStep({ domain: DOMAIN, failedAttempts: 2, nextAttemptAt: new Date(T0 - 1) }, T0), 'attempt');
	});

	it('renews once renewalDate passes, honoring backoff after a failed renewal', () => {
		const issued = { domain: DOMAIN, issueDate: new Date(T0 - 70 * DAY), renewalDate: new Date(T0 - DAY) };
		assert.equal(nextStep({ ...issued, renewalDate: new Date(T0 + DAY) }, T0), 'none');
		assert.equal(nextStep(issued, T0), 'attempt');
		assert.equal(nextStep({ ...issued, failedAttempts: 1, nextAttemptAt: new Date(T0 + MINUTE) }, T0), 'none');
	});

	it('renews an issued certificate whose renewal date is missing', () => {
		assert.equal(nextStep({ domain: DOMAIN, issueDate: new Date(T0 - DAY) }, T0), 'attempt');
	});
});

describe('retryDelay', () => {
	it('doubles from the base delay and caps', () => {
		assert.equal(retryDelay(1), RETRY_BASE_DELAY_MS);
		assert.equal(retryDelay(2), 2 * RETRY_BASE_DELAY_MS);
		assert.equal(retryDelay(5), 16 * RETRY_BASE_DELAY_MS);
		assert.equal(retryDelay(50), RETRY_MAX_DELAY_MS);
	});
});

describe('renewalDateFor', () => {
	it('renews with a third of the lifetime left', () => {
		assert.equal(
			renewalDateFor({ notBefore: new Date(T0), notAfter: new Date(T0 + 90 * DAY) }, T0).getTime(),
			T0 + 60 * DAY
		);
		assert.equal(
			renewalDateFor({ notBefore: new Date(T0), notAfter: new Date(T0 + 45 * DAY) }, T0).getTime(),
			T0 + 30 * DAY
		);
	});

	it('takes the renewal date from the leaf of a real certificate chain', () => {
		// fixtures/chain.pem: a 90-day leaf from 2026-10-08T16:18:29Z, followed by a 5-year intermediate
		const chain = readFileSync(new URL('./fixtures/chain.pem', import.meta.url), 'utf8');
		const renewalDate = renewalDateFor(acme.crypto.readCertificateInfo(chain), T0);
		assert.equal(renewalDate.toISOString(), '2026-12-07T16:18:29.000Z');
	});

	it('falls back to 30 days when the certificate dates are unusable', () => {
		assert.equal(renewalDateFor(undefined, T0).getTime(), T0 + 30 * DAY);
		assert.equal(renewalDateFor({ notBefore: new Date(T0), notAfter: new Date(T0) }, T0).getTime(), T0 + 30 * DAY);
	});
});

describe('challengeTokenFromUrl', () => {
	it('extracts only acme-challenge tokens', () => {
		assert.equal(challengeTokenFromUrl('/.well-known/acme-challenge/abc'), 'abc');
		assert.equal(challengeTokenFromUrl('/.well-known/acme-challenge/abc?x=1'), 'abc');
		assert.equal(challengeTokenFromUrl('/.well-known/security.txt'), undefined);
		assert.equal(challengeTokenFromUrl('/.well-known/other/abc'), undefined);
		assert.equal(challengeTokenFromUrl('/.well-known/acme-challenge/'), undefined);
		assert.equal(challengeTokenFromUrl('/.well-known/acme-challenge/a/b'), undefined);
		assert.equal(challengeTokenFromUrl('/api'), undefined);
		assert.equal(challengeTokenFromUrl(undefined), undefined);
	});
});

function createTable(records = []) {
	const rows = new Map(records.map((record) => [record.domain, { ...record }]));
	return {
		rows,
		failNextGet: false,
		failPatch: undefined,
		async get(id) {
			if (this.failNextGet) {
				this.failNextGet = false;
				throw new Error('table unavailable');
			}
			const row = rows.get(id);
			return row && { ...row };
		},
		async *search() {
			for (const row of [...rows.values()]) yield { ...row };
		},
		// Like an upsert: a patch for a missing row creates it, so callers have to check first.
		async patch(record) {
			if (this.failPatch?.(record)) {
				this.failPatch = undefined;
				throw new Error('patch failed');
			}
			rows.set(record.domain, { ...rows.get(record.domain), ...record });
		},
	};
}

/**
 * A CA behind acme-client's real `auto()` flow. The overridden calls follow acme-client 5.4.0 order
 * semantics, in particular `getCertificate` reading a `ready` order as final.
 */
function createFakeAcme(table, { lifetimeDays = 90, clock } = {}) {
	const ca = {
		accountsCreated: 0,
		orders: 0,
		completed: [],
		authorizationValid: false,
		failValidations: 0,
		failFinalize: 0,
		onComplete: undefined,
		certificates: new Map(),
	};
	class Client extends acme.Client {
		#registered = false;
		async createAccount() {
			ca.accountsCreated++;
			this.#registered = true;
			return {};
		}
		getAccountUrl() {
			if (!this.#registered) throw new Error('No account URL found');
			return 'https://ca.test/account/1';
		}
		async createOrder({ identifiers }) {
			const id = ++ca.orders;
			return {
				url: `https://ca.test/order/${id}`,
				status: ca.authorizationValid ? 'ready' : 'pending',
				finalize: `https://ca.test/order/${id}/finalize`,
				identifiers,
			};
		}
		async getAuthorizations(order) {
			const id = order.url.split('/').pop();
			return [
				{
					identifier: order.identifiers[0],
					status: ca.authorizationValid ? 'valid' : 'pending',
					challenges: [
						{ type: 'dns-01', token: `dns-${id}`, url: `https://ca.test/challenge/dns-${id}` },
						{ type: 'http-01', token: `token-${id}`, url: `https://ca.test/challenge/http-${id}` },
					],
				},
			];
		}
		async getChallengeKeyAuthorization(challenge) {
			return `${challenge.token}.thumbprint`;
		}
		async completeChallenge(challenge) {
			ca.completed.push({ token: challenge.token, servedContent: table.rows.get(DOMAIN)?.challengeContent });
			ca.onComplete?.();
		}
		async deactivateAuthorization() {}
		async waitForValidStatus(item) {
			if (item.url.includes('/challenge/')) {
				if (ca.failValidations > 0) {
					ca.failValidations--;
					throw new Error(`Invalid response from http://${DOMAIN}/.well-known/acme-challenge/${item.token}`);
				}
				ca.authorizationValid = true;
				return { ...item, status: 'valid' };
			}
			return { ...item, status: 'valid', certificate: `${item.url}/certificate` };
		}
		async finalizeOrder(order) {
			if (ca.failFinalize > 0) {
				ca.failFinalize--;
				throw new Error('finalize failed');
			}
			return { url: order.url, status: 'processing' };
		}
		async getCertificate(order) {
			if (!['ready', 'valid'].includes(order.status)) order = await this.waitForValidStatus(order);
			if (!order.certificate) throw new Error('Unable to download certificate, URL not found');
			const certificate = `-----BEGIN CERTIFICATE-----\n${order.certificate}\n-----END CERTIFICATE-----\n`;
			ca.certificates.set(certificate, {
				notBefore: new Date(clock()),
				notAfter: new Date(clock() + lifetimeDays * DAY),
			});
			return certificate;
		}
	}
	const fakeAcme = {
		...acme,
		Client,
		crypto: { ...acme.crypto, readCertificateInfo: (certificate) => ca.certificates.get(certificate) },
	};
	return { ca, fakeAcme };
}

function createHarness({
	records = [{ domain: DOMAIN }],
	lifetimeDays,
	isLeader = true,
	installTimeoutMs,
	table = createTable(records),
	sleep = async () => {},
} = {}) {
	let clock = T0;
	const { ca, fakeAcme } = createFakeAcme(table, { lifetimeDays, clock: () => clock });
	const installs = [];
	const logs = [];
	const sleeps = [];
	const harness = {
		table,
		ca,
		installs,
		logs,
		sleeps,
		failInstalls: 0,
		hangInstalls: 0,
		advance(ms) {
			clock += ms;
		},
		now: () => clock,
		row: () => table.rows.get(DOMAIN),
		async scan() {
			await Promise.all(await harness.manager.scan());
		},
	};
	const level =
		(name) =>
		(...args) =>
			logs.push({ level: name, message: args.map(String).join(' ') });
	harness.manager = createCertificateManager({
		tables: { ChallengeCertificate: table },
		acme: fakeAcme,
		directoryUrl: DIRECTORY_URL,
		installCertificate: async (domain, certificate, privateKey) => {
			installs.push({
				domain,
				certificate,
				privateKey,
				issuedBeforeInstall: Boolean(table.rows.get(domain)?.issueDate),
			});
			if (harness.hangInstalls > 0) {
				harness.hangInstalls--;
				return new Promise(() => {});
			}
			if (harness.failInstalls > 0) {
				harness.failInstalls--;
				throw new Error('add_certificate failed');
			}
		},
		getLeadership: async () => ({ isLeader, totalNodes: 3 }),
		installTimeoutMs,
		logger: { notify: level('notify'), warn: level('warn'), error: level('error'), trace: level('trace') },
		sleep: (ms) => {
			sleeps.push(ms);
			return sleep(ms);
		},
		now: () => clock,
	});
	return harness;
}

describe('certificate manager', () => {
	it('schedules a new domain behind the deployment delay, then issues and installs it', async () => {
		const harness = createHarness();
		await harness.scan();
		assert.equal(harness.ca.orders, 0);
		assert.equal(harness.row().nextAttemptAt.getTime(), T0 + 2 * DEPLOYMENT_DELAY_PER_NODE_MS);

		harness.advance(2 * DEPLOYMENT_DELAY_PER_NODE_MS);
		await harness.scan();

		assert.deepEqual(harness.ca.completed, [{ token: 'token-1', servedContent: 'token-1.thumbprint' }]);
		assert.deepEqual(harness.sleeps, [CHALLENGE_PUBLISH_DELAY_MS]);
		assert.equal(harness.installs.length, 1);
		assert.equal(harness.installs[0].domain, DOMAIN);
		assert.match(harness.installs[0].privateKey, /PRIVATE KEY/);
		assert.equal(harness.installs[0].issuedBeforeInstall, false, 'the record is marked issued only after install');
		const row = harness.row();
		assert.equal(row.issueDate.getTime(), harness.now());
		assert.equal(row.renewalDate.getTime(), harness.now() + 60 * DAY);
		assert.equal(row.inProgress, false);
		assert.equal(row.failedAttempts, 0);
		assert.equal(row.nextAttemptAt, null);
		assert.equal(row.challengeToken, null);
		assert.equal(row.challengeContent, null);

		await harness.scan();
		assert.equal(harness.ca.orders, 1, 'an issued domain is left alone');
	});

	it('records a failed attempt and retries it with backoff', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.ca.failValidations = 1;
		await harness.scan();

		let row = harness.row();
		assert.equal(row.inProgress, false);
		assert.equal(row.failedAttempts, 1);
		assert.equal(row.nextAttemptAt.getTime(), T0 + RETRY_BASE_DELAY_MS);
		assert.match(row.lastError, /Invalid response/);
		assert.equal(row.challengeToken, null);
		assert.ok(harness.logs.some(({ level, message }) => level === 'warn' && message.includes('attempt 1')));

		await harness.scan();
		assert.equal(harness.ca.orders, 1, 'no attempt before nextAttemptAt');

		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		row = harness.row();
		assert.ok(row.issueDate);
		assert.equal(row.failedAttempts, 0);
		assert.equal(row.lastError, null);
	});

	it('picks up a domain left inProgress by an interrupted attempt', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, inProgress: true, challengeToken: 'stale' }] });
		await harness.scan();
		harness.advance(2 * DEPLOYMENT_DELAY_PER_NODE_MS);
		await harness.scan();
		assert.ok(harness.row().issueDate);
		assert.equal(harness.installs.length, 1);
	});

	it('recovers when the process stops mid-attempt and a new one starts', async () => {
		const stopped = createHarness({
			records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }],
			sleep: () => new Promise(() => {}),
		});
		stopped.manager.scan();
		while (!stopped.row().challengeToken) await new Promise((resolve) => setImmediate(resolve));
		assert.equal(stopped.row().inProgress, true);

		const restarted = createHarness({ table: stopped.table });
		await restarted.scan();
		assert.equal(restarted.installs.length, 1);
		assert.ok(stopped.row().issueDate);
		assert.equal(stopped.row().inProgress, false);
		assert.equal(stopped.installs.length, 0);
	});

	it('completes an order the CA creates ready because the authorization is still valid', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.ca.failFinalize = 1;
		await harness.scan();
		assert.equal(harness.row().failedAttempts, 1);
		assert.equal(harness.ca.authorizationValid, true);

		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		assert.equal(harness.ca.orders, 2);
		assert.equal(harness.ca.completed.length, 1, 'the still-valid authorization is not challenged again');
		assert.ok(harness.row().issueDate);
		assert.equal(harness.installs.length, 1);
	});

	it('retries a failed install without requesting another certificate', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.failInstalls = 1;
		await harness.scan();
		assert.equal(harness.row().failedAttempts, 1);
		assert.equal(harness.row().issueDate, undefined);

		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		assert.equal(harness.ca.orders, 1);
		assert.equal(harness.installs.length, 2);
		assert.equal(harness.installs[1].certificate, harness.installs[0].certificate);
		assert.ok(harness.row().issueDate);
	});

	it('reinstalls instead of requesting again when recording the success fails', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.table.failPatch = (record) => Boolean(record.issueDate);
		await harness.scan();
		assert.equal(harness.row().failedAttempts, 1);

		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		assert.equal(harness.ca.orders, 1);
		assert.equal(harness.installs.length, 2);
		assert.ok(harness.row().issueDate);
	});

	it('gives up on an install that never finishes and retries it', async () => {
		const harness = createHarness({ installTimeoutMs: 10, records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.hangInstalls = 1;
		await harness.scan();
		assert.match(harness.row().lastError, /did not finish/);

		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		assert.equal(harness.ca.orders, 1);
		assert.ok(harness.row().issueDate);
	});

	it('renews a due certificate on the CA lifetime it was issued with', async () => {
		const harness = createHarness({
			lifetimeDays: 45,
			records: [{ domain: DOMAIN, issueDate: new Date(T0 - 61 * DAY), renewalDate: new Date(T0 - DAY) }],
		});
		await harness.scan();
		assert.equal(harness.installs.length, 1);
		assert.equal(harness.row().issueDate.getTime(), T0);
		assert.equal(harness.row().renewalDate.getTime(), T0 + 30 * DAY);
	});

	it('does not recreate a domain that is removed during its request', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.ca.onComplete = () => harness.table.rows.delete(DOMAIN);
		await harness.scan();
		assert.equal(harness.table.rows.has(DOMAIN), false);
		assert.equal(harness.installs.length, 0);

		harness.table.rows.set(DOMAIN, { domain: DOMAIN, nextAttemptAt: new Date(T0) });
		harness.ca.authorizationValid = false;
		harness.ca.failValidations = 1;
		harness.ca.onComplete = () => harness.table.rows.delete(DOMAIN);
		await harness.scan();
		assert.equal(harness.table.rows.has(DOMAIN), false, 'a failure is not recorded onto a removed domain');
		assert.equal(harness.installs.length, 0);
	});

	it('runs one attempt per domain at a time', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		await Promise.all([
			harness.manager.reconcileDomain(DOMAIN),
			harness.manager.reconcileDomain(DOMAIN),
			harness.scan(),
		]);
		assert.equal(harness.ca.orders, 1);
	});

	it('registers one ACME account per process and reuses it', async () => {
		const harness = createHarness({
			records: [
				{ domain: DOMAIN, nextAttemptAt: new Date(T0) },
				{ domain: 'api.example.com', nextAttemptAt: new Date(T0) },
			],
		});
		harness.ca.failValidations = 1;
		await harness.scan();
		harness.advance(RETRY_BASE_DELAY_MS);
		await harness.scan();
		assert.ok(harness.row().issueDate);
		assert.ok(harness.table.rows.get('api.example.com').issueDate);
		assert.equal(harness.ca.accountsCreated, 1);
	});

	it('waits for the component tables to load before starting', (t) => {
		t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
		const tables = {};
		const table = createTable();
		let subscriptions = 0;
		table.subscribe = async () => {
			subscriptions++;
			return (async function* () {})();
		};
		const errors = [];
		const manager = createCertificateManager({
			tables,
			acme,
			directoryUrl: DIRECTORY_URL,
			installCertificate: async () => {},
			getLeadership: async () => ({ isLeader: false, totalNodes: 1 }),
			logger: { error: (...args) => errors.push(args) },
		});
		manager.start();
		t.mock.timers.tick(1000);
		assert.equal(subscriptions, 0);

		tables.ChallengeCertificate = table;
		t.mock.timers.tick(1000);
		assert.equal(subscriptions, 1);
		assert.deepEqual(errors, []);
	});

	it('restarts a subscription that ends', async (t) => {
		t.mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
		const table = createTable();
		let subscriptions = 0;
		table.subscribe = async () => {
			subscriptions++;
			return (async function* () {})();
		};
		const logs = [];
		const manager = createCertificateManager({
			tables: { ChallengeCertificate: table },
			acme,
			directoryUrl: DIRECTORY_URL,
			installCertificate: async () => {},
			getLeadership: async () => ({ isLeader: false, totalNodes: 1 }),
			logger: { warn: (message) => logs.push(message) },
		});
		manager.start();
		await new Promise((resolve) => setImmediate(resolve));
		assert.equal(subscriptions, 1);
		t.mock.timers.tick(5000);
		assert.equal(subscriptions, 2);
		assert.match(logs[0], /subscription ended/);
	});

	it('does nothing on a node that is not the leader', async () => {
		const harness = createHarness({ isLeader: false, records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		await harness.scan();
		await harness.manager.reconcileDomain(DOMAIN);
		assert.equal(harness.ca.orders, 0);
		assert.equal(harness.row().nextAttemptAt.getTime(), T0);
	});

	it('logs a failing table read and recovers on the next pass', async () => {
		const harness = createHarness({ records: [{ domain: DOMAIN, nextAttemptAt: new Date(T0) }] });
		harness.table.failNextGet = true;
		await harness.scan();
		assert.ok(harness.logs.some(({ level, message }) => level === 'error' && message.includes('table unavailable')));
		await harness.scan();
		assert.ok(harness.row().issueDate);
	});
});
