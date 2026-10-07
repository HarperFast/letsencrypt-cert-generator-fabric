const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const SCAN_INTERVAL_MS = MINUTE;
export const DEPLOYMENT_DELAY_PER_NODE_MS = MINUTE;
export const CHALLENGE_PUBLISH_DELAY_MS = MINUTE;
export const RETRY_BASE_DELAY_MS = 2 * MINUTE;
export const RETRY_MAX_DELAY_MS = 6 * HOUR;
const INSTALL_TIMEOUT_MS = 5 * MINUTE;
const FAILED_ATTEMPTS_BEFORE_ERROR = 6;
// Only used when the issued certificate cannot be parsed; renews well inside a 45-day lifetime.
const FALLBACK_RENEWAL_MS = 30 * DAY;
const MAX_ERROR_LENGTH = 500;
const TABLES_POLL_INTERVAL_MS = 1000;
const SUBSCRIPTION_RESTART_DELAY_MS = 5000;

const CHALLENGE_PATH_PREFIX = '/.well-known/acme-challenge/';

export function challengeTokenFromUrl(url) {
	if (!url?.startsWith(CHALLENGE_PATH_PREFIX)) return undefined;
	const token = url.slice(CHALLENGE_PATH_PREFIX.length).split('?')[0];
	return token && !token.includes('/') ? token : undefined;
}

function toMillis(value) {
	return value == null ? undefined : new Date(value).getTime();
}

function withTimeout(promise, ms, message) {
	let timer;
	const timeout = new Promise((resolve, reject) => {
		timer = setTimeout(() => reject(new Error(message)), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export function retryDelay(failedAttempts) {
	return Math.min(RETRY_BASE_DELAY_MS * 2 ** Math.max(failedAttempts - 1, 0), RETRY_MAX_DELAY_MS);
}

/** Renew with a third of the certificate's lifetime remaining, so the schedule follows the CA's lifetime. */
export function renewalDateFor(certificateInfo, issuedAt) {
	const notBefore = toMillis(certificateInfo?.notBefore);
	const notAfter = toMillis(certificateInfo?.notAfter);
	if (!(notAfter > notBefore)) return new Date(issuedAt + FALLBACK_RENEWAL_MS);
	return new Date(notAfter - (notAfter - notBefore) / 3);
}

/**
 * Reads schedule fields only; `inProgress` is never a gate (see DESIGN.md).
 * @returns {'none' | 'schedule' | 'attempt'}
 */
export function nextStep(record, now) {
	if (record.issueDate) {
		if (toMillis(record.renewalDate) > now) return 'none';
	} else if (record.nextAttemptAt == null && !record.failedAttempts) {
		return 'schedule';
	}
	return toMillis(record.nextAttemptAt) > now ? 'none' : 'attempt';
}

/**
 * @param {object} options
 * @param {object} options.tables Harper `tables`; read on each use since the component's tables load after its resources
 * @param {object} options.acme acme-client module
 * @param {string} options.directoryUrl ACME directory URL
 * @param {(domain: string, certificate: string, privateKey: string) => Promise<void>} options.installCertificate
 * @param {() => Promise<{isLeader: boolean, totalNodes: number}>} options.getLeadership
 * @param {object} options.logger
 */
export function createCertificateManager({
	tables,
	acme,
	directoryUrl,
	installCertificate,
	getLeadership,
	logger,
	installTimeoutMs = INSTALL_TIMEOUT_MS,
	sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
	now = Date.now,
}) {
	const inFlight = new Set();
	// Issued but not yet installed; retrying the install must not spend another certificate.
	const pendingInstall = new Map();
	let accountClient;
	let scanning = false;

	async function writeIfPresent(domain, fields) {
		if (!(await tables.ChallengeCertificate.get(domain))) return false;
		await tables.ChallengeCertificate.patch({ domain, ...fields });
		return true;
	}

	async function connectAccount() {
		const stored = await tables.AcmeAccount.get(directoryUrl);
		const accountKey = stored?.accountKey ?? (await acme.crypto.createPrivateKey()).toString();
		if (!stored?.accountKey) await tables.AcmeAccount.put({ directoryUrl, accountKey });
		const client = new acme.Client({ directoryUrl, accountKey });
		if (stored?.accountKey) {
			try {
				// For a known key, plain createAccount() follows up with an account update the CA can reject.
				await client.createAccount({ onlyReturnExisting: true });
				return client;
			} catch (error) {
				logger.warn?.('Stored ACME account was not found, registering it again:', error);
			}
		}
		await client.createAccount({ termsOfServiceAgreed: true });
		return client;
	}

	async function getAccountClient() {
		accountClient ??= connectAccount();
		try {
			return await accountClient;
		} catch (error) {
			accountClient = undefined;
			throw error;
		}
	}

	function readRenewalDate(domain, certificate, issuedAt) {
		try {
			return renewalDateFor(acme.crypto.readCertificateInfo(certificate), issuedAt);
		} catch (error) {
			logger.warn?.(`Could not read the certificate issued for ${domain}; renewing in 30 days:`, error);
			return renewalDateFor(undefined, issuedAt);
		}
	}

	async function requestCertificate(domain) {
		const client = await getAccountClient();
		const [privateKey, csr] = await acme.crypto.createCsr({ commonName: domain });
		const certificate = await client.auto({
			csr,
			termsOfServiceAgreed: true,
			challengePriority: ['http-01'],
			// The CA resolves the domain through public DNS, which this node may not be able to reach itself.
			skipChallengeVerification: true,
			challengeCreateFn: async (authorization, challenge, keyAuthorization) => {
				if (challenge.type !== 'http-01') throw new Error(`No HTTP-01 challenge offered for ${domain}`);
				const published = await writeIfPresent(domain, {
					challengeToken: challenge.token,
					challengeContent: keyAuthorization,
				});
				if (!published) throw new Error(`${domain} was removed during the certificate request`);
				// The CA may ask any node, so the token has to replicate everywhere first.
				await sleep(CHALLENGE_PUBLISH_DELAY_MS);
			},
			challengeRemoveFn: () => writeIfPresent(domain, { challengeToken: null, challengeContent: null }),
		});
		const issuedAt = now();
		return {
			certificate: certificate.toString(),
			privateKey: privateKey.toString(),
			issuedAt,
			renewalDate: readRenewalDate(domain, certificate, issuedAt),
		};
	}

	async function recordFailure(record, error) {
		const { domain } = record;
		const failedAttempts = (record.failedAttempts ?? 0) + 1;
		const delay = retryDelay(failedAttempts);
		const recorded = await writeIfPresent(domain, {
			inProgress: false,
			challengeToken: null,
			challengeContent: null,
			failedAttempts,
			nextAttemptAt: new Date(now() + delay),
			lastError: String(error?.message ?? error).slice(0, MAX_ERROR_LENGTH),
		});
		if (!recorded) {
			pendingInstall.delete(domain);
			logger.notify?.(`${domain} was removed while its certificate was being requested; stopping`);
			return;
		}
		const level = failedAttempts === FAILED_ATTEMPTS_BEFORE_ERROR ? 'error' : 'warn';
		logger[level]?.(
			`Certificate attempt ${failedAttempts} for ${domain} failed, retrying in ${Math.round(delay / MINUTE)} min:`,
			error
		);
	}

	async function attemptCertificate(record) {
		const { domain } = record;
		const renewal = Boolean(record.issueDate);
		try {
			if (!(await writeIfPresent(domain, { inProgress: true }))) return;
			logger.notify?.(`${renewal ? 'Renewing' : 'Requesting'} certificate for ${domain}`);
			let issued = pendingInstall.get(domain);
			if (!issued || issued.renewalDate.getTime() <= now()) {
				issued = await requestCertificate(domain);
				pendingInstall.set(domain, issued);
			}
			if (!(await tables.ChallengeCertificate.get(domain))) {
				pendingInstall.delete(domain);
				return;
			}
			await withTimeout(
				installCertificate(domain, issued.certificate, issued.privateKey),
				installTimeoutMs,
				`Installing the certificate for ${domain} did not finish within ${installTimeoutMs / 1000}s`
			);
			await writeIfPresent(domain, {
				issueDate: new Date(issued.issuedAt),
				renewalDate: issued.renewalDate,
				challengeToken: null,
				challengeContent: null,
				inProgress: false,
				failedAttempts: 0,
				nextAttemptAt: null,
				lastError: null,
			});
			pendingInstall.delete(domain);
			logger.notify?.(
				`Certificate ${renewal ? 'renewed' : 'issued'} for ${domain}, renewal due ${issued.renewalDate.toISOString()}`
			);
		} catch (error) {
			await recordFailure(record, error);
		}
	}

	/** Never rejects; safe to call without awaiting. */
	async function reconcileDomain(domain, leadership) {
		if (!domain || inFlight.has(domain)) return;
		inFlight.add(domain);
		try {
			const { isLeader, totalNodes } = leadership ?? (await getLeadership());
			if (!isLeader) return;
			const record = await tables.ChallengeCertificate.get(domain);
			if (!record) return;
			const step = nextStep(record, now());
			if (step === 'schedule') {
				// Give the component time to finish deploying to the other nodes before the CA calls them.
				const delay = Math.max(totalNodes - 1, 0) * DEPLOYMENT_DELAY_PER_NODE_MS;
				await writeIfPresent(domain, { nextAttemptAt: new Date(now() + delay) });
				logger.notify?.(`Certificate requested for ${domain}, first attempt in ${delay / 1000}s`);
			} else if (step === 'attempt') {
				await attemptCertificate(record);
			}
		} catch (error) {
			logger.error?.(`Certificate reconciliation for ${domain} failed:`, error);
		} finally {
			inFlight.delete(domain);
		}
	}

	/** Never rejects. Resolves once every due domain has been started, with their completion promises. */
	async function scan() {
		if (scanning) return [];
		scanning = true;
		try {
			const leadership = await getLeadership();
			if (!leadership.isLeader) return [];
			const domains = [];
			for await (const record of tables.ChallengeCertificate.search([])) domains.push(record.domain);
			return domains.map((domain) => reconcileDomain(domain, leadership));
		} catch (error) {
			logger.error?.('Certificate scan failed:', error);
			return [];
		} finally {
			scanning = false;
		}
	}

	async function subscribe() {
		try {
			for await (const event of await tables.ChallengeCertificate.subscribe()) {
				reconcileDomain(event.value?.domain ?? event.id);
			}
			logger.warn?.('ChallengeCertificate subscription ended, restarting in 5 seconds');
		} catch (error) {
			logger.error?.('ChallengeCertificate subscription failed, restarting in 5 seconds:', error);
		}
		setTimeout(subscribe, SUBSCRIPTION_RESTART_DELAY_MS).unref?.();
	}

	function start() {
		if (!tables.ChallengeCertificate || !tables.AcmeAccount) {
			setTimeout(start, TABLES_POLL_INTERVAL_MS);
			return;
		}
		subscribe();
		scan();
		setInterval(scan, SCAN_INTERVAL_MS).unref?.();
	}

	return { start, scan, reconcileDomain };
}
