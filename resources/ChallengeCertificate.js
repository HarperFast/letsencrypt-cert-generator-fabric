import * as acme from 'acme-client';
import { challengeTokenFromUrl, createCertificateManager } from '../lib/certificateManager.js';

const ACME_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Serves ACME HTTP-01 challenge tokens. Let's Encrypt validates domain ownership by requesting
 * http://<domain>/.well-known/acme-challenge/<token> from whichever node the domain resolves to.
 */
server.http(async (request, next) => {
	const token = challengeTokenFromUrl(request.url);
	if (token && tables.ChallengeCertificate) {
		for await (const challenge of tables.ChallengeCertificate.search({
			conditions: [{ attribute: 'challengeToken', comparator: 'equals', value: token }],
		})) {
			if (challenge.challengeContent) {
				return {
					status: 200,
					headers: {},
					body: challenge.challengeContent,
				};
			}
		}
	}
	return next(request);
});

/**
 * Only the first node in hdb_nodes requests certificates, so the cluster makes one request per domain.
 * A node with no hdb_nodes entries is not clustered and leads itself.
 */
async function getLeadership() {
	let totalNodes = 0;
	let firstNodeName;
	for await (const hdbNode of databases.system.hdb_nodes.search()) {
		totalNodes++;
		firstNodeName ??= hdbNode.name;
	}
	return {
		isLeader: totalNodes === 0 || firstNodeName === server.config.replication?.hostname,
		totalNodes,
	};
}

if (server.workerIndex === 0) {
	acme.axios.defaults.timeout = ACME_REQUEST_TIMEOUT_MS;
	acme.setLogger((message) => {
		if (message.startsWith('Caught ')) logger.warn(`acme-client: ${message}`);
		else logger.trace(`acme-client: ${message}`);
	});

	createCertificateManager({
		tables,
		acme,
		directoryUrl: process.env.ACME_DIRECTORY_URL || acme.directory.letsencrypt.production,
		installCertificate: (domain, certificate, privateKey) =>
			server.operation({
				operation: 'add_certificate',
				name: domain,
				certificate,
				is_authority: false,
				private_key: privateKey,
				replicated: true,
			}),
		getLeadership,
		logger,
	}).start();
}
