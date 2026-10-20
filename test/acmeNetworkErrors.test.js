import { createServer as createHttpServer } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { once } from 'node:events';
import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as acme from 'acme-client';
import { preserveAcmeNetworkErrors } from '../lib/acmeNetworkErrors.js';

async function listen(server) {
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	return `http://127.0.0.1:${server.address().port}/directory`;
}

describe('preserveAcmeNetworkErrors', () => {
	const originalSettings = { ...acme.axios.defaults.acmeSettings };
	const originalTimeout = acme.axios.defaults.timeout;
	const servers = [];

	before(() => {
		acme.axios.defaults.acmeSettings.retryMaxAttempts = 2;
		acme.axios.defaults.acmeSettings.retryDefaultDelay = 0;
		preserveAcmeNetworkErrors(acme);
	});

	after(() => {
		Object.assign(acme.axios.defaults.acmeSettings, originalSettings);
		acme.axios.defaults.timeout = originalTimeout;
		for (const server of servers) server.close();
	});

	it('reports a refused connection instead of a TypeError', async () => {
		await assert.rejects(acme.axios.get('http://127.0.0.1:1/directory'), (error) => {
			assert.equal(error.code, 'ECONNREFUSED');
			assert.match(error.message, /^ACME request to http:\/\/127\.0\.0\.1:1\/directory failed: .*ECONNREFUSED/);
			return true;
		});
	});

	it('keeps acme-client retrying a dropped connection before reporting it', async () => {
		let connections = 0;
		const server = createTcpServer((socket) => {
			connections++;
			socket.destroy();
		});
		servers.push(server);
		const url = await listen(server);

		await assert.rejects(acme.axios.get(url), (error) => {
			assert.equal(error.code, 'ECONNRESET');
			assert.match(error.message, new RegExp(`^ACME request to ${url} failed: `));
			return true;
		});
		assert.equal(connections, 3, 'the first request plus retryMaxAttempts retries');
	});

	it('reports a timeout, which acme-client does not retry', async () => {
		let connections = 0;
		const server = createTcpServer(() => connections++);
		servers.push(server);
		const url = await listen(server);

		acme.axios.defaults.timeout = 100;
		try {
			await assert.rejects(acme.axios.get(url), (error) => {
				assert.equal(error.code, 'ECONNABORTED');
				assert.match(error.message, /timeout of 100ms exceeded/);
				return true;
			});
		} finally {
			acme.axios.defaults.timeout = originalTimeout;
		}
		assert.equal(connections, 1);
	});

	it('leaves HTTP error responses to acme-client', async () => {
		const statuses = [503, 200];
		const server = createHttpServer((request, response) => {
			response.writeHead(statuses.shift() ?? 400, { 'Content-Type': 'application/json' });
			response.end('{}');
		});
		servers.push(server);
		const url = await listen(server);

		assert.equal((await acme.axios.get(url)).status, 200, 'a 503 is retried');
		await assert.rejects(acme.axios.get(url), (error) => {
			assert.equal(error.response?.status, 400);
			return true;
		});
	});

	it('refuses an axios whose interceptors it cannot reorder, and can be retried', () => {
		const fakeAxios = { interceptors: { response: { use: () => assert.fail('nothing should be registered') } } };
		assert.throws(() => preserveAcmeNetworkErrors({ axios: fakeAxios }), /handlers array/);
		assert.throws(() => preserveAcmeNetworkErrors({ axios: fakeAxios }), /handlers array/);
	});

	it('installs its interceptor once', () => {
		const count = acme.axios.interceptors.response.handlers.filter(Boolean).length;
		preserveAcmeNetworkErrors(acme);
		assert.equal(acme.axios.interceptors.response.handlers.filter(Boolean).length, count);
	});
});
