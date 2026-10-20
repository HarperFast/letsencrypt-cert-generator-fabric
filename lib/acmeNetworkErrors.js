const patchedInstances = new WeakSet();

/**
 * acme-client 5.4.0 loses every request error that has no HTTP response (connection refused, DNS failure,
 * timeout): once it stops retrying, its response interceptor reads `response.config` from the missing response
 * and throws `Cannot read properties of undefined (reading 'config')` instead.
 *
 * This puts a response interceptor ahead of acme-client's. Errors acme-client will retry pass through unchanged;
 * the final one is replaced by an error without `config`, which acme-client's interceptor passes on as is.
 * @param {object} acme acme-client module
 */
export function preserveAcmeNetworkErrors(acme) {
	const instance = acme.axios;
	if (patchedInstances.has(instance)) return;
	patchedInstances.add(instance);

	instance.interceptors.response.use(null, (error) => {
		const { config, response } = error;
		if (!config || response || acmeClientWillRetry(error, instance.defaults.acmeSettings)) {
			return Promise.reject(error);
		}
		const networkError = new Error(`ACME request to ${config.url} failed: ${error.message || error.code}`);
		networkError.code = error.code;
		return Promise.reject(networkError);
	});
	// Axios runs response interceptors in registration order, and acme-client registered its own on import.
	// acme-client never ejects its interceptor, so moving entries does not invalidate an id it holds.
	const { handlers } = instance.interceptors.response;
	handlers.unshift(handlers.pop());
}

/** Mirrors acme-client's isRetryableError and retry count for an error without a response. */
function acmeClientWillRetry(error, { retryMaxAttempts }) {
	const retryable = error.code !== 'ECONNABORTED' && error.code !== 'ERR_NOCK_NO_MATCH';
	return retryable && (error.config.retryAttempt ?? 0) < retryMaxAttempts;
}
