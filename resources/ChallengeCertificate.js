import * as acme from 'acme-client';

const { replication } = server.config;

/**
 * HTTP middleware to serve ACME HTTP-01 challenge tokens.
 * Let's Encrypt validates domain ownership by requesting a token from:
 * http://<domain>/.well-known/acme-challenge/<token>
 *
 * This middleware intercepts those requests and serves the challenge content
 * from the ChallengeCertificate table.
 */
server.http(async (request, next) => {
  // Check if this is an ACME challenge request
  if (request.url.startsWith('/.well-known/')) {
    const pathParts = request.url.split('/');
    // Expected format: /.well-known/acme-challenge/<token>
    if (pathParts.length !== 4) return next(request);

    // Look up the challenge token in the database
    for await (const challenge of tables.ChallengeCertificate.search({
      conditions: [{attribute: 'challengeToken', comparator: "equals", value: pathParts[3]}]
    })) {
      if (challenge.challengeContent) {
        // Serve the challenge content
        return {
          status: 200,
          headers: {},
          body: challenge.challengeContent
        };
      }
    }
  }
  // Otherwise, forward on through the middleware
  return next(request);
});

/**
 * Attempts to perform an HTTP challenge with exponential backoff retry logic.
 *
 * @param {string} domain - The domain to issue a certificate for
 * @param {number} initialDelay - Delay in milliseconds before starting (for cluster coordination)
 *
 * Retry strategy:
 * - Up to 5 retries with exponential backoff starting at 2 minutes
 * - Delays: 2min, 4min, 8min, 16min, 32min
 */
async function performHttpChallengeWithRetry(domain, initialDelay = 0) {
	logger.notify("Waiting to start http challenge for domain:", domain);

  const maxRetries = 5;
  const delayInterval = 120000; // 2 minutes
  let lastError;

  // Sleep before starting the retry loop to allow cluster nodes to sync
  if (initialDelay > 0) {
    await new Promise(resolve => setTimeout(resolve, initialDelay));
  }

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      await performHttpChallenge(domain);
      return; // Success
    } catch (error) {
      lastError = error;
      if (attempt < maxRetries) {
        // Exponential backoff: 2min * 2^attempt
        const delay = delayInterval * Math.pow(2, attempt);
        logger.warn(`HTTP challenge attempt ${attempt + 1} failed for ${domain}, retrying in ${delay}ms:`, error.message);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        logger.error(`HTTP challenge failed for ${domain} after ${maxRetries + 1} attempts:`, lastError);
      }
    }
  }
}

/**
 * Subscribes to ChallengeCertificate table changes to automatically process
 * new certificate requests.
 *
 * When a new record is created with only a domain (no challengeToken, issueDate, or inProgress),
 * the leader node will initiate the ACME challenge process.
 *
 * Cluster coordination:
 * - Only the leader node processes challenges to avoid duplicate requests
 * - Waits 60 seconds per node to allow for cluster synchronization
 * - Auto-restarts on failure to maintain resilience
 */
const startSubscription = async () => {
  try {
    for await (let event of await tables.ChallengeCertificate.subscribe()) {
      try {
        const domain = event.value?.domain;
        const challengeToken = event.value?.challengeToken;
				const issueDate = event.value?.issueDate;
				const inProgress = event.value?.inProgress;
        if (!domain) continue;

        // Only process new certificate requests (no token, date, or in-progress flag)
        if (!challengeToken && !issueDate && !inProgress) {
          const { isLeader, totalNodes } = await isChallengeLeader();
          if (isLeader) {
						// Mark as in progress to prevent duplicate processing
						await tables.ChallengeCertificate.patch({
							domain: domain,
							inProgress: true
						});

            // Wait 60 seconds per additional node before starting the challenge for deployment
            const initialDelay = (totalNodes - 1) * 60000;
            // Fire and forget - don't block other events
            performHttpChallengeWithRetry(domain, initialDelay);
          }
        }
      } catch (err) {
        // Log individual event processing errors but keep subscription alive
        logger.error('Error processing ChallengeCertificate event:', err);
      }
    }
  } catch (err) {
    // Subscription failed, log and restart
    logger.error('Challenge Certificate subscription crashed, restarting in 5 seconds:', err);
    setTimeout(startSubscription, 5000);
  }
};

/**
 * Initialize certificate management on worker 0 only to avoid duplicate processing.
 */
if (server.workerIndex === 0) {
  // Start listening for new certificate requests
  startSubscription();

  // Check for certificates that need renewal every 12 hours
  const interval = setInterval(async () => {
    // Find certificates with renewal date in the past
    for await (const challengeDomain of tables.ChallengeCertificate.search({
      conditions: [{attribute: 'renewalDate',  comparator: 'less_than', value: new Date()}]
    })){
      const { isLeader } = await isChallengeLeader();
      if (isLeader) {
				// Mark as in progress to prevent duplicate renewal attempts
				await tables.ChallengeCertificate.patch({
					domain: challengeDomain.domain,
					inProgress: true
				});

        // Perform renewal challenge
        await performHttpChallenge(challengeDomain.domain, true);
      }
    }
  }, 43200000); // Every 12 hours

  // Allow the process to exit even if this timer is still active
  interval.unref();
}

/**
 * Performs the ACME HTTP-01 challenge to obtain an SSL/TLS certificate from Let's Encrypt.
 * @param {string} domain - The domain to issue/renew a certificate for
 * @param {boolean} renewal - Whether this is a renewal (affects order finalization)
 * @returns {Promise<string>} The PEM-encoded certificate chain
 */
async function performHttpChallenge(domain, renewal = false) {
  try {
    // Create ACME client for Let's Encrypt production
    const client = new acme.Client({
      directoryUrl: acme.directory.letsencrypt.production,
      accountKey: await acme.crypto.createPrivateKey()
    });

    // Create account or use existing one
    await client.createAccount({ termsOfServiceAgreed: true });

    // Generate a private key and Certificate Signing Request (CSR)
    const [privateKey, csr] = await acme.crypto.createCsr({
      commonName: domain
    });

    // Request a certificate order from Let's Encrypt
    const order = await client.createOrder({
      identifiers: [
        { type: 'dns', value: domain }
      ]
    });

    // Get the authorization challenges for this order
    const authorizations = await client.getAuthorizations(order);

    for (const authz of authorizations) {
      // Find the HTTP-01 challenge type
      const httpChallenge = authz.challenges.find(c => c.type === 'http-01');

      if (!httpChallenge) {
        throw new Error(`No HTTP-01 challenge available for ${domain}`);
      }

      // Get the key authorization content that Let's Encrypt expects to find
      const keyAuthorization = await client.getChallengeKeyAuthorization(httpChallenge);

      // Store challenge in database so the HTTP middleware can serve it
      await tables.ChallengeCertificate.patch({
        domain: domain,
        challengeToken: httpChallenge.token,
        challengeContent: keyAuthorization
      });

      // Wait for database replication, server restarts, and deployment synchronization
      await new Promise((resolve) => setTimeout(resolve, 60000));

      // Tell Let's Encrypt we're ready for validation
      await client.completeChallenge(httpChallenge);

      // Wait for Let's Encrypt to validate the challenge
      await client.waitForValidStatus(httpChallenge);
    }

    // Submit the CSR to finalize the certificate order
    await client.finalizeOrder(order, csr);

    let cert = null;
    if (renewal) {
      // For renewals, ensure the order is fully processed before retrieving certificate
      await client.waitForValidStatus(order);
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const finalizedOrder = await client.getOrder(order);
      cert = await client.getCertificate(finalizedOrder);
    } else {
      cert = await client.getCertificate(order);
    }

    // Calculate renewal date: 60 days from now (30 days before 90-day expiry)
    const now = new Date();
    const renewalDate = new Date(now);
    renewalDate.setDate(renewalDate.getDate() + 60);

    // Update database with certificate info and clear challenge data
    await tables.ChallengeCertificate.put({
      domain: domain,
      issueDate: now,
      renewalDate: renewalDate,
      challengeToken: null,
      challengeContent: null,
			inProgress: false,
    });

    logger.notify(`Certificate issued successfully for ${domain}`);

    // Install the certificate on the server
    await server.operation(
      {
        operation: 'add_certificate',
        name: `${domain}`,
        certificate:`${cert}`,
        is_authority: false,
        private_key: `${privateKey}`,
        replicated: true
      });

    return cert;

  } catch (error) {
    console.error(`Failed to issue certificate for ${domain}:`, error);
    throw error;
  }
}

/**
 * Determines if this node is the challenge leader in a distributed cluster.
 *
 * Leader election ensures only one node processes certificate challenges
 * to avoid duplicate requests to Let's Encrypt.
 *
 * Leadership rules:
 * - If no HDB nodes exist, this node becomes the leader
 * - Otherwise, the first node in hdb_nodes (alphabetically) is the leader
 * - This node is leader if its hostname matches the first node's name
 *
 * @returns {Promise<{isLeader: boolean, totalNodes: number}>}
 *   isLeader: true if this node should process challenges
 *   totalNodes: total count of nodes in the cluster
 */
async function isChallengeLeader() {
  let totalCount = 0;
  let isLeader = false;
  let firstNodeName = null;

  // Iterate through all nodes in the cluster
  for await (const hdbNode of databases.system.hdb_nodes.search()) {
    totalCount++;

    // Store the first node's name to determine leadership
    if (totalCount === 1) {
      firstNodeName = hdbNode.name;
    }
  }

  // Determine if this node is the leader
  if (totalCount === 0) {
    // If no HDB nodes exist, this node is the leader by default
    isLeader = true;
  } else if (firstNodeName === replication.hostname) {
    // This node is the first node, so it's the leader
    isLeader = true;
  }

  return { isLeader, totalNodes: totalCount };
}