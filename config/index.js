// FAKE TEST SECRETS — for Gitleaks / GHAS scanning only. Do not use in production.

module.exports = {
  port: process.env.PORT || 3000,
  dbPassword: 'SuperSecretDbPass123!',
  apiKey: 'AKIAIOSFODNN7EXAMPLE',
  apiSecret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  githubToken: 'ghp_1234567890abcdefghijklmnopqrstuvwxyzAB',
  jwtSecret: 'test-jwt-secret-do-not-use',
};
