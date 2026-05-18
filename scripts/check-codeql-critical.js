#!/usr/bin/env node
/**
 * Parses CodeQL SARIF output and exits 1 if any critical-severity findings exist.
 * GitHub maps security-severity > 9.0 as critical.
 * Usage: node scripts/check-codeql-critical.js [sarif-directory]
 */

const fs = require('fs');
const path = require('path');

const CRITICAL_THRESHOLD = 9.0;
const sarifDir = process.argv[2] || 'codeql-results';

function collectSarifFiles(dir) {
  if (!fs.existsSync(dir)) {
    return [];
  }
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectSarifFiles(full));
    } else if (entry.name.endsWith('.sarif') || entry.name.endsWith('.sarif.json')) {
      files.push(full);
    }
  }
  return files;
}

function getSecuritySeverity(rule, result) {
  const fromResult = result?.properties?.['security-severity'];
  if (fromResult != null) {
    return parseFloat(fromResult);
  }
  const fromRule = rule?.properties?.['security-severity'];
  if (fromRule != null) {
    return parseFloat(fromRule);
  }
  if (result?.level === 'error') {
    return 9.1;
  }
  return 0;
}

function analyzeSarif(filePath) {
  const sarif = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const critical = [];

  for (const run of sarif.runs || []) {
    const rulesById = {};
    for (const rule of run.tool?.driver?.rules || []) {
      rulesById[rule.id] = rule;
    }

    for (const result of run.results || []) {
      const rule = rulesById[result.ruleId] || {};
      const severity = getSecuritySeverity(rule, result);
      if (severity > CRITICAL_THRESHOLD) {
        critical.push({
          file: filePath,
          ruleId: result.ruleId,
          message: result.message?.text || result.message?.markdown || 'No message',
          severity,
          location: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri,
        });
      }
    }
  }

  return critical;
}

const sarifFiles = collectSarifFiles(sarifDir);

if (sarifFiles.length === 0) {
  console.log(`No SARIF files found in ${sarifDir}; skipping critical check.`);
  process.exit(0);
}

const allCritical = sarifFiles.flatMap(analyzeSarif);

if (allCritical.length > 0) {
  console.error(`Found ${allCritical.length} critical CodeQL finding(s):`);
  for (const finding of allCritical) {
    console.error(`  [${finding.ruleId}] severity=${finding.severity} ${finding.location || ''}`);
    console.error(`    ${finding.message}`);
  }
  process.exit(1);
}

console.log('No critical CodeQL findings detected.');
process.exit(0);
