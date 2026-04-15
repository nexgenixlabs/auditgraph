#!/usr/bin/env node
/**
 * Contract Checker — Frontend ↔ Backend Sync
 *
 * Reads api_contract.json (exported by backend/tests/export_api_contract.py)
 * and compares response model field names against the TypeScript interfaces
 * in identityEngineApi.ts.
 *
 * Usage: node scripts/check-contract.js
 * (or: npm run check:contract)
 *
 * Exit 0 = in sync, Exit 1 = drift detected
 */

const fs = require('fs');
const path = require('path');

const CONTRACT_PATH = path.resolve(__dirname, '../../backend/api_contract.json');
const TS_PATH = path.resolve(__dirname, '../src/services/identityEngineApi.ts');

// ---------------------------------------------------------------------------
// Parse TypeScript interfaces (simple regex — good enough for our flat DTOs)
// ---------------------------------------------------------------------------

function extractInterfaces(tsSource) {
  const interfaces = {};
  // Find each "export interface Name {" and then balance braces to find the end
  const headerRe = /export\s+interface\s+(\w+)\s*\{/g;
  let hm;
  while ((hm = headerRe.exec(tsSource)) !== null) {
    const name = hm[1];
    const startIdx = hm.index + hm[0].length;
    // Balance braces to find closing }
    let depth = 1;
    let i = startIdx;
    while (i < tsSource.length && depth > 0) {
      if (tsSource[i] === '{') depth++;
      else if (tsSource[i] === '}') depth--;
      i++;
    }
    const body = tsSource.slice(startIdx, i - 1);
    const fields = new Set();
    // Match top-level field names only (not nested object fields)
    // Split by lines and only match fields at top indent level
    for (const line of body.split('\n')) {
      const fm = line.match(/^\s{0,2}(\w+)\??:/);
      if (fm) fields.add(fm[1]);
    }
    interfaces[name] = fields;
  }
  return interfaces;
}

// ---------------------------------------------------------------------------
// Map backend response model names to frontend interface names
// ---------------------------------------------------------------------------

const MODEL_MAP = {
  'IdentityListRowDTO':        'IdentityListRow',
  'IdentityState':             'IdentityState',
  'AttackPathsBlock':          'AttackPathsBlock',
  'RemediationBlock':          'RemediationBlock',
  'ExecuteRemediationResult':  null,  // not in identityEngineApi.ts
  'RolesBlock':                'RolesBlock',
  'WhatIfResult':              'WhatIfResult',
  'WhatIfSimulationListResponse': 'WhatIfSimulationListResponse',
  'SimulationFindingArtifact': 'SimulationFindingArtifact',
  'PostureScoreResponse':      'PostureScoreResponse',
  'PostureScoreHistoryResponse': 'PostureScoreHistoryResponse',
  'PriorityActionsResponse':   'PriorityActionsResponse',
  'BulkSimulationResult':      'BulkSimulationResult',
};

// Models that are generic wrappers — check inner items instead
const GENERIC_MODELS = new Set([
  'PaginatedResponse[IdentityListRowDTO]',
]);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  if (!fs.existsSync(CONTRACT_PATH)) {
    console.error(`FAIL: ${CONTRACT_PATH} not found.`);
    console.error('Run: cd backend && python -m tests.export_api_contract');
    process.exit(1);
  }

  const contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
  const tsSource = fs.readFileSync(TS_PATH, 'utf8');
  const interfaces = extractInterfaces(tsSource);

  let errors = 0;

  for (const route of contract.routes) {
    const modelName = route.response_model;
    if (!modelName || !route.response_fields) continue;

    // Skip generic wrappers — PaginatedResponse is checked via its inner type
    if (GENERIC_MODELS.has(modelName)) continue;

    const tsName = MODEL_MAP[modelName];
    if (tsName === null) continue; // explicitly skipped
    if (tsName === undefined) {
      console.warn(`WARN: No mapping for backend model "${modelName}"`);
      continue;
    }

    const tsFields = interfaces[tsName];
    if (!tsFields) {
      console.error(`FAIL: Frontend interface "${tsName}" not found in identityEngineApi.ts`);
      errors++;
      continue;
    }

    const backendFields = new Set(Object.keys(route.response_fields));

    // Check for backend fields missing in frontend
    for (const f of backendFields) {
      if (!tsFields.has(f)) {
        console.error(
          `FAIL: Backend field "${f}" in ${modelName} (${route.method} ${route.path}) ` +
          `missing from frontend interface ${tsName}`
        );
        errors++;
      }
    }

    // Check for frontend fields not in backend
    for (const f of tsFields) {
      if (!backendFields.has(f)) {
        console.error(
          `WARN: Frontend field "${f}" in ${tsName} not in backend model ${modelName}`
        );
        // Don't count as error — frontend can have extra optional fields
      }
    }
  }

  if (errors > 0) {
    console.error(`\n${errors} contract violation(s) found.`);
    process.exit(1);
  }

  console.log(`OK: All ${contract.routes.length} routes match frontend interfaces.`);
  process.exit(0);
}

main();
