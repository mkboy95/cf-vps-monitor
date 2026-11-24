import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const severities = ['info', 'low', 'moderate', 'high', 'critical'];

function requireSuccessfulScan(name, result) {
  if (result.error || result.status !== 0 || typeof result.stdout !== 'string') {
    const detail = result.error?.message || result.stderr || result.stdout || 'scanner did not complete';
    throw new Error(`${name} failed (exit ${result.status ?? 'unavailable'}):\n${String(detail).trim().slice(0, 12000)}`);
  }
}

// govulncheck's text layout changed across versions: newer builds keep the
// "No vulnerabilities found." symbol result but append a summary paragraph
// ("Your code is affected by 0 vulnerabilities." plus imported-but-uncalled
// counts). Validate the semantics of a clean scan instead of an exact whole
// string, while still failing closed on findings, JSON mode, or partial output.
function isCleanGoTextScan(stdout) {
  const text = String(stdout ?? '').trim();
  if (!text || /^[{[]/.test(text)) return false; // empty or JSON/progress output
  if (/Vulnerability\s+#\d+\s*:/i.test(text)) return false; // a concrete finding
  if (!/\bNo vulnerabilities found\.\s*$/m.test(text)) return false; // clean confirmation must be a whole line
  const affected = /\bYour code is affected by\s+(\d+)\s+vulnerabilit/i.exec(text);
  if (affected && Number(affected[1]) !== 0) return false; // summary must report zero
  return true;
}

// The runner is the subprocess boundary; the same validation runs locally and in
// CI. A registry outage or truncated result must never be treated as a clean scan.
export function runSecurityChecks({ run = spawnSync, log = console.log } = {}) {
  const npmCli = process.env.npm_execpath;
  const auditArgs = ['audit', '--audit-level=low', '--include=dev', '--json'];
  const npm = run(npmCli ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm', npmCli ? [npmCli, ...auditArgs] : auditArgs, {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    shell: !npmCli && process.platform === 'win32', timeout: 120000, maxBuffer: 16 * 1024 * 1024,
  });
  requireSuccessfulScan('npm audit', npm);
  let report;
  try { report = JSON.parse(npm.stdout); }
  catch { throw new Error('npm audit returned malformed JSON.'); }
  const counts = report?.metadata?.vulnerabilities;
  if (report?.auditReportVersion !== 2 || report.error || !report.vulnerabilities
    || typeof report.vulnerabilities !== 'object' || Array.isArray(report.vulnerabilities)
    || !counts || ![...severities, 'total'].every(key => Number.isSafeInteger(counts[key]) && counts[key] >= 0)
    || severities.reduce((sum, key) => sum + counts[key], 0) !== counts.total) {
    throw new Error('npm audit returned an incomplete or inconsistent report.');
  }
  if (counts.total !== 0 || Object.keys(report.vulnerabilities).length !== 0) {
    throw new Error(`npm audit found vulnerable dependencies: ${Object.keys(report.vulnerabilities).join(', ') || counts.total}`);
  }
  log('npm audit: no vulnerabilities found.');

  // Keep the pinned scanner in default text mode. Its JSON mode can exit zero
  // with findings, so JSON/progress/partial output is not accepted as success.
  // Use go install + binary execution: go run pkg@version fails under
  // GOTOOLCHAIN=local in CI (exit status 3 during module resolution).
  const goInstall = run('go', ['install', 'golang.org/x/vuln/cmd/govulncheck@v1.7.0'], {
    cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 300000, maxBuffer: 16 * 1024 * 1024,
  });
  requireSuccessfulScan('govulncheck install', goInstall);
  // Resolve the installed binary path so we don't depend on PATH propagation.
  // go install uses $GOBIN if set, otherwise $GOPATH/bin.
  const goBinDir = run('go', ['env', 'GOBIN'], {
    cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10000, maxBuffer: 1024,
  });
  const goBin = goBinDir.status === 0 && goBinDir.stdout?.trim()
    ? goBinDir.stdout.trim()
    : null;
  let goVulncheck;
  if (goBin) {
    goVulncheck = join(goBin, 'govulncheck');
  } else {
    const goPathDir = run('go', ['env', 'GOPATH'], {
      cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000, maxBuffer: 1024,
    });
    const goPath = goPathDir.status === 0 && goPathDir.stdout?.trim()
      ? goPathDir.stdout.trim()
      : join(root, 'agent');
    goVulncheck = join(goPath, 'bin', 'govulncheck');
  }
  const go = run(goVulncheck, ['./...'], {
    cwd: join(root, 'agent'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 300000, maxBuffer: 16 * 1024 * 1024,
  });
  requireSuccessfulScan('govulncheck', go);
  if (!isCleanGoTextScan(go.stdout)) {
    throw new Error(`govulncheck did not return a complete clean text scan:\n${String(go.stdout).trim().slice(0, 12000)}`);
  }
  log('govulncheck: no vulnerabilities found.');
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runSecurityChecks(); }
  catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
