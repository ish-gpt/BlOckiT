'use strict';

(function () {
  const MAX_DOMAINS = 500;
  const MIN_PASSWORD = 6;
  const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  const form = document.getElementById('blockForm');
  const textarea = document.getElementById('domains');
  const status = document.getElementById('status');
  const button = document.getElementById('submitBtn');
  const btnLabel = document.getElementById('btnLabel');
  const chips = document.querySelectorAll('.chip');
  const lockToggle = document.getElementById('lockToggle');
  const lockFields = document.getElementById('lockFields');
  const lockPassword = document.getElementById('lockPassword');
  const lockConfirm = document.getElementById('lockPasswordConfirm');
  const modeRadios = document.querySelectorAll('input[name="lockMode"]');
  const passwordMode = document.getElementById('passwordMode');
  const permanentMode = document.getElementById('permanentMode');
  const permanentAck = document.getElementById('permanentAck');

  function isPermanent() {
    return lockToggle.checked && document.querySelector('input[name="lockMode"]:checked').value === 'permanent';
  }

  // Mirrors lib/profile.js normaliseDomain; the server re-validates everything.
  function normalise(raw) {
    let s = raw.trim().toLowerCase();
    if (!s) return null;
    s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
    s = s.replace(/^[^@]*@/, '').replace(/:\d+$/, '').replace(/^\*\./, '').replace(/\.$/, '');
    let host;
    try {
      host = new URL('http://' + s).hostname;
    } catch (e) {
      return null;
    }
    const labels = host.split('.');
    if (host.length > 253 || labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return null;
    if (/^\d+$/.test(labels[labels.length - 1])) return null;
    return host;
  }

  function apex(domain) {
    return domain && domain.startsWith('www.') && domain.split('.').length > 2 ? domain.slice(4) : domain;
  }

  function read() {
    const valid = new Set();
    const invalid = [];
    for (const entry of textarea.value.split(/[\s,]+/)) {
      if (!entry) continue;
      const d = normalise(entry);
      if (d) valid.add(d);
      else invalid.push(entry);
    }
    return { valid, invalid };
  }

  function setStatus(text, kind) {
    status.textContent = text;
    status.className = 'status' + (kind ? ' is-' + kind : '');
  }

  // Returns an error message, '' when the lock is off or valid, or null when still incomplete.
  function lockProblem() {
    if (!lockToggle.checked) return '';
    if (isPermanent()) return permanentAck.checked ? '' : null;
    const pw = lockPassword.value;
    const confirm = lockConfirm.value;
    if (!pw) return null;
    if (pw.length < MIN_PASSWORD) return 'Lock password needs at least ' + MIN_PASSWORD + ' characters.';
    if (!confirm) return null;
    if (pw !== confirm) return "The two lock passwords don't match.";
    return '';
  }

  function refresh() {
    const { valid, invalid } = read();
    const n = valid.size;
    const lockIssue = lockProblem();

    const apexes = new Set([...valid].map(apex));
    chips.forEach((chip) => chip.classList.toggle('is-on', apexes.has(chip.dataset.domain)));

    if (invalid.length) {
      setStatus('Not a domain: ' + invalid.slice(0, 3).join(', ') + (invalid.length > 3 ? '…' : ''), 'error');
    } else if (n > MAX_DOMAINS) {
      setStatus('That is a lot of sites. Keep it under ' + MAX_DOMAINS + '.', 'error');
    } else if (lockIssue) {
      setStatus(lockIssue, 'error');
    } else {
      setStatus('');
    }

    const ok = n > 0 && !invalid.length && n <= MAX_DOMAINS && lockIssue === '';
    const sites = n + (n === 1 ? ' site' : ' sites');
    button.disabled = !ok;
    if (n === 0) btnLabel.textContent = 'Add a site to start';
    else if (isPermanent() && lockIssue === null) btnLabel.textContent = 'Tick the box to lock forever';
    else if (lockToggle.checked && lockIssue === null) btnLabel.textContent = 'Set a lock password';
    else if (isPermanent()) btnLabel.textContent = 'Block ' + sites + ' forever';
    else btnLabel.textContent = (lockToggle.checked ? 'Block & lock ' : 'Block ') + sites;
  }

  function toggleDomain(domain) {
    const lines = textarea.value.split('\n').map((l) => l.trim()).filter(Boolean);
    const has = lines.some((l) => apex(normalise(l)) === domain);
    const next = has ? lines.filter((l) => apex(normalise(l)) !== domain) : lines.concat(domain);
    textarea.value = next.join('\n') + (next.length ? '\n' : '');
    refresh();
  }

  chips.forEach((chip) => chip.addEventListener('click', () => toggleDomain(chip.dataset.domain)));
  textarea.addEventListener('input', refresh);
  lockPassword.addEventListener('input', refresh);
  lockConfirm.addEventListener('input', refresh);

  // Disabled inputs aren't submitted, so only the active lock mode's fields reach the server.
  function syncLock() {
    const on = lockToggle.checked;
    const permanent = isPermanent();
    lockFields.hidden = !on;
    modeRadios.forEach((r) => (r.disabled = !on));
    passwordMode.hidden = permanent;
    permanentMode.hidden = !permanent;
    lockPassword.disabled = !on || permanent;
    lockConfirm.disabled = !on || permanent;
    permanentAck.disabled = !on || !permanent;
    button.classList.toggle('is-danger', permanent);
  }
  lockToggle.addEventListener('change', () => {
    syncLock();
    if (lockToggle.checked && !isPermanent()) lockPassword.focus();
    refresh();
  });
  modeRadios.forEach((r) =>
    r.addEventListener('change', () => {
      syncLock();
      refresh();
    }),
  );
  permanentAck.addEventListener('change', refresh);

  form.addEventListener('submit', (event) => {
    refresh();
    if (button.disabled) {
      event.preventDefault();
      return;
    }
    // Native form POST so iOS Safari hands the response straight to the profile installer.
    setStatus(
      isPermanent()
        ? 'Permanent profile on its way. Install it, then delete the file without opening it.'
        : lockToggle.checked
        ? 'Locked profile on its way. Delete the file after installing.'
        : 'Profile on its way — tap Allow, then open Settings.',
      'ok',
    );
    button.classList.add('is-sent');
    setTimeout(() => button.classList.remove('is-sent'), 1200);
  });

  syncLock();
  refresh();
})();
