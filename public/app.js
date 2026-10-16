'use strict';

(function () {
  const MAX_DOMAINS = 500;
  const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  const form = document.getElementById('blockForm');
  const textarea = document.getElementById('domains');
  const status = document.getElementById('status');
  const button = document.getElementById('submitBtn');
  const btnLabel = document.getElementById('btnLabel');
  const chips = document.querySelectorAll('.chip');

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

  function refresh() {
    const { valid, invalid } = read();
    const n = valid.size;

    const apexes = new Set([...valid].map(apex));
    chips.forEach((chip) => chip.classList.toggle('is-on', apexes.has(chip.dataset.domain)));

    if (invalid.length) {
      setStatus('Not a domain: ' + invalid.slice(0, 3).join(', ') + (invalid.length > 3 ? '…' : ''), 'error');
    } else if (n > MAX_DOMAINS) {
      setStatus('That is a lot of sites. Keep it under ' + MAX_DOMAINS + '.', 'error');
    } else {
      setStatus('');
    }

    const ok = n > 0 && !invalid.length && n <= MAX_DOMAINS;
    button.disabled = !ok;
    btnLabel.textContent = n === 0 ? 'Add a site to start' : 'Block ' + n + (n === 1 ? ' site' : ' sites');
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

  form.addEventListener('submit', (event) => {
    refresh();
    if (button.disabled) {
      event.preventDefault();
      return;
    }
    // Native form POST so iOS Safari hands the response straight to the profile installer.
    setStatus('Profile on its way — tap Allow, then open Settings.', 'ok');
    button.classList.add('is-sent');
    setTimeout(() => button.classList.remove('is-sent'), 1200);
  });

  refresh();
})();
