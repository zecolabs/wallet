(function () {
  "use strict";

  const ADDR_PREFIX = 'rx';
  const TOKEN_SYMBOL = 'ZP';

  function go(name) {
    if (name !== 'export-key') {
      const k = document.getElementById('exportKeyValue');
      if (k) k.value = '';
    }
    if (name !== 'reveal-phrase') {
      revealedMnemonic = null;
      const g = document.getElementById('revealGrid');
      if (g) g.textContent = '';
    }
    if (name !== 'sign') {
      const m = document.getElementById('signMessageInput');
      if (m) m.value = '';
      const pv = document.getElementById('signProofValue');
      if (pv) pv.value = '';
      const r = document.getElementById('signResult');
      if (r) r.style.display = 'none';
      const se = document.getElementById('signError');
      if (se) se.style.display = 'none';
    }
    if (name !== 'verify') {
      ['verifyMessageInput', 'verifyProofInput', 'verifyAddressValue', 'verifyPubkeyValue'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
      });
      const vr = document.getElementById('verifyResult');
      if (vr) vr.style.display = 'none';
      const ve = document.getElementById('verifyError');
      if (ve) ve.style.display = 'none';
    }
    if (['home', 'welcome', 'unlock', 'accounts', 'add-wallet'].includes(name)) {
      addMode = false;
      pendingMnemonic = null;
    }
    if (name !== 'confirm-tx') pendingTx = null;
    if (name === 'settings') refreshNetworkLabel();
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    const target = document.querySelector('.screen[data-screen="' + name + '"]');
    if (target) { target.classList.add('active'); target.scrollTop = 0; }
  }

  document.querySelectorAll('[data-go]').forEach(el => {
    el.addEventListener('click', () => go(el.dataset.go));
  });

  const isExtension = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage;

  function send(msg) {
    return new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
          if (res && res.error) return reject(new Error(res.error));
          resolve(res);
        });
      } catch (e) {
        reject(new Error('Failed to send message to background: ' + e.message));
      }
    });
  }

  let pendingMnemonic = null;
  let currentAddress = null;
  let currentName = 'Main Wallet';
  let addMode = false;
  let trafficCache = null;
  let balanceRaw = 0n;
  let feeRaw = 0n;
  let selectedTip = 'low';
  let pendingTx = null;
  let revealedMnemonic = null;

  const withPrefix = (a) => a ? ADDR_PREFIX + String(a).replace(new RegExp('^' + ADDR_PREFIX, 'i'), '') : '';
  const stripAddr  = (a) => String(a || '').replace(new RegExp('^' + ADDR_PREFIX, 'i'), '');

  const shortAddr = (a) => {
    if (!a) return '-';
    const full = withPrefix(a);
    return full.length > 14 ? full.slice(0, 8) + '...' + full.slice(-6) : full;
  };

  function formatUnits(baseUnitsStr, decimals = 18) {
    if (baseUnitsStr == null) return '-';
    let v;
    try { v = BigInt(baseUnitsStr); } catch { return String(baseUnitsStr); }
    const s = v.toString().padStart(decimals + 1, '0');
    const intPart = s.slice(0, -decimals);
    const fracPart = s.slice(-decimals).replace(/0+$/, '');
    return fracPart ? `${intPart}.${fracPart}` : intPart;
  }

  function parseAmountToUnits(str, decimals = 18) {
    const s = String(str).trim();
    if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('Invalid amount.');
    const [intPart, fracRaw = ''] = s.split('.');
    if (fracRaw.length > decimals) throw new Error(`Maximum ${decimals} decimal places.`);
    const frac = fracRaw.padEnd(decimals, '0');
    return BigInt(intPart) * (10n ** BigInt(decimals)) + BigInt(frac);
  }

  function copyToClipboard(text) {
    return navigator.clipboard.writeText(text || '')
      .catch(() => showAlert('Failed to copy to clipboard.', 'Failed', 'error'));
  }

  function clearPasswordFields() {
    ['pw1', 'pw2', 'unlockPw'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
  }

  function showModal({ title, message, showInput, isPassword, showCancel }) {
    return new Promise((resolve) => {
      const overlay = document.getElementById('modalOverlay');
      document.getElementById('modalTitle').textContent = title;
      document.getElementById('modalMessage').textContent = message;
      const inputEl = document.getElementById('modalInput');
      inputEl.style.display = showInput ? 'block' : 'none';
      inputEl.type = isPassword ? 'password' : 'text';
      inputEl.value = '';
      const okBtn = document.getElementById('modalOkBtn');
      const cancelBtn = document.getElementById('modalCancelBtn');
      cancelBtn.style.display = showCancel ? 'inline-flex' : 'none';
      overlay.classList.add('active');
      if (showInput) setTimeout(() => inputEl.focus(), 50);

      function cleanup(result) {
        overlay.classList.remove('active');
        okBtn.removeEventListener('click', onOk);
        cancelBtn.removeEventListener('click', onCancel);
        inputEl.removeEventListener('keydown', onKeydown);
        inputEl.value = '';
        resolve(result);
      }
      function onOk() { cleanup({ confirmed: true, value: inputEl.value }); }
      function onCancel() { cleanup({ confirmed: false, value: null }); }
      function onKeydown(e) { if (e.key === 'Enter') onOk(); if (e.key === 'Escape') onCancel(); }
      okBtn.addEventListener('click', onOk);
      cancelBtn.addEventListener('click', onCancel);
      inputEl.addEventListener('keydown', onKeydown);
    });
  }

  const TOAST_ICONS = {
    success: '<svg viewBox="0 0 24 24"><path d="m5 12 5 5 9-10"/></svg>',
    error: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 9v4M12 17h.01M10.3 3.86l-8.2 14.2A1 1 0 0 0 3 19.8h18a1 1 0 0 0 .9-1.74l-8.2-14.2a1 1 0 0 0-1.8 0Z"/></svg>',
  };
  const TOAST_CLOSE = '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>';

  const STATUS_SVG_ATTR = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"';
  const STATUS_SVG = {
    success: '<svg ' + STATUS_SVG_ATTR + '><path d="m5 12 5 5 9-10"/></svg>',
    danger:  '<svg ' + STATUS_SVG_ATTR + '><path d="M6 6l12 12M18 6 6 18"/></svg>',
    pending: '<svg ' + STATUS_SVG_ATTR + '><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
  };
  const TOAST_MS = { success: 4000, warning: 5500, error: 6500 };

  function dismissToast(el) {
    if (!el || el.classList.contains('leaving')) return;
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 200);
  }

  function mountToast(el, ms) {
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.innerHTML = TOAST_CLOSE;
    closeBtn.addEventListener('click', () => dismissToast(el));
    el.appendChild(closeBtn);
    document.getElementById('toastLayer').appendChild(el);
    if (ms) setTimeout(() => dismissToast(el), ms);
  }

  function showAlert(message, title = 'Notice', type = 'warning') {
    if (!TOAST_ICONS[type]) type = 'warning';
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');

    const ico = document.createElement('div');
    ico.className = 'toast-ico';
    ico.innerHTML = TOAST_ICONS[type];

    const body = document.createElement('div');
    body.className = 'toast-body';
    const t = document.createElement('div');
    t.className = 'toast-title';
    t.textContent = title;
    const m = document.createElement('div');
    m.className = 'toast-msg';
    m.textContent = message;
    body.append(t, m);

    el.append(ico, body);
    mountToast(el, TOAST_MS[type]);
    return Promise.resolve();
  }

  function showTxSuccess(txHash) {
    const el = document.createElement('div');
    el.className = 'toast success tx';
    el.setAttribute('role', 'status');

    const check = document.createElement('div');
    check.className = 'toast-check';
    check.setAttribute('aria-hidden', 'true');
    check.innerHTML = STATUS_SVG.success;

    const title = document.createElement('div');
    title.className = 'toast-title';
    title.textContent = 'Success';

    const wrap = document.createElement('div');
    wrap.className = 'input-wrap';
    wrap.innerHTML =
      '<span class="lead"><svg viewBox="0 0 24 24"><path d="M5 9h14M5 15h14M10 3 8 21M16 3l-2 18"/></svg></span>' +
      '<input class="input compact has-copy" readonly spellcheck="false" autocomplete="off" aria-label="Transaction hash">' +
      '<button type="button" class="copy-btn" aria-label="Copy tx hash"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>';
    const input = wrap.querySelector('input');
    input.value = txHash || '';
    const copyBtn = wrap.querySelector('.copy-btn');
    copyBtn.addEventListener('click', () => copyWithFeedback(input.value, copyBtn));

    el.append(check, title, wrap);
    mountToast(el, 0);
    input.scrollLeft = 0;
  }
  async function showPrompt(message, title = 'Enter Password') {
    const result = await showModal({ title, message, showInput: true, isPassword: true, showCancel: true });
    return result.confirmed ? result.value : null;
  }

  function renderMnemonic(phrase, gridId = 'mnemonicGrid') {
    const grid = document.getElementById(gridId);
    grid.textContent = '';
    phrase.trim().split(/\s+/).forEach((w, i) => {
      const cell = document.createElement('div');
      cell.className = 'mnemonic-word';
      const idx = document.createElement('span');
      idx.textContent = (i + 1) + '.';
      cell.append(idx, w);
      grid.appendChild(cell);
    });
  }

  const phraseToText = (p) => String(p || '').trim().split(/\s+/).join(' ');

  function flashCopied(btn) {
    if (!btn || btn.dataset.flashing) return;
    btn.dataset.flashing = '1';
    const svg = btn.querySelector('svg');
    const lbl = btn.querySelector('.lbl');
    const oldSvg = svg ? svg.innerHTML : '';
    const oldLbl = lbl ? lbl.textContent : '';
    if (svg) svg.innerHTML = CHECK_SVG;
    if (lbl) lbl.textContent = 'Copied';
    btn.classList.add('ok');
    setTimeout(() => {
      if (svg) svg.innerHTML = oldSvg;
      if (lbl) lbl.textContent = oldLbl;
      btn.classList.remove('ok');
      delete btn.dataset.flashing;
    }, 1400);
  }
  async function copyWithFeedback(text, btn) {
    try {
      await navigator.clipboard.writeText(text || '');
      flashCopied(btn);
    } catch {
      await showAlert('Failed to copy to clipboard.', 'Failed', 'error');
    }
  }
  const warnClipboard = () =>
    showAlert('Phrase/key copied to clipboard. Paste it somewhere safe, then copy other text to overwrite it.', 'Warning', 'warning');

  function renderHome() {
    document.getElementById('homeAccountName').textContent = currentName;
    document.getElementById('homeAddress').textContent = shortAddr(currentAddress);
    document.getElementById('homeSymbol').textContent = TOKEN_SYMBOL;
  }

  function formatBalance(raw) {
    const s = formatUnits(raw);
    if (s === '-' || !s.includes('.')) return s;
    const [i, f] = s.split('.');
    return i + '.' + f.slice(0, 6);
  }
  async function loadBalance() {
    const el = document.getElementById('homeBalance');
    if (!el) return;
    try {
      const { account } = await send({ type: 'GET_ACCOUNT' });
      if (account && account.balance != null) { try { balanceRaw = BigInt(account.balance); } catch {} }
      el.textContent = account && account.balance != null ? formatBalance(account.balance) : '0';
    } catch (e) {
      console.warn('Failed to fetch balance:', e.message);
      el.textContent = '0';
    }
  }

  async function startCreateFlow() {
    try {
      const { mnemonic } = await send({ type: 'PREVIEW_NEW_WALLET' });
      pendingMnemonic = mnemonic;
      renderMnemonic(mnemonic);
      document.getElementById('word4').value = '';
      document.getElementById('word9').value = '';
      document.getElementById('confirmError').style.display = 'none';
      go('create-1');
    } catch (e) {
      await showAlert('Failed to generate phrase: ' + e.message, 'Failed', 'error');
    }
  }
  document.getElementById('btnCreate').onclick = () => { addMode = false; startCreateFlow(); };

  const btnCopyCreatePhrase = document.getElementById('btnCopyCreatePhrase');
  if (btnCopyCreatePhrase) btnCopyCreatePhrase.onclick = async () => {
    await copyWithFeedback(phraseToText(pendingMnemonic), btnCopyCreatePhrase);
    warnClipboard();
  };

  document.getElementById('btnImportSubmit').onclick = async () => {
    const phrase = document.getElementById('importPhrase').value.trim().replace(/\s+/g, ' ');
    if (!phrase) { await showAlert('Enter your recovery phrase.', 'Incomplete', 'warning'); return; }
    if (addMode) { await addWalletFlow(phrase); return; }
    pendingMnemonic = phrase;
    document.getElementById('setPasswordMode').value = 'import';
    go('set-password');
  };

  document.getElementById('btnConfirmWords').onclick = async () => {
    if (!pendingMnemonic) {
      await showAlert('The phrase session was lost, please start creating the wallet again.', 'Session Expired', 'warning');
      go(addMode ? 'add-wallet' : 'welcome');
      return;
    }
    const words = pendingMnemonic.trim().split(/\s+/);
    const w4 = document.getElementById('word4').value.trim();
    const w9 = document.getElementById('word9').value.trim();
    const err = document.getElementById('confirmError');
    if (w4 !== words[3] || w9 !== words[8]) { err.style.display = 'block'; return; }
    err.style.display = 'none';
    if (addMode) { await addWalletFlow(pendingMnemonic); return; }
    document.getElementById('setPasswordMode').value = 'create';
    go('set-password');
  };

  document.querySelectorAll('[data-social]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.social;
      if (!url) return;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) chrome.tabs.create({ url });
      else window.open(url, '_blank', 'noopener');
    });
  });

  document.getElementById('btnCreate1Back').onclick = () => go(addMode ? 'add-wallet' : 'welcome');
  document.getElementById('btnImportBack').onclick = () => go(addMode ? 'add-wallet' : 'welcome');

  document.getElementById('btnPwBack').onclick = () => {
    const mode = document.getElementById('setPasswordMode').value;
    document.getElementById('pwError').style.display = 'none';
    go(mode === 'import' ? 'import' : 'create-2');
  };

  document.getElementById('btnSetPassword').onclick = async () => {
    const p1 = document.getElementById('pw1').value;
    const p2 = document.getElementById('pw2').value;
    const err = document.getElementById('pwError');
    if (p1.length < 10) { err.textContent = 'Minimum 10 characters.'; err.style.display = 'block'; return; }
    if (p1 !== p2) { err.textContent = 'Passwords do not match.'; err.style.display = 'block'; return; }
    if (!pendingMnemonic) {
      err.textContent = 'The phrase session was lost, please start over.';
      err.style.display = 'block';
      return;
    }
    err.style.display = 'none';
    const mode = document.getElementById('setPasswordMode').value;
    try {
      const msgType = mode === 'import' ? 'IMPORT_WALLET' : 'FINALIZE_WALLET';
      const { address, name } = await send({ type: msgType, mnemonic: pendingMnemonic, password: p1 });
      currentAddress = address;
      currentName = name || currentName;
      pendingMnemonic = null;
      clearPasswordFields();
      renderHome();
      loadHistoryAndRender();
      go('home');
    } catch (e) {
      err.textContent = e.message || 'Failed to save wallet.';
      err.style.display = 'block';
    }
  };
 
  document.getElementById('btnUnlock').onclick = async () => {
    const pw = document.getElementById('unlockPw').value;
    const err = document.getElementById('unlockError');
    err.style.display = 'none';
    try {
      const { address, name } = await send({ type: 'UNLOCK', password: pw });
      currentAddress = address;
      currentName = name || currentName;
      clearPasswordFields();
      renderHome();
      loadHistoryAndRender();
      go('home');
    } catch (e) {
      err.textContent = e.message || 'Incorrect password.';
      err.style.display = 'block';
    }
  };

  document.getElementById('btnLock').onclick = async () => {
    try {
      await send({ type: 'LOCK' });
    } catch (e) {
      console.warn('Failed to send LOCK:', e.message);
    }
    currentAddress = null;
    clearPasswordFields();
    go('unlock');
  };

  const CHECK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg>';
  const WALLET_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5h-4a2 2 0 0 1 0-4h4Z"/></svg>';

  function renderWalletList(wallets, activeId) {
    const list = document.getElementById('walletList');
    list.textContent = '';
    wallets.forEach(w => {
      const row = document.createElement('div');
      row.className = 'row-item';
      row.style.cursor = 'pointer';

      const ico = document.createElement('div');
      ico.className = 'ico';
      ico.innerHTML = WALLET_ICON;

      const main = document.createElement('div');
      main.className = 'main';
      const t1 = document.createElement('div');
      t1.className = 't1';
      t1.textContent = w.name;
      const t2 = document.createElement('div');
      t2.className = 't2';
      t2.textContent = shortAddr(w.address);
      main.append(t1, t2);

      const chev = document.createElement('div');
      chev.className = 'chev';
      if (w.id === activeId) { chev.innerHTML = CHECK_ICON; chev.style.color = 'var(--accent-dark)'; }

      row.append(ico, main, chev);
      row.onclick = () => switchToWallet(w.id, w.id === activeId);
      list.appendChild(row);
    });
  }

  async function openAccounts() {
    try {
      const { wallets, activeId } = await send({ type: 'GET_WALLETS' });
      renderWalletList(wallets, activeId);
      go('accounts');
    } catch (e) {
      await showAlert(e.message, 'Failed', 'error');
    }
  }

  async function switchToWallet(id, alreadyActive) {
    if (alreadyActive) { go('home'); return; }
    try {
      const { address, name } = await send({ type: 'SWITCH_WALLET', id });
      applyActiveWallet(address, name);
      go('home');
    } catch (e) {
      await showAlert(e.message, 'Failed', 'error');
    }
  }

  function applyActiveWallet(address, name) {
    currentAddress = address;
    currentName = name || currentName;
    balanceRaw = 0n;
    document.getElementById('homeBalance').textContent = '0';
    renderHistory([]);
    renderHome();
    loadHistoryAndRender();
  }

  async function addWalletFlow(mnemonic) {
    const pw = await showPrompt('Enter your password to add this wallet.', 'Confirm Password');
    if (pw === null) return;
    if (!pw) { await showAlert('Password cannot be empty.', 'Incomplete', 'warning'); return; }
    try {
      const { address, name } = await send({ type: 'ADD_WALLET', mnemonic, password: pw });
      document.getElementById('importPhrase').value = '';
      go('home');
      applyActiveWallet(address, name);
      showAlert('"' + name + '" was added and is now active.', 'Wallet Added', 'success');
    } catch (e) {
      await showAlert(e.message, 'Failed', 'error');
    }
  }

  document.getElementById('btnAccount').onclick = openAccounts;
  document.getElementById('btnAddWallet').onclick = () => go('add-wallet');
  document.getElementById('btnAddCreate').onclick = () => { addMode = true; startCreateFlow(); };
  document.getElementById('btnAddImport').onclick = () => {
    addMode = true;
    pendingMnemonic = null;
    document.getElementById('importPhrase').value = '';
    go('import');
  };

  const hostLabel = (url) => { try { return new URL(url).host; } catch { return url; } };

  async function refreshNetworkLabel() {
    try {
      const cfg = await send({ type: 'GET_RPC' });
      document.getElementById('settingsNetworkSub').textContent =
        hostLabel(cfg.url) + (cfg.isDefault ? ' (default)' : '');
    } catch { /* leave label as is */ }
  }

  function setRpcStatus(text, kind) {   // kind: 'ok' | 'err' | undefined
    const el = document.getElementById('rpcStatus');
    el.textContent = text;
    el.className = 'subtitle' + (kind === 'err' ? ' err-text' : '');
    el.style.color = kind === 'ok' ? 'var(--success)' : '';
  }
  const describeRpc = (i) => 'Connected · Chain ID ' + i.chainid + ' · Block ' + i.blockNumber + ' · ' + i.latencyMs + ' ms';

  function setRpcBusy(busy) {
    ['btnRpcSave', 'btnRpcTest', 'btnRpcReset'].forEach(id => { document.getElementById(id).disabled = busy; });
  }

  function rpcOrigin(raw) {
    let u;
    try { u = new URL(raw); } catch { throw new Error('Invalid URL. Example: http://127.0.0.1:3000'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('URL must start with http:// or https://');
    return u.origin;
  }
  const isLoopback = (raw) => {
    const h = new URL(raw).hostname;
    return h === 'localhost' || h === '[::1]' || /^127\./.test(h);
  };

  async function ensureHostPermission(origin) {
    if (!chrome.permissions || !chrome.permissions.request) return true;
    const req = { origins: [origin + '/*'] };
    if (await chrome.permissions.contains(req)) return true;
    return chrome.permissions.request(req);
  }

  async function openNetwork() {
    go('network');
    const input = document.getElementById('rpcUrlInput');
    setRpcBusy(true);
    setRpcStatus('Checking connection…');
    try {
      const cfg = await send({ type: 'GET_RPC' });
      input.value = cfg.url;
      try {
        setRpcStatus(describeRpc(await send({ type: 'TEST_RPC' })), 'ok');
      } catch (e) {
        setRpcStatus(e.message, 'err');
      }
    } catch (e) {
      setRpcStatus(e.message, 'err');
    }
    setRpcBusy(false);
  }

  async function applyRpc(save) {
    const raw = document.getElementById('rpcUrlInput').value.trim();
    let origin;
    try { origin = rpcOrigin(raw); } catch (e) { setRpcStatus(e.message, 'err'); return; }

    if (save && /^http:/i.test(raw) && !isLoopback(raw)) {
      const r = await showModal({
        title: 'Insecure Connection',
        message: 'This address uses http:// (unencrypted). Others on the network can see which addresses you check, or forge node responses (for example, balances). Your wallet keys stay safe on this device. Continue?',
        showCancel: true,
      });
      if (!r.confirmed) return;
    }

    setRpcBusy(true);
    try {
      let granted = false;
      try { granted = await ensureHostPermission(origin); } catch { granted = false; }
      if (!granted) {
        setRpcStatus('Access to ' + origin + ' was denied. Without permission, the wallet cannot connect to this node.', 'err');
        return;
      }
      setRpcStatus('Checking connection…');
      if (save) {
        const info = await send({ type: 'SET_RPC', url: raw });
        document.getElementById('rpcUrlInput').value = info.url;
        setRpcStatus('Saved. ' + describeRpc(info), 'ok');
        showAlert('RPC address saved.', 'Network', 'success');
      } else {
        setRpcStatus(describeRpc(await send({ type: 'TEST_RPC', url: raw })), 'ok');
      }
    } catch (e) {
      setRpcStatus(e.message, 'err');
    } finally {
      setRpcBusy(false);
    }
  }

  document.getElementById('btnNetwork').onclick = openNetwork;
  document.getElementById('btnRpcSave').onclick = () => applyRpc(true);
  document.getElementById('btnRpcTest').onclick = () => applyRpc(false);
  document.getElementById('btnRpcReset').onclick = async () => {
    setRpcBusy(true);
    try {
      const cfg = await send({ type: 'RESET_RPC' });
      document.getElementById('rpcUrlInput').value = cfg.url;
      setRpcStatus('Checking connection…');
      try { setRpcStatus('Reset to default. ' + describeRpc(await send({ type: 'TEST_RPC' })), 'ok'); }
      catch (e) { setRpcStatus('Reset to default, but: ' + e.message, 'err'); }
    } catch (e) {
      setRpcStatus(e.message, 'err');
    } finally {
      setRpcBusy(false);
    }
  };

  const btnCopyAddr = document.getElementById('btnCopyAddr');
  const COPY_SVG = '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>';
  const CHECK_SVG = '<path d="m5 12 5 5 9-10"/>';
  if (btnCopyAddr) btnCopyAddr.onclick = async () => {
    await copyToClipboard(withPrefix(currentAddress));
    const icon = document.getElementById('copyIcon');
    btnCopyAddr.classList.add('ok');
    icon.innerHTML = CHECK_SVG;
    setTimeout(() => { btnCopyAddr.classList.remove('ok'); icon.innerHTML = COPY_SVG; }, 1400);
  };
  const TIP_KEYS = ['low', 'medium', 'fast'];
  const TIP_EL_ID = { low: 'tipLow', medium: 'tipMedium', fast: 'tipFast' };

  function renderSendBalance() {
    const el = document.getElementById('sendBalance');
    if (el) el.textContent = formatBalance(balanceRaw.toString());
    const sym = document.getElementById('sendBalanceSym');
    if (sym) sym.textContent = TOKEN_SYMBOL;
  }

  function currentTipRaw() {
    try { return trafficCache && trafficCache[selectedTip] != null ? BigInt(trafficCache[selectedTip]) : 0n; }
    catch { return 0n; }
  }

  function fillAmountFromBalance(pct) {
    const amtEl = document.getElementById('sendAmount');
    const costs = feeRaw + currentTipRaw();
    const spendable = balanceRaw > costs ? balanceRaw - costs : 0n;
    let raw = pct >= 100 ? spendable : (balanceRaw * BigInt(pct)) / 100n;
    if (raw > spendable) raw = spendable;
    amtEl.value = formatUnits(raw.toString());
  }

  function selectTip(key) {
    selectedTip = key;
    document.querySelectorAll('.tip-btn').forEach(b =>
      b.classList.toggle('selected', b.dataset.tip === key));
  }

  function renderTipAmounts() {
    TIP_KEYS.forEach(k => {
      const el = document.getElementById(TIP_EL_ID[k]);
      if (el) el.textContent = trafficCache && trafficCache[k] != null ? formatUnits(trafficCache[k]) : '0';
    });
  }

  document.querySelectorAll('.pct-btn').forEach(b =>
    b.addEventListener('click', () => fillAmountFromBalance(Number(b.dataset.pct))));
  document.getElementById('btnMax').addEventListener('click', () => fillAmountFromBalance(100));
  document.querySelectorAll('.tip-btn').forEach(b =>
    b.addEventListener('click', () => selectTip(b.dataset.tip)));

  document.getElementById('btnGoSend').onclick = async () => {
    const toEl = document.getElementById('sendTo');
    const amtEl = document.getElementById('sendAmount');
    const se = document.getElementById('sendError');
    if (toEl) toEl.value = '';
    if (amtEl) amtEl.value = '';
    if (se) se.style.display = 'none';
    selectTip('low');
    trafficCache = null;
    feeRaw = 0n;
    renderTipAmounts();
    renderSendBalance();
    go('send');

    send({ type: 'GET_ACCOUNT' }).then(({ account }) => {
      if (account && account.balance != null) balanceRaw = BigInt(account.balance);
      renderSendBalance();
    }).catch(e => console.warn('Failed to fetch balance:', e.message));

    // Fetch the transfer fee (fixed, set by the protocol).
    send({ type: 'GET_FEE_INFO' }).then(({ info }) => {
      if (info && info.fee != null) feeRaw = BigInt(info.fee);
    }).catch(e => console.warn('Failed to fetch fee:', e.message));

    try {
      const { traffic } = await send({ type: 'GET_TRAFFIC' });
      trafficCache = traffic;
      renderTipAmounts();
    } catch (e) {
      console.warn('Failed to fetch traffic:', e.message);
      trafficCache = null;
    }
  };

  document.getElementById('btnReviewSend').onclick = async () => {
    const err = document.getElementById('sendError');
    err.style.display = 'none';
    const toRaw = document.getElementById('sendTo').value.trim();
    if (/^0x/i.test(toRaw)) {
      err.textContent = 'The 0x prefix is no longer supported. Addresses on this network use the rx prefix.';
      err.style.display = 'block';
      return;
    }
    const to = stripAddr(toRaw);
    if (!/^rx/i.test(toRaw) || !/^[0-9a-fA-F]{40}$/.test(to)) {
      err.textContent = 'Destination address must start with rx followed by 40 hex characters (20 bytes).';
      err.style.display = 'block';
      return;
    }
    const amountStr = document.getElementById('sendAmount').value.trim();

    if (!/^[0-9a-fA-F]{40}$/.test(to)) {
      err.textContent = 'Destination address must be 20 bytes of hex (40 characters).';
      err.style.display = 'block';
      return;
    }

    let amountUnit;
    try {
      amountUnit = parseAmountToUnits(amountStr, 18);
    } catch (e) {
      err.textContent = e.message; err.style.display = 'block'; return;
    }
    if (!(amountUnit > 0n)) {
      err.textContent = 'Amount must be greater than 0.'; err.style.display = 'block'; return;
    }

    const tipVal = trafficCache && trafficCache[selectedTip];
    if (tipVal == null) {
      err.textContent = 'Network tip estimates are not available yet, wait a moment and try again.';
      err.style.display = 'block';
      return;
    }
    const tip = String(tipVal);

    if (!(feeRaw > 0n)) {
      err.textContent = 'Fee info is not available yet, wait a moment and try again.';
      err.style.display = 'block';
      return;
    }
    const total = amountUnit + BigInt(tip) + feeRaw;
    if (total > balanceRaw) {
      err.textContent = 'Insufficient balance for amount + tip + fee.';
      err.style.display = 'block';
      return;
    }

    pendingTx = { to, amount: amountUnit.toString(), tip };
    document.getElementById('confirmTo').value = ADDR_PREFIX + to;
    document.getElementById('confirmAmount').textContent = formatUnits(amountUnit.toString());
    document.getElementById('confirmFee').textContent = formatUnits(feeRaw.toString());
    document.getElementById('confirmTip').textContent = formatUnits(tip);
    document.getElementById('confirmTotal').textContent = formatUnits(total.toString());
    document.getElementById('confirmTxError').style.display = 'none';
    go('confirm-tx');
    document.getElementById('confirmTo').scrollLeft = 0;
  };


  document.getElementById('btnConfirmBack').onclick = () => go('send');
  document.getElementById('btnConfirmCancel').onclick = () => go('send');

  document.getElementById('btnConfirmSend').onclick = async () => {
    const tx = pendingTx;
    const err = document.getElementById('confirmTxError');
    if (!tx) { go('send'); return; }
    err.style.display = 'none';

    const btn = document.getElementById('btnConfirmSend');
    const cancel = document.getElementById('btnConfirmCancel');
    const back = document.getElementById('btnConfirmBack');
    const prev = btn.textContent;
    btn.disabled = cancel.disabled = back.disabled = true;
    btn.textContent = 'Sending…';
    try {
      const { txHash, status } = await send({ type: 'SEND_TX', tx });

      if (status === 'success') {
        showTxSuccess(txHash);
      } else if (status === 'failed') {
        showAlert(`The network failed to process the transaction.\nHash: ${txHash}`, 'Failed', 'error');
      } else {
        showAlert(`Transaction status: ${status}\nHash: ${txHash}`, 'Transaction Sent', 'warning');
      }
      loadHistoryAndRender();
      go('home');
    } catch (e) {
      err.textContent = 'Failed: ' + e.message;
      err.style.display = 'block';
    } finally {
      btn.disabled = cancel.disabled = back.disabled = false;
      btn.textContent = prev;
    }
  };

  document.getElementById('btnRevealPhrase').onclick = async () => {
    const pw = await showPrompt('Enter your password to reveal the recovery phrase:', 'Reveal Recovery Phrase');
    if (!pw) return;
    try {
      const { mnemonic } = await send({ type: 'REVEAL_MNEMONIC', password: pw });
      renderMnemonic(mnemonic, 'revealGrid');
      go('reveal-phrase');
      revealedMnemonic = mnemonic;
    } catch (e) {
      await showAlert(e.message || 'Incorrect password.', 'Failed', 'error');
    }
  };

  document.getElementById('btnExportKey').onclick = async () => {
    const pw = await showPrompt('Enter your password to export the private key:', 'Export Private Key');
    if (!pw) return;
    try {
      const { privateKey } = await send({ type: 'EXPORT_PRIVATE_KEY', password: pw });
      go('export-key');
      const keyEl = document.getElementById('exportKeyValue');
      keyEl.value = privateKey;
      keyEl.scrollLeft = 0;
    } catch (e) {
      await showAlert(e.message || 'Incorrect password.', 'Failed', 'error');
    }
  };

  const btnCopyRevealPhrase = document.getElementById('btnCopyRevealPhrase');
  if (btnCopyRevealPhrase) btnCopyRevealPhrase.onclick = async () => {
    await copyWithFeedback(phraseToText(revealedMnemonic), btnCopyRevealPhrase);
    warnClipboard();
  };
  const btnRevealOk = document.getElementById('btnRevealOk');
  if (btnRevealOk) btnRevealOk.onclick = () => go('settings');
  const btnCopyPrivKey = document.getElementById('btnCopyPrivKey');
  if (btnCopyPrivKey) btnCopyPrivKey.onclick = async () => {
    await copyWithFeedback(document.getElementById('exportKeyValue').value, btnCopyPrivKey);
    warnClipboard();
  };

  const MAX_SIGN_MSG_BYTES = 1024;
  const btnSignMessage = document.getElementById('btnSignMessage');
  btnSignMessage.onclick = async () => {
    const msgEl = document.getElementById('signMessageInput');
    const err = document.getElementById('signError');
    const result = document.getElementById('signResult');
    err.style.display = 'none';
    result.style.display = 'none';

    const message = msgEl.value;
    if (!message.trim()) {
      err.textContent = 'Message cannot be empty.'; err.style.display = 'block'; return;
    }
    if (new TextEncoder().encode(message).length > MAX_SIGN_MSG_BYTES) {
      err.textContent = 'Message is too long (max ' + MAX_SIGN_MSG_BYTES + ' bytes).'; err.style.display = 'block'; return;
    }

    const confirmSign = await showModal({
      title: 'Sign Message?',
      message: 'Do not sign messages from sources you do not trust. The signature is made with the active wallet key and cannot be undone.',
      showCancel: true,
    });
    if (!confirmSign.confirmed) return;

    const prev = btnSignMessage.textContent;
    btnSignMessage.disabled = true; btnSignMessage.textContent = 'Signing…';
    try {
      const { proof } = await send({ type: 'SIGN_MESSAGE', message });
      const out = document.getElementById('signProofValue');
      out.value = proof;
      out.scrollLeft = 0;
      result.style.display = 'block';
    } catch (e) {
      err.textContent = 'Failed: ' + e.message; err.style.display = 'block';
    } finally {
      btnSignMessage.disabled = false; btnSignMessage.textContent = prev;
    }
  };

  const btnCopyProof = document.getElementById('btnCopyProof');
  if (btnCopyProof) btnCopyProof.onclick = () =>
    copyWithFeedback(document.getElementById('signProofValue').value, btnCopyProof);

  const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];
  const KECCAK_ROT = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
  const KECCAK_PI = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
  const M64 = 0xffffffffffffffffn;
  const rotl64 = (x, n) => ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64;

  function keccakF1600(st) {
    const bc = new Array(5);
    for (let round = 0; round < 24; round++) {
      for (let x = 0; x < 5; x++) bc[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
      for (let x = 0; x < 5; x++) {
        const t = bc[(x + 4) % 5] ^ rotl64(bc[(x + 1) % 5], 1);
        for (let y = 0; y < 25; y += 5) st[y + x] ^= t;
      }
      let t = st[1];
      for (let i = 0; i < 24; i++) {
        const j = KECCAK_PI[i];
        const tmp = st[j];
        st[j] = rotl64(t, KECCAK_ROT[i]);
        t = tmp;
      }
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) bc[x] = st[y + x];
        for (let x = 0; x < 5; x++) st[y + x] ^= (~bc[(x + 1) % 5] & M64) & bc[(x + 2) % 5];
      }
      st[0] ^= KECCAK_RC[round];
    }
  }

  function keccak256(data) {
    const RATE = 136;
    const padded = new Uint8Array(Math.ceil((data.length + 1) / RATE) * RATE);
    padded.set(data);
    padded[data.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    const st = new Array(25).fill(0n);
    for (let off = 0; off < padded.length; off += RATE) {
      for (let i = 0; i < RATE / 8; i++) {
        let lane = 0n;
        for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
        st[i] ^= lane;
      }
      keccakF1600(st);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) for (let b = 0; b < 8; b++) out[i * 8 + b] = Number((st[i] >> BigInt(8 * b)) & 0xffn);
    return out;
  }

  const hexToBytes = (hex) => Uint8Array.from(hex.match(/.{2}/g), (h) => parseInt(h, 16));
  const bytesToHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
  function addressFromPubkeyHex(pubkeyHex) {
    return ADDR_PREFIX + bytesToHex(keccak256(hexToBytes(pubkeyHex)).slice(12));
  }

  const PROOF_HEX_LEN = 208; // 104 bytes
  const ICON_OK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/></svg>';
  const ICON_BAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>';

  const btnVerifyMessage = document.getElementById('btnVerifyMessage');
  btnVerifyMessage.onclick = async () => {
    const err = document.getElementById('verifyError');
    const result = document.getElementById('verifyResult');
    err.style.display = 'none';
    result.style.display = 'none';

    const message = document.getElementById('verifyMessageInput').value;
    let proof = document.getElementById('verifyProofInput').value.replace(/\s+/g, '');
    if (/^0x/i.test(proof)) proof = proof.slice(2);

    if (!message.trim()) {
      err.textContent = 'Message cannot be empty.'; err.style.display = 'block'; return;
    }
    if (new TextEncoder().encode(message).length > MAX_SIGN_MSG_BYTES) {
      err.textContent = 'Message is too long (max ' + MAX_SIGN_MSG_BYTES + ' bytes).'; err.style.display = 'block'; return;
    }
    if (!proof) {
      err.textContent = 'Proof cannot be empty.'; err.style.display = 'block'; return;
    }
    if (!/^[0-9a-fA-F]+$/.test(proof) || proof.length !== PROOF_HEX_LEN) {
      err.textContent = 'Proof must be ' + PROOF_HEX_LEN + ' hex characters (104 bytes).'; err.style.display = 'block'; return;
    }

    const prev = btnVerifyMessage.textContent;
    btnVerifyMessage.disabled = true; btnVerifyMessage.textContent = 'Verifying…';
    try {
      const { valid } = await send({ type: 'VERIFY_MESSAGE', message, proof });
      const status = document.getElementById('verifyStatus');
      const detail = document.getElementById('verifyDetail');
      status.className = 'verify-status ' + (valid ? 'ok' : 'bad');
      document.getElementById('verifyStatusIcon').innerHTML = valid ? ICON_OK : ICON_BAD;
      document.getElementById('verifyStatusText').textContent = valid
        ? 'Valid — this message was signed by the owner of the address below.'
        : 'Invalid — the message and proof do not match.';
      if (valid) {
        const pubkeyHex = proof.slice(0, 64).toLowerCase();
        const signerAddr = addressFromPubkeyHex(pubkeyHex);
        const addrEl = document.getElementById('verifyAddressValue');
        addrEl.value = signerAddr;
        addrEl.scrollLeft = 0;
        const pk = document.getElementById('verifyPubkeyValue');
        pk.value = pubkeyHex;
        pk.scrollLeft = 0;
        const mine = !!currentAddress && signerAddr.toLowerCase() === withPrefix(currentAddress).toLowerCase();
        const tsSec = BigInt('0x' + proof.slice(192, 208));
        const when = tsSec <= 8640000000000n
          ? new Date(Number(tsSec) * 1000).toLocaleString('en-US')
          : 'timestamp ' + tsSec.toString();
        document.getElementById('verifyTime').textContent =
          (mine ? 'This is your active wallet. ' : '') + 'Signed: ' + when;
        detail.style.display = 'block';
      } else {
        detail.style.display = 'none';
      }
      result.style.display = 'block';
    } catch (e) {
      err.textContent = 'Failed: ' + e.message; err.style.display = 'block';
    } finally {
      btnVerifyMessage.disabled = false; btnVerifyMessage.textContent = prev;
    }
  };

  const btnCopyVerifyAddress = document.getElementById('btnCopyVerifyAddress');
  if (btnCopyVerifyAddress) btnCopyVerifyAddress.onclick = () =>
    copyWithFeedback(document.getElementById('verifyAddressValue').value, btnCopyVerifyAddress);
  const btnCopyVerifyPubkey = document.getElementById('btnCopyVerifyPubkey');
  if (btnCopyVerifyPubkey) btnCopyVerifyPubkey.onclick = () =>
    copyWithFeedback(document.getElementById('verifyPubkeyValue').value, btnCopyVerifyPubkey);

  function statusMeta(status) {
    if (status === 'success') return { icon: STATUS_SVG.success, label: 'Success', cls: 'success' };
    if (status === 'failed') return { icon: STATUS_SVG.danger, label: 'Failed', cls: 'danger' };
    return { icon: STATUS_SVG.pending, label: 'Pending', cls: 'pending' };
  }

  const ICON_SENT = '<svg viewBox="0 0 24 24"><path d="M7 17 17 7M8 7h9v9"/></svg>';
  const BADGE_ICON = {
    success: '<svg viewBox="0 0 24 24"><path d="m5 12 5 5 9-10"/></svg>',
    danger: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>',
    pending: '<svg viewBox="0 0 24 24"><path d="M12 7v5l3 2"/></svg>',
  };
  const pad2 = (n) => String(n).padStart(2, '0');
  function formatDateTime(ts) {
    if (!ts) return '-';
    const d = new Date(Number(ts) * 1000);
    if (isNaN(d)) return '-';
    return `${pad2(d.getDate())}-${pad2(d.getMonth() + 1)}-${d.getFullYear()} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  const longAddr = (a) => {
    const full = withPrefix(a);
    return full.length > 22 ? full.slice(0, 10) + '....' + full.slice(-8) : (full || '-');
  };

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function renderHistory(list) {
    const emptyEl = document.getElementById('historyEmpty');
    const listEl = document.getElementById('historyList');
    if (!list || list.length === 0) {
      emptyEl.style.display = 'flex';
      listEl.style.display = 'none';
      listEl.innerHTML = '';
      return;
    }
    emptyEl.style.display = 'none';
    listEl.style.display = 'flex';
    listEl.innerHTML = list.map((tx, i) => {
      const meta = statusMeta(tx.status);
      const chip = meta.cls === 'success' ? '' : `<span class="h-chip ${meta.cls}">${meta.label}</span>`;
      return `<div class="h-tx" data-idx="${i}">
        <div class="h-ava ${meta.cls === 'danger' ? 'danger' : ''}">${ICON_SENT}<span class="h-badge ${meta.cls}">${BADGE_ICON[meta.cls]}</span></div>
        <div class="h-txmain">
          <div class="h-lbl">Sent to</div>
          <div class="h-to">${esc(longAddr(tx.to))}</div>
          <div class="h-time">${esc(formatDateTime(tx.timestamp))}</div>
        </div>
        <div class="h-val"><b>-${esc(formatUnits(tx.amount))}</b>${chip}</div>
      </div>`;
    }).join('');
    listEl.querySelectorAll('.h-tx').forEach((card) => {
      card.addEventListener('click', () => showTxDetail(list[Number(card.dataset.idx)]));
    });
  }

  const shortMid = (s) => (s && s.length > 22) ? s.slice(0, 10) + '....' + s.slice(-8) : (s || '-');

  function setCopyable(valueId, btnId, full) {
    const v = document.getElementById(valueId);
    const b = document.getElementById(btnId);
    if (v) v.textContent = full ? shortMid(full) : '-';
    if (b) { b.dataset.copy = full || ''; b.style.display = full ? 'inline-flex' : 'none'; }
  }

  function senderForDisplay(sender) {
    const h = stripAddr(sender);
    if (/^[0-9a-fA-F]{40}$/.test(h)) return withPrefix(h);
    return currentAddress ? withPrefix(currentAddress) : '';
  }

  function renderTxDetailFields(tx) {
    const meta = statusMeta(tx.status);
    document.getElementById('txDetailIcon').innerHTML = meta.icon;
    document.getElementById('txDetailIcon').className = 'tx-detail-icon ' + meta.cls;
    document.getElementById('txDetailStatus').textContent = meta.label;
    document.getElementById('txDetailStatus').className = 'tx-detail-status-label ' + meta.cls;
    document.getElementById('txDetailAmount').textContent = formatUnits(tx.amount) + ' ' + TOKEN_SYMBOL;

    setCopyable('txDetailSender', 'txDetailSenderCopy', senderForDisplay(tx.sender));
    setCopyable('txDetailTo', 'txDetailToCopy', tx.to ? withPrefix(tx.to) : '');
    setCopyable('txDetailHash', 'txDetailHashCopy', tx.txHash || '');

    document.getElementById('txDetailBlock').textContent = tx.blockNumber != null ? String(tx.blockNumber) : '-';
    document.getElementById('txDetailFee').textContent = tx.fee != null ? formatUnits(tx.fee) : '-';
    document.getElementById('txDetailTip').textContent = tx.tip != null ? formatUnits(tx.tip) : '-';
    document.getElementById('txDetailTime').textContent = formatDateTime(tx.timestamp);
  }

  async function showTxDetail(tx) {
    renderTxDetailFields(tx);
    go('tx-detail');

    if (tx && tx.txHash) {
      try {
        const { detail } = await send({ type: 'GET_TX_DETAIL', txHash: tx.txHash });
        renderTxDetailFields({
          status: detail.txStatusText,
          amount: detail.amount,
          to: detail.to,
          txHash: tx.txHash,
          fee: detail.fee,
          tip: detail.tip,
          timestamp: detail.timestamp,
          sender: detail.sender && detail.sender.address,
          nonce: detail.nonce,
          blockNumber: detail.blockNumber,
        });
      } catch (e) {
        console.warn('Failed to fetch on-chain detail, using local data:', e.message);
      }
    }
  }

  async function loadHistoryAndRender() {
    loadBalance();
    try {
      const { history } = await send({ type: 'GET_HISTORY' });
      renderHistory(history);
    } catch (e) {
      console.warn('Failed to fetch history:', e.message);
      renderHistory([]);
    }
  }

  document.addEventListener('click', (e) => {
    const b = e.target.closest('.copy-mini');
    if (b && b.dataset.copy) copyWithFeedback(b.dataset.copy, b);
  });

  (async () => {
    if (!isExtension) {
      const banner = document.getElementById('demoBanner');
      if (banner) {
        banner.style.display = 'flex';
        banner.textContent =
          'This page only works when run as a real Chrome extension (it needs background.js).';
      }
      go('welcome');
      return;
    }
    try {
      const { exists } = await send({ type: 'HAS_WALLET' });
      if (!exists) { go('welcome'); return; }

      let session = { unlocked: false };
      try { session = await send({ type: 'GET_SESSION' }); } catch (e) { console.warn('GET_SESSION failed:', e.message); }
      if (session && session.unlocked && session.address) {
        currentAddress = session.address;
        currentName = session.name || currentName;
        renderHome();
        loadHistoryAndRender();
        go('home');
      } else {
        go('unlock');
      }
    } catch (e) {
      console.warn('HAS_WALLET failed:', e.message);
      go('welcome');
    }
  })();

})();
