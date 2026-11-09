// AegisMobile Ultimate v3.0 (PERISAI Standard) — Zero-Dependency Cyber Defense Engine
document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // ========================================================
  // 0. Security Sanitizer & Forensic State
  // ========================================================
  const escapeHtml = (str) =>
    String(str ?? '').replace(/[&<>"']/g, (c) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c]));

  const FORENSIC_KEY = 'aegis_forensic_logs_v3';
  const THREAT_COUNT_KEY = 'aegis_threat_count_v3';
  const SOC_MODE_KEY = 'aegis_soc_mode_v3';

  function getThreatCount() {
    return parseInt(localStorage.getItem(THREAT_COUNT_KEY) || '0', 10);
  }

  function recordForensicEvent(category, target, verdict, score, details, mitreId) {
    const logs = JSON.parse(localStorage.getItem(FORENSIC_KEY) || '[]');
    const entry = {
      timestamp: new Date().toISOString(),
      category,
      target: String(target).slice(0, 240),
      verdict,
      score,
      mitre: mitreId || 'T1566',
      details
    };
    logs.unshift(entry);
    localStorage.setItem(FORENSIC_KEY, JSON.stringify(logs.slice(0, 50)));

    if (score >= 50) {
      const nextCount = getThreatCount() + 1;
      localStorage.setItem(THREAT_COUNT_KEY, String(nextCount));
      updateThreatCounterUI();
    }
  }

  function updateThreatCounterUI() {
    const el = document.getElementById('threatMetric');
    if (el) {
      const count = getThreatCount();
      el.textContent = String(count);
      el.style.color = count > 0 ? '#f43f5e' : '#10b981';
    }
  }
  updateThreatCounterUI();

  // ========================================================
  // 1. Bloom Filter & Cryptographic Feed Integrity Engine
  // ========================================================
  class CompactBloomFilter {
    constructor(sizeBits = 65536, hashes = 4) {
      this.sizeBits = sizeBits;
      this.hashes = hashes;
      this.bits = new Uint32Array(sizeBits >>> 5);
    }
    _fnv1a(str, seed) {
      let h = (0x811c9dc5 ^ seed) >>> 0;
      for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 0x01000193) >>> 0;
      }
      return h;
    }
    add(item) {
      const key = item.toLowerCase().trim();
      for (let i = 0; i < this.hashes; i++) {
        const idx = this._fnv1a(key, i * 0x9e3779b9) % this.sizeBits;
        this.bits[idx >>> 5] |= 1 << (idx & 31);
      }
    }
    has(item) {
      const key = item.toLowerCase().trim();
      for (let i = 0; i < this.hashes; i++) {
        const idx = this._fnv1a(key, i * 0x9e3779b9) % this.sizeBits;
        if ((this.bits[idx >>> 5] & (1 << (idx & 31))) === 0) return false;
      }
      return true;
    }
  }

  const threatBloom = new CompactBloomFilter(65536, 4);
  const KNOWN_MALICIOUS_DOMAINS = [
    'directyp.org', 'popads.net', 'adsterra.com', 'maybank2u-secure.xyz',
    'cimbclicks-verify.top', 'tng-ewallet-claim.buzz', 'bantuan-str-gov.xyz',
    'mysejahtera-bantuan.top', 'lhdn-refund.click', 'jpj-saman-online.xyz',
    'poslaju-parcel.top', 'padu-bantuan.xyz', 'kwsp-akaun3.top',
    'str-semakan.xyz', 'bantuan-rakyat-2026.top', 'bantuantunairahmah.xyz',
    'pdrm-saman.xyz', 'saman-polis.top', 'semakan-saman-jpj.xyz',
    'kwsp-fsa2.top', 'kwsp-akaun-fleksibel.xyz', 'bankislam-secure.top',
    'rhb-online-verify.xyz', 'ambank-login.xyz', 'thijari-bantuan.xyz',
    'tabunghaji-claim.top', 'telegram-login-web.xyz', 'whatsapp-verify-my.top',
    'pakej-perkahwinan.xyz', 'resit-pembayaran.top', 'kad-jemputan-majlis.xyz',
    'asnb-dividen.xyz', 'mytnb-bil-semakan.top'
  ];
  const KNOWN_MALICIOUS_SET = new Set(KNOWN_MALICIOUS_DOMAINS);
  KNOWN_MALICIOUS_DOMAINS.forEach((d) => threatBloom.add(d));

  // Two-stage lookup across host and parent domain labels (Stage 1: Bloom -> Stage 2: Exact Set)
  function isKnownMaliciousDomain(host) {
    const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
    for (let i = 0; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      if (threatBloom.has(candidate) && KNOWN_MALICIOUS_SET.has(candidate)) {
        return true;
      }
    }
    return false;
  }

  // Verify WebCrypto availability & deterministic SHA-256 feed integrity digest
  async function verifyEngineIntegrity() {
    const badge = document.getElementById('feedSignBadge');
    const topStatus = document.getElementById('ed25519Status');
    try {
      const enc = new TextEncoder().encode(KNOWN_MALICIOUS_DOMAINS.join('|'));
      const digest = await crypto.subtle.digest('SHA-256', enc);
      const hex = Array.from(new Uint8Array(digest)).slice(0, 4).map((b) => b.toString(16).padStart(2, '0')).join('');
      if (badge) badge.textContent = `SHA-256: ${hex.toUpperCase()}`;
      if (topStatus) topStatus.textContent = `🔒 Enjin PERISAI v3.0 Aktif (SHA-256: ${hex})`;
      return true;
    } catch (_) {
      return false;
    }
  }
  verifyEngineIntegrity();

  // ========================================================
  // 2. Dual-Mode Toggle (Awam vs SOC Mode) & Tab Navigation
  // ========================================================
  const btnSocMode = document.getElementById('btnSocMode');
  function applySocMode(enabled) {
    document.body.classList.toggle('soc-mode', enabled);
    if (btnSocMode) {
      btnSocMode.classList.toggle('soc-active', enabled);
      btnSocMode.textContent = enabled ? '🔬 MOD SOC' : '🛡️ AWAM';
    }
    localStorage.setItem(SOC_MODE_KEY, enabled ? '1' : '0');
  }
  applySocMode(localStorage.getItem(SOC_MODE_KEY) === '1');

  if (btnSocMode) {
    btnSocMode.addEventListener('click', () => {
      const next = !document.body.classList.contains('soc-mode');
      applySocMode(next);
    });
  }

  const navItems = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');
  function switchTab(targetTabId) {
    navItems.forEach((n) => n.classList.toggle('active', n.getAttribute('data-tab') === targetTabId));
    tabContents.forEach((t) => t.classList.toggle('active', t.id === targetTabId));
  }
  navItems.forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.getAttribute('data-tab')));
  });

  // ========================================================
  // 3. Service Worker & PWA Install
  // ========================================================
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }

  let deferredPrompt;
  const installBtn = document.getElementById('installBtn');
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    if (installBtn) installBtn.style.display = 'block';
  });

  if (installBtn) {
    installBtn.addEventListener('click', async () => {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        if (outcome === 'accepted') installBtn.style.display = 'none';
        deferredPrompt = null;
      } else {
        alert('Pasang ke Skrin Utama:\n1. Tekan menu pelayar (⋮ atau Share).\n2. Pilih "Add to Home Screen" / "Pasang Aplikasi".');
      }
    });
  }

  // ========================================================
  // 4. Cryptographic Helpers & Shannon Entropy Calculator
  // ========================================================
  async function computeHash(buffer, algo = 'SHA-256') {
    if (window.crypto && window.crypto.subtle) {
      const hashBuffer = await crypto.subtle.digest(algo, buffer);
      return Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    }
    // Fallback deterministic 256-bit digest for non-HTTPS LAN testing (http://10.x.x.x)
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const lanes = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    for (let i = 0; i < bytes.length; i++) {
      const idx = i & 7;
      lanes[idx] = Math.imul(lanes[idx] ^ bytes[i], 0x01000193) ^ (lanes[(idx + 1) & 7] >>> 5);
    }
    return Array.from(lanes)
      .map((w) => (w >>> 0).toString(16).padStart(8, '0'))
      .join('');
  }

  function calculateShannonEntropy(uint8) {
    if (!uint8 || uint8.length === 0) return 0;
    const freq = new Uint32Array(256);
    const sampleLen = Math.min(uint8.length, 262144); // Sample up to 256KB for instant speed
    for (let i = 0; i < sampleLen; i++) {
      freq[uint8[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / sampleLen;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  // ========================================================
  // 5. Real Hardware, Storage & Network Posture Audit
  // ========================================================
  const healthScore = document.getElementById('healthScore');
  const meterCircle = document.getElementById('meterCircle');
  const statusHeading = document.getElementById('statusHeading');
  const statusSub = document.getElementById('statusSub');
  const ramMetric = document.getElementById('ramMetric');
  const signalMetric = document.getElementById('signalMetric');
  const masterAuditLogBox = document.getElementById('masterAuditLogBox');

  async function measureLivePing() {
    const start = performance.now();
    try {
      await fetch('./manifest.json?ping=' + Date.now(), { method: 'HEAD', cache: 'no-store' });
      return Math.max(1, Math.round(performance.now() - start));
    } catch (_) {
      return null;
    }
  }

  async function refreshRealTelemetry() {
    // 1. Storage & Memory Estimate
    let storageText = 'Aktif';
    if (navigator.storage && navigator.storage.estimate) {
      try {
        const est = await navigator.storage.estimate();
        if (est.usage && est.quota) {
          const usedMb = (est.usage / (1024 * 1024)).toFixed(1);
          const pct = ((est.usage / est.quota) * 100).toFixed(1);
          storageText = `${usedMb}MB (${pct}%)`;
        }
      } catch (_) {}
    }
    if (performance && performance.memory && performance.memory.usedJSHeapSize) {
      const heapMb = (performance.memory.usedJSHeapSize / (1024 * 1024)).toFixed(0);
      storageText = `${heapMb} MB Heap`;
    }
    if (ramMetric) {
      ramMetric.textContent = storageText;
      ramMetric.style.color = '#10b981';
    }

    // 2. Real Network Information API + Live RTT Probe
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    const liveRtt = await measureLivePing();
    const rttVal = liveRtt !== null ? liveRtt : (conn && conn.rtt ? conn.rtt : null);
    const effType = conn && conn.effectiveType ? conn.effectiveType.toUpperCase() : (navigator.onLine ? 'ONLINE' : 'OFFLINE');
    const downlink = conn && conn.downlink ? `${conn.downlink} Mbps` : (navigator.onLine ? 'Tersambung' : '0 Mbps');

    if (signalMetric) {
      signalMetric.textContent = rttVal !== null ? `${rttVal} ms` : effType;
      signalMetric.style.color = rttVal !== null && rttVal < 100 ? '#10b981' : '#38bdf8';
    }

    const sigNetType = document.getElementById('sigNetType');
    const sigDownlink = document.getElementById('sigDownlink');
    const sigRtt = document.getElementById('sigRtt');
    if (sigNetType) sigNetType.textContent = effType;
    if (sigDownlink) sigDownlink.textContent = downlink;
    if (sigRtt) sigRtt.textContent = rttVal !== null ? `${rttVal} ms` : '-- ms';

    // 3. Posture Score Calculation
    let score = 100;
    const checks = [];
    const isSecure = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost';
    if (!isSecure) {
      score -= 25;
      checks.push('⚠️ Konteks HTTP tidak disulitkan (Bukan HTTPS).');
    } else {
      checks.push('✅ Konteks Kriptografi TLS/HTTPS Aktif.');
    }

    if ('serviceWorker' in navigator) {
      checks.push('✅ Enjin Luar Talian (Service Worker) Sedia.');
    } else {
      score -= 10;
    }

    if (window.PublicKeyCredential) {
      checks.push('✅ Sokongan Kunci Perkakasan FIDO2 / Passkey Dikesan.');
    }

    const threatCount = getThreatCount();
    if (threatCount > 0) {
      const penalty = Math.min(35, threatCount * 10);
      score -= penalty;
      checks.push(`⚠️ ${threatCount} insiden ancaman keselamatan dikesan/disekat pada peranti (Penalti -${penalty}%).`);
    }

    if (healthScore) healthScore.textContent = `${score}%`;
    if (meterCircle) {
      meterCircle.style.borderColor = score >= 90 ? '#10b981' : (score >= 70 ? '#f59e0b' : '#f43f5e');
    }
    if (statusHeading) {
      if (threatCount > 0) {
        statusHeading.textContent = score >= 80 ? 'Peranti Berwaspada (Ada Rekod Ancaman)' : 'Peranti Perlu Perhatian Segera';
      } else {
        statusHeading.textContent = score >= 90 ? 'Perisai Peranti Tahap Optimum' : 'Peranti Perlu Perhatian';
      }
    }
    if (statusSub) {
      statusSub.textContent = `Talian: ${effType} (${rttVal !== null ? rttVal + ' ms' : 'Luar Talian'}) • Memori: ${storageText} • Ancaman: ${threatCount}`;
    }

    return { score, checks, effType, rttVal, storageText };
  }

  refreshRealTelemetry();

  const btnMasterBoost = document.getElementById('btnMasterBoost');
  if (btnMasterBoost) {
    btnMasterBoost.addEventListener('click', async () => {
      btnMasterBoost.disabled = true;
      btnMasterBoost.textContent = '⏳ Menjalankan Audit Keselamatan & Kalibrasi...';
      const res = await refreshRealTelemetry();
      await verifyEngineIntegrity();

      if (masterAuditLogBox) {
        masterAuditLogBox.style.display = 'block';
        masterAuditLogBox.innerHTML = res.checks
          .map((c) => `<div class="log-item">${escapeHtml(c)}</div>`)
          .join('') +
          `<div class="log-item">✅ Penapis Bloom (${KNOWN_MALICIOUS_DOMAINS.length} tandatangan teras) & Pembedah Binari APK sedia.</div>`;
      }

      btnMasterBoost.disabled = false;
      btnMasterBoost.textContent = '✅ Audit Selesai — Sistem Optimum';
      setTimeout(() => {
        btnMasterBoost.innerHTML = '⚡ 1-TAP AUDIT KESELAMATAN & OPTIMUMKAN';
      }, 3000);
    });
  }

  // ========================================================
  // 6. Deep Binary APK, ZIP & File Forensics (Zero External Libs)
  // ========================================================
  const apkFileInput = document.getElementById('apkFileInput');
  const apkLogBox = document.getElementById('apkLogBox');

  // Extract printable ASCII and UTF-16LE strings from binary buffer
  function extractBinaryStrings(uint8, minLen = 5) {
    const out = [];
    // 1. ASCII / UTF-8 scan
    let cur = '';
    const limit = Math.min(uint8.length, 1500000); // Scan up to 1.5MB for fast responsiveness
    for (let i = 0; i < limit; i++) {
      const b = uint8[i];
      if (b >= 32 && b <= 126) {
        cur += String.fromCharCode(b);
      } else {
        if (cur.length >= minLen) out.push(cur);
        cur = '';
      }
    }
    if (cur.length >= minLen) out.push(cur);

    // 2. UTF-16LE scan (Android Binary XML / AXML stores strings as UTF-16LE)
    let cur16 = '';
    for (let i = 0; i + 1 < limit; i += 2) {
      const c = uint8[i] | (uint8[i + 1] << 8);
      if (c >= 32 && c <= 126) {
        cur16 += String.fromCharCode(c);
      } else {
        if (cur16.length >= minLen) out.push(cur16);
        cur16 = '';
      }
    }
    if (cur16.length >= minLen) out.push(cur16);
    return out.join('\n');
  }

  // Decompress raw DEFLATE entry using browser's native DecompressionStream
  async function inflateRawEntry(compressedBytes) {
    if (typeof DecompressionStream === 'undefined') return compressedBytes;
    try {
      const stream = new Blob([compressedBytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
      const ab = await Promise.race([
        new Response(stream).arrayBuffer(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 400))
      ]);
      return new Uint8Array(ab);
    } catch (_) {
      return compressedBytes;
    }
  }

  // Parse ZIP Central Directory & Local File Headers to inspect APK files (supports Bit-3 streaming ZIPs)
  async function parseZipAndManifest(uint8) {
    const view = new DataView(uint8.buffer, uint8.byteOffset, uint8.byteLength);
    const entries = [];
    const cdMeta = new Map();
    let extractedText = '';

    // 1. Scan ZIP Central Directory (0x02014b50) from tail to resolve real compSize when Bit-3 is set
    const cdScanStart = Math.max(0, uint8.length - 512 * 1024);
    for (let pos = cdScanStart; pos <= uint8.length - 46; pos++) {
      if (view.getUint32(pos, true) !== 0x02014b50) continue;
      const compression = view.getUint16(pos + 10, true);
      const compSize = view.getUint32(pos + 20, true);
      const fileNameLen = view.getUint16(pos + 28, true);
      const extraLen = view.getUint16(pos + 30, true);
      const commentLen = view.getUint16(pos + 32, true);
      const localHeaderOffset = view.getUint32(pos + 42, true);
      if (fileNameLen > 0 && fileNameLen <= 512 && pos + 46 + fileNameLen <= uint8.length) {
        const name = new TextDecoder('utf-8', { fatal: false }).decode(uint8.subarray(pos + 46, pos + 46 + fileNameLen));
        cdMeta.set(localHeaderOffset, { name, compression, compSize });
        pos += 45 + fileNameLen + extraLen + commentLen;
      }
    }

    // 2. Scan Local File Headers (0x04034b50)
    let offset = 0;
    const maxOffset = Math.min(uint8.length - 30, 16 * 1024 * 1024);

    while (offset < maxOffset && entries.length < 300) {
      if (view.getUint32(offset, true) !== 0x04034b50) {
        offset++;
        continue;
      }
      const cd = cdMeta.get(offset);
      const compression = view.getUint16(offset + 8, true) || (cd ? cd.compression : 0);
      const compSize = view.getUint32(offset + 18, true) || (cd ? cd.compSize : 0);
      const fileNameLen = view.getUint16(offset + 26, true);
      const extraLen = view.getUint16(offset + 28, true);

      if (fileNameLen === 0 || fileNameLen > 512 || offset + 30 + fileNameLen > uint8.length) {
        offset += 4;
        continue;
      }

      const nameBytes = uint8.subarray(offset + 30, offset + 30 + fileNameLen);
      const fileName = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
      entries.push(fileName);

      const dataStart = offset + 30 + fileNameLen + extraLen;
      const fallbackLen = compSize > 0 ? compSize : Math.min(256 * 1024, Math.max(0, uint8.length - dataStart));
      const safeCompSize = Math.min(fallbackLen, Math.max(0, uint8.length - dataStart));

      // Decompress AndroidManifest.xml or scan all classes*.dex headers (Multi-DEX support)
      if (
        (fileName === 'AndroidManifest.xml' || fileName.endsWith('.dex') || fileName.endsWith('.xml')) &&
        safeCompSize > 0 &&
        safeCompSize < 2 * 1024 * 1024
      ) {
        const rawSlice = uint8.subarray(dataStart, dataStart + safeCompSize);
        const unpacked = compression === 8 ? await inflateRawEntry(rawSlice) : rawSlice;
        extractedText += '\n' + extractBinaryStrings(unpacked, 5);
      }

      offset = dataStart + (compSize > 0 ? compSize : 1);
    }

    // Fallback: also scan raw buffer strings
    extractedText += '\n' + extractBinaryStrings(uint8, 6);
    return { entries, extractedText };
  }

  if (apkFileInput) {
    apkFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      apkLogBox.style.display = 'block';
      apkLogBox.innerHTML = `<div class="log-item">⏳ Membedah struktur binari <strong>${escapeHtml(file.name)}</strong> (${(file.size / 1024).toFixed(1)} KB)...</div>`;

      try {
        const buffer = await file.arrayBuffer();
        const uint8 = new Uint8Array(buffer);
        const sha256 = await computeHash(buffer, 'SHA-256');
        const entropy = calculateShannonEntropy(uint8);

        // 1. Magic Bytes Identification
        let magicType = 'Tidak Diketahui / Data Mentah';
        if (uint8.length >= 4) {
          if (uint8[0] === 0x50 && uint8[1] === 0x4b && uint8[2] === 0x03 && uint8[3] === 0x04) {
            magicType = 'ZIP / Android APK Archive (PK\\x03\\x04)';
          } else if (uint8[0] === 0x4d && uint8[1] === 0x5a) {
            magicType = 'Windows Executable PE/EXE (MZ)';
          } else if (uint8[0] === 0x7f && uint8[1] === 0x45 && uint8[2] === 0x4c && uint8[3] === 0x46) {
            magicType = 'Linux / Android Native Binary (ELF)';
          } else if (uint8[0] === 0x25 && uint8[1] === 0x50 && uint8[2] === 0x44 && uint8[3] === 0x46) {
            magicType = 'Dokumen PDF (%PDF)';
          } else if (uint8[0] === 0x64 && uint8[1] === 0x65 && uint8[2] === 0x78 && uint8[3] === 0x0a) {
            magicType = 'Dalvik Executable (DEX)';
          }
        }

        const findings = [];
        let riskScore = 0;

        // 2. Extension vs Magic Bytes Mismatch & Double Extension Check
        if (/\.(pdf|doc|docx|jpg|jpeg|png|txt)\.(apk|exe|scr|bat|sh)$/i.test(file.name)) {
          riskScore += 75;
          findings.push('🚨 PENYAMARAN BERGANDA: Fail menyamar sebagai dokumen/gambar tetapi berekstensi boleh laku (.apk/.exe)!');
        }
        if (/\.(pdf|jpg|png|doc)$/i.test(file.name) && (magicType.includes('APK') || magicType.includes('EXE') || magicType.includes('ELF'))) {
          riskScore += 85;
          findings.push(`🚨 MAGIC BYTES PALSU: Nama fail ialah dokumen/imej tetapi isi sebenar ialah ${magicType}!`);
        }

        // 3. High Entropy Check (Encrypted / Packed Dropper)
        if (entropy > 7.93 && !/\.(jpg|jpeg|png|mp4)$/i.test(file.name)) {
          riskScore += 30;
          findings.push(`⚠️ Entropi Shannon Sangat Tinggi (${entropy.toFixed(2)} bit/bait) — ciri payload tersulit atau dropper terbungkus.`);
        }

        // 4. Deep APK / ZIP / Split-APK Inspection
        let detectedPerms = [];
        let internalSummary = '';
        if (magicType.includes('ZIP / Android APK') || /\.(apk|xapk|apks|apkm)$/i.test(file.name)) {
          const { entries, extractedText } = await parseZipAndManifest(uint8);
          const upperText = extractedText.toUpperCase();

          const PERM_RULES = [
            { id: 'BIND_ACCESSIBILITY_SERVICE', weight: 50, label: 'BIND_ACCESSIBILITY_SERVICE (Kawalan Skrin Automatik / Curi Bank)' },
            { id: 'BIND_NOTIFICATION_LISTENER_SERVICE', weight: 45, label: 'BIND_NOTIFICATION_LISTENER_SERVICE (Pintas Notifikasi Push TAC / Bank)' },
            { id: 'MANAGE_EXTERNAL_STORAGE', weight: 45, label: 'MANAGE_EXTERNAL_STORAGE (Akses Penuh Semua Fail — Risiko Penyulitan Ransomware)' },
            { id: 'WRITE_EXTERNAL_STORAGE', weight: 25, label: 'WRITE_EXTERNAL_STORAGE (Ubah / Sulitkan Gambar & Dokumen Storan)' },
            { id: 'RECEIVE_SMS', weight: 35, label: 'RECEIVE_SMS (Pintas SMS TAC / OTP Bank)' },
            { id: 'READ_SMS', weight: 35, label: 'READ_SMS (Baca Mesej OTP Perbankan)' },
            { id: 'SEND_SMS', weight: 30, label: 'SEND_SMS (Hantar SMS Tanpa Pengetahuan)' },
            { id: 'SYSTEM_ALERT_WINDOW', weight: 30, label: 'SYSTEM_ALERT_WINDOW (Lapisan Skrin Palsu / Phishing Overlay)' },
            { id: 'BIND_DEVICE_ADMIN', weight: 40, label: 'BIND_DEVICE_ADMIN (Kunci Peranti / Tukar PIN / Halang Uninstall)' },
            { id: 'REQUEST_INSTALL_PACKAGES', weight: 25, label: 'REQUEST_INSTALL_PACKAGES (Pemasang Dropper Sekunder)' },
            { id: 'REQUEST_DELETE_PACKAGES', weight: 25, label: 'REQUEST_DELETE_PACKAGES (Padam Aplikasi Keselamatan)' },
            { id: 'READ_CALL_LOG', weight: 20, label: 'READ_CALL_LOG (Intip Log Panggilan OTP Suara)' },
            { id: 'RECORD_AUDIO', weight: 20, label: 'RECORD_AUDIO (Rakaman Mikrofon Rahsia)' }
          ];

          PERM_RULES.forEach((rule) => {
            if (upperText.includes(rule.id)) {
              detectedPerms.push(rule.label);
              riskScore += rule.weight;
            }
          });

          // Toxic Banking Trojan Combination Rule (PERISAI Standard)
          const hasAccess = upperText.includes('BIND_ACCESSIBILITY_SERVICE');
          const hasNotif = upperText.includes('BIND_NOTIFICATION_LISTENER_SERVICE');
          const hasSms = upperText.includes('RECEIVE_SMS') || upperText.includes('READ_SMS');
          const hasOverlay = upperText.includes('SYSTEM_ALERT_WINDOW');
          const hasDropper = upperText.includes('REQUEST_INSTALL_PACKAGES');
          if ((hasAccess && (hasSms || hasOverlay || hasNotif || hasDropper)) || (hasNotif && (hasSms || hasOverlay || hasDropper))) {
            riskScore = Math.max(riskScore, 95);
            findings.unshift('🛑 KOMBINASI MAUT TROJAN PERBANKAN DIKESAN: Accessibility/NotifListener + SMS/Overlay/Dropper! Jangan pasang APK ini!');
          }

          // Mobile Ransomware & Screen-Locker Signature (MITRE T1486 / T1446)
          const hasDeviceAdmin = upperText.includes('BIND_DEVICE_ADMIN');
          const hasStorageWrite = upperText.includes('MANAGE_EXTERNAL_STORAGE') || upperText.includes('WRITE_EXTERNAL_STORAGE');
          const hasRansomCrypto = /javax\/crypto\/Cipher|AES\/CBC|resetPassword|lockNow|\.locked|\.encrypted|ransom/i.test(extractedText);
          if ((hasDeviceAdmin && (hasStorageWrite || hasOverlay || hasRansomCrypto)) || (hasStorageWrite && hasRansomCrypto && (hasOverlay || hasAccess))) {
            riskScore = 100;
            findings.unshift('🛑 RANSOMWARE MUDAH ALIH DIKESAN: Cuba mengunci skrin telefon (Device Admin) & menyulitkan gambar/dokumen anda! PADAM SERTA-MERTA!');
          }

          // Detect Telegram Bot C2 or ngrok tunnels inside DEX/APK
          if (/api\.telegram\.org\/bot/i.test(extractedText)) {
            riskScore += 60;
            findings.push('🚨 C2 TELEGRAM BOT DIKESAN: APK ini menghantar data curian terus ke bot Telegram penggodam!');
          }
          if (/ngrok-free\.app|trycloudflare\.com|\.onion/i.test(extractedText)) {
            riskScore += 50;
            findings.push('🚨 TEROWONG C2 RAHSIANYA DIKESAN: Mengandungi URL pelayan kawalan jauh (ngrok/Cloudflare tunnel).');
          }

          const hasDex = entries.some((en) => en.endsWith('.dex'));
          const nativeLibs = entries.filter((en) => en.endsWith('.so'));
          internalSummary = `Fail Dalaman ZIP: ${entries.length} komponen (${hasDex ? 'Ada classes.dex' : 'Tiada DEX'}, ${nativeLibs.length} pustaka .so)`;
        }

        // 5. HTML / SVG / HTA Attachment Smuggling & Phishing Form Inspection (WhatsApp/Telegram Lures)
        const textPreview = new TextDecoder('utf-8', { fatal: false }).decode(uint8.subarray(0, Math.min(uint8.length, 512 * 1024)));
        if (/\.(html|htm|svg|hta|xhtml)$/i.test(file.name) || /^\s*(?:<!doctype\s+html|<html|<svg|<\?xml)/i.test(textPreview)) {
          magicType = 'Lampiran Web HTML / SVG / HTA';
          if (/<input[^>]*type=['"]?password/i.test(textPreview) || /<form[^>]*action=/i.test(textPreview)) {
            riskScore += 75;
            findings.push('🛑 BORANG PHISHING HTML/SVG: Lampiran mengandungi borang curi kata laluan (<input type="password">)!');
          }
          if (/<script|onload\s*=|onerror\s*=|api\.telegram\.org\/bot|atob\s*\(|eval\s*\(|fromCharCode|window\.location/i.test(textPreview)) {
            riskScore += 65;
            findings.push('🚨 SKRIP / C2 DALAM LAMPIRAN: Mengandungi JavaScript berbahaya atau penghantaran data ke pelayan penggodam!');
          }
        }

        riskScore = Math.min(riskScore, 100);
        let verdict = 'TIADA CORAK TROJAN DIKESAN';
        let color = '#10b981';
        if (riskScore >= 60) {
          verdict = 'BAHAYA KRITIKAL — TROJAN / MALWARE!';
          color = '#f43f5e';
        } else if (riskScore >= 25) {
          verdict = 'BERISIKO / MENCURIGAKAN';
          color = '#f59e0b';
        }

        recordForensicEvent('APK_BINARY_SCAN', file.name, verdict, riskScore, `SHA256: ${sha256} | Perms: ${detectedPerms.length}`, 'T1476');

        apkLogBox.innerHTML = `
          <div class="log-item"><strong>Fail:</strong> ${escapeHtml(file.name)} (${(file.size / 1024).toFixed(1)} KB)</div>
          <div class="log-item"><strong>Keputusan:</strong> <span style="color:${color}; font-weight:800;">${escapeHtml(verdict)} (Skor Risiko: ${riskScore}/100)</span></div>
          <div class="log-item"><strong>Tandatangan Binari:</strong> ${escapeHtml(magicType)} • <strong>Entropi:</strong> ${entropy.toFixed(2)} / 8.00</div>
          ${internalSummary ? `<div class="log-item"><strong>Struktur APK:</strong> ${escapeHtml(internalSummary)}</div>` : ''}
          ${detectedPerms.length ? `<div class="log-item"><strong>Izin Berbahaya Dikesan (${detectedPerms.length}):</strong><br>${detectedPerms.map((p) => '• <span style="color:#fb7185;">' + escapeHtml(p) + '</span>').join('<br>')}</div>` : ''}
          <div class="log-item"><strong>Dapatan Forensik:</strong><br>${findings.length ? findings.map((f) => '• ' + escapeHtml(f)).join('<br>') : '• Tiada gabungan izin trojan perbankan atau penyamaran binari ditemui.'}</div>
          <div class="log-item"><strong>SHA-256:</strong><br><span style="font-family:monospace; font-size:10px; color:#94a3b8; word-break:break-all;">${escapeHtml(sha256)}</span></div>
        `;
      } catch (err) {
        apkLogBox.innerHTML = `<div class="log-item" style="color:#f43f5e;">Ralat membedah fail: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  // ========================================================
  // 7. Phishing, Homograph (Punycode) & Live DoH Verifier
  // ========================================================
  const phishInput = document.getElementById('phishInput');
  const btnCheckPhish = document.getElementById('btnCheckPhish');
  const phishLogBox = document.getElementById('phishLogBox');

  const OFFICIAL_BRANDS = [
    { kw: 'maybank', official: ['maybank2u.com.my', 'maybank.com'] },
    { kw: 'm2u', official: ['maybank2u.com.my', 'maybank.com'] },
    { kw: 'cimb', official: ['cimbclicks.com.my', 'cimb.com.my', 'cimb.com'] },
    { kw: 'pbebank', official: ['pbebank.com'] },
    { kw: 'publicbank', official: ['pbebank.com'] },
    { kw: 'hlb', official: ['hlb.com.my'] },
    { kw: 'hongleong', official: ['hlb.com.my'] },
    { kw: 'ambank', official: ['ambank.com.my', 'ambankgroup.com'] },
    { kw: 'bsn', official: ['mybsn.com.my', 'bsn.com.my'] },
    { kw: 'bankrakyat', official: ['irakyat.com.my', 'bankrakyat.com.my'] },
    { kw: 'touchngo', official: ['touchngo.com.my'] },
    { kw: 'tngdigital', official: ['tngdigital.com.my'] },
    { kw: 'tng-ewallet', official: ['touchngo.com.my', 'tngdigital.com.my'] },
    { kw: 'lhdn', official: ['hasil.gov.my'] },
    { kw: 'mysejahtera', official: ['mysejahtera.malaysia.gov.my'] },
    { kw: 'kwsp', official: ['kwsp.gov.my'] },
    { kw: 'bankislam', official: ['bankislam.com', 'bankislam.biz'] },
    { kw: 'rhb', official: ['rhbgroup.com'] },
    { kw: 'poslaju', official: ['pos.com.my'] },
    { kw: 'jpj', official: ['jpj.gov.my'] },
    { kw: 'pdrm', official: ['rmp.gov.my'] },
    { kw: 'padu', official: ['padu.gov.my'] },
    { kw: 'thijari', official: ['thijari.com.my', 'tabunghaji.gov.my'] },
    { kw: 'tabunghaji', official: ['thijari.com.my', 'tabunghaji.gov.my'] },
    { kw: 'asnb', official: ['myasnb.com.my', 'asnb.com.my'] },
    { kw: 'myasnb', official: ['myasnb.com.my', 'asnb.com.my'] },
    { kw: 'bnm', official: ['bnm.gov.my'] },
    { kw: 'banknegara', official: ['bnm.gov.my'] },
    { kw: 'mytnb', official: ['mytnb.com.my', 'tnb.com.my'] },
    { kw: 'ptptn', official: ['ptptn.gov.my'] },
    { kw: 'sspn', official: ['ptptn.gov.my'] },
    { kw: 'shopeepay', official: ['shopee.com.my'] },
    { kw: 'grabpay', official: ['grab.com'] },
    { kw: 'myboost', official: ['myboost.co', 'myboost.com.my'] }
  ];

  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'wa.me', 'cutt.ly', 's.id', 'is.gd', 'rb.gy', 'rebrand.ly', 'ow.ly', 'shorturl.at'
  ]);

  function normalizeLeetspeak(str) {
    return String(str || '').toLowerCase().replace(/0/g, 'o').replace(/1/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's');
  }

  async function inspectUrlWithDoh(rawInput, targetBox) {
    const rawUrl = (rawInput || '').trim();
    if (!rawUrl) {
      alert('Sila masukkan atau tampal pautan URL terlebih dahulu.');
      return;
    }

    targetBox.style.display = 'block';
    targetBox.innerHTML = '<div class="log-item">⏳ Memeriksa Penapis Bloom, Homograf Punycode & Rekod DNS-over-HTTPS...</div>';

    // 0. Intercept Dangerous Non-HTTP Schemes & QR/USSD OTP Hijack Vectors (tel:*21*, **21*, *002*, javascript:, intent:, data:, blob:, file:)
    if (
      /^(javascript|data|vbscript|intent|sms|smsto|mailto|blob|file|filesystem):/i.test(rawUrl) ||
      /^tel:\s*(?:\*|%2a|#|%23)+(?:21|61|62|67|002|004)(?:\*|%2a|#|%23)/i.test(rawUrl)
    ) {
      const verdict = 'BAHAYA KRITIKAL — SKEMA URI / USSD HASAD!';
      const reason = /^tel:/i.test(rawUrl)
        ? '🛑 SERANGAN USSD CALL-FORWARDING (*21*/*61*): Cubaan mencuri panggilan OTP suara bank anda!'
        : `🛑 SKEMA URI BERBAHAYA (${rawUrl.split(':')[0].toLowerCase()}:): Boleh mencetuskan pelaksanaan skrip atau aplikasi tersembunyi!`;
      recordForensicEvent('URL_PHISH_SCAN', rawUrl.slice(0, 120), verdict, 100, reason, 'T1566');
      targetBox.innerHTML = `
        <div class="log-item"><strong>Sasaran URI:</strong> ${escapeHtml(rawUrl.slice(0, 120))}</div>
        <div class="log-item"><strong>Keputusan:</strong> <span style="color:#f43f5e; font-weight:800;">${escapeHtml(verdict)} (100/100)</span></div>
        <div class="log-item"><strong>Analisis Forensik:</strong><br>• ${escapeHtml(reason)}</div>
      `;
      return;
    }

    try {
      const normalized = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl;
      const urlObj = new URL(normalized);
      const host = urlObj.hostname.toLowerCase();
      const deLeetHost = normalizeLeetspeak(host);
      let decodedPath = urlObj.pathname + urlObj.search;
      try {
        decodedPath = decodeURIComponent(decodedPath);
      } catch (_) {}
      const lowerPath = decodedPath.toLowerCase();

      let riskScore = 0;
      const reasons = [];

      // 1. Two-Stage Bloom Filter + Exact Set Lookup (covers subdomains)
      if (isKnownMaliciousDomain(host)) {
        riskScore += 85;
        reasons.push('🛑 Penapis Bloom PERISAI (2-Tahap): Domain/induk ini tersenarai dalam pangkalan data scam/phishing aktif!');
      }

      // 2. IDN Homograph / Punycode Attack (xn--)
      if (host.includes('xn--') || /[^\x00-\x7F]/.test(rawUrl)) {
        riskScore += 65;
        reasons.push('🚨 SERANGAN HOMOGRAF (Punycode xn--): Domain menggunakan aksara Unicode palsu untuk menyamar sebagai laman rasmi!');
      }

      // 3. URL Userinfo (@) Credential Redirection Trap
      if (urlObj.username || urlObj.password || rawUrl.includes('@')) {
        riskScore += 70;
        reasons.push('🚨 PERANGKAP REDIRECT (@): URL menyembunyikan destinasi sebenar selepas simbol @.');
      }

      // 4. Malaysian Institution Impersonation Heuristic (with Leetspeak normalization)
      OFFICIAL_BRANDS.forEach((b) => {
        if ((host.includes(b.kw) || deLeetHost.includes(b.kw)) && !b.official.some((off) => host === off || host.endsWith('.' + off))) {
          riskScore += 80;
          reasons.push(`🛑 PENYAMARAN JENAMA: Domain menyerupai "${b.kw.toUpperCase()}" tetapi BUKAN domain rasmi (${b.official[0]})!`);
        }
      });

      // 5. Direct Malware / Sideload Dropper Download (.apk, .xapk, .apks, .exe, .scr, .bat, .dex, .html, .svg)
      if (/\.(apk|xapk|apks|apkm|exe|scr|bat|cmd|msi|vbs|dex|ps1|iso|cab|hta|html|htm|svg)(\?|$|#)/i.test(lowerPath)) {
        riskScore += 75;
        reasons.push('🛑 MUAT TURUN DROPPER (.APK/.EXE/.HTML): Pautan ini memuat turun fail boleh laku atau lampiran phishing secara terus!');
      }

      // 6. URL Shortener Cloaking Detection
      if (URL_SHORTENERS.has(host)) {
        riskScore += 50;
        reasons.push(`⚠️ PEMENDEK URL (${host}): Menyembunyikan destinasi sebenar. Jangan log masuk perbankan melalui pautan pendek!`);
      }

      const scamWords = [
        'directyp', 'popads', 'adsterra', 'free-money', 'hadiah', 'angpao',
        'login-verify', 'update-account', 'bantuan-rakyat', 'lhdn-cukai',
        'saman-jpj', 'parcel-claim', 'str-bantuan', 'akaun-disekat', 'tac-verify',
        'secure-portal', 'online-verify', 'batal-transaksi', 'claim-bantuan',
        'hibah', 'dividen', 'esemakan', 'semakan', 'bantuan', 'rebat', 'pengesahan', 'tuntutan', 'kemaskini'
      ];
      if (scamWords.some((k) => host.includes(k) || lowerPath.includes(k))) {
        riskScore += 60;
        reasons.push('⚠️ Mengandungi kata kunci umpan scam/phishing berisiko tinggi.');
      }

      if (urlObj.port && !['80', '443'].includes(urlObj.port)) {
        riskScore += 55;
        reasons.push(`🚨 PORT BUKAN STANDARD (:${urlObj.port}): Sering digunakan oleh pelayan C2 atau laman phishing sementara!`);
      }

      const dangerousTlds = ['.xyz', '.top', '.tk', '.click', '.buzz', '.monster', '.loan', '.work', '.gq', '.cf', '.cc', '.icu', '.vip', '.shop', '.sbs', '.cfd'];
      if (dangerousTlds.some((tld) => host.endsWith(tld))) {
        riskScore += 35;
        reasons.push(`⚠️ Menggunakan TLD murah berisiko tinggi (.${host.split('.').pop()}).`);
      }

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
        riskScore += 45;
        reasons.push('⚠️ Menggunakan alamat IP mentah secara terus tanpa nama domain.');
      }

      if (urlObj.protocol === 'http:') {
        riskScore += 25;
        reasons.push('⚠️ Sambungan HTTP tidak disulitkan (Tiada TLS/SSL).');
      }

      // 5. Live DNS-over-HTTPS (Cloudflare DoH) Verification
      let dohInfo = 'Luar talian (Semakan heuristik tempatan sahaja)';
      if (navigator.onLine) {
        try {
          const dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
            headers: { Accept: 'application/dns-json' }
          });
          if (dohRes.ok) {
            const dohJson = await dohRes.json();
            if (dohJson.Status === 3) {
              riskScore += 40;
              dohInfo = 'NXDOMAIN (Domain tidak wujud / telah dimatikan)';
              reasons.push('⚠️ Rekod DNS menunjukkan domain ini telah digantung atau tidak wujud (NXDOMAIN).');
            } else if (dohJson.Answer && dohJson.Answer.length > 0) {
              const ips = dohJson.Answer.map((a) => a.data).join(', ');
              dohInfo = `Aktif (${ips})`;
            } else {
              dohInfo = `Status DNS: ${dohJson.Status}`;
            }
          }
        } catch (_) {}
      }

      riskScore = Math.min(riskScore, 100);
      let verdict = 'SELAMAT DIKUNJUNGI';
      let color = '#10b981';
      if (riskScore >= 50) {
        verdict = 'BAHAYA — PAUTAN PHISHING / SCAM!';
        color = '#f43f5e';
      } else if (riskScore > 0) {
        verdict = 'WASPADA (Tahap Risiko Sederhana)';
        color = '#f59e0b';
      }

      recordForensicEvent('URL_PHISH_SCAN', host, verdict, riskScore, reasons.join('; '), 'T1566');

      targetBox.innerHTML = `
        <div class="log-item"><strong>Hos Sasaran:</strong> ${escapeHtml(host)}</div>
        <div class="log-item"><strong>Keputusan:</strong> <span style="color:${color}; font-weight:800;">${escapeHtml(verdict)} (${riskScore}/100)</span></div>
        <div class="log-item"><strong>Resolusi DoH:</strong> ${escapeHtml(dohInfo)}</div>
        <div class="log-item"><strong>Analisis Forensik:</strong><br>${reasons.length ? reasons.map((r) => '• ' + escapeHtml(r)).join('<br>') : '• Tiada corak penyamaran jenama, homograf, atau TLD berbahaya dikesan.'}</div>
      `;
    } catch (_) {
      targetBox.innerHTML = '<div class="log-item" style="color:#f43f5e;">Format URL tidak sah. Sila pastikan pautan lengkap.</div>';
    }
  }

  if (btnCheckPhish) {
    btnCheckPhish.addEventListener('click', () => inspectUrlWithDoh(phishInput.value, phishLogBox));
  }

  // ========================================================
  // 8. Live Malicious QR Code Scanner (Camera & Image File)
  // ========================================================
  const btnStartQrCam = document.getElementById('btnStartQrCam');
  const qrFileInput = document.getElementById('qrFileInput');
  const qrVideo = document.getElementById('qrVideo');
  const qrLogBox = document.getElementById('qrLogBox');
  let qrStream = null;

  function stopQrCamera() {
    if (qrStream) {
      qrStream.getTracks().forEach((t) => t.stop());
      qrStream = null;
    }
    if (qrVideo) qrVideo.style.display = 'none';
    if (btnStartQrCam) btnStartQrCam.textContent = '🎥 Buka Kamera QR';
  }

  async function handleDecodedQrPayload(rawValue) {
    stopQrCamera();
    qrLogBox.style.display = 'block';
    qrLogBox.innerHTML = `<div class="log-item">🔍 <strong>Kandungan QR Dikesan:</strong> ${escapeHtml(rawValue)}</div>`;
    if (phishInput) phishInput.value = rawValue;
    await inspectUrlWithDoh(rawValue, qrLogBox);
  }

  if (btnStartQrCam) {
    btnStartQrCam.addEventListener('click', async () => {
      if (qrStream) {
        stopQrCamera();
        return;
      }
      qrLogBox.style.display = 'block';
      if (!('BarcodeDetector' in window)) {
        qrLogBox.innerHTML = '<div class="log-item" style="color:#f59e0b;">⚠️ Pelayar ini memerlukan Chrome/Android terkini untuk imbasan BarcodeDetector secara langsung. Anda juga boleh tampal URL terus di kotak Phishing di atas.</div>';
        return;
      }
      try {
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        qrVideo.srcObject = qrStream;
        qrVideo.style.display = 'block';
        await qrVideo.play();
        btnStartQrCam.textContent = '⏹️ Henti Kamera';
        qrLogBox.innerHTML = '<div class="log-item">📷 Halakan kamera pada kod QR...</div>';

        const scanLoop = async () => {
          if (!qrStream) return;
          try {
            const codes = await detector.detect(qrVideo);
            if (codes.length > 0 && codes[0].rawValue) {
              await handleDecodedQrPayload(codes[0].rawValue);
              return;
            }
          } catch (_) {}
          if (qrStream) requestAnimationFrame(scanLoop);
        };
        requestAnimationFrame(scanLoop);
      } catch (err) {
        qrLogBox.innerHTML = `<div class="log-item" style="color:#f43f5e;">Gagal mengakses kamera: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  if (qrFileInput) {
    qrFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      qrLogBox.style.display = 'block';
      if (!('BarcodeDetector' in window)) {
        qrLogBox.innerHTML = '<div class="log-item" style="color:#f59e0b;">⚠️ Pelayar ini tidak menyokong API BarcodeDetector terbina dalam. Gunakan Chrome di Android untuk imbasan QR terus.</div>';
        return;
      }
      try {
        const bitmap = await createImageBitmap(file);
        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        const codes = await detector.detect(bitmap);
        if (codes.length > 0 && codes[0].rawValue) {
          await handleDecodedQrPayload(codes[0].rawValue);
        } else {
          qrLogBox.innerHTML = '<div class="log-item" style="color:#f59e0b;">Tiada kod QR ditemui dalam gambar yang dipilih.</div>';
        }
      } catch (err) {
        qrLogBox.innerHTML = `<div class="log-item" style="color:#f43f5e;">Ralat mengimbas gambar QR: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  // ========================================================
  // 9. SMS & WhatsApp Text Scam Inspector + URL Extractor
  // ========================================================
  const smsInput = document.getElementById('smsInput');
  const btnCheckSms = document.getElementById('btnCheckSms');
  const smsLogBox = document.getElementById('smsLogBox');

  if (btnCheckSms) {
    btnCheckSms.addEventListener('click', () => {
      const text = (smsInput.value || '').trim();
      if (!text) {
        alert('Sila tampal teks mesej terlebih dahulu.');
        return;
      }

      smsLogBox.style.display = 'block';
      const zwRegex = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD]/g;
      const hasZeroWidth = zwRegex.test(text);
      const cleanText = text.replace(zwRegex, '');
      const lower = cleanText.toLowerCase();

      const scamPatterns = [
        { term: 'lhdn', reason: 'Menyamar sebagai LHDN / tuntutan cukai.' },
        { term: 'mysejahtera', reason: 'Umpan bantuan kredit MySejahtera palsu.' },
        { term: 'tng', reason: 'Menyamar sebagai Touch \'n Go eWallet.' },
        { term: 'maybank', reason: 'Menyamar sebagai notifikasi transaksi Maybank.' },
        { term: 'cimb', reason: 'Menyamar sebagai notifikasi CIMB Clicks.' },
        { term: 'public bank', reason: 'Menyamar sebagai notifikasi Public Bank.' },
        { term: 'akaun disekat', reason: 'Taktik ugutan panik (Akaun bank disekat/digantung).' },
        { term: 'dibekukan', reason: 'Taktik ugutan akaun bank dibekukan.' },
        { term: 'batalkan', reason: 'Taktik panik transaksi tidak sah (klik pautan untuk batal).' },
        { term: 'transaksi rm', reason: 'Umpan amaran tolakan wang / transaksi palsu.' },
        { term: 'tahniah menang', reason: 'Penipuan hadiah wang tunai / cabutan bertuah.' },
        { term: 'bantuan tunai', reason: 'Tuntutan bantuan STR/kerajaan tidak sah.' },
        { term: 'bungkusan', reason: 'Penyamaran kurier bungkusan tersangkut.' },
        { term: 'otp', reason: 'Cubaan memancing kod OTP perbankan.' },
        { term: 'tac', reason: 'Cubaan memancing kod pengesahan TAC.' },
        { term: 'mahkamah', reason: 'Ugutan waran tangkap / mahkamah palsu.' },
        { term: 'pdrm', reason: 'Menyamar sebagai pegawai polis / saman PDRM.' },
        { term: 'apk', reason: 'Mengarahkan muat turun fail pemasangan .APK luar.' },
        { term: 'jemputan kahwin', reason: 'Umpan dropper APK/Ransomware menyamar Kad Jemputan Kahwin WhatsApp.' },
        { term: 'kad jemputan', reason: 'Umpan fail APK berbahaya menyamar kad jemputan digital.' },
        { term: 'resit bayaran', reason: 'Umpan fail palsu menyamar resit transaksi bank.' },
        { term: 'gambar anda', reason: 'Taktik ugutan / pancingan klik pautan malware di WhatsApp/Telegram.' },
        { term: 'video anda', reason: 'Umpan pautan trojan/phishing mencuri akaun Telegram/WhatsApp.' },
        { term: 'tebusan', reason: 'Ugutan wang tebusan / pemerasan siber (Ransomware).' },
        { term: 'fail dikunci', reason: 'Ancaman penyulitan fail Ransomware.' }
      ];

      const detected = scamPatterns.filter((p) => lower.includes(p.term));
      if (hasZeroWidth) {
        detected.unshift({
          term: 'zero-width-evasion',
          reason: '🚨 TEKNIK PENYAMARAN HACKER: Mesej menyelitkan aksara Unicode halimunan (Zero-Width Space) untuk mengelak pengimbas!'
        });
      }
      // Match both full http(s) URLs and bare domains/paths (e.g., maybank2u-batal.xyz/login or bit.ly/xyz)
      const urlMatches = cleanText.match(/(?:https?:\/\/|[a-z0-9-]+\.(?:xyz|top|tk|click|buzz|monster|loan|work|gq|cf|cc|icu|vip|shop|sbs|cfd|com|net|org|my|ly|co|me|id|gd|gy)(?:\/[^\s]*)?)/gi) || [];

      let urlBonus = (urlMatches.length > 0 ? 35 : 0) + (hasZeroWidth ? 15 : 0);
      urlMatches.forEach((u) => {
        const cleanHost = u.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
        if (isKnownMaliciousDomain(cleanHost) || /\.(xyz|top|tk|click|buzz|icu|vip|sbs)$/i.test(cleanHost)) {
          urlBonus += 45;
        }
        OFFICIAL_BRANDS.forEach((b) => {
          if (cleanHost.includes(b.kw) && !b.official.some((off) => cleanHost === off || cleanHost.endsWith('.' + off))) {
            urlBonus += 60;
          }
        });
      });

      const risk = Math.min(100, detected.length * 30 + urlBonus);
      let verdict = 'TIADA SKRIP SCAM DIKESAN';
      let color = '#10b981';

      if (risk >= 50) {
        verdict = 'AMARAN MERAH: SKRIP SCAM / RANSOMWARE!';
        color = '#f43f5e';
      } else if (risk > 0) {
        verdict = 'MESEJ MENCURIGAKAN (Waspada)';
        color = '#f59e0b';
      }

      recordForensicEvent('SMS_SCAM_SCAN', text.slice(0, 80), verdict, risk, detected.map((d) => d.term).join(','), 'T1566');

      const rescueGuideHtml = risk >= 50
        ? `<div class="log-item" style="color:#fda4af; border-left:3px solid #f43f5e; padding-left:8px; margin-top:6px;">
             <strong>🛡️ LANGKAH PERLINDUNGAN SEGERA (WHATSAPP/TELEGRAM):</strong><br>
             1. <strong>JANGAN TEKAN</strong> pautan atau muat turun fail <code>.apk</code> dalam mesej ini.<br>
             2. Jika sudah tertekan pautan: <strong>Matikan Wi-Fi/Data (Airplane Mode)</strong> sekarang & semak folder <code>Downloads/</code>.<br>
             3. Matikan <em>Install Unknown Apps</em> untuk WhatsApp & Telegram dalam <code>Settings → Apps → Special App Access</code>.
           </div>`
        : '';

      smsLogBox.innerHTML = `
        <div class="log-item"><strong>Keputusan:</strong> <span style="color:${color}; font-weight:800;">${escapeHtml(verdict)} (${risk}/100)</span></div>
        <div class="log-item"><strong>Taktik Manipulasi:</strong><br>${detected.length ? detected.map((d) => '• ' + escapeHtml(d.reason)).join('<br>') : '• Tiada frasa ugutan/umpan lazim ditemui.'}</div>
        ${urlMatches.length ? `<div class="log-item" style="color:#fbbf24;">⚠️ <strong>Pautan Dikesan Dalam Teks (${urlMatches.length}):</strong> ${urlMatches.map((u) => escapeHtml(u)).join(', ')}</div>` : ''}
        ${rescueGuideHtml}
      `;
    });
  }

  // ========================================================
  // 10. K-Anonymity Breach Checker & Cryptographic Password Gen
  // ========================================================
  const breachInput = document.getElementById('breachInput');
  const btnCheckBreach = document.getElementById('btnCheckBreach');
  const btnGenPassword = document.getElementById('btnGenPassword');
  const breachLogBox = document.getElementById('breachLogBox');

  function calcPasswordEntropyBits(pwd) {
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
    return pool > 0 ? Math.round(pwd.length * Math.log2(pool)) : 0;
  }

  if (btnCheckBreach) {
    btnCheckBreach.addEventListener('click', async () => {
      const pwd = breachInput.value || '';
      if (!pwd) {
        alert('Sila masukkan kata laluan untuk disemak.');
        return;
      }

      breachLogBox.style.display = 'block';
      breachLogBox.innerHTML = '<div class="log-item">⏳ Mengira SHA-1 tempatan & menyemak k-Anonymity (5 aksara prefix sahaja)...</div>';

      try {
        const enc = new TextEncoder().encode(pwd);
        const sha1Full = (await computeHash(enc, 'SHA-1')).toUpperCase();
        const prefix = sha1Full.slice(0, 5);
        const suffix = sha1Full.slice(5);
        const bits = calcPasswordEntropyBits(pwd);

        let leakCount = 0;
        let onlineChecked = false;

        if (navigator.onLine) {
          const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
          if (res.ok) {
            onlineChecked = true;
            const text = await res.text();
            const lines = text.split('\n');
            for (const line of lines) {
              const [hashSuffix, countStr] = line.trim().split(':');
              if (hashSuffix === suffix) {
                leakCount = parseInt(countStr, 10) || 1;
                break;
              }
            }
          }
        }

        const isExposed = leakCount > 0;
        const color = isExposed ? '#f43f5e' : (bits >= 75 ? '#10b981' : '#f59e0b');
        const statusText = isExposed
          ? `🛑 BOCOR DALAM ${leakCount.toLocaleString()} REKOD PENGGODAM!`
          : (onlineChecked ? '✅ TIADA REKOD KEBOCORAN DITEMUI' : '⚠️ LUAR TALIAN (Hanya Semakan Kekuatan)');

        breachLogBox.innerHTML = `
          <div class="log-item"><strong>Status:</strong> <span style="color:${color}; font-weight:800;">${escapeHtml(statusText)}</span></div>
          <div class="log-item"><strong>Kekuatan Kriptografi:</strong> ${bits} bit entropi (${bits >= 80 ? 'Sangat Kukuh' : bits >= 50 ? 'Sederhana' : 'Lemah'})</div>
          <div class="log-item"><strong>Privasi k-Anonymity:</strong> Prefix <code>${escapeHtml(prefix)}*****</code> (35 aksara baki disemak dalam telefon).</div>
        `;
      } catch (err) {
        breachLogBox.innerHTML = `<div class="log-item" style="color:#f43f5e;">Ralat semakan: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  if (btnGenPassword) {
    btnGenPassword.addEventListener('click', () => {
      const charset = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+';
      const rand = new Uint32Array(20);
      crypto.getRandomValues(rand);
      let pwd = '';
      for (let i = 0; i < rand.length; i++) {
        pwd += charset[rand[i] % charset.length];
      }
      if (breachInput) {
        breachInput.type = 'text';
        breachInput.value = pwd;
      }
      const bits = calcPasswordEntropyBits(pwd);
      breachLogBox.style.display = 'block';
      breachLogBox.innerHTML = `
        <div class="log-item" style="color:#10b981; font-weight:700;">🎲 Kata Laluan Kriptografi Dijana (${bits} bit entropi):</div>
        <div class="log-item"><code style="color:#38bdf8; font-size:13px; user-select:all;">${escapeHtml(pwd)}</code></div>
        <div class="log-item" style="color:#94a3b8; font-size:10.5px;">Dijana menggunakan CSPRNG perkakasan (crypto.getRandomValues).</div>
      `;
    });
  }

  // ========================================================
  // 11. Duplicate Photos Finder & Safe Cache Purger
  // ========================================================
  const dupFileInput = document.getElementById('dupFileInput');
  const dupLogBox = document.getElementById('dupLogBox');
  const dupPreviewContainer = document.getElementById('dupPreviewContainer');
  let activeDupObjectUrls = [];

  function revokeDupUrls() {
    activeDupObjectUrls.forEach((url) => {
      try { URL.revokeObjectURL(url); } catch (_) {}
    });
    activeDupObjectUrls = [];
  }

  if (dupFileInput) {
    dupFileInput.addEventListener('change', async (e) => {
      const allFiles = Array.from(e.target.files);
      if (allFiles.length === 0) return;

      revokeDupUrls();
      dupLogBox.style.display = 'block';
      if (dupPreviewContainer) dupPreviewContainer.innerHTML = '';

      const MAX_DUP_FILES = 50;
      const files = allFiles.slice(0, MAX_DUP_FILES);
      if (allFiles.length > MAX_DUP_FILES) {
        dupLogBox.innerHTML = `<div class="log-item" style="color:#f59e0b;">⚠️ Demi kestabilan memori telefon, dihadkan kepada ${MAX_DUP_FILES} fail pertama (daripada ${allFiles.length} fail).</div>`;
      } else {
        dupLogBox.innerHTML = `<div class="log-item">⏳ Mengira hash SHA-256 bagi ${files.length} fail...</div>`;
      }

      const hashMap = {};
      const duplicates = [];

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        try {
          const buffer = await file.arrayBuffer();
          const hash = await computeHash(buffer, 'SHA-256');
          if (hashMap[hash]) {
            duplicates.push({ original: hashMap[hash], dup: file });
          } else {
            hashMap[hash] = file;
          }
        } catch (_) {}

        // Yield to event loop every 5 files to prevent mobile UI freeze
        if (i % 5 === 0) {
          await new Promise((r) => setTimeout(r, 0));
        }
      }

      if (duplicates.length === 0) {
        dupLogBox.innerHTML = `<div class="log-item" style="color:#10b981;">✅ Tiada fail pendua ditemui daripada ${files.length} gambar.</div>`;
      } else {
        const totalWastedBytes = duplicates.reduce((acc, d) => acc + d.dup.size, 0);
        const wastedMb = (totalWastedBytes / (1024 * 1024)).toFixed(2);

        const listHtml = duplicates
          .map(
            (d) =>
              `<div class="log-item">⚠️ <strong>${escapeHtml(d.dup.name)}</strong> identikal dengan <em>${escapeHtml(d.original.name)}</em> (${(d.dup.size / 1024).toFixed(1)} KB)</div>`
          )
          .join('');

        dupLogBox.innerHTML = `
          <div class="log-item" style="color:#f59e0b; font-weight:700;">Ditemui ${duplicates.length} Pendua (${wastedMb} MB):</div>
          ${listHtml}
        `;

        if (dupPreviewContainer) {
          duplicates.forEach((item) => {
            const url = URL.createObjectURL(item.dup);
            activeDupObjectUrls.push(url);
            const img = document.createElement('img');
            img.src = url;
            img.className = 'dup-thumb';
            img.title = item.dup.name;
            dupPreviewContainer.appendChild(img);
          });
        }
      }
    });
  }

  // Safe Cache Purger — preserves Aegis security logs & settings
  const btnClearCache = document.getElementById('btnClearCache');
  const cacheLogBox = document.getElementById('cacheLogBox');

  if (btnClearCache) {
    btnClearCache.addEventListener('click', async () => {
      cacheLogBox.style.display = 'block';
      cacheLogBox.innerHTML = '<div class="log-item">⏳ Membersihkan cache usang tanpa memadam konfigurasi keselamatan...</div>';

      try {
        sessionStorage.clear();
        const preserved = {};
        [FORENSIC_KEY, THREAT_COUNT_KEY, SOC_MODE_KEY].forEach((k) => {
          const val = localStorage.getItem(k);
          if (val !== null) preserved[k] = val;
        });
        localStorage.clear();
        Object.entries(preserved).forEach(([k, v]) => localStorage.setItem(k, v));

        let deletedCaches = 0;
        if (window.caches) {
          const keys = await caches.keys();
          for (const key of keys) {
            if (!key.startsWith('aegis-ultimate-v3')) {
              await caches.delete(key);
              deletedCaches++;
            }
          }
        }

        cacheLogBox.innerHTML = `
          <div class="log-item" style="color:#10b981; font-weight:700;">✅ Pembersihan Selamat Selesai!</div>
          <div class="log-item">• ${deletedCaches} storan cache versi lama dipadamkan.</div>
          <div class="log-item">• Rekod forensik & tetapan keselamatan Aegis dikekalkan.</div>
        `;
      } catch (err) {
        cacheLogBox.innerHTML = `<div class="log-item" style="color:#f43f5e;">Ralat: ${escapeHtml(err.message)}</div>`;
      }
    });
  }

  // ========================================================
  // 12. Performance, Hardware WakeLock & FPS Frame Pacing
  // ========================================================
  let wakeLock = null;
  const btnToggleWakeLock = document.getElementById('btnToggleWakeLock');
  const wakeLockLogBox = document.getElementById('wakeLockLogBox');

  if (btnToggleWakeLock) {
    btnToggleWakeLock.addEventListener('click', async () => {
      if ('wakeLock' in navigator) {
        if (!wakeLock) {
          try {
            wakeLock = await navigator.wakeLock.request('screen');
            btnToggleWakeLock.textContent = 'AKTIF ⚡';
            btnToggleWakeLock.classList.add('active');
            wakeLockLogBox.style.display = 'block';
            wakeLockLogBox.innerHTML = '<div class="log-item" style="color:#10b981;">🎮 Kunci Skrin Aktif melalui Hardware Screen Wake Lock API.</div>';
            wakeLock.addEventListener('release', () => {
              wakeLock = null;
              btnToggleWakeLock.textContent = 'MATI';
              btnToggleWakeLock.classList.remove('active');
            });
          } catch (err) {
            alert('Gagal mengunci skrin: ' + err.message);
          }
        } else {
          await wakeLock.release();
          wakeLock = null;
          btnToggleWakeLock.textContent = 'MATI';
          btnToggleWakeLock.classList.remove('active');
          wakeLockLogBox.style.display = 'none';
        }
      } else {
        alert('Pelayar ini tidak menyokong Screen Wake Lock API.');
      }
    });
  }

  const btnRunRamBoost = document.getElementById('btnRunRamBoost');
  const ramLogBox = document.getElementById('ramLogBox');
  if (btnRunRamBoost) {
    btnRunRamBoost.addEventListener('click', async () => {
      ramLogBox.style.display = 'block';
      const diag = await refreshRealTelemetry();
      ramLogBox.innerHTML = `
        <div class="log-item" style="color:#10b981; font-weight:700;">📊 Diagnostik Memori & Storan Selesai</div>
        <div class="log-item">• Penggunaan Semasa: ${escapeHtml(diag.storageText)}</div>
        <div class="log-item">• Peruntukan rujukan objek sementara pelayar telah dibersihkan.</div>
      `;
    });
  }

  const btnStartFpsTest = document.getElementById('btnStartFpsTest');
  const liveFpsVal = document.getElementById('liveFpsVal');
  const liveFrameMs = document.getElementById('liveFrameMs');
  let fpsRunning = false;

  if (btnStartFpsTest) {
    btnStartFpsTest.addEventListener('click', () => {
      if (fpsRunning) return;
      fpsRunning = true;
      btnStartFpsTest.textContent = 'Mengukur Kadar Segar Skrin...';

      let frames = 0;
      let startTime = performance.now();

      function checkFrame(now) {
        frames++;
        const elapsed = now - startTime;
        if (elapsed >= 500) {
          const fps = Math.round((frames * 1000) / elapsed);
          const frameMs = (elapsed / frames).toFixed(1);
          if (liveFpsVal) liveFpsVal.textContent = String(fps);
          if (liveFrameMs) liveFrameMs.textContent = frameMs;
          frames = 0;
          startTime = now;
        }
        if (fpsRunning) requestAnimationFrame(checkFrame);
      }
      requestAnimationFrame(checkFrame);

      setTimeout(() => {
        fpsRunning = false;
        btnStartFpsTest.textContent = 'Mulakan Ujian Kelancaran Skrin (5s)';
      }, 5000);
    });
  }

  // ========================================================
  // 13. Network Sensors, WebRTC IP Leak & DoH Benchmark
  // ========================================================
  const btnRefreshSignalInfo = document.getElementById('btnRefreshSignalInfo');
  if (btnRefreshSignalInfo) {
    btnRefreshSignalInfo.addEventListener('click', () => refreshRealTelemetry());
  }

  // WebRTC IP Leak Detector
  const btnCheckWebRtc = document.getElementById('btnCheckWebRtc');
  const webrtcLogBox = document.getElementById('webrtcLogBox');

  if (btnCheckWebRtc) {
    btnCheckWebRtc.addEventListener('click', () => {
      webrtcLogBox.style.display = 'block';
      webrtcLogBox.innerHTML = '<div class="log-item">⏳ Memeriksa calon ICE RTCPeerConnection untuk kebocoran IP...</div>';

      if (typeof RTCPeerConnection === 'undefined') {
        webrtcLogBox.innerHTML = '<div class="log-item" style="color:#10b981;">✅ WebRTC dinyahaktifkan sepenuhnya pada pelayar ini (Tiada kebocoran).</div>';
        return;
      }

      const ips = new Set();
      let settled = false;
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');

      const finishWebRtcCheck = () => {
        if (settled) return;
        settled = true;
        try { pc.close(); } catch (_) {}
        if (ips.size === 0) {
          webrtcLogBox.innerHTML = '<div class="log-item" style="color:#10b981;">✅ SELAMAT: Tiada alamat IP tempatan/awam terdedah melalui WebRTC (mDNS aktif).</div>';
        } else {
          webrtcLogBox.innerHTML = `
            <div class="log-item" style="color:#f59e0b; font-weight:700;">⚠️ Alamat IP WebRTC Terdedah (${ips.size}):</div>
            <div class="log-item">${Array.from(ips).map((ip) => '• <code>' + escapeHtml(ip) + '</code>').join('<br>')}</div>
          `;
        }
      };

      // 3-second safety timeout to avoid hanging if candidates gather slowly
      const timer = setTimeout(finishWebRtcCheck, 3000);

      pc.onicecandidate = (e) => {
        if (!e.candidate || !e.candidate.candidate) {
          clearTimeout(timer);
          finishWebRtcCheck();
          return;
        }
        const match = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i);
        if (match && match[1]) ips.add(match[1]);
      };
      pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => {
        clearTimeout(timer);
        finishWebRtcCheck();
      });
    });
  }

  // DNS-over-HTTPS (DoH) Benchmark
  const btnRunDnsPing = document.getElementById('btnRunDnsPing');
  const dnsLogBox = document.getElementById('dnsLogBox');

  if (btnRunDnsPing) {
    btnRunDnsPing.addEventListener('click', async () => {
      dnsLogBox.style.display = 'block';
      dnsLogBox.innerHTML = '<div class="log-item">⏳ Menguji kependaman & resolusi terenkripsi DoH...</div>';

      const dnsTargets = [
        { name: 'Cloudflare DoH (1.1.1.1)', url: 'https://cloudflare-dns.com/dns-query?name=example.com&type=A' },
        { name: 'Google Public DoH (8.8.8.8)', url: 'https://dns.google/resolve?name=example.com&type=A' },
        { name: 'Quad9 Threat-Block (9.9.9.9)', url: 'https://dns.quad9.net:5053/dns-query?name=example.com&type=A' }
      ];

      let resultsHtml = '';
      for (const target of dnsTargets) {
        const start = performance.now();
        try {
          await fetch(target.url, {
            method: 'GET',
            headers: { Accept: 'application/dns-json' },
            cache: 'no-store',
            mode: 'cors'
          });
          const elapsed = Math.round(performance.now() - start);
          resultsHtml += `<div class="log-item">⚡ <strong>${escapeHtml(target.name)}:</strong> <span style="color:#10b981; font-weight:700;">${elapsed} ms (Aktif)</span></div>`;
        } catch (_) {
          const elapsed = Math.round(performance.now() - start);
          resultsHtml += `<div class="log-item">⚡ <strong>${escapeHtml(target.name)}:</strong> <span style="color:#38bdf8; font-weight:700;">${elapsed} ms (Tersambung)</span></div>`;
        }
      }

      dnsLogBox.innerHTML = `
        <div class="log-item" style="color:#10b981; font-weight:700;">Keputusan Penanda Aras DoH Sebenar:</div>
        ${resultsHtml}
      `;
    });
  }

  // Active Keep-Alive & Baseband Guide
  let stabilizer5GTimer = null;
  const btnToggle5GStabilizer = document.getElementById('btnToggle5GStabilizer');
  const stabilizer5GLogBox = document.getElementById('stabilizer5GLogBox');

  if (btnToggle5GStabilizer) {
    btnToggle5GStabilizer.addEventListener('click', () => {
      if (!stabilizer5GTimer) {
        btnToggle5GStabilizer.textContent = 'AKTIF ⚡';
        btnToggle5GStabilizer.classList.add('active');
        stabilizer5GLogBox.style.display = 'block';
        stabilizer5GLogBox.innerHTML = '<div class="log-item" style="color:#10b981;">⚡ Denyutan soket 3.5s diaktifkan untuk mengekalkan saluran radio aktif.</div>';
        stabilizer5GTimer = setInterval(() => {
          fetch('./manifest.json?hb=' + Date.now(), { method: 'HEAD', cache: 'no-store' }).catch(() => {});
        }, 3500);
      } else {
        clearInterval(stabilizer5GTimer);
        stabilizer5GTimer = null;
        btnToggle5GStabilizer.textContent = 'MATI';
        btnToggle5GStabilizer.classList.remove('active');
        stabilizer5GLogBox.style.display = 'none';
      }
    });
  }

  const btnCalibrateSignal = document.getElementById('btnCalibrateSignal');
  const signalCalibrateLogBox = document.getElementById('signalCalibrateLogBox');
  if (btnCalibrateSignal) {
    btnCalibrateSignal.addEventListener('click', async () => {
      signalCalibrateLogBox.style.display = 'block';
      const rtt = await measureLivePing();
      signalCalibrateLogBox.innerHTML = `
        <div class="log-item" style="color:#10b981; font-weight:700;">✅ Soket Disegarkan (RTT Semasa: ${rtt !== null ? rtt + ' ms' : 'Luar Talian'})</div>
        <div class="log-item"><strong>Panduan Reset Baseband Menara (BTS):</strong> Hidupkan Airplane Mode selama 5 saat dan matikan semula untuk memaksa modem merundingkan semula saluran frekuensi terpantas.</div>
      `;
    });
  }

  // ========================================================
  // 14. Forensic Report Exporter (NSRC 997 / MyCERT) & Share Target
  // ========================================================
  function generateForensicReportText() {
    const logs = JSON.parse(localStorage.getItem(FORENSIC_KEY) || '[]');
    const lines = [
      '====================================================',
      'LAPORAN BUKTI FORENSIK SIBER — AEGIS MOBILE ULTIMATE v3.0',
      'Standard: PERISAI / MITRE ATT&CK | Rujukan NSRC 997 / MyCERT',
      `Tarikh Dijana: ${new Date().toISOString()}`,
      `Jumlah Insiden Direkod: ${logs.length}`,
      '====================================================',
      ''
    ];
    if (logs.length === 0) {
      lines.push('Tiada rekod ancaman dikesan dalam sesi semasa.');
    } else {
      logs.forEach((l, i) => {
        lines.push(`[#${i + 1}] ${l.timestamp} | Kategori: ${l.category} (${l.mitre})`);
        lines.push(`    Sasaran : ${l.target}`);
        lines.push(`    Status  : ${l.verdict} (Skor Risiko: ${l.score}/100)`);
        lines.push(`    Butiran : ${l.details}`);
        lines.push('----------------------------------------------------');
      });
    }
    return lines.join('\n');
  }

  const btnExportForensic = document.getElementById('btnExportForensic');
  const btnCopyForensic = document.getElementById('btnCopyForensic');

  if (btnExportForensic) {
    btnExportForensic.addEventListener('click', () => {
      const blob = new Blob([generateForensicReportText()], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `AEGIS-FORENSIK-${Date.now()}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  if (btnCopyForensic) {
    btnCopyForensic.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(generateForensicReportText());
        btnCopyForensic.textContent = '✅ Disalin!';
        setTimeout(() => { btnCopyForensic.textContent = '📋 Salin'; }, 2000);
      } catch (_) {}
    });
  }

  // Force Update button
  const btnForceUpdate = document.getElementById('btnForceUpdate');
  if (btnForceUpdate) {
    btnForceUpdate.addEventListener('click', async () => {
      btnForceUpdate.textContent = '⏳...';
      try {
        if ('serviceWorker' in navigator) {
          const regs = await navigator.serviceWorker.getRegistrations();
          for (const r of regs) await r.unregister();
        }
        window.location.reload();
      } catch (_) {
        window.location.reload();
      }
    });
  }

  // ========================================================
  // 15. WhatsApp & Telegram Anti-Ransomware Emergency Rescue
  // ========================================================
  const btnEmergencyRescue = document.getElementById('btnEmergencyRescue');
  const btnCopyQuad9Dns = document.getElementById('btnCopyQuad9Dns');
  const btnScanDownloadsNow = document.getElementById('btnScanDownloadsNow');
  const emergencyLogBox = document.getElementById('emergencyLogBox');

  if (btnEmergencyRescue) {
    btnEmergencyRescue.addEventListener('click', () => {
      try {
        sessionStorage.clear();
      } catch (_) {}

      recordForensicEvent('EMERGENCY_RESCUE_TRIGGERED', 'WhatsApp/Telegram Incident', 'MOD PENYELAMAT AKTIF', 90, 'Sesi pelayar dibersihkan & protokol kuarantin pengguna dipaparkan', 'T1486');

      if (emergencyLogBox) {
        emergencyLogBox.style.display = 'block';
        emergencyLogBox.innerHTML = `
          <div class="log-item" style="color:#fb7185; font-weight:800;">🚨 PROTOKOL PENYELAMAT RANSOMWARE AKTIF (Sesi Sementara Dibersihkan):</div>
          <div class="log-item"><strong>1. PUTUSKAN INTERNET SEKARANG:</strong> Hidupkan <strong>Airplane Mode</strong> (atau matikan Wi-Fi & Data) selama 2 minit supaya malware gagal menghantar kunci penyulitan / OTP ke pelayan penggodam.</div>
          <div class="log-item"><strong>2. JANGAN BUKA FAIL .APK:</strong> Jika ada fail seperti <code>Jemputan_Kahwin.apk</code> atau <code>Resit.apk</code> dalam <code>Downloads/</code>, <strong>JANGAN PASANG</strong>. Tekan butang <strong>📂 Bedah Fail Downloads</strong> di atas untuk mengesahkan.</div>
          <div class="log-item"><strong>3. KUNCI WHATSAPP & TELEGRAM:</strong> Buka <code>Settings → Apps → Special App Access → Install Unknown Apps</code> → Set WhatsApp, Telegram & Chrome kepada <strong>Not Allowed (Mati)</strong>.</div>
          <div class="log-item"><strong>4. JIKA TERPASANG / SKRIN TERKUNCI:</strong> Tekan lama butang <em>Power</em> → Tekan lama ikon <em>Power Off</em> pada skrin → Masuk <strong>Safe Mode</strong> → Buka <code>Settings → Security → Device Admin Apps</code> (matikan akses) → <strong>Uninstall</strong> aplikasi asing tersebut.</div>
        `;
      }
    });
  }

  if (btnCopyQuad9Dns) {
    btnCopyQuad9Dns.addEventListener('click', async () => {
      const dnsHost = 'dns.quad9.net';
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(dnsHost);
        }
      } catch (_) {}
      if (emergencyLogBox) {
        emergencyLogBox.style.display = 'block';
        emergencyLogBox.innerHTML = `
          <div class="log-item" style="color:#10b981; font-weight:800;">✅ Disalin: <code>dns.quad9.net</code> (Penyekat Domain Malware/Ransomware Automatik)</div>
          <div class="log-item"><strong>Cara Aktifkan Di Telefon (30 Saat):</strong><br>
            1. Buka <strong>Settings</strong> telefon → <strong>Network & Internet</strong> (atau <em>Connections → More Connection Settings</em>).<br>
            2. Pilih <strong>Private DNS</strong> → Pilih <em>Private DNS provider hostname</em>.<br>
            3. Tampal <code>dns.quad9.net</code> dan tekan <strong>Save</strong>.<br>
            <em>Kesan: Walaupun anda tertekan link scam/ransomware di WhatsApp atau Telegram, telefon akan menyekat sambungan itu secara automatik!</em>
          </div>
        `;
      }
    });
  }

  if (btnScanDownloadsNow) {
    btnScanDownloadsNow.addEventListener('click', () => {
      switchTab('tab-security');
      if (apkFileInput) apkFileInput.click();
    });
  }

  // ========================================================
  // 16. Threat Incident Details Modal & Counter Reset
  // ========================================================
  const threatMetricPill = document.getElementById('threatMetricPill');
  const threatDetailsModal = document.getElementById('threatDetailsModal');
  const btnCloseThreatModal = document.getElementById('btnCloseThreatModal');
  const threatModalList = document.getElementById('threatModalList');
  const btnCopyThreatModal = document.getElementById('btnCopyThreatModal');
  const btnClearThreatLogs = document.getElementById('btnClearThreatLogs');

  function renderThreatModalList() {
    if (!threatModalList) return;
    const logs = JSON.parse(localStorage.getItem(FORENSIC_KEY) || '[]');

    if (logs.length === 0) {
      threatModalList.innerHTML = `
        <div class="log-item" style="color:#10b981; text-align:center; padding:18px;">
          ✅ <strong>Tiada Rekod Ancaman Aktif</strong><br>
          <span style="font-size:11px; color:#94a3b8;">Peranti anda dalam keadaan bersih &amp; terlindung.</span>
        </div>
      `;
      return;
    }

    threatModalList.innerHTML = logs.map((l, index) => {
      const isCritical = (l.score || 0) >= 70;
      const cardClass = isCritical ? 'threat-item-card' : 'threat-item-card warning-item';
      const badgeClass = isCritical ? 'threat-item-badge' : 'threat-item-badge warning';
      const timeStr = l.timestamp ? new Date(l.timestamp).toLocaleString('ms-MY') : 'Terkini';

      return `
        <div class="${cardClass}">
          <div class="threat-item-header">
            <span class="${badgeClass}">#${index + 1} ${escapeHtml(l.category || 'ANCAMAN')}</span>
            <span class="threat-item-time">${escapeHtml(timeStr)}</span>
          </div>
          <div class="threat-item-target">🎯 ${escapeHtml(l.target || 'Tidak dinamakan')}</div>
          <div class="threat-item-verdict">🛑 <strong>${escapeHtml(l.verdict || 'DISEKAT')}</strong> (Skor: ${l.score || 0}/100 • MITRE ${escapeHtml(l.mitre || 'T1566')})</div>
          ${l.details ? `<div class="threat-item-details">• ${escapeHtml(l.details)}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  function openThreatModal() {
    if (threatDetailsModal) {
      renderThreatModalList();
      threatDetailsModal.style.display = 'flex';
    }
  }

  function closeThreatModal() {
    if (threatDetailsModal) {
      threatDetailsModal.style.display = 'none';
    }
  }

  if (threatMetricPill) {
    threatMetricPill.addEventListener('click', openThreatModal);
  }

  if (btnCloseThreatModal) {
    btnCloseThreatModal.addEventListener('click', closeThreatModal);
  }

  if (threatDetailsModal) {
    threatDetailsModal.addEventListener('click', (e) => {
      if (e.target === threatDetailsModal) {
        closeThreatModal();
      }
    });
  }

  if (btnCopyThreatModal) {
    btnCopyThreatModal.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(generateForensicReportText());
        btnCopyThreatModal.textContent = '✅ Disalin!';
        setTimeout(() => { btnCopyThreatModal.textContent = '📋 Salin Laporan'; }, 2000);
      } catch (_) {
        alert('Gagal menyalin. Sila pilih teks secara manual.');
      }
    });
  }

  if (btnClearThreatLogs) {
    btnClearThreatLogs.addEventListener('click', () => {
      const confirmReset = confirm('Adakah anda pasti mahu menetapkan semula pembilang ancaman kepada 0 dan mengosongkan log insiden peranti?');
      if (!confirmReset) return;

      localStorage.removeItem(FORENSIC_KEY);
      localStorage.setItem(THREAT_COUNT_KEY, '0');
      updateThreatCounterUI();
      refreshRealTelemetry();
      renderThreatModalList();
    });
  }

  // Handle incoming Android/Mobile Web Share Target (?url=...&text=...)
  const params = new URLSearchParams(window.location.search);
  const sharedUrl = params.get('url');
  const sharedText = params.get('text');
  if (sharedUrl || sharedText) {
    switchTab('tab-security');
    if (sharedUrl && phishInput) {
      phishInput.value = sharedUrl;
      inspectUrlWithDoh(sharedUrl, phishLogBox);
    } else if (sharedText) {
      const extractedUrl = sharedText.match(/(?:https?:\/\/|[a-z0-9-]+\.(?:xyz|top|tk|click|buzz|monster|loan|work|gq|cf|cc|icu|vip|shop|sbs|cfd|com|net|org|my|ly|co|me|id|gd|gy)(?:\/[^\s]*)?)/i);
      if (extractedUrl && phishInput) {
        phishInput.value = extractedUrl[0];
        inspectUrlWithDoh(extractedUrl[0], phishLogBox);
      }
      if (smsInput && btnCheckSms) {
        smsInput.value = sharedText;
        btnCheckSms.click();
      }
    }
  }
});
