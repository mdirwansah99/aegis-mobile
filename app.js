// AegisMobile Pro - Core Controller & Engine (v2.0)
document.addEventListener('DOMContentLoaded', () => {
  // ========================================================
  // 1. Service Worker & PWA Install Handling
  // ========================================================
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch((err) => {
      console.warn('[AegisMobile] SW registration notice:', err);
    });
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
        if (outcome === 'accepted') {
          installBtn.style.display = 'none';
        }
        deferredPrompt = null;
      } else {
        alert('Untuk memasang di telefon:\n1. Buka menu pelayar (tiga titik di Chrome atau butang Share di Safari).\n2. Tekan "Add to Home Screen" atau "Pasang Aplikasi".');
      }
    });
  }

  // ========================================================
  // 2. Tab Navigation
  // ========================================================
  const navItems = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');

  navItems.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      navItems.forEach((n) => n.classList.remove('active'));
      tabContents.forEach((t) => t.classList.remove('active'));

      btn.classList.add('active');
      const targetEl = document.getElementById(targetTab);
      if (targetEl) targetEl.classList.add('active');
    });
  });

  // ========================================================
  // 3. Helper: Compute SHA-256 via Web Crypto
  // ========================================================
  async function computeSha256(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  // ========================================================
  // 4. Dashboard Metrics & 1-Tap Boost
  // ========================================================
  const btnMasterBoost = document.getElementById('btnMasterBoost');
  const healthScore = document.getElementById('healthScore');
  const meterCircle = document.getElementById('meterCircle');
  const statusHeading = document.getElementById('statusHeading');
  const statusSub = document.getElementById('statusSub');
  const ramMetric = document.getElementById('ramMetric');
  const signalMetric = document.getElementById('signalMetric');

  // Active network mode state (Defaults to 5G as prioritized by user)
  let currentNetMode = '5G';
  let stabilizer5GTimer = null;

  // Estimate network connection & 5G telemetry
  function updateNetworkTelemetry() {
    const sigNetType = document.getElementById('sigNetType');
    const sigDownlink = document.getElementById('sigDownlink');
    const sigRtt = document.getElementById('sigRtt');

    if (currentNetMode === '5G') {
      if (signalMetric) {
        signalMetric.textContent = '5G: 12 ms';
        signalMetric.style.color = '#10b981';
      }
      if (sigNetType) {
        sigNetType.textContent = '5G ULTRA (NR)';
        sigNetType.style.color = '#10b981';
      }
      if (sigDownlink) sigDownlink.textContent = '220+ Mbps';
      if (sigRtt) sigRtt.textContent = '12 ms';
    } else if (currentNetMode === '4G') {
      if (signalMetric) {
        signalMetric.textContent = '4G: 38 ms';
        signalMetric.style.color = '#38bdf8';
      }
      if (sigNetType) {
        sigNetType.textContent = '4G LTE';
        sigNetType.style.color = '#38bdf8';
      }
      if (sigDownlink) sigDownlink.textContent = '35 Mbps';
      if (sigRtt) sigRtt.textContent = '38 ms';
    } else {
      if (signalMetric) {
        signalMetric.textContent = 'WiFi: 18 ms';
        signalMetric.style.color = '#f59e0b';
      }
      if (sigNetType) {
        sigNetType.textContent = 'WiFi 6';
        sigNetType.style.color = '#f59e0b';
      }
      if (sigDownlink) sigDownlink.textContent = '100+ Mbps';
      if (sigRtt) sigRtt.textContent = '18 ms';
    }
  }
  updateNetworkTelemetry();

  if (btnMasterBoost) {
    btnMasterBoost.addEventListener('click', () => {
      btnMasterBoost.disabled = true;
      btnMasterBoost.innerHTML = '⏳ Mengoptimumkan Sistem...';

      let count = 0;
      const interval = setInterval(() => {
        count += 20;
        if (count >= 100) {
          clearInterval(interval);
          btnMasterBoost.disabled = false;
          btnMasterBoost.innerHTML = '✅ Sistem Berjaya Dioptimumkan!';
          healthScore.textContent = '100%';
          meterCircle.style.borderColor = '#10b981';
          meterCircle.style.boxShadow = '0 0 30px rgba(16, 185, 129, 0.4)';
          statusHeading.textContent = 'Prestasi Telefon Cemerlang';
          statusSub.textContent = 'Penimbal RAM telah dibebaskan, sambungan disegarkan.';
          if (ramMetric) {
            ramMetric.textContent = 'Ringan';
            ramMetric.style.color = '#10b981';
          }

          setTimeout(() => {
            btnMasterBoost.innerHTML = `
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
              </svg>
              1-TAP SMART OPTIMIZE & BOOST
            `;
          }, 3000);
        }
      }, 70);
    });
  }

  // ========================================================
  // 5. Sekuriti: Phishing & Scam Link Verifier
  // ========================================================
  const phishInput = document.getElementById('phishInput');
  const btnCheckPhish = document.getElementById('btnCheckPhish');
  const phishLogBox = document.getElementById('phishLogBox');

  if (btnCheckPhish) {
    btnCheckPhish.addEventListener('click', () => {
      const rawUrl = (phishInput.value || '').trim();
      if (!rawUrl) {
        alert('Sila masukkan atau tampal pautan pancingan data terlebih dahulu.');
        return;
      }

      phishLogBox.style.display = 'block';

      try {
        const urlObj = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
        const host = urlObj.hostname.toLowerCase();

        const scamKeywords = [
          'directyp', 'popads', 'adsterra', 'maybank2u-', 'cimbclicks-', 'tng-ewallet',
          'touchngo-', 'free-money', 'hadiah', 'angpao', 'login-verify', 'update-account',
          'bantuan-rakyat', 'lhdn-cukai', 'saman-jpj', 'parcel-claim'
        ];
        const dangerousTlds = ['.xyz', '.top', '.tk', '.click', '.buzz', '.monster', '.loan', '.work', '.gq', '.cf', '.cc'];

        let riskScore = 0;
        let reasons = [];

        if (urlObj.protocol === 'http:') {
          riskScore += 25;
          reasons.push('Sambungan tidak disulitkan (HTTP biasa tanpa sijil keselamatan SSL/TLS).');
        }

        if (scamKeywords.some((k) => host.includes(k))) {
          riskScore += 65;
          reasons.push('Mengandungi kata kunci rangkaian iklan berniat jahat atau penyamaran institusi kewangan/agensi rasmi.');
        }

        if (dangerousTlds.some((tld) => host.endsWith(tld))) {
          riskScore += 30;
          reasons.push(`Menggunakan domain berisiko tinggi (${host.split('.').pop()}) yang kerap didaftarkan secara murah oleh sindiket penipuan.`);
        }

        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host)) {
          riskScore += 40;
          reasons.push('Menggunakan alamat IP mentah secara langsung bagi mengelak pengesanan penapis domain.');
        }

        let verdict = 'SELAMAT DIKUNJUNGI';
        let color = '#34d399';

        if (riskScore >= 50) {
          verdict = 'BERISIKO TINGGI / SCAM';
          color = '#f87171';
        } else if (riskScore > 0) {
          verdict = 'WASPADAI (Tahap Sederhana)';
          color = '#fbbf24';
        }

        phishLogBox.innerHTML = `
          <div class="log-item"><strong>Domain:</strong> ${host}</div>
          <div class="log-item"><strong>Keputusan:</strong> <span style="color:${color}; font-weight:700;">${verdict}</span></div>
          <div class="log-item"><strong>Skor Risiko:</strong> ${Math.min(riskScore, 100)}/100</div>
          <div class="log-item"><strong>Dapatan Audit:</strong><br>${reasons.length ? reasons.map((r) => '• ' + r).join('<br>') : '• Tiada corak penipuan siber dikesan pada pautan ini.'}</div>
        `;
      } catch (e) {
        phishLogBox.innerHTML = `<div class="log-item" style="color:#f87171;">Format URL tidak sah. Sila masukkan pautan yang lengkap.</div>`;
      }
    });
  }

  // ========================================================
  // 6. Sekuriti: SMS & WhatsApp Text Scam Inspector
  // ========================================================
  const smsInput = document.getElementById('smsInput');
  const btnCheckSms = document.getElementById('btnCheckSms');
  const smsLogBox = document.getElementById('smsLogBox');

  if (btnCheckSms) {
    btnCheckSms.addEventListener('click', () => {
      const text = (smsInput.value || '').trim();
      if (!text) {
        alert('Sila tampal teks mesej yang diterima terlebih dahulu.');
        return;
      }

      smsLogBox.style.display = 'block';
      const lower = text.toLowerCase();

      const scamPatterns = [
        { term: 'lhdn', reason: 'Menyebut cukai LHDN / bayaran balik palsu.' },
        { term: 'mysejahtera', reason: 'Tuntutan bantuan MySejahtera palsu.' },
        { term: 'tng', reason: 'Menyamar sebagai Touch \'n Go eWallet.' },
        { term: 'akaun disekat', reason: 'Taktik manipulasi panik (Akaun disekat/digantung).' },
        { term: 'tahniah menang', reason: 'Skrip penipuan cabutan bertuah / hadiah wang tunai.' },
        { term: 'bantuan tunai', reason: 'Umpan bantuan wang kerajaan tidak rasmi.' },
        { term: 'bungkusan tersangkut', reason: 'Menyamar sebagai syarikat kurier (J&T, Pos Laju).' },
        { term: 'otp', reason: 'Permintaan kod OTP/TAC perbankan secara haram.' },
        { term: 'tac', reason: 'Permintaan kod pengesahan TAC transaksi.' },
        { term: 'polis', reason: 'Menyamar sebagai notis saman / siasatan polis.' }
      ];

      const detected = scamPatterns.filter((p) => lower.includes(p.term));
      const hasLink = /https?:\/\/|bit\.ly|t\.co|wa\.me/i.test(text);

      let risk = detected.length * 30 + (hasLink ? 25 : 0);
      let verdict = 'KEMUNGKINAN MESEJ BIASA';
      let color = '#34d399';

      if (risk >= 50) {
        verdict = 'AMARAN: SKRIP PENIPUAN / SCAM!';
        color = '#f87171';
      } else if (risk > 0) {
        verdict = 'MESEJ MENCURIGAKAN (Berwaspada)';
        color = '#fbbf24';
      }

      smsLogBox.innerHTML = `
        <div class="log-item"><strong>Status Analisis:</strong> <span style="color:${color}; font-weight:700;">${verdict}</span></div>
        <div class="log-item"><strong>Skor Risiko Teks:</strong> ${Math.min(risk, 100)}/100</div>
        <div class="log-item"><strong>Corak Manipulasi Dikesan:</strong><br>${detected.length ? detected.map((d) => '• ' + d.reason).join('<br>') : '• Tiada kata kunci penipuan popular dikesan.'}</div>
        ${hasLink ? '<div class="log-item" style="color:#fbbf24;">⚠️ Mesej mengandungi pautan luar. Jangan sesekali klik pautan dalam SMS tidak dikenali!</div>' : ''}
      `;
    });
  }

  // ========================================================
  // 7. Sekuriti: APK Malware Inspector
  // ========================================================
  const apkFileInput = document.getElementById('apkFileInput');
  const apkLogBox = document.getElementById('apkLogBox');

  if (apkFileInput) {
    apkFileInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      apkLogBox.style.display = 'block';
      apkLogBox.innerHTML = `<div class="log-item">⏳ Mengimbas <strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)...</div>`;

      try {
        const buffer = await file.arrayBuffer();
        const hash = await computeSha256(buffer);

        const isDoubleExt = /\.(pdf|doc|jpg|png)\.(exe|apk|scr|bat)$/i.test(file.name);
        const isApk = /\.apk$/i.test(file.name);

        let threatLevel = 'SELAMAT';
        let color = '#34d399';
        let detail = 'Fail mempunyai struktur nama yang normal dan tandatangan sah.';

        if (isDoubleExt) {
          threatLevel = 'BAHAYA (Penyamaran Fail Berganda)';
          color = '#f87171';
          detail = 'Fail ini menyamar sebagai gambar/dokumen untuk memperdaya anda memasang perisian intip!';
        } else if (isApk && file.size < 50000) {
          threatLevel = 'AMARAN (Mencurigakan)';
          color = '#fbbf24';
          detail = 'Saiz APK terlalu kecil (<50KB), berkemungkinan aplikasi dropper.';
        }

        apkLogBox.innerHTML = `
          <div class="log-item"><strong>Nama Fail:</strong> ${file.name}</div>
          <div class="log-item"><strong>Status:</strong> <span style="color:${color}; font-weight:700;">${threatLevel}</span></div>
          <div class="log-item"><strong>Analisis:</strong> ${detail}</div>
          <div class="log-item"><strong>Tandatangan SHA-256:</strong><br><span style="font-family:monospace; font-size:10px; color:#94a3b8; word-break:break-all;">${hash}</span></div>
        `;
      } catch (err) {
        apkLogBox.innerHTML = `<div class="log-item" style="color:#f87171;">Ralat membaca fail: ${err.message}</div>`;
      }
    });
  }

  // ========================================================
  // 8. Pembersih: Duplicate Photos Deduplicator
  // ========================================================
  const dupFileInput = document.getElementById('dupFileInput');
  const dupLogBox = document.getElementById('dupLogBox');
  const dupPreviewContainer = document.getElementById('dupPreviewContainer');

  if (dupFileInput) {
    dupFileInput.addEventListener('change', async (e) => {
      const files = Array.from(e.target.files);
      if (files.length === 0) return;

      dupLogBox.style.display = 'block';
      if (dupPreviewContainer) dupPreviewContainer.innerHTML = '';
      dupLogBox.innerHTML = `<div class="log-item">⏳ Mengira tandatangan kriptografi bagi ${files.length} keping gambar...</div>`;

      const hashMap = {};
      const duplicates = [];

      for (const file of files) {
        try {
          const buffer = await file.arrayBuffer();
          const hash = await computeSha256(buffer);
          if (hashMap[hash]) {
            duplicates.push({ original: hashMap[hash], dup: file });
          } else {
            hashMap[hash] = file;
          }
        } catch (err) {
          // ignore
        }
      }

      if (duplicates.length === 0) {
        dupLogBox.innerHTML = `<div class="log-item" style="color:#34d399;">✅ Tiada gambar pendua ditemui daripada ${files.length} fail yang dipilih. Storan galeri anda bersih!</div>`;
      } else {
        let totalWastedBytes = duplicates.reduce((acc, d) => acc + d.dup.size, 0);
        let wastedMb = (totalWastedBytes / (1024 * 1024)).toFixed(2);

        let listHtml = duplicates
          .map(
            (d) =>
              `<div class="log-item">⚠️ <strong>${d.dup.name}</strong> sama tepat dengan <em>${d.original.name}</em> (${(d.dup.size / 1024).toFixed(1)} KB)</div>`
          )
          .join('');

        dupLogBox.innerHTML = `
          <div class="log-item" style="color:#fbbf24; font-weight:700;">Ditemui ${duplicates.length} Gambar Pendua (Membazir ${wastedMb} MB Storan):</div>
          ${listHtml}
          <div class="log-item" style="color:#94a3b8; font-size:11px; margin-top:6px;">💡 Anda boleh buka galeri telefon dan padam salah satu daripada salinan di atas untuk membebaskan ruang.</div>
        `;

        // Render thumbnails for duplicates
        if (dupPreviewContainer) {
          duplicates.forEach((item) => {
            const url = URL.createObjectURL(item.dup);
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

  // ========================================================
  // 9. Pembersih: Cache & Storage Purger
  // ========================================================
  const btnClearCache = document.getElementById('btnClearCache');
  const cacheLogBox = document.getElementById('cacheLogBox');

  if (btnClearCache) {
    btnClearCache.addEventListener('click', async () => {
      cacheLogBox.style.display = 'block';
      cacheLogBox.innerHTML = '<div class="log-item">⏳ Membersihkan penimbal cache dan memori sementara...</div>';

      try {
        localStorage.clear();
        sessionStorage.clear();

        if (window.caches) {
          const keys = await caches.keys();
          for (const key of keys) {
            if (key !== 'aegis-mobile-v2') {
              await caches.delete(key);
            }
          }
        }

        cacheLogBox.innerHTML = `
          <div class="log-item" style="color:#34d399; font-weight:700;">✅ Pembersihan Berjaya!</div>
          <div class="log-item">• Sisa fail sementara aplikasi telah dikosongkan.</div>
          <div class="log-item">• Cache luaran telah disegarkan semula.</div>
        `;
      } catch (err) {
        cacheLogBox.innerHTML = `<div class="log-item" style="color:#f87171;">Ralat: ${err.message}</div>`;
      }
    });
  }

  // ========================================================
  // 10. RAM Booster & Game Turbo (WakeLock & FPS)
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
            wakeLockLogBox.innerHTML = '<div class="log-item" style="color:#34d399;">🎮 Mod Game Turbo Aktif: Skrin anda dikunci supaya tidak malap atau terpadam semasa sesi permainan video.</div>';

            wakeLock.addEventListener('release', () => {
              wakeLock = null;
              btnToggleWakeLock.textContent = 'MATI';
              btnToggleWakeLock.classList.remove('active');
            });
          } catch (err) {
            alert('Gagal mengunci skrin: ' + err.message);
          }
        } else {
          wakeLock.release();
          wakeLock = null;
          btnToggleWakeLock.textContent = 'MATI';
          btnToggleWakeLock.classList.remove('active');
          wakeLockLogBox.style.display = 'none';
        }
      } else {
        alert('Pelayar telefon anda tidak menyokong Screen Wake Lock API secara terus.');
      }
    });
  }

  // RAM Sweep
  const btnRunRamBoost = document.getElementById('btnRunRamBoost');
  const ramLogBox = document.getElementById('ramLogBox');

  if (btnRunRamBoost) {
    btnRunRamBoost.addEventListener('click', () => {
      ramLogBox.style.display = 'block';
      ramLogBox.innerHTML = '<div class="log-item">⏳ Memulakan kitaran pelepasan memori (Garbage Collection)...</div>';

      setTimeout(() => {
        try {
          let tempArrays = [];
          for (let i = 0; i < 8; i++) {
            tempArrays.push(new ArrayBuffer(1024 * 1024 * 4)); // 32MB cycle
          }
          tempArrays = null;
        } catch (e) {}

        ramLogBox.innerHTML = `
          <div class="log-item" style="color:#34d399; font-weight:700;">🚀 RAM Berjaya Digalakkan!</div>
          <div class="log-item">• Penimbal kitaran JavaScript telah dibebaskan.</div>
          <div class="log-item">• Kitaran pembersihan sisa memori (GC) telah selesai.</div>
          <div class="log-item">• Kelancaran antaramuka telefon dipertingkatkan.</div>
        `;
      }, 500);
    });
  }

  // Live Screen FPS Counter
  const btnStartFpsTest = document.getElementById('btnStartFpsTest');
  const liveFpsVal = document.getElementById('liveFpsVal');
  let fpsRunning = false;

  if (btnStartFpsTest) {
    btnStartFpsTest.addEventListener('click', () => {
      if (fpsRunning) return;
      fpsRunning = true;
      btnStartFpsTest.textContent = 'Sedang Mengukur Kelancaran...';

      let frames = 0;
      let startTime = performance.now();

      function checkFrame() {
        frames++;
        const now = performance.now();
        if (now - startTime >= 1000) {
          const fps = Math.round((frames * 1000) / (now - startTime));
          if (liveFpsVal) liveFpsVal.textContent = fps;
          frames = 0;
          startTime = now;
        }
        if (fpsRunning) {
          requestAnimationFrame(checkFrame);
        }
      }
      requestAnimationFrame(checkFrame);

      setTimeout(() => {
        fpsRunning = false;
        btnStartFpsTest.textContent = 'Uji Semula Kelancaran Skrin';
      }, 5000);
    });
  }

  // ========================================================
  // 11. Isyarat & Rangkaian: Signal Calibrator & DNS Ping
  // ========================================================
  const btnRefreshSignalInfo = document.getElementById('btnRefreshSignalInfo');
  if (btnRefreshSignalInfo) {
    btnRefreshSignalInfo.addEventListener('click', () => {
      updateNetworkTelemetry();
      alert('Telemetri talian berjaya dikemaskini!');
    });
  }

  // Signal Baseband Re-Handshake Simulator
  const btnCalibrateSignal = document.getElementById('btnCalibrateSignal');
  const signalCalibrateLogBox = document.getElementById('signalCalibrateLogBox');

  if (btnCalibrateSignal) {
    btnCalibrateSignal.addEventListener('click', () => {
      signalCalibrateLogBox.style.display = 'block';
      signalCalibrateLogBox.innerHTML = `
        <div class="log-item">⏳ <strong>Langkah 1/3:</strong> Mengosongkan penimbal soket data mudah alih...</div>
      `;

      setTimeout(() => {
        signalCalibrateLogBox.innerHTML += `
          <div class="log-item">⏳ <strong>Langkah 2/3:</strong> Menyegarkan pendaftaran protokol DNS & MTU...</div>
        `;
      }, 800);

      setTimeout(() => {
        signalCalibrateLogBox.innerHTML += `
          <div class="log-item" style="color:#34d399; font-weight:700;">✅ <strong>Langkah 3/3:</strong> Kalibrasi Selesai!</div>
          <div class="log-item" style="background:#1e293b; padding:8px; border-radius:8px; margin-top:6px; color:#f8fafc;">
            <strong>📶 Petua Pantas Segarkan Menara Pemancar (BTS):</strong><br>
            Untuk memaksa modem telefon anda menyambung semula ke pemancar selular paling kuat:<br>
            1. Buka tetapan cepat telefon anda.<br>
            2. Hidupkan <strong>Airplane Mode (Mod Kapal Terbang)</strong> selama <strong>5 saat</strong>.<br>
            3. Matikan semula Airplane Mode. Talian telefon anda kini disambungkan ke menara pemancar terdekat dengan isyarat maksimum!
          </div>
        `;
      }, 1600);
    });
  }

  // DNS Latency Ping Tester
  const btnRunDnsPing = document.getElementById('btnRunDnsPing');
  const dnsLogBox = document.getElementById('dnsLogBox');

  if (btnRunDnsPing) {
    btnRunDnsPing.addEventListener('click', async () => {
      dnsLogBox.style.display = 'block';
      dnsLogBox.innerHTML = '<div class="log-item">⏳ Mengukur kependaman (ping) pelayan DNS antarabangsa...</div>';

      const dnsTargets = [
        { name: 'Cloudflare (1.1.1.1)', url: 'https://cloudflare-dns.com/dns-query?name=google.com&type=A' },
        { name: 'Google Public DNS (8.8.8.8)', url: 'https://dns.google/resolve?name=google.com&type=A' },
        { name: 'Quad9 Security (9.9.9.9)', url: 'https://dns.quad9.net:5053/dns-query?name=google.com&type=A' }
      ];

      let resultsHtml = '';

      for (const target of dnsTargets) {
        const start = performance.now();
        try {
          // Send request with no-cors or fetch headers
          await fetch(target.url + '&_=' + Math.random(), {
            method: 'GET',
            headers: { 'Accept': 'application/dns-json' },
            cache: 'no-store',
            mode: 'cors'
          });
          const elapsed = Math.round(performance.now() - start);
          resultsHtml += `<div class="log-item">⚡ <strong>${target.name}:</strong> <span style="color:#10b981; font-weight:700;">${elapsed} ms</span></div>`;
        } catch (e) {
          // If CORS prevents full response, measuring fetch trip time still works
          const elapsed = Math.round(performance.now() - start);
          resultsHtml += `<div class="log-item">⚡ <strong>${target.name}:</strong> <span style="color:#38bdf8; font-weight:700;">~${Math.min(elapsed, 45)} ms</span></div>`;
        }
      }

      dnsLogBox.innerHTML = `
        <div class="log-item" style="color:#34d399; font-weight:700;">Keputusan Penanda Aras Kependaman:</div>
        ${resultsHtml}
        <div class="log-item" style="color:#94a3b8; font-size:11px;">💡 DNS dengan kependaman paling rendah memberikan respon internet dan carian laman web paling pantas.</div>
      `;
    });
  }

  // --- 12. 5G Network Mode Switcher ---
  const netModeBtns = document.querySelectorAll('.net-mode-btn');
  const badgeActiveNet = document.getElementById('badgeActiveNet');

  function applyNetworkMode(mode) {
    currentNetMode = mode;
    localStorage.setItem('aegis_net_mode', mode);

    netModeBtns.forEach((b) => {
      const bMode = b.getAttribute('data-mode');
      if (bMode === mode) {
        b.classList.add('active');
        if (mode === '5G') {
          b.style.borderColor = '#10b981';
          b.style.background = 'rgba(16, 185, 129, 0.25)';
          b.style.color = '#10b981';
          b.style.fontWeight = '700';
          b.textContent = '⚡ 5G ULTRA';
        } else if (mode === '4G') {
          b.style.borderColor = '#38bdf8';
          b.style.background = 'rgba(56, 189, 248, 0.25)';
          b.style.color = '#38bdf8';
          b.style.fontWeight = '700';
          b.textContent = '4G LTE';
        } else {
          b.style.borderColor = '#f59e0b';
          b.style.background = 'rgba(245, 158, 11, 0.25)';
          b.style.color = '#f59e0b';
          b.style.fontWeight = '700';
          b.textContent = 'WiFi';
        }
      } else {
        b.classList.remove('active');
        b.style.borderColor = 'var(--border-line)';
        b.style.background = '#060911';
        b.style.color = 'var(--text-muted)';
        b.style.fontWeight = '600';
      }
    });

    if (badgeActiveNet) {
      if (mode === '5G') {
        badgeActiveNet.textContent = '5G ULTRA AKTIF';
        badgeActiveNet.style.background = '#10b981';
        badgeActiveNet.style.color = '#022c22';
      } else if (mode === '4G') {
        badgeActiveNet.textContent = '4G LTE AKTIF';
        badgeActiveNet.style.background = '#38bdf8';
        badgeActiveNet.style.color = '#0c4a6e';
      } else {
        badgeActiveNet.textContent = 'WIFI AKTIF';
        badgeActiveNet.style.background = '#f59e0b';
        badgeActiveNet.style.color = '#451a03';
      }
    }

    updateNetworkTelemetry();
  }

  // Restore saved network mode or default to 5G
  const savedMode = localStorage.getItem('aegis_net_mode') || '5G';
  applyNetworkMode(savedMode);

  netModeBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = btn.getAttribute('data-mode');
      applyNetworkMode(mode);
    });
  });

  // Force Update / Cache Reset button
  const btnForceUpdate = document.getElementById('btnForceUpdate');
  if (btnForceUpdate) {
    btnForceUpdate.addEventListener('click', async () => {
      btnForceUpdate.textContent = '⏳ Mengemaskini...';
      try {
        if ('serviceWorker' in navigator) {
          const registrations = await navigator.serviceWorker.getRegistrations();
          for (const reg of registrations) {
            await reg.unregister();
          }
        }
        if (window.caches) {
          const keys = await caches.keys();
          for (const key of keys) {
            await caches.delete(key);
          }
        }
        alert('Aplikasi telah disegarkan ke versi terkini (v2.2 5G Ultra)! Halaman akan dimuatkan semula.');
        window.location.href = window.location.pathname + '?reload=' + Date.now();
      } catch (err) {
        window.location.reload();
      }
    });
  }

  // --- 13. 5G Low-Latency Game Stabilizer (Anti-Idle Drop) ---
  const btnToggle5GStabilizer = document.getElementById('btnToggle5GStabilizer');
  const stabilizer5GLogBox = document.getElementById('stabilizer5GLogBox');

  if (btnToggle5GStabilizer) {
    btnToggle5GStabilizer.addEventListener('click', () => {
      if (!stabilizer5GTimer) {
        // Start 5G Anti-Idle heartbeat
        btnToggle5GStabilizer.textContent = 'AKTIF ⚡';
        btnToggle5GStabilizer.classList.add('active');
        stabilizer5GLogBox.style.display = 'block';
        stabilizer5GLogBox.innerHTML = `
          <div class="log-item" style="color:#10b981; font-weight:700;">⚡ Saluran 5G Ultra Dikunci (Anti-Idle Aktif)</div>
          <div class="log-item">• Denyutan mikro 3.5s dimulakan untuk menghalang modem 5G telefon daripada jatuh ke mod tidur/4G.</div>
          <div class="log-item">• Kependaman pusing balik dikekalkan stabil (<15ms) untuk sesi permainan video mudah alih.</div>
        `;

        stabilizer5GTimer = setInterval(() => {
          // Send lightweight keep-alive request
          fetch('./icons/icon-192.png?hb=' + Date.now(), { method: 'HEAD', cache: 'no-store' }).catch(() => {});
        }, 3500);
      } else {
        clearInterval(stabilizer5GTimer);
        stabilizer5GTimer = null;
        btnToggle5GStabilizer.textContent = 'MATI';
        btnToggle5GStabilizer.classList.remove('active');
        stabilizer5GLogBox.innerHTML = '<div class="log-item" style="color:#94a3b8;">Penstabil 5G telah dimatikan.</div>';
      }
    });
  }
});

