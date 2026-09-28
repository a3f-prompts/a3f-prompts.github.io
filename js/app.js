/**
 * UI logic: file upload, drag-drop, progress, options, rooting, download.
 */

(() => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const progressContainer = document.getElementById('progress-container');
  const progressBar = document.getElementById('progress-bar');
  const fitInfo = document.getElementById('fit-info');
  const fitInfoContent = document.getElementById('fit-info-content');
  const errorBox = document.getElementById('error-box');
  const options = document.getElementById('options');
  const optModel = document.getElementById('opt-model');
  const optKernel = document.getElementById('opt-kernel');
  const kernelUpload = document.getElementById('kernel-upload');
  const kernelFileInput = document.getElementById('kernel-file-input');
  const kernelFileName = document.getElementById('kernel-file-name');
  const optInitramfs = document.getElementById('opt-initramfs');
  const initramfsUpload = document.getElementById('initramfs-upload');
  const initramfsFileInput = document.getElementById('initramfs-file-input');
  const initramfsFileName = document.getElementById('initramfs-file-name');
  const optMethod = document.getElementById('opt-method');
  const methodNotes = document.querySelectorAll('.method-note');
  const entryOption = document.getElementById('entry-option');
  const optFitAddress = document.getElementById('opt-fit-address');
  const rootBtn = document.getElementById('root-btn');
  const downloadSection = document.getElementById('download-section');
  const downloadLink = document.getElementById('download-link');
  const catArt = document.querySelector('.cat-art');

  const fitSelect = document.getElementById('fit-select');
  const fitSelectList = document.getElementById('fit-select-list');
  const fitConfigContent = document.getElementById('fit-config-content');

  const debugMode = new URLSearchParams(window.location.search).has('debug');
  const debugOptions = document.getElementById('debug-options');
  const optRecomputeHashes = document.getElementById('opt-recompute-hashes');
  const optRedirectSignatures = document.getElementById('opt-redirect-signatures');
  if (debugMode) debugOptions.classList.remove('hidden');

  let fitBuffer = null;       // The FIT image data (extracted or direct)
  let diskBuffer = null;      // Original disk image (null if file was a plain FIT)
  let diskFitInfo = null;     // { offset, totalsize } if extracted from disk image
  let kernelBuffer = null;
  let initramfsBuffer = null;
  let fitFileName = 'image.fit';
  let lastValidateResult = null;
  let hasHAB = false;

  // --- Cat image switching ---
  const catImgBefore = document.getElementById('cat-img-before');
  const catImgAfter = document.getElementById('cat-img-after');

  function showAfterImage() {
    if (catImgBefore && catImgAfter) {
      catImgBefore.classList.add('cat-hidden');
      catImgAfter.classList.remove('cat-hidden');
    }
  }

  function showBeforeImage() {
    if (catImgBefore && catImgAfter) {
      catImgBefore.classList.remove('cat-hidden');
      catImgAfter.classList.add('cat-hidden');
    }
  }

  // --- Helpers ---

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove('hidden');
  }

  function hideError() {
    errorBox.classList.add('hidden');
  }

  function resetUI() {
    fitInfo.classList.add('hidden');
    fitSelect.classList.add('hidden');
    options.classList.add('hidden');
    rootBtn.classList.add('hidden');
    downloadSection.classList.add('hidden');
    hideError();
    progressContainer.classList.add('hidden');
    progressBar.style.width = '0%';
    fitBuffer = null;
    diskBuffer = null;
    diskFitInfo = null;
    lastValidateResult = null;
    hasHAB = false;

    // Revoke previous download blob URL to free memory
    if (downloadLink.href && downloadLink.href.startsWith('blob:')) {
      URL.revokeObjectURL(downloadLink.href);
    }
    downloadLink.href = '';

    // Reset kernel/initramfs options so stale selections don't carry over
    optKernel.checked = false;
    kernelUpload.classList.add('hidden');
    kernelFileInput.value = '';
    kernelBuffer = null;
    kernelFileName.textContent = 'No file selected';

    optInitramfs.checked = false;
    initramfsUpload.classList.add('hidden');
    initramfsFileInput.value = '';
    initramfsBuffer = null;
    initramfsFileName.textContent = 'No file selected';

    showBeforeImage();
  }

  /**
   * Rudimentary HAB (High Assurance Boot) detection.
   * Checks for an IVT header at fitOffset + 0x1000 in the raw buffer.
   * IVT: tag=0xD1, length=0x0020 (BE), version & 0xF0 == 0x40,
   *       reserved1 == 0, reserved2 == 0.
   */
  function detectHAB(buf, fitOffset) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    const ivtOff = fitOffset + 0x1000;
    if (ivtOff + 32 > u8.byteLength) return false;
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

    const tag = u8[ivtOff];
    const len = (u8[ivtOff + 1] << 8) | u8[ivtOff + 2];
    const ver = u8[ivtOff + 3];

    if (tag !== 0xD1) return false;
    if (len !== 0x0020) return false;
    if ((ver & 0xF0) !== 0x40) return false;

    // reserved1 at offset 8, reserved2 at offset 28 (little-endian uint32)
    const reserved1 = dv.getUint32(ivtOff + 8, true);
    const reserved2 = dv.getUint32(ivtOff + 28, true);
    if (reserved1 !== 0 || reserved2 !== 0) return false;

    return true;
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  // --- Progress simulation ---

  let progressGen = 0;

  function animateProgress(target, duration) {
    // Supersede any animation still in flight: handleFile() starts a 0->60
    // ramp before the FileReader completes, and a small file lets the
    // follow-up 60->100 ramp finish first. Without this the older, longer
    // animation keeps writing and leaves the bar stuck partway.
    const gen = ++progressGen;
    return new Promise(resolve => {
      progressContainer.classList.remove('hidden');
      const start = parseFloat(progressBar.style.width) || 0;
      const startTime = performance.now();
      function step(now) {
        if (gen !== progressGen) {
          resolve();
          return;
        }
        const elapsed = now - startTime;
        const pct = Math.min(start + (target - start) * (elapsed / duration), target);
        progressBar.style.width = pct + '%';
        if (elapsed < duration) {
          requestAnimationFrame(step);
        } else {
          progressBar.style.width = target + '%';
          resolve();
        }
      }
      requestAnimationFrame(step);
    });
  }

  // --- File handling ---

  function handleFile(file) {
    resetUI();
    fitFileName = file.name;

    const reader = new FileReader();
    animateProgress(60, 300);

    reader.onload = () => {
      const buf = reader.result;
      animateProgress(100, 200).then(() => {
        showAfterImage();
        tryParseFitOrDisk(buf);
      });
    };

    reader.onerror = () => {
      showError('Failed to read file');
    };

    reader.readAsArrayBuffer(file);
  }

  function tryParseFitOrDisk(buf) {
    // First, try as a plain FIT image
    const directResult = FitOps.validate(buf);
    if (directResult.valid) {
      fitBuffer = buf;
      diskBuffer = null;
      diskFitInfo = null;
      hasHAB = detectHAB(buf, 0);
      parseFit();
      return;
    }

    // Not a valid FIT — scan for embedded FIT images in a disk image
    const fits = FitScanner.scan(buf);
    if (fits.length === 0) {
      showError(directResult.error);
      return;
    }

    if (fits.length === 1) {
      selectFitFromDisk(buf, fits[0]);
      return;
    }

    // Multiple FITs — let user choose
    showFitSelection(buf, fits);
  }

  function selectFitFromDisk(buf, info) {
    diskBuffer = buf;
    diskFitInfo = info;
    fitBuffer = FitScanner.extract(buf, info.offset, info.totalsize).buffer;
    hasHAB = detectHAB(buf, info.offset);
    parseFit();
  }

  function showFitSelection(buf, fits) {
    fitSelectList.innerHTML = '';
    for (let i = 0; i < fits.length; i++) {
      const fit = fits[i];
      const btn = document.createElement('button');
      btn.className = 'fit-select-btn';
      btn.innerHTML =
        `<strong>FIT #${i + 1}</strong> — ` +
        `offset 0x${fit.offset.toString(16)}, ` +
        `${formatSize(fit.totalsize)}` +
        (fit.description ? ` — ${esc(fit.description)}` : '');
      btn.addEventListener('click', () => {
        fitSelect.classList.add('hidden');
        selectFitFromDisk(buf, fit);
      });
      fitSelectList.appendChild(btn);
    }
    fitSelect.classList.remove('hidden');
  }

  const typeExtMap = {
    flat_dt: '.dtb',
    ramdisk: '.cpio',
    kernel: '.bin',
    kernel_noload: '.bin',
  };

  const compExtMap = {
    gzip: '.gz',
    bzip2: '.bz2',
    lzma: '.lzma',
    lzo: '.lzo',
    lz4: '.lz4',
    zstd: '.zst',
  };

  const knownExts = ['.dtb', '.cpio', '.bin', '.img', '.gz', '.bz2', '.lzma', '.lzo', '.lz4', '.zst', '.zstd', '.xz'];

  function artifactName(imageName, type, compression, description) {
    // If description contains a filename with a known extension, use it
    if (description) {
      const words = description.split(/\s+/);
      for (const w of words) {
        if (knownExts.some(ext => w.endsWith(ext))) return w;
      }
    }
    let name = imageName;
    if (!knownExts.some(ext => name.endsWith(ext))) {
      const baseExt = typeExtMap[type] || '.bin';
      const compExt = compExtMap[compression] || '';
      name += baseExt + compExt;
    }
    return name;
  }

  function downloadImageData(tree, imageName) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return;
    const imgNode = imagesNode.children.find(c => c.name === imageName);
    if (!imgNode) return;
    const data = FDT.getProperty(imgNode, 'data');
    if (!data) return;
    const type = FDT.getStringProperty(imgNode, 'type') || '';
    const compression = FDT.getStringProperty(imgNode, 'compression') || 'none';
    const desc = FDT.getStringProperty(imgNode, 'description') || '';
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = artifactName(imageName, type, compression, desc);
    a.click();
    URL.revokeObjectURL(url);
  }

  function renderImageTable(result, opts) {
    const isRooted = !!opts;
    const verdict = isRooted ? sigVerdict(opts) : null;
    const modifiedTypes = new Set();
    if (opts) {
      if (opts.changeDtModel) modifiedTypes.add('flat_dt');
      if (opts.replaceKernel) modifiedTypes.add('kernel');
      if (opts.appendInitramfs) modifiedTypes.add('ramdisk');
    }

    let html = '<table>';
    if (result.description) {
      html += `<tr><td>Description</td><td colspan="3">${esc(result.description)}</td></tr>`;
    }

    // Summary line: X images across Y [signed] configurations
    const sigResult = isRooted ? lastValidateResult : result;
    let summary = `${result.images.length} image${result.images.length !== 1 ? 's' : ''}`;
    if (result.numConfigs > 0) {
      const allSigned = sigResult.numSignedConfigs === result.numConfigs && sigResult.hasSignatures;
      const algoStr = sigResult.sigAlgos.length > 0 ? ` (${sigResult.sigAlgos.join(', ')})` : '';
      if (allSigned) {
        if (isRooted) {
          summary += ` across <span class="sig-count">${result.numConfigs} signed configuration${result.numConfigs !== 1 ? 's' : ''}${algoStr}</span> &mdash; <span class="${verdict.badge}">${verdict.label}</span>`;
        } else {
          summary += ` across <span class="sig-count">${result.numConfigs} signed configuration${result.numConfigs !== 1 ? 's' : ''}${algoStr}</span>`;
        }
      } else {
        summary += ` across ${result.numConfigs} configuration${result.numConfigs !== 1 ? 's' : ''}`;
        if (sigResult.hasSignatures) {
          if (isRooted) {
            summary += ` <span class="sig-count">(${sigResult.numSignedConfigs} signed${algoStr})</span> &mdash; <span class="${verdict.badge}">${verdict.label}</span>`;
          } else {
            summary += ` <span class="sig-count">(${sigResult.numSignedConfigs} signed${algoStr})</span>`;
          }
        }
      }
    }
    if (hasHAB) summary += ' <span class="badge-hab">HAB</span>';
    html += `<tr><td>Contents</td><td colspan="3">${summary}</td></tr>`;

    for (const img of result.images) {
      const rowClass = img.isOrig ? ' class="row-orig"' : '';
      const nameHtml = img.isOrig
        ? `&nbsp;&nbsp;${esc(img.name)}`
        : `&nbsp;&nbsp;<a class="img-download" data-img="${esc(img.name)}">${esc(img.name)}</a>`;

      let typeStr = esc(img.type);
      if (img.compression !== 'none') typeStr += ` (${esc(img.compression)})`;

      let extra = '';
      if (img.description) extra = esc(img.description);
      if (img.arch && (img.type === 'kernel' || img.type === 'kernel_noload')) extra += ` (${esc(img.arch)})`;
      if (img.isX509) extra += ' <span class="badge-x509">X.509</span>';
      if (img.isVAB) extra += ' <span class="badge-vab">VAB</span>';
      if (img.entryEscapes) {
        extra += ' <span class="badge-entry" title="entry does not point into this' +
          ' image\'s data">entry outside</span>';
      }
      if (isRooted && !img.isOrig) {
        const isPwned = img.description.includes('(Pwnd)') || modifiedTypes.has(img.type);
        if (isPwned) extra += ' <span class="badge-pwned">pwned</span>';
      }

      html += `<tr${rowClass}><td>${nameHtml}</td><td>${typeStr}</td><td>${formatSize(img.size)}</td><td>${extra}</td></tr>`;
    }

    html += '</table>';

    fitInfoContent.innerHTML = html;

    // Bind click handlers for image download links
    fitInfoContent.querySelectorAll('.img-download').forEach(a => {
      a.addEventListener('click', () => {
        downloadImageData(result.tree, a.dataset.img);
      });
    });
  }

  function renderConfigTab(result, opts) {
    const isRooted = !!opts;
    const verdict = isRooted ? sigVerdict(opts) : null;
    const sigResult = isRooted ? lastValidateResult : result;
    const configs = result.configs || [];
    if (configs.length === 0) {
      fitConfigContent.innerHTML = '<p class="empty-note">No configurations found.</p>';
      return;
    }

    // Build image lookup for showing details
    const imageMap = {};
    for (const img of result.images) {
      imageMap[img.name] = img;
    }

    let html = '';
    for (const cfg of configs) {
      const defaultBadge = cfg.isDefault ? ' <span class="badge-default">default</span>' : '';
      const sigBadges = cfg.signatures.map(s => {
        if (isRooted) {
          return ` <span class="${verdict.badge}">${esc(s.algo)} &mdash; ${verdict.label}</span>`;
        }
        return ` <span class="badge-signed">${esc(s.algo)}</span>`;
      }).join('');
      const descStr = cfg.description ? ` &mdash; ${esc(cfg.description)}` : '';

      html += `<div class="config-entry">`;
      html += `<div class="config-header" data-config="${esc(cfg.name)}">`;
      html += `<span class="config-toggle">&#9654;</span> `;
      html += `<strong>${esc(cfg.name)}</strong>${descStr}${defaultBadge}${sigBadges}`;
      html += `</div>`;
      html += `<div class="config-images hidden">`;

      if (cfg.imageRefs.length > 0) {
        html += '<table>';
        for (const ref of cfg.imageRefs) {
          const img = imageMap[ref.image];
          if (img) {
            let typeStr = esc(img.type);
            if (img.compression !== 'none') typeStr += ` (${esc(img.compression)})`;
            html += `<tr><td>&nbsp;&nbsp;${esc(ref.role)}</td><td><a class="img-download" data-img="${esc(ref.image)}">${esc(ref.image)}</a></td><td>${typeStr}</td><td>${formatSize(img.size)}</td></tr>`;
          } else {
            html += `<tr><td>&nbsp;&nbsp;${esc(ref.role)}</td><td>${esc(ref.image)}</td><td colspan="2"></td></tr>`;
          }
        }
        html += '</table>';
      } else {
        html += '<p class="empty-note-sm">&nbsp;&nbsp;No image references</p>';
      }

      html += `</div></div>`;
    }

    fitConfigContent.innerHTML = html;

    // Toggle expand/collapse on config headers
    fitConfigContent.querySelectorAll('.config-header').forEach(header => {
      header.addEventListener('click', () => {
        const images = header.nextElementSibling;
        const toggle = header.querySelector('.config-toggle');
        images.classList.toggle('hidden');
        toggle.innerHTML = images.classList.contains('hidden') ? '&#9654;' : '&#9660;';
      });
    });

    // Bind download links in config tab
    fitConfigContent.querySelectorAll('.img-download').forEach(a => {
      a.addEventListener('click', (e) => {
        e.stopPropagation();
        downloadImageData(result.tree, a.dataset.img);
      });
    });
  }

  function initTabs() {
    fitInfo.querySelectorAll('.fit-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        fitInfo.querySelectorAll('.fit-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        fitInfo.querySelectorAll('.fit-tab-content').forEach(c => c.classList.add('hidden'));
        document.getElementById('fit-tab-' + tab.dataset.tab).classList.remove('hidden');
      });
    });
  }
  initTabs();

  function parseFit() {
    const result = FitOps.validate(fitBuffer);
    if (!result.valid) {
      showError(result.error);
      return;
    }
    lastValidateResult = result;

    renderImageTable(result, null);
    renderConfigTab(result, null);
    fitInfo.classList.remove('hidden');
    options.classList.remove('hidden');
    rootBtn.classList.remove('hidden');

    // Disable initramfs option if no ramdisk exists
    const hasRamdisk = result.images.some(img => img.type === 'ramdisk');
    optInitramfs.dataset.unavailable = String(!hasRamdisk);
    if (!hasRamdisk) {
      optInitramfs.checked = false;
      initramfsUpload.classList.add('hidden');
      initramfsBuffer = null;
    }
    updateMethodNote();
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  // What the run did to the configuration signature.  The sanity check
  // deliberately leaves it covering data it no longer matches, so calling that
  // result "bypassed" would be a lie: it is a signature that must now fail.
  function sigVerdict(opts) {
    return opts.method === 'sanity-check'
      ? { label: 'broken', badge: 'badge-broken' }
      : { label: 'bypassed', badge: 'badge-pwned' };
  }

  function showRootedInfo(outputBuffer, opts) {
    const result = FitOps.validate(outputBuffer);
    if (!result.valid) return;
    renderImageTable(result, opts);
    renderConfigTab(result, opts);
  }

  // --- Drag and drop ---

  dropzone.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFile(fileInput.files[0]);
    }
  });

  dropzone.addEventListener('dragover', e => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
  });

  dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  // --- Bypass method ---

  // Moving the entry point leaves every signed byte where it is, so it does
  // not combine with the operations that rewrite image contents: those are
  // switched off and disabled rather than left to fail in FitOps.root().
  function updateMethodNote() {
    for (const note of methodNotes) {
      note.classList.toggle('hidden', note.dataset.method !== optMethod.value);
    }

    const entryMethod = optMethod.value === 'entry-address';
    entryOption.classList.toggle('hidden', !entryMethod);

    if (entryMethod) {
      optModel.checked = false;
      optInitramfs.checked = false;
      initramfsUpload.classList.add('hidden');
      initramfsBuffer = null;
      if (!optKernel.checked) {
        optKernel.checked = true;
        kernelUpload.classList.remove('hidden');
      }
    }

    optModel.disabled = entryMethod;
    optInitramfs.disabled = entryMethod || optInitramfs.dataset.unavailable === 'true';
    for (const opt of [optModel, optInitramfs]) {
      opt.parentElement.classList.toggle('option-disabled', opt.disabled);
    }
  }

  optMethod.addEventListener('change', updateMethodNote);
  updateMethodNote();

  // --- Kernel file picker ---

  optKernel.addEventListener('change', () => {
    if (optKernel.checked) {
      kernelUpload.classList.remove('hidden');
    } else {
      kernelUpload.classList.add('hidden');
      kernelBuffer = null;
      kernelFileName.textContent = 'No file selected';
    }
  });

  document.getElementById('kernel-browse-btn').addEventListener('click', () => {
    kernelFileInput.click();
  });

  kernelFileInput.addEventListener('change', () => {
    if (kernelFileInput.files.length > 0) {
      const file = kernelFileInput.files[0];
      kernelFileName.textContent = file.name;
      const reader = new FileReader();
      reader.onload = () => { kernelBuffer = reader.result; };
      reader.readAsArrayBuffer(file);
    }
  });

  // --- Initramfs file picker ---

  optInitramfs.parentElement.addEventListener('click', () => {
    if (optInitramfs.disabled) {
      showError('No ramdisk to append found in FIT');
    }
  });

  optInitramfs.addEventListener('change', () => {
    if (optInitramfs.checked) {
      initramfsUpload.classList.remove('hidden');
    } else {
      initramfsUpload.classList.add('hidden');
      initramfsBuffer = null;
      initramfsFileName.textContent = 'No file selected';
    }
  });

  document.getElementById('initramfs-browse-btn').addEventListener('click', () => {
    initramfsFileInput.click();
  });

  initramfsFileInput.addEventListener('change', () => {
    if (initramfsFileInput.files.length > 0) {
      const file = initramfsFileInput.files[0];
      initramfsFileName.textContent = file.name;
      const reader = new FileReader();
      reader.onload = () => { initramfsBuffer = reader.result; };
      reader.readAsArrayBuffer(file);
    }
  });

  // --- Root action ---

  rootBtn.addEventListener('click', async () => {
    if (!fitBuffer) return;

    hideError();
    downloadSection.classList.add('hidden');
    rootBtn.disabled = true;
    rootBtn.textContent = 'rooting...';

    try {
      const opts = {
        changeDtModel: optModel.checked,
        replaceKernel: optKernel.checked,
        kernelData: kernelBuffer,
        appendInitramfs: optInitramfs.checked,
        initramfsData: initramfsBuffer,
        method: optMethod.value,
        fitLoadAddress: optFitAddress.value,
        recomputeHashes: !debugMode || optRecomputeHashes.checked,
        redirectSignatures: !debugMode || optRedirectSignatures.checked,
      };

      if (opts.replaceKernel && !opts.kernelData) {
        throw new Error('Please select a replacement kernel file');
      }

      if (opts.appendInitramfs && !opts.initramfsData) {
        throw new Error('Please select an initramfs file to append');
      }

      progressBar.style.width = '0%';
      progressContainer.classList.remove('hidden');
      await animateProgress(40, 200);

      const result = await FitOps.root(fitBuffer, opts);

      await animateProgress(100, 200);

      // Re-validate the output to show updated info
      showRootedInfo(result, opts);

      // Create download — splice back into disk image if applicable
      let outputData;
      let outputExt;
      const suffix = '-' + sigVerdict(opts).label;
      if (diskBuffer && diskFitInfo) {
        outputData = FitScanner.splice(diskBuffer, diskFitInfo.offset, diskFitInfo.totalsize, result);
        outputExt = suffix + (fitFileName.includes('.') ? fitFileName.replace(/^.*(\.[^.]+)$/, '$1') : '.img');
      } else {
        outputData = result;
        outputExt = suffix + '.fit';
      }
      const blob = new Blob([outputData], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const baseName = fitFileName.replace(/\.[^.]+$/, '');
      downloadLink.href = url;
      downloadLink.download = baseName + outputExt;
      downloadSection.classList.remove('hidden');
    } catch (e) {
      showError(e.message);
    } finally {
      rootBtn.disabled = false;
      rootBtn.textContent = 'root!';
    }
  });
})();
