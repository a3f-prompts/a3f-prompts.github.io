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
  const rootBtn = document.getElementById('root-btn');
  const downloadSection = document.getElementById('download-section');
  const downloadLink = document.getElementById('download-link');
  const catArt = document.querySelector('.cat-art');

  const fitSelect = document.getElementById('fit-select');
  const fitSelectList = document.getElementById('fit-select-list');

  let fitBuffer = null;       // The FIT image data (extracted or direct)
  let diskBuffer = null;      // Original disk image (null if file was a plain FIT)
  let diskFitInfo = null;     // { offset, totalsize } if extracted from disk image
  let kernelBuffer = null;
  let fitFileName = 'image.fit';
  let lastValidateResult = null;

  // --- Cat image switching ---
  const catImgBefore = document.getElementById('cat-img-before');
  const catImgAfter = document.getElementById('cat-img-after');

  function showAfterImage() {
    if (catImgBefore && catImgAfter) {
      catImgBefore.classList.add('hidden');
      catImgAfter.classList.remove('hidden');
    }
  }

  function showBeforeImage() {
    if (catImgBefore && catImgAfter) {
      catImgBefore.classList.remove('hidden');
      catImgAfter.classList.add('hidden');
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
    diskBuffer = null;
    diskFitInfo = null;
    showBeforeImage();
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  // --- Progress simulation ---

  function animateProgress(target, duration) {
    return new Promise(resolve => {
      progressContainer.classList.remove('hidden');
      const start = parseFloat(progressBar.style.width) || 0;
      const startTime = performance.now();
      function step(now) {
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
    const baseExt = typeExtMap[type] || '.bin';
    const compExt = compExtMap[compression] || '';
    name += baseExt + compExt;
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
    const modifiedTypes = new Set();
    if (opts) {
      if (opts.changeDtModel) modifiedTypes.add('flat_dt');
      if (opts.replaceKernel) modifiedTypes.add('kernel');
    }

    let html = '<table>';
    if (result.description) {
      html += `<tr><td>Description</td><td colspan="3">${esc(result.description)}</td></tr>`;
    }

    // Summary line: X images across Y configurations (N signed)
    const sigResult = isRooted ? lastValidateResult : result;
    let summary = `${result.images.length} image${result.images.length !== 1 ? 's' : ''}`;
    if (result.numConfigs > 0) {
      summary += ` across ${result.numConfigs} configuration${result.numConfigs !== 1 ? 's' : ''}`;
    }
    if (sigResult.hasSignatures) {
      if (isRooted) {
        summary += ` (<span class="badge-pwned">${sigResult.signatures.length} signed &mdash; bypassed</span>)`;
      } else {
        summary += ` <span style="color:#e67e22;font-weight:bold">(${sigResult.signatures.length} signed)</span>`;
      }
    }
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

  function parseFit() {
    const result = FitOps.validate(fitBuffer);
    if (!result.valid) {
      showError(result.error);
      return;
    }
    lastValidateResult = result;

    renderImageTable(result, null);
    fitInfo.classList.remove('hidden');
    options.classList.remove('hidden');
    rootBtn.classList.remove('hidden');
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function showRootedInfo(outputBuffer, opts) {
    const result = FitOps.validate(outputBuffer);
    if (!result.valid) return;
    renderImageTable(result, opts);
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
        signatureBypass: true,
      };

      if (opts.replaceKernel && !opts.kernelData) {
        throw new Error('Please select a replacement kernel file');
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
      if (diskBuffer && diskFitInfo) {
        outputData = FitScanner.splice(diskBuffer, diskFitInfo.offset, diskFitInfo.totalsize, result);
        outputExt = '-bypassed' + (fitFileName.includes('.') ? fitFileName.replace(/^.*(\.[^.]+)$/, '$1') : '.img');
      } else {
        outputData = result;
        outputExt = '-bypassed.fit';
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
