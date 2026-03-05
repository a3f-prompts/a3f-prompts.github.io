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

  let fitBuffer = null;
  let kernelBuffer = null;
  let fitFileName = 'image.fit';

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
    options.classList.add('hidden');
    rootBtn.classList.add('hidden');
    downloadSection.classList.add('hidden');
    hideError();
    progressContainer.classList.add('hidden');
    progressBar.style.width = '0%';
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
      fitBuffer = reader.result;
      animateProgress(100, 200).then(() => {
        showAfterImage();
        parseFit();
      });
    };

    reader.onerror = () => {
      showError('Failed to read file');
    };

    reader.readAsArrayBuffer(file);
  }

  function parseFit() {
    const result = FitOps.validate(fitBuffer);
    if (!result.valid) {
      showError(result.error);
      return;
    }

    // Build info table
    let html = '<table>';
    if (result.description) {
      html += `<tr><td>Description</td><td>${esc(result.description)}</td></tr>`;
    }
    html += `<tr><td>Images</td><td>${result.images.length}</td></tr>`;

    for (const img of result.images) {
      html += `<tr><td>&nbsp;&nbsp;${esc(img.name)}</td><td>${esc(img.type)} &mdash; ${formatSize(img.size)}`;
      if (img.description) html += ` &mdash; ${esc(img.description)}`;
      if (img.compression !== 'none') html += ` (${esc(img.compression)})`;
      html += '</td></tr>';
    }
    html += '</table>';

    fitInfoContent.innerHTML = html;
    fitInfo.classList.remove('hidden');
    options.classList.remove('hidden');
    rootBtn.classList.remove('hidden');
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
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
      };

      if (opts.replaceKernel && !opts.kernelData) {
        throw new Error('Please select a replacement kernel file');
      }

      progressBar.style.width = '0%';
      progressContainer.classList.remove('hidden');
      await animateProgress(40, 200);

      const result = await FitOps.root(fitBuffer, opts);

      await animateProgress(100, 200);

      // Create download
      const blob = new Blob([result], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const baseName = fitFileName.replace(/\.[^.]+$/, '');
      downloadLink.href = url;
      downloadLink.download = baseName + '-rooted.fit';
      downloadSection.classList.remove('hidden');
    } catch (e) {
      showError(e.message);
    } finally {
      rootBtn.disabled = false;
      rootBtn.textContent = 'root!';
    }
  });
})();
