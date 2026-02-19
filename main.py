from __future__ import annotations

import io
import importlib
from datetime import datetime

from cryptography.hazmat.primitives.serialization import pkcs12
from flask import Flask, jsonify, make_response, render_template_string, request, send_file
from pypdf import PdfReader
from werkzeug.exceptions import HTTPException
from pyhanko.keys.internal import (
  translate_pyca_cryptography_cert_to_asn1,
  translate_pyca_cryptography_key_to_asn1,
)
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers import PdfSignatureMetadata, PdfSigner
from pyhanko.stamp import TextStampStyle
from pyhanko_certvalidator.registry import SimpleCertificateStore


app = Flask(__name__)
APP_VERSION = "2026-02-19-sign-editor-v3"


def _candidate_passphrases(password: str) -> list[bytes | None]:
  value = password or ""
  if value == "":
    return [None, b""]

  candidates: list[bytes | None] = []
  for enc in ("utf-8", "utf-16le", "latin-1"):
    try:
      encoded = value.encode(enc)
    except UnicodeEncodeError:
      continue
    if encoded not in candidates:
      candidates.append(encoded)
  return candidates


def _load_signer_from_p12_bytes(p12_bytes: bytes, password: str):
  last_error = None

  for passphrase in _candidate_passphrases(password):
    try:
      pyca_private_key, pyca_cert, pyca_other_certs = pkcs12.load_key_and_certificates(
        p12_bytes,
        passphrase,
      )
    except Exception as exc:
      last_error = exc
      continue

    if pyca_private_key is None:
      return None, "P12 loaded, but no private key was found in the file."
    if pyca_cert is None:
      return None, "P12 loaded, but no signing certificate was found in the file."

    try:
      signing_key = translate_pyca_cryptography_key_to_asn1(pyca_private_key)
      signing_cert = translate_pyca_cryptography_cert_to_asn1(pyca_cert)

      cert_store = SimpleCertificateStore()
      if pyca_other_certs:
        cert_store.register_multiple(
          translate_pyca_cryptography_cert_to_asn1(c) for c in pyca_other_certs
        )

      signer = signers.SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=cert_store,
      )
      return signer, None
    except Exception as exc:
      return None, f"P12 was decrypted, but signer setup failed: {exc}"

  if last_error is not None:
    return None, f"Could not decrypt/read P12 ({type(last_error).__name__})."
  return None, "Could not read P12 data."


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PNPKI PDF Signer</title>
  <style>
    :root {
      color-scheme: light dark;
      font-family: Arial, sans-serif;
    }
    body {
      margin: 0;
      padding: 24px;
      background: #0f172a;
      color: #e2e8f0;
    }
    .wrap {
      max-width: 980px;
      margin: 0 auto;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 20px;
    }
    h1 {
      margin-top: 0;
      font-size: 1.5rem;
    }
    .row {
      margin: 12px 0;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    label {
      display: block;
      margin-bottom: 6px;
      font-weight: 600;
    }
    input, button, select {
      width: 100%;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid #475569;
      background: #0b1220;
      color: #e2e8f0;
      box-sizing: border-box;
    }
    button {
      background: #2563eb;
      border: 0;
      font-weight: 600;
      cursor: pointer;
      margin-top: 6px;
    }
    button:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }
    .preview-wrap {
      margin-top: 14px;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 10px;
      background: #0b1220;
    }
    #pdfHost {
      position: relative;
      width: fit-content;
      max-width: 100%;
      margin: 0 auto;
      overflow: auto;
    }
    #pdfCanvas {
      display: block;
      max-width: 100%;
      border: 1px solid #334155;
    }
    #sigBox {
      position: absolute;
      left: 40px;
      top: 40px;
      width: 170px;
      height: 60px;
      border: 2px dashed #22d3ee;
      background: rgba(34, 211, 238, 0.18);
      cursor: move;
      user-select: none;
      touch-action: none;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #e0f2fe;
      font-size: 12px;
      font-weight: 700;
      white-space: pre-wrap;
      overflow: hidden;
    }
    #signEditor {
      margin-top: 10px;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 10px;
      background: #0b1220;
    }
    #editorCanvas {
      position: relative;
      width: 100%;
      max-width: 520px;
      height: 190px;
      border: 1px dashed #475569;
      border-radius: 8px;
      overflow: hidden;
      background: rgba(15, 23, 42, 0.35);
      margin: 0 auto;
    }
    #editorImage {
      position: absolute;
      left: 50%;
      top: 50%;
      transform: translate(-50%, -50%);
      cursor: move;
      display: none;
      user-select: none;
      -webkit-user-drag: none;
    }
    #editorText {
      position: absolute;
      left: 50%;
      top: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
      white-space: pre-wrap;
      line-height: 1.2;
      cursor: move;
      user-select: none;
      color: #e0f2fe;
      font-size: 24px;
      font-family: "Segoe UI", Arial, sans-serif;
      font-weight: 700;
      padding: 4px 6px;
      text-shadow: 0 1px 1px rgba(0, 0, 0, 0.35);
    }
    .card {
      background: #0b1220;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 12px;
      margin-top: 14px;
      white-space: pre-wrap;
      font-family: Consolas, monospace;
      font-size: 0.9rem;
    }
    .ok { color: #4ade80; }
    .err { color: #f87171; }
    .muted { color: #94a3b8; }
    .action-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-top: 8px;
    }
    .config-area {
      margin-top: 12px;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 10px;
      background: #0b1220;
      display: none;
    }
    .config-tabs {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-bottom: 10px;
    }
    .config-panel {
      display: none;
    }
    .config-panel.active {
      display: block;
    }
    .tab-active {
      outline: 2px solid #22d3ee;
    }
    .page-nav {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 10px;
    }
    .page-nav button {
      width: auto;
      min-width: 90px;
      margin-top: 0;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>PNPKI PDF Signer (Acrobat-compatible) - {{ app_version }}</h1>

    <div class="grid">
      <div class="row">
        <label for="pdfFile">PDF document</label>
        <input id="pdfFile" type="file" accept="application/pdf" />
      </div>
      <div class="row">
        <label>
          <input id="batchSignAll" type="checkbox" style="width:auto; margin-right:8px;" />
          Batch sign all pages using current signature position/design
        </label>
      </div>
    </div>

    <div class="action-grid">
      <button id="updateP12Btn" type="button">Update Saved P12</button>
      <button id="updateSignBtn" type="button">Update Saved Signature</button>
    </div>

    <div id="configArea" class="config-area">
      <div class="config-tabs">
        <button id="tabP12Btn" type="button">PNPKI P12</button>
        <button id="tabSignBtn" type="button">Signature</button>
      </div>

      <div id="tabP12" class="config-panel">
        <div class="row">
          <label for="p12File">PNPKI (.p12 / .pfx)</label>
          <input id="p12File" type="file" accept=".p12,.pfx,application/x-pkcs12" />
        </div>
        <div class="row">
          <label for="p12Pass">P12 password</label>
          <input id="p12Pass" type="password" placeholder="Enter certificate password" />
        </div>
        <div class="row">
          <label>
            <input id="rememberCreds" type="checkbox" style="width:auto; margin-right:8px;" />
            Remember certificate + password in this browser (less secure)
          </label>
        </div>
        <button id="saveP12Btn" type="button">Save P12 Changes</button>
      </div>

      <div id="tabSign" class="config-panel">
        <div class="grid">
          <div class="row">
            <label for="signerName">Signer display name</label>
            <input id="signerName" type="text" placeholder="e.g., Juan Dela Cruz" />
          </div>
          <div class="row">
            <label for="signNote">Signature note (optional)</label>
            <input id="signNote" type="text" placeholder="e.g., Approved" />
          </div>
          <div class="row">
            <label for="signImage">Signature image (optional)</label>
            <input id="signImage" type="file" accept="image/*" />
          </div>
          <div class="row">
            <label for="textSize">Text size</label>
            <input id="textSize" type="range" min="10" max="48" value="24" />
          </div>
          <div class="row">
            <label for="fontFamily">Text font</label>
            <select id="fontFamily">
              <option value="'Segoe UI', Arial, sans-serif">Segoe UI</option>
              <option value="Arial, Helvetica, sans-serif">Arial</option>
              <option value="'Times New Roman', Times, serif">Times New Roman</option>
              <option value="Georgia, serif">Georgia</option>
              <option value="'Courier New', Courier, monospace">Courier New</option>
              <option value="'Comic Sans MS', 'Segoe UI', sans-serif">Comic Sans</option>
              <option value="cursive">Cursive</option>
            </select>
          </div>
          <div class="row">
            <label for="textColor">Text color</label>
            <input id="textColor" type="color" value="#e0f2fe" />
          </div>
          <div class="row">
            <label for="imageScale">Image size (%)</label>
            <input id="imageScale" type="range" min="15" max="150" value="60" />
          </div>
        </div>

        <div id="signEditor">
          <strong>Signature Editor</strong>
          <div class="muted" style="margin-top:4px; margin-bottom:8px;">
            Drag text and image to position them. Use controls above to style and resize.
          </div>
          <div id="editorCanvas">
            <img id="editorImage" alt="Signature Layer" />
            <div id="editorText">SIGN HERE</div>
          </div>
        </div>

        <button id="saveSignBtn" type="button">Save Signature Changes</button>
      </div>

      <button id="clearSavedBtn" type="button">Clear Saved Certificate/Password</button>
      <div id="savedInfo" class="card muted" style="margin-top:8px;">No saved certificate.</div>
    </div>

    <button id="signBtn">Sign PDF</button>

    <div class="preview-wrap">
      <div id="pdfHost">
        <canvas id="pdfCanvas"></canvas>
        <div id="sigBox">SIGN HERE</div>
      </div>
      <div class="page-nav">
        <button id="prevPageBtn" type="button">◀ Prev</button>
        <div id="pageIndicator" class="muted">Page 0 / 0</div>
        <button id="nextPageBtn" type="button">Next ▶</button>
      </div>
    </div>

    <div id="status" class="card muted">Load a PDF, drag the signature box, then click Sign PDF.</div>
  </div>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.min.mjs" type="module"></script>
  <script type="module">
    import * as pdfjsLib from 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.min.mjs';

    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.worker.min.mjs';

    const pdfInput = document.getElementById('pdfFile');
    const batchSignAll = document.getElementById('batchSignAll');
    const p12Input = document.getElementById('p12File');
    const p12Pass = document.getElementById('p12Pass');
    const signerNameInput = document.getElementById('signerName');
    const signNoteInput = document.getElementById('signNote');
    const signImageInput = document.getElementById('signImage');
    const textSizeInput = document.getElementById('textSize');
    const fontFamilyInput = document.getElementById('fontFamily');
    const textColorInput = document.getElementById('textColor');
    const imageScaleInput = document.getElementById('imageScale');
    const rememberCreds = document.getElementById('rememberCreds');
    const configArea = document.getElementById('configArea');
    const tabP12Btn = document.getElementById('tabP12Btn');
    const tabSignBtn = document.getElementById('tabSignBtn');
    const tabP12 = document.getElementById('tabP12');
    const tabSign = document.getElementById('tabSign');
    const updateP12Btn = document.getElementById('updateP12Btn');
    const updateSignBtn = document.getElementById('updateSignBtn');
    const saveP12Btn = document.getElementById('saveP12Btn');
    const saveSignBtn = document.getElementById('saveSignBtn');
    const clearSavedBtn = document.getElementById('clearSavedBtn');
    const savedInfo = document.getElementById('savedInfo');
    const signBtn = document.getElementById('signBtn');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageIndicator = document.getElementById('pageIndicator');
    const statusEl = document.getElementById('status');
    const canvas = document.getElementById('pdfCanvas');
    const host = document.getElementById('pdfHost');
    const sigBox = document.getElementById('sigBox');
    const editorCanvas = document.getElementById('editorCanvas');
    const editorImage = document.getElementById('editorImage');
    const editorText = document.getElementById('editorText');
    const ctx = canvas.getContext('2d');

    let pdfDoc = null;
    let currentPage = 1;
    let totalPages = 0;
    let currentPdfFile = null;
    let savedP12File = null;
    const STORAGE_KEY = 'pnpki-signer-creds-v1';
    const DESIGN_STORAGE_KEY = 'pnpki-sign-design-v3';
    let editorImageDataUrl = '';
    let sigPreviewObjectUrl = '';
    let editorImageNatural = { width: 0, height: 0 };
    const editorState = {
      textX: 50,
      textY: 50,
      imgX: 50,
      imgY: 50,
    };

    function setStatus(msg, kind = 'muted') {
      statusEl.className = `card ${kind}`;
      statusEl.textContent = msg;
    }

    function clamp(val, min, max) {
      return Math.max(min, Math.min(max, val));
    }

    function updatePageControls() {
      pageIndicator.textContent = `Page ${totalPages ? currentPage : 0} / ${totalPages}`;
      prevPageBtn.disabled = !totalPages || currentPage <= 1;
      nextPageBtn.disabled = !totalPages || currentPage >= totalPages;
    }

    function fileToBase64(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const result = String(reader.result || '');
          const base64 = result.includes(',') ? result.split(',')[1] : result;
          resolve(base64);
        };
        reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
        reader.readAsDataURL(file);
      });
    }

    function base64ToUint8(base64) {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }

    function saveCredsUiInfo(message, kind = 'muted') {
      savedInfo.className = `card ${kind}`;
      savedInfo.textContent = message;
    }

    function setEditorCenter(el, xPct, yPct) {
      el.style.left = `${xPct}%`;
      el.style.top = `${yPct}%`;
    }

    function activateConfigTab(tabName) {
      configArea.style.display = 'block';
      const isP12 = tabName === 'p12';
      tabP12.classList.toggle('active', isP12);
      tabSign.classList.toggle('active', !isP12);
      tabP12Btn.classList.toggle('tab-active', isP12);
      tabSignBtn.classList.toggle('tab-active', !isP12);
    }

    function refreshSigPreview() {
      const name = (signerNameInput.value || '').trim() || 'SIGN HERE';
      const note = (signNoteInput.value || '').trim();
      sigBox.setAttribute('data-preview', note ? `${name}\n${note}` : name);
      scheduleSigDesignPreview();
    }

    function refreshEditorText() {
      const name = (signerNameInput.value || '').trim() || 'Signer';
      const note = (signNoteInput.value || '').trim();
      editorText.textContent = note ? `${name}\n${note}` : name;
      editorText.style.fontSize = `${Number(textSizeInput.value || 24)}px`;
      editorText.style.color = textColorInput.value || '#e0f2fe';
      editorText.style.fontFamily = fontFamilyInput.value || "'Segoe UI', Arial, sans-serif";
      setEditorCenter(editorText, editorState.textX, editorState.textY);
      scheduleSigDesignPreview();
    }

    function refreshEditorImage() {
      if (!editorImageDataUrl) {
        editorImage.style.display = 'none';
        scheduleSigDesignPreview();
        return;
      }

      editorImage.src = editorImageDataUrl;
      editorImage.style.display = 'block';
      setEditorCenter(editorImage, editorState.imgX, editorState.imgY);

      const canvasW = editorCanvas.clientWidth || 520;
      const baseW = canvasW * (Number(imageScaleInput.value || 60) / 100);
      const ratio = editorImageNatural.width > 0 && editorImageNatural.height > 0
        ? editorImageNatural.width / editorImageNatural.height
        : 2;
      const targetW = Math.max(20, baseW);
      const targetH = Math.max(20, targetW / ratio);
      editorImage.style.width = `${targetW}px`;
      editorImage.style.height = `${targetH}px`;
      scheduleSigDesignPreview();
    }

    function persistDesignSettings() {
      const payload = {
        signerName: signerNameInput.value || '',
        signNote: signNoteInput.value || '',
        textSize: Number(textSizeInput.value || 24),
        textColor: textColorInput.value || '#e0f2fe',
        fontFamily: fontFamilyInput.value || "'Segoe UI', Arial, sans-serif",
        imageScale: Number(imageScaleInput.value || 60),
        imageDataUrl: editorImageDataUrl || '',
        editorState,
      };
      localStorage.setItem(DESIGN_STORAGE_KEY, JSON.stringify(payload));
    }

    function restoreDesignSettings() {
      const raw = localStorage.getItem(DESIGN_STORAGE_KEY);
      if (!raw) return;
      try {
        const data = JSON.parse(raw);
        if (typeof data.signerName === 'string') signerNameInput.value = data.signerName;
        if (typeof data.signNote === 'string') signNoteInput.value = data.signNote;
        if (data.textSize) textSizeInput.value = String(data.textSize);
        if (data.textColor) textColorInput.value = data.textColor;
        if (data.fontFamily) fontFamilyInput.value = data.fontFamily;
        if (data.imageScale) imageScaleInput.value = String(data.imageScale);
        if (data.editorState) {
          editorState.textX = Number(data.editorState.textX ?? 50);
          editorState.textY = Number(data.editorState.textY ?? 50);
          editorState.imgX = Number(data.editorState.imgX ?? 50);
          editorState.imgY = Number(data.editorState.imgY ?? 50);
        }
        if (typeof data.imageDataUrl === 'string' && data.imageDataUrl.startsWith('data:image/')) {
          editorImageDataUrl = data.imageDataUrl;
        }
      } catch {
        localStorage.removeItem(DESIGN_STORAGE_KEY);
      }
    }

    function clampPercent(value) {
      return Math.max(5, Math.min(95, value));
    }

    function makeEditorDraggable(el, onMove) {
      let drag = null;
      el.addEventListener('pointerdown', (event) => {
        const rect = editorCanvas.getBoundingClientRect();
        drag = {
          rect,
        };
        el.setPointerCapture(event.pointerId);
        event.preventDefault();
      });

      el.addEventListener('pointermove', (event) => {
        if (!drag) return;
        const xPct = clampPercent(((event.clientX - drag.rect.left) / drag.rect.width) * 100);
        const yPct = clampPercent(((event.clientY - drag.rect.top) / drag.rect.height) * 100);
        onMove(xPct, yPct);
        refreshEditorText();
        refreshEditorImage();
        refreshSigPreview();
      });

      el.addEventListener('pointerup', () => {
        drag = null;
      });
    }

    function readFileAsDataUrl(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ''));
        reader.onerror = () => reject(reader.error || new Error('Failed to read file'));
        reader.readAsDataURL(file);
      });
    }

    function loadImageFromUrl(url) {
      return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error('Failed to load image'));
        img.src = url;
      });
    }

    function getDesignOutputSize() {
      const boxW = Math.max(40, sigBox.offsetWidth || 170);
      const boxH = Math.max(20, sigBox.offsetHeight || 60);
      const ratio = boxW / boxH;
      const width = 1000;
      const height = Math.max(220, Math.round(width / ratio));
      return { width, height };
    }

    async function drawEditorDesign(designCanvas) {
      const dctx = designCanvas.getContext('2d');
      dctx.clearRect(0, 0, designCanvas.width, designCanvas.height);

      const editorRect = editorCanvas.getBoundingClientRect();
      const editorW = editorRect.width || editorCanvas.clientWidth || 520;
      const editorH = editorRect.height || editorCanvas.clientHeight || 190;
      const scaleX = designCanvas.width / editorW;
      const scaleY = designCanvas.height / editorH;
      const hasLiveEditorLayout = !!editorRect.width && !!editorRect.height;

      if (editorImageDataUrl) {
        const img = await loadImageFromUrl(editorImageDataUrl);
        if (hasLiveEditorLayout) {
          const imageRect = editorImage.getBoundingClientRect();
          const relX = (imageRect.left - editorRect.left) * scaleX;
          const relY = (imageRect.top - editorRect.top) * scaleY;
          const relW = imageRect.width * scaleX;
          const relH = imageRect.height * scaleY;
          if (relW > 0 && relH > 0) {
            dctx.drawImage(img, relX, relY, relW, relH);
          }
        } else {
          const ratio = editorImageNatural.width > 0 && editorImageNatural.height > 0
            ? editorImageNatural.width / editorImageNatural.height
            : 2;
          const baseW = editorW * (Number(imageScaleInput.value || 60) / 100);
          const imgW = Math.max(20, baseW) * scaleX;
          const imgH = Math.max(20, (baseW / ratio)) * scaleY;
          const centerX = (editorState.imgX / 100) * designCanvas.width;
          const centerY = (editorState.imgY / 100) * designCanvas.height;
          dctx.drawImage(img, centerX - imgW / 2, centerY - imgH / 2, imgW, imgH);
        }
      }

      const lines = String(editorText.textContent || '').split(String.fromCharCode(10));
      let centerX;
      let centerY;
      let fontFamily;
      let fontWeight;
      let fontSize;
      let lineGap;
      let fillStyle;

      if (hasLiveEditorLayout) {
        const textRect = editorText.getBoundingClientRect();
        const computed = getComputedStyle(editorText);
        const fontSizePx = Number.parseFloat(computed.fontSize) || Number(textSizeInput.value || 24);
        const lineHeightPx = Number.parseFloat(computed.lineHeight) || (fontSizePx * 1.2);
        centerX = ((textRect.left - editorRect.left) + textRect.width / 2) * scaleX;
        centerY = ((textRect.top - editorRect.top) + textRect.height / 2) * scaleY;
        fontFamily = computed.fontFamily || (fontFamilyInput.value || 'Arial, sans-serif');
        fontWeight = computed.fontWeight || '700';
        fontSize = fontSizePx * scaleY;
        lineGap = lineHeightPx * scaleY;
        fillStyle = computed.color || (textColorInput.value || '#e0f2fe');
      } else {
        centerX = (editorState.textX / 100) * designCanvas.width;
        centerY = (editorState.textY / 100) * designCanvas.height;
        fontFamily = fontFamilyInput.value || 'Arial, sans-serif';
        fontWeight = '700';
        fontSize = Number(textSizeInput.value || 24) * scaleY;
        lineGap = fontSize * 1.2;
        fillStyle = textColorInput.value || '#e0f2fe';
      }

      dctx.fillStyle = fillStyle;
      dctx.textAlign = 'center';
      dctx.textBaseline = 'middle';
      dctx.font = `${fontWeight} ${fontSize}px ${fontFamily}`;
      const startY = centerY - ((lines.length - 1) * lineGap) / 2;
      for (let i = 0; i < lines.length; i++) {
        dctx.fillText(lines[i], centerX, startY + (i * lineGap));
      }
    }

    async function buildDesignBlob() {
      const { width, height } = getDesignOutputSize();
      const designCanvas = document.createElement('canvas');
      designCanvas.width = width;
      designCanvas.height = height;
      await drawEditorDesign(designCanvas);

      return await new Promise((resolve) => designCanvas.toBlob(resolve, 'image/png'));
    }

    async function updateSigBoxDesignPreview() {
      try {
        const designBlob = await buildDesignBlob();
        if (!designBlob) {
          return;
        }
        if (sigPreviewObjectUrl) {
          URL.revokeObjectURL(sigPreviewObjectUrl);
        }
        sigPreviewObjectUrl = URL.createObjectURL(designBlob);
        sigBox.style.backgroundImage = `url('${sigPreviewObjectUrl}')`;
        sigBox.style.backgroundSize = '100% 100%';
        sigBox.style.backgroundRepeat = 'no-repeat';
        sigBox.textContent = '';
      } catch {
      }
    }

    let sigPreviewRenderPending = false;
    function scheduleSigDesignPreview() {
      if (sigPreviewRenderPending) return;
      sigPreviewRenderPending = true;
      requestAnimationFrame(async () => {
        sigPreviewRenderPending = false;
        await updateSigBoxDesignPreview();
      });
    }

    function clearSavedCreds() {
      localStorage.removeItem(STORAGE_KEY);
      savedP12File = null;
      saveCredsUiInfo('No saved certificate.', 'muted');
    }

    function restoreSavedCreds() {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) {
        saveCredsUiInfo('No saved certificate.', 'muted');
        return;
      }

      try {
        const data = JSON.parse(raw);
        if (data.password) {
          p12Pass.value = data.password;
        }
        if (data.signerName) {
          signerNameInput.value = data.signerName;
        }
        if (data.signNote) {
          signNoteInput.value = data.signNote;
        }
        if (data.p12Base64) {
          const bytes = base64ToUint8(data.p12Base64);
          savedP12File = new File([bytes], data.p12Name || 'saved.p12', { type: 'application/x-pkcs12' });
          saveCredsUiInfo(`Saved certificate loaded: ${savedP12File.name}`, 'ok');
        } else {
          saveCredsUiInfo('Saved entry found, but no certificate bytes.', 'err');
        }
        rememberCreds.checked = true;
        refreshSigPreview();
      } catch {
        clearSavedCreds();
        saveCredsUiInfo('Saved certificate data was invalid and has been cleared.', 'err');
      }
    }

    async function persistCredsIfEnabled() {
      if (!rememberCreds.checked) return;

      const currentP12 = p12Input.files?.[0] || savedP12File;
      if (!currentP12) return;

      const p12Base64 = await fileToBase64(currentP12);
      const payload = {
        p12Name: currentP12.name,
        p12Base64,
        password: p12Pass.value || '',
        signerName: signerNameInput.value || '',
        signNote: signNoteInput.value || '',
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
      saveCredsUiInfo(`Saved certificate loaded: ${currentP12.name}`, 'ok');
    }

    clearSavedBtn.addEventListener('click', () => {
      clearSavedCreds();
      setStatus('Saved certificate/password cleared.', 'ok');
    });

    tabP12Btn.addEventListener('click', () => {
      activateConfigTab('p12');
    });

    tabSignBtn.addEventListener('click', () => {
      activateConfigTab('sign');
    });

    updateP12Btn.addEventListener('click', () => {
      activateConfigTab('p12');
      setStatus('PNPKI P12 update tab opened.', 'ok');
    });

    updateSignBtn.addEventListener('click', () => {
      activateConfigTab('sign');
      setStatus('Signature update tab opened.', 'ok');
    });

    saveP12Btn.addEventListener('click', async () => {
      if (!rememberCreds.checked) {
        setStatus('Enable "Remember certificate + password" first.', 'err');
        return;
      }
      await persistCredsIfEnabled();
      setStatus('Saved P12/password updated.', 'ok');
    });

    saveSignBtn.addEventListener('click', () => {
      persistDesignSettings();
      setStatus('Saved signature design updated.', 'ok');
    });

    p12Input.addEventListener('change', () => {
      const current = p12Input.files?.[0];
      if (current) {
        savedP12File = current;
        saveCredsUiInfo(`Selected certificate: ${current.name}`, 'ok');
      }
    });

    signerNameInput.addEventListener('input', () => {
      refreshSigPreview();
      refreshEditorText();
    });
    signNoteInput.addEventListener('input', () => {
      refreshSigPreview();
      refreshEditorText();
    });
    textSizeInput.addEventListener('input', () => {
      refreshEditorText();
    });
    textColorInput.addEventListener('input', () => {
      refreshEditorText();
    });
    fontFamilyInput.addEventListener('change', () => {
      refreshEditorText();
    });
    imageScaleInput.addEventListener('input', () => {
      refreshEditorImage();
    });

    signImageInput.addEventListener('change', () => {
      const imageFile = signImageInput.files?.[0];
      if (!imageFile) {
        editorImageDataUrl = '';
        editorImageNatural = { width: 0, height: 0 };
        refreshEditorImage();
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        editorImageDataUrl = String(reader.result || '');
        const img = new Image();
        img.onload = () => {
          editorImageNatural = { width: img.width, height: img.height };
          refreshEditorImage();
        };
        img.src = editorImageDataUrl;
      };
      reader.readAsDataURL(imageFile);
    });

    makeEditorDraggable(editorText, (xPct, yPct) => {
      editorState.textX = xPct;
      editorState.textY = yPct;
    });
    makeEditorDraggable(editorImage, (xPct, yPct) => {
      editorState.imgX = xPct;
      editorState.imgY = yPct;
    });

    restoreSavedCreds();
    restoreDesignSettings();
    refreshEditorText();
    refreshEditorImage();
    refreshSigPreview();
    updatePageControls();
    activateConfigTab('p12');
    configArea.style.display = 'none';

    async function renderPage(targetPage = currentPage) {
      const pdfFile = pdfInput.files?.[0];
      if (!pdfFile) {
        pdfDoc = null;
        currentPdfFile = null;
        totalPages = 0;
        currentPage = 1;
        updatePageControls();
        setStatus('Please choose a PDF first.', 'err');
        return;
      }

      if (!pdfDoc || currentPdfFile !== pdfFile) {
        const bytes = await pdfFile.arrayBuffer();
        pdfDoc = await pdfjsLib.getDocument({ data: bytes }).promise;
        currentPdfFile = pdfFile;
        totalPages = pdfDoc.numPages;
      }

      const requestedPage = clamp(Number(targetPage || 1), 1, Math.max(1, totalPages));

      setStatus('Rendering preview...', 'muted');

      const page = await pdfDoc.getPage(requestedPage);
      const viewport = page.getViewport({ scale: 1.35 });
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: ctx, viewport }).promise;
      currentPage = requestedPage;
      updatePageControls();

      const maxX = Math.max(0, canvas.width - sigBox.offsetWidth);
      const maxY = Math.max(0, canvas.height - sigBox.offsetHeight);
      sigBox.style.left = `${clamp(parseFloat(sigBox.style.left || '40'), 0, maxX)}px`;
      sigBox.style.top = `${clamp(parseFloat(sigBox.style.top || '40'), 0, maxY)}px`;

      setStatus('Preview ready. Drag the SIGN HERE box to desired location.', 'ok');
    }

    let drag = null;

    sigBox.addEventListener('pointerdown', (event) => {
      const rect = sigBox.getBoundingClientRect();
      drag = {
        startX: event.clientX,
        startY: event.clientY,
        left: rect.left - host.getBoundingClientRect().left,
        top: rect.top - host.getBoundingClientRect().top,
      };
      sigBox.setPointerCapture(event.pointerId);
      event.preventDefault();
    });

    sigBox.addEventListener('pointermove', (event) => {
      if (!drag) return;
      const dx = event.clientX - drag.startX;
      const dy = event.clientY - drag.startY;
      const maxX = Math.max(0, canvas.width - sigBox.offsetWidth);
      const maxY = Math.max(0, canvas.height - sigBox.offsetHeight);
      const nextLeft = clamp(drag.left + dx, 0, maxX);
      const nextTop = clamp(drag.top + dy, 0, maxY);
      sigBox.style.left = `${nextLeft}px`;
      sigBox.style.top = `${nextTop}px`;
    });

    sigBox.addEventListener('pointerup', () => {
      drag = null;
    });

    pdfInput.addEventListener('change', async () => {
      try {
        currentPage = 1;
        totalPages = 0;
        pdfDoc = null;
        currentPdfFile = null;
        updatePageControls();
        await renderPage(1);
      } catch (error) {
        setStatus(`Preview error: ${error.message || error}`, 'err');
      }
    });

    prevPageBtn.addEventListener('click', async () => {
      if (!totalPages || currentPage <= 1) return;
      try {
        await renderPage(currentPage - 1);
      } catch (error) {
        setStatus(`Preview error: ${error.message || error}`, 'err');
      }
    });

    nextPageBtn.addEventListener('click', async () => {
      if (!totalPages || currentPage >= totalPages) return;
      try {
        await renderPage(currentPage + 1);
      } catch (error) {
        setStatus(`Preview error: ${error.message || error}`, 'err');
      }
    });

    signBtn.addEventListener('click', async () => {
      try {
        const pdfFile = pdfInput.files?.[0];
        const p12File = p12Input.files?.[0] || savedP12File;
        const signImageFile = signImageInput.files?.[0];
        const password = p12Pass.value || '';
        const signerName = signerNameInput.value || '';
        const signNote = signNoteInput.value || '';
        const pageNumber = currentPage;
        const signAllPages = !!batchSignAll.checked;

        if (!pdfFile) {
          setStatus('Please choose a PDF file.', 'err');
          return;
        }
        if (!p12File) {
          setStatus('Please choose a .p12/.pfx file.', 'err');
          return;
        }
        if (!pdfDoc) {
          await renderPage();
        }

        const displayWidth = canvas.width;
        const displayHeight = canvas.height;

        if (!displayWidth || !displayHeight) {
          setStatus('Render preview first before signing.', 'err');
          return;
        }

        const boxX = parseFloat(sigBox.style.left || '0');
        const boxY = parseFloat(sigBox.style.top || '0');
        const boxW = sigBox.offsetWidth;
        const boxH = sigBox.offsetHeight;

        const payload = new FormData();
        payload.append('pdf_file', pdfFile);
        payload.append('p12_file', p12File);
        payload.append('password', password);
        payload.append('signer_name', signerName);
        payload.append('sign_note', signNote);
        payload.append('page', String(pageNumber));
        payload.append('sign_all_pages', signAllPages ? 'true' : 'false');
        payload.append('x_ratio', String(boxX / displayWidth));
        payload.append('y_ratio', String(boxY / displayHeight));
        payload.append('w_ratio', String(boxW / displayWidth));
        payload.append('h_ratio', String(boxH / displayHeight));
        if (signImageFile) {
          payload.append('sign_image', signImageFile);
        }

        const designBlob = await buildDesignBlob();
        if (designBlob) {
          payload.append('sign_design', designBlob, 'sign-design.png');
        }

        signBtn.disabled = true;
  setStatus(signAllPages ? 'Applying digital signature on all pages...' : 'Applying digital signature...', 'muted');

        const res = await fetch('/sign-pdf', {
          method: 'POST',
          body: payload,
        });

        if (!res.ok) {
          const errText = await res.text();
          setStatus(`Sign failed: ${errText}`, 'err');
          return;
        }

        const blob = await res.blob();
        const cd = res.headers.get('Content-Disposition') || '';
        const match = cd.match(/filename="([^"]+)"/i);
        const outName = match?.[1] || 'signed.pdf';

        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = outName;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);

        setStatus(`Signed PDF downloaded: ${outName}`, 'ok');
      } catch (error) {
        setStatus(`Sign failed: ${error.message || error}`, 'err');
      } finally {
        signBtn.disabled = false;
      }
    });
  </script>
</body>
</html>
"""


@app.get("/")
def index():
  response = make_response(render_template_string(PAGE, app_version=APP_VERSION))
  response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
  response.headers["Pragma"] = "no-cache"
  response.headers["Expires"] = "0"
  return response


@app.post("/sign-pdf")
def sign_pdf():
    pdf_file = request.files.get("pdf_file")
    p12_file = request.files.get("p12_file")
    sign_image_file = request.files.get("sign_image")
    sign_design_file = request.files.get("sign_design")
    password = request.form.get("password", "")
    sign_all_pages = (request.form.get("sign_all_pages", "false") or "false").strip().lower() in (
      "1",
      "true",
      "yes",
      "on",
    )
    signer_name = (request.form.get("signer_name", "") or "").strip()
    sign_note = (request.form.get("sign_note", "") or "").strip()

    if not pdf_file or not p12_file:
        return "Missing PDF or P12 file.", 400

    try:
        page_number = int(request.form.get("page", "1"))
        x_ratio = float(request.form.get("x_ratio", "0"))
        y_ratio = float(request.form.get("y_ratio", "0"))
        w_ratio = float(request.form.get("w_ratio", "0.2"))
        h_ratio = float(request.form.get("h_ratio", "0.08"))
    except ValueError:
        return "Invalid positioning data.", 400

    pdf_bytes = pdf_file.read()
    if not pdf_bytes:
        return "Empty PDF file.", 400

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception:
        return "Uploaded document is not a valid PDF.", 400

    if page_number < 1 or page_number > len(reader.pages):
        return f"Page out of range. PDF has {len(reader.pages)} page(s).", 400

    pages_to_sign = list(range(1, len(reader.pages) + 1)) if sign_all_pages else [page_number]

    p12_bytes = p12_file.read()
    if not p12_bytes:
      return "Empty P12 file.", 400

    signer, signer_error = _load_signer_from_p12_bytes(p12_bytes, password)
    if signer is None:
      return f"P12 load failed: {signer_error}", 400

    custom_stamp_style = None
    if sign_design_file:
      design_bytes = sign_design_file.read()
      if design_bytes:
        try:
          pil_image_module = importlib.import_module("PIL.Image")
          pdf_images_module = importlib.import_module("pyhanko.pdf_utils.images")
          image_obj = pil_image_module.open(io.BytesIO(design_bytes))
          PdfImage = pdf_images_module.PdfImage
          custom_stamp_style = TextStampStyle(
            stamp_text="",
            background=PdfImage(image_obj, writer=None),
            background_opacity=1.0,
            border_width=0,
          )
        except Exception as exc:
          return f"Invalid sign editor design image: {exc}", 400

    if custom_stamp_style is None:
      stamp_style_kwargs = {
        "stamp_text": "Digitally signed by %(signer)s\\n%(note_line)sDate: %(ts)s",
      }
      if sign_image_file:
        image_bytes = sign_image_file.read()
        if image_bytes:
          try:
            pil_image_module = importlib.import_module("PIL.Image")
            pdf_images_module = importlib.import_module("pyhanko.pdf_utils.images")

            image_obj = pil_image_module.open(io.BytesIO(image_bytes))
            PdfImage = pdf_images_module.PdfImage
            stamp_style_kwargs["background"] = PdfImage(image_obj, writer=None)
            stamp_style_kwargs["background_opacity"] = 1.0
          except Exception as exc:
            return (
              "Invalid signature image or missing Pillow package. "
              f"Details: {exc}",
              400,
            )
      stamp_style = TextStampStyle(**stamp_style_kwargs)
    else:
      stamp_style = custom_stamp_style

    display_name = signer_name or signer.subject_name or "Signer"
    note_line = f"{sign_note}\\n" if sign_note else ""

    current_bytes = pdf_bytes
    try:
      for page_no in pages_to_sign:
        loop_reader = PdfReader(io.BytesIO(current_bytes))
        page = loop_reader.pages[page_no - 1]
        page_width = float(page.mediabox.width)
        page_height = float(page.mediabox.height)

        left = x_ratio * page_width
        box_height = h_ratio * page_height
        box_width = w_ratio * page_width
        bottom = page_height - ((y_ratio * page_height) + box_height)

        left = max(0.0, min(left, page_width - box_width))
        bottom = max(0.0, min(bottom, page_height - box_height))
        right = left + box_width
        top = bottom + box_height

        field_name = f"Signature_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}_{page_no}"

        writer = IncrementalPdfFileWriter(io.BytesIO(current_bytes))
        fields.append_signature_field(
          writer,
          SigFieldSpec(
            sig_field_name=field_name,
            box=(left, bottom, right, top),
            on_page=page_no - 1,
          ),
        )

        meta = PdfSignatureMetadata(
          field_name=field_name,
          name=display_name,
        )
        pdf_signer = PdfSigner(
          signature_meta=meta,
          signer=signer,
          stamp_style=stamp_style,
        )

        loop_output = io.BytesIO()
        pdf_signer.sign_pdf(
          writer,
          output=loop_output,
          appearance_text_params={
            "signer": display_name,
            "note_line": note_line,
          },
        )
        current_bytes = loop_output.getvalue()
    except Exception as exc:
      return f"Could not sign PDF with this certificate: {exc}", 400

    output = io.BytesIO(current_bytes)
    output.seek(0)
    original_name = pdf_file.filename or "document.pdf"
    if original_name.lower().endswith(".pdf"):
        download_name = f"{original_name[:-4]}-signed.pdf"
    else:
        download_name = "signed.pdf"

    return send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name,
    )


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.errorhandler(Exception)
def handle_unexpected_error(exc: Exception):
  if isinstance(exc, HTTPException):
    return exc
  app.logger.exception("Unhandled application error")
  return f"Unhandled server error: {exc}", 500


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=False)
