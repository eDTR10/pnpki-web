"""
pnpki_local.py  –  DTR PNPKI Signing Server
============================================
Minimal Flask server that exposes a single endpoint used by the
React frontend (PrintDTR) to digitally sign a DTR PDF with a PNPKI
P12/PFX certificate.

HOW TO RUN
----------
1. Install dependencies (one time):
       pip install flask flask-cors cryptography pypdf pyhanko pyhanko-certvalidator pillow

2. Start the server:
       python pnpki_local.py

   The server will listen on http://localhost:5000

ENDPOINTS
---------
POST /sign-pdf      – sign a DTR PDF (called by the React app)
GET  /health        – liveness check
"""

from __future__ import annotations

import io
import importlib
from datetime import datetime, timezone

# ── third-party ───────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.serialization import pkcs12
except ImportError:
    raise SystemExit(
        "\n[ERROR] 'cryptography' is not installed.\n"
        "Run:  pip install flask flask-cors cryptography pypdf pyhanko pyhanko-certvalidator pillow\n"
    )

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS          # pip install flask-cors
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

# ── app ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Allow requests from the Vite dev server and any localhost origin
CORS(app, origins=[
    "http://localhost:6969",
    "http://192.168.1.50:6969",
    "https://edtr10.github.io",
    "edtrmisor.pythonanywhere.com"
])

PORT = 5000


# ── helpers ───────────────────────────────────────────────────────────────────

def _candidate_passphrases(password: str) -> list[bytes | None]:
    """Return a list of byte encodings to try for the P12 password."""
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


def _load_signer(p12_bytes: bytes, password: str):
    """
    Load a pyhanko SimpleSigner from raw P12 bytes.
    Returns (signer, None) on success or (None, error_message) on failure.
    """
    last_error = None
    for passphrase in _candidate_passphrases(password):
        try:
            pyca_key, pyca_cert, pyca_chain = pkcs12.load_key_and_certificates(
                p12_bytes, passphrase
            )
        except Exception as exc:
            last_error = exc
            continue

        if pyca_key is None:
            return None, "P12 loaded but no private key found."
        if pyca_cert is None:
            return None, "P12 loaded but no signing certificate found."

        try:
            signing_key  = translate_pyca_cryptography_key_to_asn1(pyca_key)
            signing_cert = translate_pyca_cryptography_cert_to_asn1(pyca_cert)
            cert_store   = SimpleCertificateStore()
            if pyca_chain:
                cert_store.register_multiple(
                    translate_pyca_cryptography_cert_to_asn1(c) for c in pyca_chain
                )
            signer = signers.SimpleSigner(
                signing_cert=signing_cert,
                signing_key=signing_key,
                cert_registry=cert_store,
            )
            return signer, None
        except Exception as exc:
            return None, f"Signer setup failed: {exc}"

    if last_error is not None:
        return None, f"Could not decrypt P12 ({type(last_error).__name__}): {last_error}"
    return None, "Could not read P12 data."


# ── routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Simple liveness check."""
    return jsonify({"ok": True, "service": "pnpki-dtr-signer"})


@app.post("/verify-pdf")
def verify_pdf():
    """
    Verify all digital signatures in a PDF.
    Returns a JSON array of signature validation results.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext as CertVC

    pdf_file = request.files.get("pdf_file")
    if not pdf_file:
        return "Missing pdf_file.", 400

    pdf_bytes = pdf_file.read()
    if not pdf_bytes:
        return "pdf_file is empty.", 400

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
    except Exception:
        return "Not a valid PDF file.", 400

    try:
        embedded_sigs = reader.embedded_signatures
    except Exception as exc:
        return f"Could not read signature fields: {exc}", 400

    if not embedded_sigs:
        return jsonify({"signatures": [], "message": "No digital signatures found."})

    results = []
    for sig in embedded_sigs:
        entry: dict = {"field_name": sig.field_name}
        try:
            vc = CertVC(allow_fetching=False, revocation_mode="soft-fail")
            status = validate_pdf_signature(sig, signer_validation_context=vc)
            cert = status.signing_cert
            if cert is not None:
                subject     = str(cert.subject.human_friendly)
                issuer      = str(cert.issuer.human_friendly)
                tbs         = cert["tbs_certificate"]
                not_before  = str(tbs["validity"]["not_before"].native)
                not_after   = str(tbs["validity"]["not_after"].native)
            else:
                subject = issuer = not_before = not_after = "Unknown"

            entry.update({
                "signer":     subject,
                "issuer":     issuer,
                "not_before": not_before,
                "not_after":  not_after,
                "signed_at":  str(status.signer_reported_dt) if status.signer_reported_dt else "Not recorded",
                "intact":     bool(status.intact),
                "valid":      bool(status.valid),
                "modification_level": str(status.modification_level)
                    if hasattr(status, "modification_level") and status.modification_level else None,
                "coverage": str(status.coverage)
                    if hasattr(status, "coverage") and status.coverage else None,
            })
        except Exception as exc:
            entry["error"] = str(exc)

        # Attempt to extract bounding box + page number
        rect = None
        page_num = 1
        try:
            field    = sig.sig_field
            rect_raw = field.get("/Rect")
            if rect_raw is not None:
                rect = [float(x) for x in rect_raw]
            n_pages = reader.get_num_pages()
            for pidx in range(n_pages):
                pg     = reader.get_page(pidx)
                annots = pg.get("/Annots")
                if not annots:
                    continue
                for a in annots:
                    try:
                        aobj = a.get_object() if hasattr(a, "get_object") else reader.get_object(a)
                        t    = aobj.get("/T")
                        if t is not None and str(t) == sig.field_name:
                            page_num = pidx + 1
                            if rect is None:
                                wr = aobj.get("/Rect")
                                if wr is not None:
                                    rect = [float(x) for x in wr]
                            raise StopIteration
                    except StopIteration:
                        raise
                    except Exception:
                        continue
        except StopIteration:
            pass
        except Exception:
            pass

        entry["rect"] = rect
        entry["page"] = page_num
        results.append(entry)

    return jsonify({"signatures": results})


@app.post("/sign-pdf")
def sign_pdf():
    """
    Sign a PDF with a PNPKI P12 certificate.

    Expected multipart/form-data fields
    ─────────────────────────────────────
    pdf_file        (file)   – PDF to sign
    p12_file        (file)   – .p12 / .pfx certificate
    password        (str)    – P12 passphrase (may be empty)
    signer_name     (str)    – override display name (optional)
    sign_note       (str)    – extra text line below name (optional)
    page            (int)    – 1-based page number to place signature on
    sign_all_pages  (bool)   – "true" / "false"
    x_ratio         (float)  – left edge as fraction of page width   (0–1)
    y_ratio         (float)  – top  edge as fraction of page height  (0–1, from top)
    w_ratio         (float)  – box width  as fraction of page width
    h_ratio         (float)  – box height as fraction of page height
    sign_image      (file)   – optional PNG/JPG background for the sig box
    """

    # ── validate required files ──────────────────────────────────────────────
    pdf_file = request.files.get("pdf_file")
    p12_file = request.files.get("p12_file")

    if not pdf_file:
        return "Missing pdf_file.", 400
    if not p12_file:
        return "Missing p12_file.", 400

    # ── read inputs ──────────────────────────────────────────────────────────
    pdf_bytes = pdf_file.read()
    p12_bytes = p12_file.read()

    if not pdf_bytes:
        return "pdf_file is empty.", 400
    if not p12_bytes:
        return "p12_file is empty.", 400

    # ── parse form params ────────────────────────────────────────────────────
    password       = request.form.get("password", "")
    signer_name    = (request.form.get("signer_name", "") or "").strip()
    sign_note      = (request.form.get("sign_note",  "") or "").strip()
    sign_all_pages = (request.form.get("sign_all_pages", "false") or "false").strip().lower() in (
        "1", "true", "yes", "on"
    )

    try:
        page_number = int(request.form.get("page", "1"))
        x_ratio     = float(request.form.get("x_ratio", "0.55"))
        y_ratio     = float(request.form.get("y_ratio", "0.87"))
        w_ratio     = float(request.form.get("w_ratio", "0.38"))
        h_ratio     = float(request.form.get("h_ratio", "0.06"))
    except ValueError:
        return "Invalid numeric positioning data.", 400

    # ── validate PDF ─────────────────────────────────────────────────────────
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
    except Exception:
        return "Uploaded file is not a valid PDF.", 400

    total_pages = len(reader.pages)
    if page_number < 1 or page_number > total_pages:
        return f"Page {page_number} out of range (PDF has {total_pages} page(s)).", 400

    pages_to_sign = list(range(1, total_pages + 1)) if sign_all_pages else [page_number]

    # ── load signer ──────────────────────────────────────────────────────────
    signer, err = _load_signer(p12_bytes, password)
    if signer is None:
        return f"P12 error: {err}", 400

    # ── build stamp style ────────────────────────────────────────────────────
    # Priority: sign_design (pre-rendered canvas from React editor) > sign_image > default text
    sign_design_file = request.files.get("sign_design")
    sign_image_file  = request.files.get("sign_image")

    custom_stamp_style = None

    if sign_design_file:
        design_bytes = sign_design_file.read()
        if design_bytes:
            try:
                PIL_Image  = importlib.import_module("PIL.Image")
                pdf_images = importlib.import_module("pyhanko.pdf_utils.images")
                img_obj    = PIL_Image.open(io.BytesIO(design_bytes)).convert("RGBA")
                custom_stamp_style = TextStampStyle(
                    stamp_text=" ",          # non-empty so pyhanko renders the stamp
                    background=pdf_images.PdfImage(img_obj),
                    background_opacity=1.0,
                    border_width=0,
                )
            except Exception as exc:
                return f"Invalid sign_design image: {exc}", 400

    if custom_stamp_style is None and sign_image_file:
        image_bytes = sign_image_file.read()
        if image_bytes:
            try:
                PIL_Image  = importlib.import_module("PIL.Image")
                pdf_images = importlib.import_module("pyhanko.pdf_utils.images")
                img_obj    = PIL_Image.open(io.BytesIO(image_bytes))
                stamp_kwargs: dict = {
                    "stamp_text": "Digitally signed by: %(signer)s\n%(note_line)s",
                    "border_width": 0,
                    "background": pdf_images.PdfImage(img_obj, writer=None),
                    "background_opacity": 1.0,
                }
                custom_stamp_style = TextStampStyle(**stamp_kwargs)
            except Exception as exc:
                return f"Invalid signature image: {exc}", 400

    if custom_stamp_style is None:
        stamp_kwargs = {
            "stamp_text": "Digitally signed by: %(signer)s\n%(note_line)s",
            "border_width": 0,
        }
        custom_stamp_style = TextStampStyle(**stamp_kwargs)

    stamp_style   = custom_stamp_style
    display_name  = signer_name or signer.subject_name or "Signer"
    note_line     = f"{sign_note}\n" if sign_note else ""
    # When using a pre-rendered design image the stamp text params are already baked in
    using_design  = bool(sign_design_file)

    # ── sign each page ───────────────────────────────────────────────────────
    current_bytes = pdf_bytes
    try:
        for page_no in pages_to_sign:
            loop_reader = PdfReader(io.BytesIO(current_bytes))
            page        = loop_reader.pages[page_no - 1]
            page_w      = float(page.mediabox.width)
            page_h      = float(page.mediabox.height)

            # Convert top-origin ratios → PDF bottom-origin coordinates
            box_w  = w_ratio * page_w
            box_h  = h_ratio * page_h
            left   = x_ratio * page_w
            # y_ratio is measured from the TOP of the page
            bottom = page_h - (y_ratio * page_h) - box_h

            # Clamp so box stays within page bounds
            left   = max(0.0, min(left,   page_w - box_w))
            bottom = max(0.0, min(bottom, page_h - box_h))
            right  = left   + box_w
            top    = bottom + box_h

            field_name = (
                f"Sig_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}_{page_no}"
            )

            writer = IncrementalPdfFileWriter(io.BytesIO(current_bytes))
            fields.append_signature_field(
                writer,
                SigFieldSpec(
                    sig_field_name=field_name,
                    box=(left, bottom, right, top),
                    on_page=page_no - 1,
                ),
            )

            meta       = PdfSignatureMetadata(field_name=field_name, name=display_name)
            pdf_signer = PdfSigner(
                signature_meta=meta,
                signer=signer,
                stamp_style=stamp_style,
            )

            out = io.BytesIO()
            pdf_signer.sign_pdf(
                writer,
                output=out,
                appearance_text_params={} if using_design else {"signer": display_name, "note_line": note_line},
            )
            current_bytes = out.getvalue()

    except Exception as exc:
        return f"Signing failed: {exc}", 400

    # ── return signed PDF ────────────────────────────────────────────────────
    original_name = pdf_file.filename or "document.pdf"
    stem          = original_name[:-4] if original_name.lower().endswith(".pdf") else original_name
    download_name = f"{stem}-signed.pdf"

    return send_file(
        io.BytesIO(current_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name,
    )


# ── error handler ─────────────────────────────────────────────────────────────

@app.errorhandler(Exception)
def handle_error(exc: Exception):
    if isinstance(exc, HTTPException):
        return exc
    app.logger.exception("Unhandled error")
    return f"Server error: {exc}", 500


# ── entry point ───────────────────────────────────────────────────────────────


if __name__ == "__main__":
    app.run(debug=False)
