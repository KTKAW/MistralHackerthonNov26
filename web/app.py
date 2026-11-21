"""web/app.py — FastAPI grid on :8000. Track C (build/track-c-orchestration-ui).

  POST /runs                 {advisory_text} → {run_id, started_at}   (starts a run)
  GET  /runs/{run_id}        JSON tiles — ONLY for gate-passed repos
  GET  /                     HTML grid, polls every 2 s + 24 h countdown + approve
  POST /runs/{run_id}/approve  sends the "approve" signal (human, never automatic)
  GET  /artifacts/...        static run artifacts (verdict.json, early-warning.md)
  
  Voxtral (voice input):
  POST /api/transcribe        Upload audio file for transcription
  GET  /api/voice-status     Check if voice input is available
  POST /api/voice-start      Start voice recording (browser-based)
  POST /api/voice-stop       Stop voice recording and get transcription

Local mode (default, no DEPLOYMENT_NAME): runs are driven by a
`python -m orchestrator.workflow --run-local` subprocess, so killing the web app
does not kill runs; restart and they resume. Hosted mode: Mistral Workflows.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Voxtral availability flag (set to False if dependencies not installed)
VOXTRAL_AVAILABLE = True
try:
    from voxtral.transcribe import transcribe_audio, VoxtralAPIError, NoAPIKeyError
    from voxtral.local import transcribe_local, LocalVoxtralTranscriber
    from voxtral.transcribe import VoxtralTranscriptionError
except ImportError:
    VOXTRAL_AVAILABLE = False

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS_ROOT = os.environ.get("LE_CHONK_RUNS_ROOT", os.path.join(REPO_ROOT, "runs"))
HOSTED = bool(os.environ.get("DEPLOYMENT_NAME"))
CLOCK_HOURS = 24

app = FastAPI(title="le-chonk grid")


class StartRun(BaseModel):
    advisory_text: Optional[str] = None
    advisory_audio: Optional[str] = None  # Base64 encoded audio or file path


class TranscribeRequest(BaseModel):
    audio_format: Optional[str] = "wav"
    model: Optional[str] = "voxtral-mini-latest"
    language: Optional[str] = None
    use_local: Optional[bool] = False


# In-memory storage for voice recording state (for browser-based recording)
_voice_recording_state = {
    "is_recording": False,
    "audio_chunks": [],
    "sample_rate": 16000,
}


class VoiceRecordingState(BaseModel):
    is_recording: bool
    sample_rate: int = 16000


def _read_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _run_meta(run_id):
    return _read_json(os.path.join(RUNS_ROOT, run_id, "run.json")) or {}


def _gate_ok(v):
    g = v.get("gate") or {}
    return bool(g.get("ok")) and v.get("verdict") != "needs_human"


def _tiles(run_id):
    """Tiles ONLY for gate-passed repos — an unchecked claim never appears."""
    run_dir = os.path.join(RUNS_ROOT, run_id)
    tiles = []
    if not os.path.isdir(run_dir):
        return tiles
    for repo in sorted(os.listdir(run_dir)):
        v = _read_json(os.path.join(run_dir, repo, "verdict.json"))
        if not v or not _gate_ok(v):
            continue
        tiles.append({
            "repo": v.get("repo", repo),
            "verdict": v.get("verdict"),
            "reason": (v.get("reason") or "")[:280],
            "proof": v.get("proof") or [],
            "fix": v.get("fix"),
            "usage": v.get("usage"),
            "verdict_url": f"/artifacts/{run_id}/{repo}/verdict.json",
        })
    return tiles


def start_run(advisory_text: str):
    run_id = uuid.uuid4().hex[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    if HOSTED:
        from mistralai.client import Mistral
        client = Mistral(api_key=os.environ.get("MISTRAL_API_KEY"))
        client.workflows.execute_workflow(
            workflow_identifier="le_chonk_run",
            execution_id=run_id,
            input={"advisory_text": advisory_text},
            deployment_name=os.environ["DEPLOYMENT_NAME"],
        )
    else:
        run_dir = os.path.join(RUNS_ROOT, run_id)
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "run.json"), "w") as fh:
            json.dump({"run_id": run_id, "started_at": started_at, "status": "RUNNING",
                       "mode": "local", "advisory_text": advisory_text}, fh, indent=2)
        env = dict(os.environ)
        env.setdefault("OTEL_ENABLED", "false")
        log = open(os.path.join(run_dir, "worker.log"), "ab")
        subprocess.Popen(
            [sys.executable, "-m", "orchestrator.workflow",
             "--run-local", advisory_text, "--run-id", run_id],
            cwd=REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
    return run_id, started_at


@app.post("/runs")
async def post_run(body: StartRun):
    # Handle both text and audio input
    advisory_text = body.advisory_text
    
    if body.advisory_audio and not advisory_text:
        # Audio input provided - transcribe it
        try:
            if body.advisory_audio.startswith("data:"):
                # Base64 encoded audio data URI
                import base64
                import re
                match = re.match(r"data:audio/(\w+);base64,(.+)", body.advisory_audio)
                if match:
                    audio_format = match.group(1)
                    audio_data = base64.b64decode(match.group(2))
                    advisory_text = transcribe_audio(audio_data, format=audio_format)
            else:
                # Treat as file path
                advisory_text = transcribe_audio(body.advisory_audio)
        except (VoxtralTranscriptionError, NoAPIKeyError, VoxtralAPIError) as e:
            raise HTTPException(
                status_code=400,
                detail=f"Voice transcription failed: {str(e)}"
            )
    
    if not advisory_text:
        raise HTTPException(status_code=400, detail="Either advisory_text or advisory_audio must be provided")
    
    run_id, started_at = start_run(advisory_text)
    return {"run_id": run_id, "started_at": started_at, "advisory_text": advisory_text[:100] + "..." if len(advisory_text) > 100 else advisory_text}


@app.post("/api/transcribe")
async def api_transcribe(
    audio: UploadFile = File(...),
    model: str = "voxtral-mini-latest",
    language: Optional[str] = None,
    use_local: bool = False,
):
    """Transcribe uploaded audio file using Voxtral.
    
    Supports: WAV, MP3, OGG, FLAC, M4A, WEBM
    
    Returns:
        {"text": "transcribed text", "model": "model used", "local": true/false}
    """
    if not VOXTRAL_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Voxtral transcription is not available (missing dependencies)"
        )
    
    try:
        # Save to temp file
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp.write(await audio.read())
            tmp_path = tmp.name
        
        # Detect format from Content-Type or filename
        content_type = audio.content_type or ""
        audio_format = None
        if "wav" in content_type:
            audio_format = "wav"
        elif "mpeg" in content_type:
            audio_format = "mp3"
        elif "ogg" in content_type:
            audio_format = "ogg"
        elif "flac" in content_type:
            audio_format = "flac"
        else:
            # Try to detect from filename
            filename = audio.filename or ""
            if "." in filename:
                audio_format = filename.rsplit(".", 1)[-1].lower()
        
        # Transcribe
        if use_local:
            text = transcribe_local(tmp_path, model_size="mini" if "mini" in model else "small")
        else:
            text = transcribe_audio(tmp_path, format=audio_format, model=model, language=language)
        
        # Clean up
        os.unlink(tmp_path)
        
        return {
            "text": text,
            "model": model,
            "local": use_local,
            "language": language,
        }
        
    except (VoxtralTranscriptionError, NoAPIKeyError, VoxtralAPIError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transcription error: {str(e)}")


@app.get("/api/voice-status")
async def voice_status():
    """Check voice recording status."""
    return {
        "available": VOXTRAL_AVAILABLE,
        "is_recording": _voice_recording_state["is_recording"],
        "sample_rate": _voice_recording_state["sample_rate"],
    }


@app.post("/api/voice-start")
async def voice_start(sample_rate: int = 16000):
    """Start voice recording session."""
    _voice_recording_state["is_recording"] = True
    _voice_recording_state["audio_chunks"] = []
    _voice_recording_state["sample_rate"] = sample_rate
    return {"status": "recording_started", "sample_rate": sample_rate}


@app.post("/api/voice-stop")
async def voice_stop():
    """Stop voice recording and transcribe."""
    if not _voice_recording_state["is_recording"]:
        raise HTTPException(status_code=400, detail="No active recording")
    
    _voice_recording_state["is_recording"] = False
    audio_chunks = _voice_recording_state["audio_chunks"]
    _voice_recording_state["audio_chunks"] = []
    
    if not audio_chunks:
        raise HTTPException(status_code=400, detail="No audio recorded")
    
    # Combine chunks
    import struct
    audio_data = b"".join(audio_chunks)
    
    # Create WAV header (for raw PCM data)
    wav_header = self._create_wav_header(len(audio_data), _voice_recording_state["sample_rate"])
    full_audio = wav_header + audio_data
    
    try:
        text = transcribe_audio(full_audio, format="wav")
        return {"text": text, "status": "transcribed"}
    except (VoxtralTranscriptionError, NoAPIKeyError, VoxtralAPIError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/voice-chunk")
async def voice_chunk(audio: UploadFile = File(...)):
    """Upload audio chunk during recording (for browser streaming)."""
    if not _voice_recording_state["is_recording"]:
        raise HTTPException(status_code=400, detail="Recording not started")
    
    audio_data = await audio.read()
    _voice_recording_state["audio_chunks"].append(audio_data)
    return {"status": "chunk_received", "chunk_size": len(audio_data)}


@app.post("/api/voice-cancel")
async def voice_cancel():
    """Cancel current voice recording."""
    _voice_recording_state["is_recording"] = False
    _voice_recording_state["audio_chunks"] = []
    return {"status": "recording_cancelled"}


def _create_wav_header(data_length: int, sample_rate: int = 16000, channels: int = 1, bits_per_sample: int = 16) -> bytes:
    """Create a WAV header for raw PCM data."""
    byte_rate = sample_rate * channels * (bits_per_sample // 8)
    block_align = channels * (bits_per_sample // 8)
    
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        data_length + 36,  # File size - 8
        b"WAVE",
        b"fmt ",
        16,  # Subchunk1Size (for PCM)
        1,   # AudioFormat (1 = PCM)
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
        b"data",
        data_length,
    )
    return header


@app.get("/runs/{run_id}")
async def get_run(run_id: str):
    meta = _run_meta(run_id)
    return {
        "run_id": run_id,
        "started_at": meta.get("started_at"),
        "status": meta.get("status", "UNKNOWN"),
        "clock_hours": CLOCK_HOURS,
        "tiles": _tiles(run_id),
    }


@app.post("/runs/{run_id}/approve")
async def approve_run(run_id: str):
    if HOSTED:
        from mistralai.client import Mistral
        client = Mistral(api_key=os.environ.get("MISTRAL_API_KEY"))
        client.executions.signal_workflow_execution(
            execution_id=run_id, name="approve")
        return {"run_id": run_id, "approved": True, "mode": "hosted"}
    run_dir = os.path.join(RUNS_ROOT, run_id)
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "approved"), "w") as fh:
        fh.write(datetime.now(timezone.utc).isoformat())
    meta = _run_meta(run_id)
    meta["status"] = "APPROVED"
    with open(os.path.join(run_dir, "run.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return {"run_id": run_id, "approved": True, "mode": "local"}


def _create_wav_header(data_length: int, sample_rate: int = 16000, channels: int = 1, bits_per_sample: int = 16) -> bytes:
    """Create a WAV header for raw PCM data."""
    byte_rate = sample_rate * channels * (bits_per_sample // 8)
    block_align = channels * (bits_per_sample // 8)
    
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        data_length + 36,  # File size - 8
        b"WAVE",
        b"fmt ",
        16,  # Subchunk1Size (for PCM)
        1,   # AudioFormat (1 = PCM)
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bits_per_sample,
        b"data",
        data_length,
    )
    return header


INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>le-chonk grid</title>
<style>
 body{font-family:-apple-system,Helvetica Neue,sans-serif;margin:2rem;background:#fffdf8;color:#1d1d1b}
 h1{font-size:1.3rem} textarea{width:100%;height:6rem;font-family:monospace}
 #clock{font-size:2rem;font-variant-numeric:tabular-nums;margin:.5rem 0}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.8rem}
 .tile{border:1px solid #e4e0d6;border-radius:8px;padding:.7rem;background:#fff}
 .tile h3{margin:.1rem 0 .4rem;font-size:.95rem}
 .v-affected_fixed,.v-affected_proven{color:#8a2c1d;font-weight:600}
 .v-not_affected{color:#2c6e2c;font-weight:600}
 .v-needs_human{color:#8a6d1d;font-weight:600}
 button{padding:.4rem 1rem} .muted{color:#6b6b66;font-size:.8rem}
 /* Voice input styles */
 .voice-input-container{margin:1rem 0;display:flex;gap:.5rem;align-items:center}
 .voice-btn{background:#7a4b8c;color:#fff;border:none;border-radius:50%;width:40px;height:40px;cursor:pointer;font-size:1.2rem;display:flex;align-items:center;justify-content:center}
 .voice-btn.recording{background:#8a2c1d;animation:pulse 1s infinite}
 .voice-btn:disabled{opacity:.5;cursor:not-allowed}
 .voice-status{font-size:.8rem;color:#7a4b8c;margin-left:.5rem}
 .voice-error{color:#8a2c1d}
 @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
 .input-methods{display:flex;gap:.5rem;margin-bottom:.5rem}
 .input-methods label{cursor:pointer;display:flex;align-items:center;gap:.3rem;padding:.3rem .6rem;border:1px solid #e4e0d6;border-radius:4px;background:#fff}
 .input-methods input{display:none}
 .input-methods label:hover{border-color:#7a4b8c}
 .input-methods input:checked + label{border-color:#7a4b8c;background:#f8f5ff}
</style></head><body>
<h1>le-chonk — 24 h vulnerability response</h1>
<div class="muted">Enter a security advisory to start a run. Tiles appear only after the gate passes.</div>

<!-- Input method selector -->
<div class="input-methods">
  <input type="radio" id="input-text" name="input-method" value="text" checked>
  <label for="input-text">📝 Text</label>
  <input type="radio" id="input-voice" name="input-method" value="voice">
  <label for="input-voice">🎤 Voice</label>
</div>

<!-- Text input (default) -->
<div id="text-input">
  <textarea id="adv" placeholder="Paste security advisory text…"></textarea>
  <button onclick="startRun()">Start run</button>
</div>

<!-- Voice input -->
<div id="voice-input" style="display:none">
  <div class="voice-input-container">
    <button id="voiceBtn" class="voice-btn" onclick="toggleVoiceRecording()" title="Click to start/stop recording">🎤</button>
    <span id="voiceStatus" class="voice-status muted">Click microphone to start recording</span>
    <span id="voiceError" class="voice-error"></span>
  </div>
  <textarea id="voiceText" placeholder="Spoken advisory will appear here…" readonly style="width:100%;height:6rem;font-family:monospace;margin-top:.5rem"></textarea>
  <button id="voiceSubmitBtn" onclick="submitVoiceAdvisory()" disabled>Start run with voice</button>
</div>

<div id="clock"></div>
<div class="grid" id="grid"></div>
<button id="approveBtn" onclick="approve()" disabled>Approve early warning</button>
<div class="muted" id="status"></div>

<script>
let runId = new URLSearchParams(location.search).get('run');
let mediaRecorder = null;
let audioChunks = [];
let voiceApiAvailable = false;

// Check if voice API is available
fetch('/api/voice-status')
  .then(r => r.json())
  .then(data => {
    voiceApiAvailable = data.available;
    if (!voiceApiAvailable) {
      document.querySelector('input[value="voice"]').disabled = true;
      document.getElementById('voiceStatus').textContent = 'Voice input not available';
    }
  });

// Switch between input methods
function switchInputMethod() {
  const method = document.querySelector('input[name="input-method"]:checked').value;
  document.getElementById('text-input').style.display = method === 'text' ? 'block' : 'none';
  document.getElementById('voice-input').style.display = method === 'voice' ? 'block' : 'none';
  
  // Clear errors
  document.getElementById('voiceError').textContent = '';
  
  // Reset voice recording state
  if (method === 'voice' && voiceApiAvailable) {
    stopVoiceRecording();
  }
}

// Add event listeners for radio buttons
document.querySelectorAll('input[name="input-method"]').forEach(radio => {
  radio.addEventListener('change', switchInputMethod);
});

// Voice recording functions
async function startVoiceRecording() {
  if (!voiceApiAvailable) {
    document.getElementById('voiceError').textContent = 'Voice input not available';
    return;
  }
  
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    audioChunks = [];
    
    mediaRecorder.ondataavailable = (event) => {
      audioChunks.push(event.data);
    };
    
    mediaRecorder.onstop = async () => {
      const voiceBtn = document.getElementById('voiceBtn');
      const voiceStatus = document.getElementById('voiceStatus');
      voiceBtn.classList.remove('recording');
      voiceStatus.textContent = 'Processing...';
      
      if (audioChunks.length > 0) {
        try {
          // Combine chunks into one blob
          const audioBlob = new Blob(audioChunks, { type: 'audio/wav' });
          
          // Create form data and send to server
          const formData = new FormData();
          formData.append('audio', audioBlob, 'recording.wav');
          
          const response = await fetch('/api/transcribe', {
            method: 'POST',
            body: formData
          });
          
          const result = await response.json();
          if (response.ok) {
            document.getElementById('voiceText').value = result.text;
            document.getElementById('voiceSubmitBtn').disabled = false;
            voiceStatus.textContent = 'Recording complete. Review and submit.';
          } else {
            throw new Error(result.detail || 'Transcription failed');
          }
        } catch (error) {
          document.getElementById('voiceError').textContent = 'Error: ' + error.message;
          voiceStatus.textContent = 'Error occurred. Try again.';
        }
      } else {
        voiceStatus.textContent = 'No audio recorded. Try again.';
      }
      
      // Clean up
      stream.getTracks().forEach(track => track.stop());
    };
    
    mediaRecorder.start();
    document.getElementById('voiceBtn').classList.add('recording');
    document.getElementById('voiceStatus').textContent = 'Recording... Speak now.';
    document.getElementById('voiceError').textContent = '';
    
  } catch (error) {
    document.getElementById('voiceError').textContent = 'Error: ' + error.message;
    document.getElementById('voiceBtn').classList.remove('recording');
    document.getElementById('voiceStatus').textContent = 'Click microphone to start recording';
  }
}

function stopVoiceRecording() {
  if (mediaRecorder && mediaRecorder.state !== 'inactive') {
    mediaRecorder.stop();
  }
}

function toggleVoiceRecording() {
  if (document.getElementById('voiceBtn').classList.contains('recording')) {
    stopVoiceRecording();
  } else {
    startVoiceRecording();
  }
}

function submitVoiceAdvisory() {
  const text = document.getElementById('voiceText').value;
  if (!text.trim()) {
    document.getElementById('voiceError').textContent = 'Please record and transcribe audio first';
    return;
  }
  
  // Use the transcribed text to start a run
  startRun(text);
}

// Original functions
async function startRun(advisoryText = null){
  const advInput = document.getElementById('adv');
  const text = advisoryText || advInput.value;
  if(!text.trim()){
    document.getElementById('voiceError').textContent = 'Please provide advisory text or recording';
    return;
  }
  
  const r = await fetch('/runs',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({advisory_text:text})});
  const j = await r.json(); runId = j.run_id;
  history.replaceState(null,'','?run='+runId);
  document.getElementById('approveBtn').disabled=false;
  poll();
}

async function poll(){
  if(!runId) return;
  const r = await fetch('/runs/'+runId); const j = await r.json();
  document.getElementById('status').textContent =
    'run '+j.run_id+' — status: '+j.status;
  const t = j.started_at ? new Date(j.started_at).getTime() : Date.now();
  const left = Math.max(0, 24*3600*1000 - (Date.now()-t));
  const h = Math.floor(left/3600000), m = Math.floor(left%3600000/60000), s = Math.floor(left%60000/1000);
  document.getElementById('clock').textContent =
    String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')+' of 24:00:00';
  document.getElementById('grid').innerHTML = j.tiles.map(t=>
    `<div class="tile"><h3>${t.repo}</h3>
     <div class="v-${t.verdict}">${t.verdict}</div>
     <div>${t.reason}</div>
     ${t.proof.length?`<div class="muted">proof: ${t.proof.join(', ')}</div>`:''}
     <div class="muted"><a href="${t.verdict_url}">verdict.json</a></div></div>`).join('');
  setTimeout(poll, 2000);   // poll every 2 s
}

async function approve(){
  if(!runId) return;
  await fetch('/runs/'+runId+'/approve',{method:'POST'});
  document.getElementById('status').textContent = 'approve signal sent — run completing';
}

if(runId){ 
  document.getElementById('approveBtn').disabled=false; 
  poll(); 
}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return INDEX_HTML


if os.path.isdir(RUNS_ROOT):
    app.mount("/artifacts", StaticFiles(directory=RUNS_ROOT), name="artifacts")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
