"""Voxtral transcription via Mistral API.

Uses Mistral's hosted Voxtral service for speech-to-text transcription.
Requires MISTRAL_API_KEY environment variable.

API Documentation: https://docs.mistral.ai/api/#tag/Voice/operation/voice_transcribe
"""

from __future__ import annotations

import base64
import os
import tempfile
import wave
from io import BytesIO
from pathlib import Path
from typing import Union, Optional, BinaryIO

import httpx


class VoxtralTranscriptionError(Exception):
    """Raised when Voxtral transcription fails."""
    pass


class VoxtralAPIError(VoxtralTranscriptionError):
    """Raised when the Voxtral API returns an error."""
    pass


class NoAPIKeyError(VoxtralTranscriptionError):
    """Raised when MISTRAL_API_KEY is not set."""
    pass


# Supported audio formats and their MIME types
AUDIO_FORMATS = {
    "wav": "audio/wav",
    "mp3": "audio/mpeg",
    "ogg": "audio/ogg",
    "flac": "audio/flac",
    "m4a": "audio/mp4",
    "webm": "audio/webm",
}


def get_api_key() -> str:
    """Get the Mistral API key from environment."""
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise NoAPIKeyError(
            "MISTRAL_API_KEY environment variable is required for Voxtral API transcription. "
            "Set it with: export MISTRAL_API_KEY='your-api-key'"
        )
    return api_key


def _encode_audio(audio: Union[str, bytes, Path, BinaryIO], 
                  format: Optional[str] = None) -> tuple[str, str]:
    """Encode audio data for API upload.
    
    Returns:
        Tuple of (base64_encoded_audio, mime_type)
    """
    # Handle file path
    if isinstance(audio, (str, Path)):
        audio_path = Path(audio)
        if not audio_path.exists():
            raise FileNotFoundError(f"Audio file not found: {audio_path}")
        
        # Infer format from extension if not specified
        if format is None:
            format = audio_path.suffix.lower().lstrip(".")
        
        with open(audio_path, "rb") as f:
            audio_data = f.read()
    elif isinstance(audio, bytes):
        audio_data = audio
    elif hasattr(audio, "read"):
        # BinaryIO
        audio_data = audio.read()
    else:
        raise TypeError(f"Unsupported audio type: {type(audio)}")
    
    # Validate and get MIME type
    format = format or "wav"
    mime_type = AUDIO_FORMATS.get(format.lower(), "audio/wav")
    
    # Encode as base64
    encoded = base64.b64encode(audio_data).decode("utf-8")
    return encoded, mime_type


def _resample_audio_if_needed(audio_path: str, target_rate: int = 16000) -> str:
    """Resample audio to target rate if needed (using sox or ffmpeg).
    
    Voxtral expects 16kHz mono audio. This function resamples if necessary.
    Returns path to resampled audio file (or original if already correct).
    """
    try:
        import soundfile as sf
        info = sf.info(audio_path)
        if info.samplerate == target_rate and info.channels == 1:
            return audio_path
        
        # Need to resample
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
            tmp_path = tmp.name
        
        data, rate = sf.read(audio_path)
        if rate != target_rate:
            # Simple resampling (for better quality, use sox/ffmpeg)
            import scipy.signal
            duration = len(data) / rate
            new_length = int(duration * target_rate)
            data = scipy.signal.resample(data, new_length)
        
        if len(data.shape) > 1 and data.shape[1] > 1:
            # Convert to mono
            data = data.mean(axis=1)
        
        sf.write(tmp_path, data, target_rate, format="WAV")
        return tmp_path
    except ImportError:
        # Fall back to using ffmpeg if soundfile not available
        try:
            import subprocess
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp_path = tmp.name
            
            cmd = [
                "ffmpeg",
                "-i", audio_path,
                "-ar", str(target_rate),
                "-ac", "1",
                "-acodec", "pcm_s16le",
                tmp_path,
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return tmp_path
        except (ImportError, subprocess.CalledProcessError):
            # Return original and let API handle it
            return audio_path


async def transcribe_audio_async(
    audio: Union[str, bytes, Path, BinaryIO],
    format: Optional[str] = None,
    model: str = "voxtral-mini-latest",
    language: Optional[str] = None,
    temperature: float = 0.0,
    timeout: float = 120.0,
) -> str:
    """Transcribe audio asynchronously using Voxtral API.
    
    Args:
        audio: Audio file path, bytes, or file-like object
        format: Audio format (wav, mp3, ogg, etc.). Auto-detected from file extension if not provided.
        model: Voxtral model to use (default: voxtral-mini-latest)
        language: Optional language hint (ISO 639-1 code, e.g., "en", "fr")
        temperature: Sampling temperature (0.0 to 1.0)
        timeout: Request timeout in seconds
        
    Returns:
        Transcribed text
        
    Raises:
        NoAPIKeyError: If MISTRAL_API_KEY is not set
        VoxtralAPIError: If the API returns an error
        VoxtralTranscriptionError: For other transcription errors
    """
    api_key = get_api_key()
    
    # Encode audio
    encoded_audio, mime_type = _encode_audio(audio, format)
    
    # Build request
    url = "https://api.mistral.ai/v1/voice/transcribe"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    
    payload = {
        "audio": encoded_audio,
        "audio_mime_type": mime_type,
        "model": model,
    }
    
    if language:
        payload["language"] = language
    if temperature != 0.0:
        payload["temperature"] = temperature
    
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            result = response.json()
            return result.get("text", "")
        except httpx.HTTPStatusError as e:
            error_detail = f"HTTP {e.response.status_code}"
            try:
                error_json = e.response.json()
                error_detail += f": {error_json.get('message', str(error_json))}"
            except Exception:
                error_detail += f": {e.response.text}"
            raise VoxtralAPIError(f"Voxtral API error: {error_detail}")
        except httpx.RequestError as e:
            raise VoxtralAPIError(f"Request failed: {str(e)}")


def transcribe_audio(
    audio: Union[str, bytes, Path, BinaryIO],
    format: Optional[str] = None,
    model: str = "voxtral-mini-latest",
    language: Optional[str] = None,
    temperature: float = 0.0,
    timeout: float = 120.0,
) -> str:
    """Transcribe audio synchronously using Voxtral API.
    
    Args:
        audio: Audio file path, bytes, or file-like object
        format: Audio format (wav, mp3, ogg, etc.). Auto-detected from file extension if not provided.
        model: Voxtral model to use (default: voxtral-mini-latest)
        language: Optional language hint (ISO 639-1 code, e.g., "en", "fr")
        temperature: Sampling temperature (0.0 to 1.0)
        timeout: Request timeout in seconds
        
    Returns:
        Transcribed text
        
    Raises:
        NoAPIKeyError: If MISTRAL_API_KEY is not set
        VoxtralAPIError: If the API returns an error
        VoxtralTranscriptionError: For other transcription errors
    """
    import asyncio
    return asyncio.run(transcribe_audio_async(
        audio, format, model, language, temperature, timeout
    ))


def transcribe_microphone(
    duration: Optional[float] = None,
    model: str = "voxtral-mini-latest",
    language: Optional[str] = None,
    temperature: float = 0.0,
    sample_rate: int = 16000,
    channels: int = 1,
) -> str:
    """Record audio from microphone and transcribe using Voxtral API.
    
    Args:
        duration: Recording duration in seconds. If None, records until silence or Ctrl+C.
        model: Voxtral model to use
        language: Optional language hint
        temperature: Sampling temperature
        sample_rate: Audio sample rate (default: 16000 for Voxtral)
        channels: Audio channels (default: 1 for mono)
        
    Returns:
        Transcribed text
        
    Raises:
        NoAPIKeyError: If MISTRAL_API_KEY is not set
        VoxtralAPIError: If the API returns an error
        ImportError: If PyAudio is not installed
        RuntimeError: If microphone cannot be accessed
    """
    try:
        import pyaudio
    except ImportError:
        raise ImportError(
            "PyAudio is required for microphone recording. Install with: pip install pyaudio"
        )
    
    # Initialize PyAudio
    audio = pyaudio.PyAudio()
    
    try:
        # Open stream
        stream = audio.open(
            format=pyaudio.paInt16,
            channels=channels,
            rate=sample_rate,
            input=True,
            frames_per_buffer=1024,
        )
        
        print("Recording... Press Ctrl+C to stop or speak and wait for silence detection.")
        
        # Record audio
        audio_frames = []
        
        if duration:
            # Record for fixed duration
            import time
            start_time = time.time()
            while time.time() - start_time < duration:
                data = stream.read(1024)
                audio_frames.append(data)
        else:
            # Record until silence (simple implementation)
            import time
            silence_threshold = 500  # Arbitrary threshold for silence detection
            silence_duration = 1.0  # Seconds of silence to stop
            silent_frames = 0
            
            while True:
                try:
                    data = stream.read(1024)
                    audio_frames.append(data)
                    
                    # Simple silence detection
                    import struct
                    # Convert bytes to integers
                    audio_data = struct.unpack(f"{len(data)//2}h", data)
                    max_val = max(abs(s) for s in audio_data)
                    
                    if max_val < silence_threshold:
                        silent_frames += 1
                        if silent_frames >= (silence_duration * sample_rate / 1024):
                            break
                    else:
                        silent_frames = 0
                except KeyboardInterrupt:
                    print("Stopped by user.")
                    break
        
        # Stop and close stream
        stream.stop_stream()
        stream.close()
        
        # Convert to bytes
        audio_data = b"".join(audio_frames)
        
        # Transcribe
        return transcribe_audio(audio_data, format="wav")
        
    except Exception as e:
        stream.stop_stream()
        stream.close()
        raise RuntimeError(f"Microphone recording failed: {str(e)}")
    finally:
        audio.terminate()
