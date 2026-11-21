"""Voxtral speech-to-text integration for le-chonk.

This module provides transcription capabilities using Mistral AI's Voxtral model.
It supports both API-based transcription (via Mistral's hosted service) and
local inference for offline/private use.

Usage:
    # API-based transcription (requires MISTRAL_API_KEY)
    from voxtral.transcribe import transcribe_audio
    text = transcribe_audio("path/to/audio.wav")
    
    # Or with raw audio bytes
    text = transcribe_audio(audio_bytes, format="wav")
    
    # Local inference (requires mlx-voxtral)
    from voxtral.local import transcribe_local
    text = transcribe_local("path/to/audio.wav")
"""

from voxtral.transcribe import transcribe_audio, transcribe_microphone
from voxtral.local import transcribe_local, LocalVoxtralTranscriber

__all__ = [
    "transcribe_audio",
    "transcribe_microphone", 
    "transcribe_local",
    "LocalVoxtralTranscriber",
]
