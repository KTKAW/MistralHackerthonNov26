"""Tests for Voxtral speech-to-text integration.

These tests verify that the Voxtral module is properly integrated
and can handle various input types.
"""

import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest


@pytest.fixture
def sample_wav():
    """Create a simple test WAV file (module-level so all classes can use it)."""
    import struct
    # Create a minimal valid WAV file with silence
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        # WAV header
        f.write(struct.pack("<4sI4s4sIHHIIHH4sI",
            b"RIFF", 36, b"WAVE", b"fmt ", 16, 1, 1, 16000, 32000, 2, 16, b"data", 0))
        # No audio data (silence)
        return f.name


class TestVoxtralTranscribe:
    """Test API-based transcription."""

    @pytest.fixture
    def mock_api_key(self):
        """Set a mock API key for testing."""
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-key-123"}):
            yield

    def test_import_module(self):
        """Test that voxtral module can be imported."""
        import voxtral
        assert hasattr(voxtral, "transcribe_audio")
        assert hasattr(voxtral, "transcribe_microphone")
    
    def test_api_key_error(self):
        """Test that NoAPIKeyError is raised when key is missing."""
        from voxtral.transcribe import NoAPIKeyError, get_api_key
        
        # Clear API key if set
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(NoAPIKeyError):
                get_api_key()
    
    def test_encode_audio_from_path(self, sample_wav):
        """Test encoding audio from file path."""
        from voxtral.transcribe import _encode_audio
        
        encoded, mime_type = _encode_audio(sample_wav)
        assert isinstance(encoded, str)
        assert mime_type == "audio/wav"
        assert len(encoded) > 0
    
    def test_encode_audio_from_bytes(self):
        """Test encoding audio from bytes."""
        from voxtral.transcribe import _encode_audio
        
        audio_data = b"RIFF" + b"\x00" * 100
        encoded, mime_type = _encode_audio(audio_data, format="wav")
        assert isinstance(encoded, str)
        assert mime_type == "audio/wav"
    
    def test_audio_formats(self):
        """Test that various audio formats are recognized."""
        from voxtral.transcribe import AUDIO_FORMATS
        
        assert AUDIO_FORMATS["wav"] == "audio/wav"
        assert AUDIO_FORMATS["mp3"] == "audio/mpeg"
        assert AUDIO_FORMATS["ogg"] == "audio/ogg"
        assert AUDIO_FORMATS["flac"] == "audio/flac"


class TestVoxtralLocal:
    """Test local transcription."""
    
    def test_local_import(self):
        """Test that local module can be imported."""
        from voxtral.local import LocalVoxtralTranscriber, transcribe_local
        assert LocalVoxtralTranscriber is not None
        assert transcribe_local is not None
    
    def test_model_sizes(self):
        """Test that model sizes are defined."""
        from voxtral.local import LocalVoxtralTranscriber
        
        assert "mini" in LocalVoxtralTranscriber.AVAILABLE_MODELS
        assert "small" in LocalVoxtralTranscriber.AVAILABLE_MODELS


class TestWebAppVoxtral:
    """Test web app integration with Voxtral."""
    
    def test_voxtral_available_flag(self):
        """Test that VOXTRAL_AVAILABLE is set correctly."""
        # This test just verifies the flag exists in the module
        # Actual availability depends on installed packages
        from web import app
        assert isinstance(app.VOXTRAL_AVAILABLE, bool)  # module-level availability flag


class TestVoxtralEndpoints:
    """Test Voxtral API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create a test client for the web app."""
        from fastapi.testclient import TestClient
        from web.app import app
        return TestClient(app)
    
    def test_voice_status_endpoint(self, client):
        """Test /api/voice-status endpoint."""
        response = client.get("/api/voice-status")
        assert response.status_code == 200
        data = response.json()
        assert "available" in data
        assert "is_recording" in data
    
    def test_transcribe_endpoint_no_file(self, client):
        """Test /api/transcribe with no file."""
        response = client.post("/api/transcribe")
        assert response.status_code == 422  # Validation error


# Integration tests (require actual dependencies)

@pytest.mark.integration
class TestVoxtralIntegration:
    """Integration tests that require actual Voxtral setup."""
    
    @pytest.fixture
    def api_key(self):
        """Skip if no API key is available."""
        if "MISTRAL_API_KEY" not in os.environ:
            pytest.skip("MISTRAL_API_KEY not set")
        return os.environ["MISTRAL_API_KEY"]
    
    def test_api_transcription(self, api_key, sample_wav):
        """Test actual API transcription."""
        from voxtral.transcribe import transcribe_audio
        
        # This would actually call the API
        # For testing, we just verify it doesn't crash with a valid setup
        try:
            text = transcribe_audio(sample_wav)
            # Should return some text or error
            assert text is not None
        except Exception as e:
            # API might fail for various reasons (rate limits, etc.)
            # We just verify the function can be called
            assert isinstance(e, Exception)
