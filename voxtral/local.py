"""Local Voxtral transcription using mlx-voxtral.

Provides offline/private speech-to-text using Mistral's Voxtral model
running locally with MLX (Apple Silicon) or other backends.

Requirements:
    pip install mlx-voxtral
    
Note: This requires downloading the Voxtral model weights (~8-10GB).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Union, Optional

from voxtral.transcribe import VoxtralTranscriptionError, _encode_audio


class LocalVoxtralTranscriber:
    """Local Voxtral transcription using mlx-voxtral.
    
    This class handles loading the Voxtral model and performing transcription
    locally without sending data to external APIs.
    
    Example:
        transcriber = LocalVoxtralTranscriber(model_size="mini")
        text = transcriber.transcribe("path/to/audio.wav")
        
        # Or with raw bytes
        text = transcriber.transcribe(audio_bytes, format="wav")
    """
    
    AVAILABLE_MODELS = {
        "mini": "mistralai/Voxtral-Mini-4B-Realtime-2602",
        "small": "mistralai/Voxtral-Small-24B-Realtime-2602",
    }
    
    def __init__(
        self,
        model_size: str = "mini",
        device: Optional[str] = None,
        dtype: str = "bfloat16",
        **kwargs,
    ):
        """Initialize the local transcriber.
        
        Args:
            model_size: Model size - "mini" (4B) or "small" (24B)
            device: Device to use (e.g., "mps" for Apple Silicon). Auto-detected if None.
            dtype: Data type for computation (bfloat16, float16, float32)
            **kwargs: Additional arguments passed to the mlx model
            
        Raises:
            ImportError: If mlx or mlx-voxtral is not installed
            ValueError: If model_size is not recognized
        """
        self.model_size = model_size
        self.device = device
        self.dtype = dtype
        self.kwargs = kwargs
        
        # Try to import mlx-voxtral
        try:
            import mlx_voxtral
            self._mlx_voxtral = mlx_voxtral
        except ImportError:
            raise ImportError(
                "mlx-voxtral is required for local transcription. "
                "Install with: pip install mlx-voxtral"
            )
        
        # Validate model size
        if model_size not in self.AVAILABLE_MODELS:
            raise ValueError(
                f"Unknown model size: {model_size}. Available: {list(self.AVAILABLE_MODELS.keys())}"
            )
        
        self.model_id = self.AVAILABLE_MODELS[model_size]
        self._model = None
        self._processor = None
        
    def _ensure_model_loaded(self):
        """Load the model if not already loaded."""
        if self._model is not None:
            return
        
        import mlx.core as mx
        from mlx_voxtral import VoxtralForConditionalGeneration, VoxtralProcessor
        
        # Auto-detect device
        if self.device is None:
            self.device = mx.default_device().type
        
        print(f"Loading {self.model_size} model on {self.device}...")
        
        # Load model and processor
        self._processor = VoxtralProcessor.from_pretrained(self.model_id)
        self._model = VoxtralForConditionalGeneration.from_pretrained(
            self.model_id,
            dtype=getattr(mlx.core, self.dtype, self.dtype),
            **self.kwargs,
        )
        
        print(f"Model loaded successfully.")
        
    def _preprocess_audio(self, audio: Union[str, bytes, Path]) -> str:
        """Preprocess audio file for Voxtral.
        
        Voxtral expects 16kHz mono audio. This function handles resampling if needed.
        Returns path to a temporary processed audio file.
        """
        if isinstance(audio, (str, Path)):
            audio_path = Path(audio)
        else:
            # Save bytes to temp file
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(audio)
                audio_path = Path(tmp.name)
        
        # Check if we need to process
        try:
            import soundfile as sf
            info = sf.info(audio_path)
            
            if info.samplerate == 16000 and info.channels == 1:
                return str(audio_path)
            
            # Need to resample
            data, rate = sf.read(audio_path)
            
            # Resample if needed
            if rate != 16000:
                import scipy.signal
                duration = len(data) / rate
                new_length = int(duration * 16000)
                data = scipy.signal.resample(data, new_length)
                rate = 16000
            
            # Convert to mono
            if len(data.shape) > 1 and data.shape[1] > 1:
                data = data.mean(axis=1)
            
            # Save to temp file
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                sf.write(tmp.name, data, 16000, format="WAV")
                return tmp.name
        except ImportError:
            # Fall back to ffmpeg
            try:
                import subprocess
                with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                    tmp_path = tmp.name
                
                cmd = [
                    "ffmpeg",
                    "-i", str(audio_path),
                    "-ar", "16000",
                    "-ac", "1",
                    "-acodec", "pcm_s16le",
                    tmp_path,
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                return tmp_path
            except (ImportError, subprocess.CalledProcessError):
                return str(audio_path)
        
        return str(audio_path)
    
    def transcribe(
        self,
        audio: Union[str, bytes, Path],
        format: Optional[str] = None,
        language: Optional[str] = None,
        temperature: float = 0.0,
        **generate_kwargs,
    ) -> str:
        """Transcribe audio using local Voxtral model.
        
        Args:
            audio: Audio file path, bytes, or Path
            format: Audio format (used for raw bytes)
            language: Language hint (ISO 639-1 code)
            temperature: Sampling temperature (0.0 to 1.0)
            **generate_kwargs: Additional arguments for text generation
            
        Returns:
            Transcribed text
            
        Raises:
            VoxtralTranscriptionError: If transcription fails
        """
        self._ensure_model_loaded()
        
        import mlx.core as mx
        
        # Preprocess audio
        processed_audio = self._preprocess_audio(audio)
        
        try:
            # Load and process audio
            from mlx_voxtral import load_audio
            audio_array = load_audio(processed_audio)
            
            # Get input features
            input_features = self._processor(
                audio_array,
                sampling_rate=16000,
                return_tensors="mlx",
            ).input_features
            
            # Generate text
            generated_ids = self._model.generate(
                inputs=input_features,
                temperature=temperature,
                **generate_kwargs,
            )
            
            # Decode
            transcription = self._processor.batch_decode(
                generated_ids,
                skip_special_tokens=True,
            )[0]
            
            return transcription
            
        except Exception as e:
            raise VoxtralTranscriptionError(f"Local transcription failed: {str(e)}")
        finally:
            # Clean up temp file if it was created
            if isinstance(audio, bytes):
                try:
                    os.unlink(processed_audio)
                except OSError:
                    pass
    
    def transcribe_batch(
        self,
        audio_list: list[Union[str, bytes, Path]],
        **kwargs,
    ) -> list[str]:
        """Transcribe multiple audio files.
        
        Args:
            audio_list: List of audio files/bytes to transcribe
            **kwargs: Arguments passed to transcribe()
            
        Returns:
            List of transcribed texts
        """
        return [self.transcribe(audio, **kwargs) for audio in audio_list]


# Global transcriber instance (lazy initialization)
_local_transcriber: Optional[LocalVoxtralTranscriber] = None


def get_local_transcriber(model_size: str = "mini") -> LocalVoxtralTranscriber:
    """Get or create a global local transcriber instance.
    
    Args:
        model_size: Model size ("mini" or "small")
        
    Returns:
        LocalVoxtralTranscriber instance
    """
    global _local_transcriber
    
    if _local_transcriber is None:
        _local_transcriber = LocalVoxtralTranscriber(model_size=model_size)
    
    return _local_transcriber


def transcribe_local(
    audio: Union[str, bytes, Path],
    format: Optional[str] = None,
    model_size: str = "mini",
    language: Optional[str] = None,
    temperature: float = 0.0,
    **kwargs,
) -> str:
    """Transcribe audio using local Voxtral model.
    
    This is a convenience function that uses a global transcriber instance.
    
    Args:
        audio: Audio file path, bytes, or Path
        format: Audio format
        model_size: Model size ("mini" or "small")
        language: Language hint
        temperature: Sampling temperature
        **kwargs: Additional generation arguments
        
    Returns:
        Transcribed text
        
    Raises:
        ImportError: If mlx-voxtral is not installed
        VoxtralTranscriptionError: If transcription fails
    """
    transcriber = get_local_transcriber(model_size)
    return transcriber.transcribe(audio, format, language, temperature, **kwargs)
