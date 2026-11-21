# Voxtral Speech-to-Text Integration

This module provides voice input capabilities for the le-chonk vulnerability response system, allowing security engineers to **dictate advisories** instead of typing them. This is especially valuable during the critical 24-hour response window when speed is essential.

## Features

- ✅ **Voice-to-Text Transcription**: Dictate security advisories using Mistral's Voxtral model
- ✅ **API-Based**: Use Mistral's hosted Voxtral service (requires API key)
- ✅ **Local Inference**: Run Voxtral locally on Apple Silicon with MLX (offline/private)
- ✅ **Browser Recording**: Record directly from browser microphone
- ✅ **Audio File Upload**: Upload pre-recorded audio files (WAV, MP3, OGG, etc.)
- ✅ **Seamless Integration**: Works with the existing web UI and workflow

## Quick Start

### Option 1: API-Based (Recommended for Hackathon)

1. **Install dependencies**:
   ```bash
   pip install httpx pyaudio
   ```

2. **Set your API key**:
   ```bash
   export MISTRAL_API_KEY="your-mistral-api-key"
   ```

3. **Start the web app**:
   ```bash
   python -m web.app
   ```

4. **Open http://localhost:8000** and click the 🎤 Voice button to start dictating!

### Option 2: Local Inference (Offline/Private)

1. **Install MLX and mlx-voxtral**:
   ```bash
   pip install mlx-voxtral mlx
   ```

2. **Download model weights** (first run will do this automatically, ~8-10GB):
   ```python
   from voxtral.local import LocalVoxtralTranscriber
   transcriber = LocalVoxtralTranscriber(model_size="mini")
   ```

3. **Use local transcription**:
   ```python
   text = transcriber.transcribe("path/to/audio.wav")
   ```

## Usage Examples

### Python API

```python
# API-based transcription
from voxtral.transcribe import transcribe_audio

# From file
text = transcribe_audio("advisory.wav")

# From bytes
audio_bytes = open("advisory.wav", "rb").read()
text = transcribe_audio(audio_bytes, format="wav")

# With language hint
text = transcribe_audio("french_advisory.wav", language="fr")
```

```python
# Local inference
from voxtral.local import transcribe_local

text = transcribe_local("advisory.wav", model_size="mini")
```

```python
# Microphone recording
from voxtral.transcribe import transcribe_microphone

# Record for 10 seconds
text = transcribe_microphone(duration=10)

# Record until silence
text = transcribe_microphone()
```

### Web API

**Upload audio file**:
```bash
curl -X POST -F "audio=@advisory.wav" http://localhost:8000/api/transcribe
```

**With parameters**:
```bash
curl -X POST \
  -F "audio=@advisory.wav" \
  -F "model=voxtral-mini-latest" \
  -F "language=en" \
  http://localhost:8000/api/transcribe
```

**Local inference**:
```bash
curl -X POST -F "audio=@advisory.wav" -F "use_local=true" http://localhost:8000/api/transcribe
```

### Web UI

1. Open http://localhost:8000
2. Click the "🎤 Voice" radio button
3. Click the microphone button to start recording
4. Speak your advisory
5. Click the microphone again to stop
6. Review the transcription
7. Click "Start run with voice"

## Supported Audio Formats

- WAV (recommended)
- MP3
- OGG
- FLAC
- M4A
- WEBM

**Note**: Voxtral expects 16kHz mono audio. The system will automatically resample if needed.

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MISTRAL_API_KEY` | For API mode | Mistral AI API key for hosted Voxtral |
| `LE_CHONK_VOXTRAL_LOCAL` | No | Set to "1" to prefer local inference |

### Models Available

- `voxtral-mini-latest` (4B parameters) - Faster, lower latency
- `voxtral-small-latest` (24B parameters) - More accurate, higher latency

## Performance Tips

1. **For API mode**: Use `voxtral-mini-latest` for faster transcription
2. **For local mode**: Use Apple Silicon (M1/M2/M3) with MLX backend
3. **Audio quality**: Speak clearly, minimize background noise
4. **Silence detection**: The system automatically stops after 1 second of silence

## Error Handling

Common issues and solutions:

- **"MISTRAL_API_KEY not set"**: Set the environment variable with your API key
- **"mlx-voxtral not installed"**: Install with `pip install mlx-voxtral`
- **"PyAudio not installed"**: Install with `pip install pyaudio` (may require system dependencies)
- **"Model not found"**: First run will download weights (~8-10GB)

## Security Considerations

- **API mode**: Audio is sent to Mistral's servers. Do not use for sensitive/confidential advisories.
- **Local mode**: Audio stays on your machine. Suitable for sensitive data.
- **Browser recording**: Audio is processed client-side first, then sent to your server.

## Hackathon Tips

1. **Demo ready**: The voice input adds a "wow factor" to your demo
2. **Speed**: Dictating is faster than typing for long advisories
3. **Accessibility**: Makes the tool usable for people with disabilities
4. **Mobile-friendly**: Works on mobile devices with microphone support

## Files

- `voxtral/__init__.py` - Main module exports
- `voxtral/transcribe.py` - API-based transcription
- `voxtral/local.py` - Local inference with MLX
- `web/app.py` - Updated with voice endpoints and UI

## Testing

```python
# Test API transcription
python -c "from voxtral.transcribe import transcribe_audio; print(transcribe_audio('test.wav'))"

# Test local transcription
python -c "from voxtral.local import transcribe_local; print(transcribe_local('test.wav'))"
```

## Contributing

Pull requests welcome! Please:
- Add tests for new features
- Keep dependencies optional where possible
- Document breaking changes

## License

Same as the main project (see PROJECT.md).

## Links

- [Mistral Voxtral Documentation](https://docs.mistral.ai/models/voxtral)
- [mlx-voxtral on GitHub](https://github.com/ml-explore/mlx-voxtral)
- [antirez/voxtral.c](https://github.com/antirez/voxtral.c) - Pure C implementation
