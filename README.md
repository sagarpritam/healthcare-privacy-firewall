# 🛡️ Healthcare Privacy Firewall

A production-ready API firewall for detecting, masking, and scoring PHI/PII in healthcare API payloads. Supports text, image, and audio scanning with HIPAA-aware policy enforcement.

## Architecture

```
Client Request
    │
    ▼
┌─────────────────────────┐
│   FastAPI Gateway        │  ← Rate limiting, validation, routing
│   (proxy_server.py)      │
└──────────┬──────────────┘
           │
     ┌─────┴──────┐
     │ Redis Queue │  ← Job queue for async processing
     └─────┬──────┘
           │
   ┌───────┼────────┐
   ▼       ▼        ▼
┌──────┐ ┌──────┐ ┌──────┐
│ Text │ │Image │ │Audio │  ← Detection workers
│Worker│ │Worker│ │Worker│
└──┬───┘ └──┬───┘ └──┬───┘
   │        │        │
   ▼        ▼        ▼
┌─────────────────────────┐
│ Detection Engine         │  ← Presidio NLP + spaCy + Regex
│ (presidio + regex)       │
└──────────┬──────────────┘
           │
┌──────────┴──────────────┐
│ Masking Engine           │  ← Redact / Hash / Partial mask
│ (pii_masker, blur)       │
└──────────┬──────────────┘
           │
┌──────────┴──────────────┐
│ Intelligence Engine      │  ← Risk scoring + Policy evaluation
│ (risk + policy)          │
└──────────┬──────────────┘
           │
   ┌───────┼────────┐
   ▼       ▼        ▼
┌──────┐ ┌──────┐ ┌──────────┐
│ DB   │ │Alert │ │Analytics │
│(PgSQL)│ │(Slack)│ │Dashboard │
└──────┘ └──────┘ └──────────┘
```

## Features

- **Multi-modal scanning**: Text, image (OCR), and audio (Whisper) processing
- **Presidio + spaCy NLP**: Enterprise-grade entity recognition
- **Custom regex patterns**: Medical-specific (MRN, NPI, ICD-10, CPT, DEA) + credential detection
- **Risk scoring**: Weighted 0-100 scoring with volume/diversity/context multipliers
- **Policy engine**: HIPAA, PCI-DSS, credential leak rules with block/alert/warn actions
- **Masking strategies**: Redact, SHA-256 hash, partial mask — configurable per entity type
- **Redis queue**: Async job processing with text, image, and audio workers
- **PostgreSQL storage**: Scan logs, detections, alerts, policy audits with full audit trail
- **Slack alerts**: Rich Block Kit notifications on risk threshold breaches
- **Prometheus metrics**: Export for Grafana/monitoring integration
- **React dashboard**: Real-time analytics with charts, live scanner, and recent scans
- **Docker**: Full stack containerization with multi-service compose

## Quick Start

### Docker (Recommended)

```bash
# Clone the repository
cd healthcare-privacy-firewall

# Copy and configure environment
cp .env.example .env

# Start all services
cd docker
docker-compose up --build -d

# Verify
curl http://localhost:8000/health
```

### Local Development

```bash
cd healthcare-privacy-firewall

# Create virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Start PostgreSQL and Redis (Docker)
docker run -d --name pg -e POSTGRES_DB=healthcare_firewall \
  -e POSTGRES_USER=firewall_user -e POSTGRES_PASSWORD=firewall_pass \
  -p 5432:5432 postgres:16-alpine

docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run the gateway
python -m gateway.proxy_server
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan/text` | Scan text for PHI/PII |
| `POST` | `/scan/image` | Scan image via OCR |
| `POST` | `/scan/audio` | Scan audio via Whisper |
| `GET`  | `/scan/{id}/status` | Get async job status |
| `GET`  | `/health` | System health check |
| `GET`  | `/analytics/dashboard` | Dashboard metrics |
| `GET`  | `/analytics/metrics` | Prometheus metrics |
| `GET`  | `/queue/status` | Queue status |
| `GET`  | `/docs` | Swagger UI |

## Usage Examples

### Scan Text

```bash
curl -X POST http://localhost:8000/scan/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Patient John Doe, SSN 123-45-6789, DOB 01/15/1980, MRN: AB-123456, NPI: 1234567890"
  }'
```

**Response:**
```json
{
  "scan_id": "a1b2c3...",
  "masked_text": "Patient [PERSON], SSN [HASH:a8f3...], DOB [DATE_OF_BIRTH], MRN: [MEDICAL_RECORD_NUMBER], NPI: [NPI_NUMBER]",
  "entity_count": 5,
  "risk_score": 72.5,
  "risk_level": "high",
  "policy_result": "warn",
  "should_block": false,
  "detections": [...]
}
```

### Scan Image

```bash
curl -X POST http://localhost:8000/scan/image \
  -F "file=@medical_form.png" \
  -F "mode=blur"
```

### Async Scan (Queue)

```bash
# Submit for async processing
curl -X POST http://localhost:8000/scan/text \
  -H "Content-Type: application/json" \
  -d '{"text": "...", "async_mode": true}'

# Check status
curl http://localhost:8000/scan/{scan_id}/status
```

## Database Schema

| Table | Description |
|-------|-------------|
| `scan_logs` | Primary record of each scan (type, risk, entities, timing) |
| `detection_results` | Individual PII/PHI entities detected per scan |
| `alert_records` | Alerts generated with severity and delivery status |
| `policy_audits` | Audit trail of policy evaluations per scan |

## Configuration

### `config/policies.yaml`
- Risk thresholds (low/medium/high/critical)
- Masking strategies per entity type
- Alert channel configuration
- HIPAA compliance settings

### `config/detection_rules.yaml`
- Presidio entity selection
- Regex pattern file references
- Scan limits (text length, image size, audio duration)

### `detection/medical_patterns.yaml`
- MRN, NPI, ICD-10, CPT, DOB, Health Plan ID, DEA patterns

### `detection/credential_patterns.yaml`
- API keys, AWS credentials, passwords, JWT, private keys, DB URLs

## Project Structure

```
healthcare-privacy-firewall/
├── gateway/                  # FastAPI entry point
│   ├── proxy_server.py       # Routes & app lifecycle
│   └── request_interceptor.py# Validation & rate limiting
├── queue/
│   └── redis_client.py       # Redis job queue management
├── workers/
│   ├── text_worker/          # Presidio + regex detection
│   ├── image_worker/         # OCR + image blur
│   ├── audio_worker/         # Whisper transcription
│   └── *_worker_runner.py    # Queue consumer workers
├── intelligence/
│   ├── risk_engine.py        # Weighted risk scoring
│   └── policy_engine.py      # HIPAA/PCI-DSS policy evaluation
├── masking/
│   ├── pii_masker.py         # Full text pipeline orchestrator
│   └── blur_engine.py        # Image pipeline orchestrator
├── detection/
│   ├── medical_patterns.yaml # Healthcare PII regex patterns
│   └── credential_patterns.yaml
├── storage/
│   ├── db.py                 # Async SQLAlchemy engine
│   ├── models.py             # ORM models
│   └── repository.py         # CRUD operations
├── alerts/
│   ├── alert_engine.py       # Alert generation & routing
│   └── slack_notifier.py     # Slack webhook delivery
├── analytics/
│   └── metrics_engine.py     # Prometheus + dashboard metrics
├── dashboard/react-ui/       # React analytics dashboard
├── config/                   # YAML policy & detection config
├── docker/                   # Dockerfile & docker-compose.yml
├── requirements.txt
└── .env.example
```

## Deployment

### Production Docker

```bash
# Build and deploy
cd docker
docker-compose -f docker-compose.yml up -d --build

# Scale workers
docker-compose up -d --scale text-worker=3 --scale image-worker=2

# View logs
docker-compose logs -f gateway
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `GATEWAY_PORT` | `8000` | API gateway port |
| `SPACY_MODEL` | `en_core_web_sm` | spaCy NLP model |
| `WHISPER_MODEL` | `base` | Whisper model size |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook |
| `HIPAA_MODE` | `true` | Enable HIPAA compliance mode |

## License

MIT
