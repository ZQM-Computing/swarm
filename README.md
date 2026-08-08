# swarm

ZQM Node-1 fleet: attestation API, T1 self-heal automation, SA watchdog, claims ledger.

## Overview

This repository contains the fleet management and automation infrastructure for ZQM Node-1. Components include:

- **Attestation API**: Remote attestation and verification endpoints
- **T1 Self-Heal Automation**: Automated recovery and self-healing workflows
- **SA Watchdog**: Service availability monitoring
- **Claims Ledger**: Distributed claims tracking and verification

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ZQM-Computing/swarm.git
cd swarm

# Install dependencies
pip install -r requirements.txt

# Run the API server
python api_server.py
```

## Requirements

- Python 3.11+
- FastAPI
- See `requirements.txt` for full dependencies

## Project Structure

```
swarm/
├── api_server.py            # FastAPI attestation API
├── claims_core.py           # Claims ledger logic
├── fleet_automate.py        # Fleet automation workflows
├── fleet_rag.py             # Fleet RAG utilities
├── .github/
│   └── SECURITY.md
├── FUNDING.yml
└── README.md
```

## API Documentation

Once running, visit `http://localhost:8000/docs` for interactive API documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

See [LICENSE](LICENSE) for details.
