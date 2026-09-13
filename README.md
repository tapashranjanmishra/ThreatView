# ThreatView

## Threat Intelligence Aggregation and Monitoring Platform

ThreatView is a full-stack cybersecurity platform for collecting, storing, investigating, and monitoring Indicators of Compromise (IOCs) from multiple threat intelligence sources.

It combines automated threat intelligence ingestion, threat investigation, configurable alert rules, notification management, and a web-based security dashboard in a single platform.

---

## Features

- Automated threat intelligence ingestion
- AlienVault OTX integration
- OpenPhish Community Feed integration
- IOC search and filtering
- Threat investigation
- Threat pagination
- Dashboard statistics
- Configurable alert rules
- Alert rule creation, editing, enabling/disabling, and deletion
- Automatic alert generation
- Alert deduplication
- Notification history
- JWT authentication
- Protected API endpoints
- User-specific alert rule access control
- Ingestion health monitoring

---

## Supported IOCs

- IP Address
- Domain
- URL
- File Hash
- Email

## Supported Threat Types

- Malware
- Phishing
- Ransomware
- Botnet
- Scanning
- Other

---

## Technology Stack

### Frontend
- React
- Vite
- JavaScript
- CSS

### Backend
- Python
- FastAPI
- SQLAlchemy
- Pydantic
- JWT

### Database
- PostgreSQL
- Alembic

### Threat Intelligence
- AlienVault OTX
- OpenPhish

### Testing
- Pytest
- FastAPI TestClient

---

## System Architecture

```text
                   Threat Intelligence Sources
                    ┌──────────┴──────────┐
                    │                     │
                   OTX                OpenPhish
                    │                     │
                    └──────────┬──────────┘
                               ↓
                       Ingestion Layer
                               ↓
                    Normalize & Deduplicate
                               ↓
                          PostgreSQL
                               ↓
                        FastAPI Backend
                     ┌─────────┼─────────┐
                     │         │         │
                 Threat API  Alert API  Auth API
                     │         │         │
                     └─────────┼─────────┘
                               ↓
                         Alert Engine
                               ↓
                         Rule Matching
                               ↓
                         Notifications
                               ↓
                         React Frontend
                    ┌──────────┼──────────┐
                    ↓          ↓          ↓
                Dashboard   Threats     Alerts
