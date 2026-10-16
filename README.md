# SiteLens AI

## AI Builder Cup 2026

**Team:** Elena AI Lab

**Challenge:** Future of Work & Enterprise Productivity

## Overview

SiteLens AI is an evidence-aware site inspection assistant that helps property owners, contractors and facility teams identify visible concerns from site photographs.

The application uses Gemini 2.5 Flash through Google Cloud Vertex AI to generate structured observations, possible concerns, recommended follow-up actions, confidence levels and human-review flags.

AI-generated findings are intended to support human inspection. They do not certify construction quality, repair completion or safety.

## Google Cloud Architecture

- **Cloud Run:** Hosts the Flask-based Judge application.
- **Vertex AI / Gemini 2.5 Flash:** Performs multimodal photograph analysis.
- **Firestore:** Stores access-grant state, request reservations and usage controls.
- **Secret Manager:** Supplies runtime secrets without embedding them in source code.
- **Cloud Build / Artifact Registry:** Support container build and deployment.

## Analysis Workflow

1. Open the access-protected Judge interface.
2. Authenticate using an authorized demonstration access code.
3. Upload one supported site photograph.
4. Validate the image, session, CSRF token and request identifier.
5. Apply Firestore-backed admission controls.
6. Analyze the photograph using Gemini.
7. Return structured findings for human review.

Supported image formats: JPEG, PNG and WebP.

Maximum image size: 8 MiB.

## Verified Prototype Evidence

A production end-to-end test successfully submitted a real JPEG through the deployed Judge service.

Verified results:

- HTTP status: 200
- Model: Gemini 2.5 Flash
- Structured findings: 3
- Human-review flags: Present

Separately, 14 isolated mock guard tests passed.

This is functional verification, not an accuracy, latency, throughput or scalability benchmark.

## Security Design

The Judge application includes:

- Access-code-protected sessions
- Session expiration
- Origin and CSRF checks
- Firestore-backed request admission and usage limits
- Input validation
- Server-side secret management

The public repository intentionally excludes production credentials, access codes and private deployment materials.

## Repository Structure

- `app.py` — Flask application and routes
- `judge_access.py` — Access control and Firestore admission logic
- `phase1.py` — Image analysis integration
- `templates/` — Judge and analysis interfaces
- `Dockerfile` — Container configuration
- `requirements*.txt` — Python dependencies
- `gunicorn.conf.py` — Application server configuration

## Deployment Notes

This repository contains application source code, not a complete production environment export.

Running a deployment requires separately configured Google Cloud services, IAM permissions, Firestore data, runtime environment variables and Secret Manager secrets.

No production access credentials are distributed in this repository.

## Limitations

- AI findings require professional human review.
- The prototype does not provide safety certification.
- No formal accuracy or performance benchmark has been established.
- Demonstration access is controlled and may expire.

## Live Prototype

https://sitelens-judge-415043547033.asia-southeast1.run.app/judge

Access requires a valid demonstration code.

## Competition

AI Builder Cup 2026 — Elena AI Lab
