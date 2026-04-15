# Network Test Connection UI

A small Python web app for testing network connectivity from a browser.

## Features

- Unlimited rows for IP / DNS and port checks
- One-click add row
- CSV import with `target,port`
- TCP connectivity checks
- DNS resolution details
- Latency measurement
- Timeout setting for disconnect handling

## Run Locally

```bash
python app.py
```

Open `http://127.0.0.1:8000`.

## CSV Import

Use this format:

```csv
target,port
example.com,80
10.0.0.5,443
```

You can also add rows manually with the `Add Row` button.

## Run with Docker

```bash
docker compose up --build
```

Then open `http://localhost:8000`.

## Notes

- The app is intentionally dependency-free and uses only Python's standard library.
- You can test targets like `example.com`, `10.0.0.5:5432`, or `https://example.com`.
