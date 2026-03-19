# gottaphish — phishing awareness fingerprint collector

## Project structure

```
gottaphish/
├── app/
│   ├── app.py
│   ├── requirements.txt
│   ├── data/               ← SQLite DB + CSV export (auto-created)
│   └── templates/
│       └── index.html
├── docker-compose.yml
└── README.md
```

## Routes

| Route | Description |
|---|---|
| `GET  /gottaphish/test1/` | Landing page + JS fingerprint |
| `POST /gottaphish/test1/api/collect` | Receives FingerprintJS payload |
| `GET  /gottaphish/test1/api/stats` | JSON summary |
| `GET  /gottaphish/test1/api/export` | Download CSV |

## Run locally

```bash
docker compose up --build
# Page:      http://localhost/gottaphish/test1/
# Stats:     http://localhost/gottaphish/test1/api/stats
# Export:    http://localhost/gottaphish/test1/api/export
# Traefik:   http://localhost:8080
```


## Bot detection signals

| Signal | Reason flagged |
|---|---|
| Known bot User-Agent | UA match (GSB, crawlers...) |
| No JS executed | Bot did not run JavaScript |
| No WebGL | No GPU / headless browser |
| SwiftShader / LLVMpipe renderer | Software/virtual GPU |
| JS exec time < 5ms | Headless execution |
| hw_concurrency = 0 | Virtual machine |

