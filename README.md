### ✅ IP Geolocation–Centric README



# 🌍 Domain Scope – IP & Domain Intelligence Toolkit

<p align="center">
  <a href="https://domain-scope-three.vercel.app"><img src="https://img.shields.io/website?down_color=red&down_message=offline&up_color=green&up_message=online&url=https%3A%2F%2Fdomain-scope-three.vercel.app&style=for-the-badge" alt="Live Site" /></a>
  <a href="https://github.com/vaishnav4281/Domain-scope/stargazers"><img src="https://img.shields.io/github/stars/vaishnav4281/Domain-scope?style=for-the-badge" /></a>
  <a href="https://github.com/vaishnav4281/Domain-scope/blob/main/LICENSE"><img src="https://img.shields.io/github/license/vaishnav4281/Domain-scope?style=for-the-badge" /></a>
</p>

> 🌐 An open-source IP & Domain Intelligence Platform with geolocation, WHOIS, DNS, and abuse detection. Powered by FastAPI & React.

---
<p align="center">
<img width="1440" height="1024" alt="Mockup 02" src="https://github.com/user-attachments/assets/03e08e4a-32c6-4700-93bb-d89c464a2bac" />
</p>  

## 🔥 Live Demo

| Frontend (UI)                              | Backend (API)                             |
|-------------------------------------------|-------------------------------------------|
| 🌎 https://domain-scope-three.vercel.app  | ⚙️ https://whois-aoi.onrender.com         |

---
<p align="center">
<img width="1440" height="1024" alt="Mockup 01" src="https://github.com/user-attachments/assets/9ee70a77-9526-4ab7-a3fe-c06d4dfe4536" />
</p>





## 🔎 Core Features

- 📍 **IP Geolocation Lookup**
  - Country, region, city, lat/lon
- 🛡️ **Abuse Score Lookup**
  - Reports via AbuseIPDB
- 🌐 **WHOIS Information**
  - Registrar, dates, DNSSEC
- 📬 **DNS Record Scanner**
  - A, MX, AAAA, NS records
- 🕓 **Domain Age Calculator**
- � **Metascraper Integration**
  - 30+ metadata fields extraction
  - Open Graph, Twitter Cards, JSON-LD
  - SEO analysis and completeness scoring
- 🛡️ **VirusTotal Security Analysis**
  - 70+ antivirus vendor detections
  - Domain reputation scoring
  - DNS & SSL certificate analysis
  - Threat categorization
- �🚀 Modular REST API endpoints

---

## 🧱 Tech Stack

| Layer      | Stack                              |
|------------|------------------------------------|
| Frontend   | React + Vite + Tailwind CSS        |
| Backend    | FastAPI + Gunicorn                 |
| APIs Used  | IP2Location, AbuseIPDB, WhoisXML, VirusTotal |
| Metadata   | Metascraper (30+ fields)           |
| Deployment | Vercel (UI), Render (API)          |

---

## 🐳 Run with Docker

```bash
# Backend setup
cd backend
cp .env.example .env
docker build -t domain-api .
docker run -p 8000:8000 --env-file .env domain-api
````

---

## ⚙️ Local Development

### Backend (FastAPI)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend (Vite + React)

```bash
cd frontend
cp .env.example .env  # set VITE_API_BASE and VITE_VIRUSTOTAL_API_KEY
npm install
npm run dev
```

**Get your VirusTotal API key**: https://www.virustotal.com/gui/my-apikey
See [VIRUSTOTAL_INTEGRATION.md](VIRUSTOTAL_INTEGRATION.md) for detailed setup instructions.

---

## 📦 API Routes

| Route             | Purpose                           |
| ----------------- | --------------------------------- |
| `/whois/?domain=` | WHOIS info for domain             |
| `/ipgeo/?ip=`     | IP2Location geolocation           |
| `/abuse/?ip=`     | AbuseIPDB risk assessment         |
| `/dns/?domain=`   | A, MX, NS, AAAA records           |
| VirusTotal API    | Domain security & reputation (v3) |
| Metascraper       | Client-side metadata extraction   |

---

## 📸 Screenshots

| IP Location Lookup         | WHOIS Domain Data          |
| -------------------------- | -------------------------- |
| ![](screenshots/ipgeo.png) | ![](screenshots/whois.png) |

---

## 📂 Folder Structure

```bash
Domain-scope/
├── frontend/       # Vite + React frontend
├── backend/        # FastAPI microservice API
│   ├── app/api/    # Routers: whois, ipgeo, dns, abuse
│   ├── services/   # Logic layer for API calls
│   └── .env        # API keys and config
└── README.md
```

---

## 🙋‍♂️ Author

**Vaishnav K**
🔗 [LinkedIn](https://www.linkedin.com/in/vaishnav-k-5a15a527b/)
💻 [GitHub](https://github.com/vaishnav4281)

---

## 🧠 Ideas for Future

* 🔎 Reverse IP & ASN lookups
* ✈️ Export results (JSON/CSV)
* 🧩 Plugin support (via API keys)
* 🧠 Threat scoring & classification
* 📊 Historical domain reputation tracking
* 🔗 Bulk VirusTotal scanning with rate limiting
* 🎨 Custom risk assessment rules

---

## 📜 License

MIT — free for personal and commercial use.

