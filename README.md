# AutoForge — AI-Powered DevSecOps Platform

> **Phase 1 Project Requirements & Master Plan**  
> **Department:** CSE/IT, Government Engineering College, Ajmer  
> **Course:** 7th Semester, Project-I (July – December 2026)  
> **Team:** Dhruv Vasvani · Birendra Nagar · Abhishek Vijayvargiya · Kartik Sharma  

---

##  Problem Statement
Security scanners generate a large volume of alerts upon GitHub pushes, leading to severe alert fatigue due to false positives and dead-code vulnerabilities. AutoForge addresses this by prioritizing actionable security issues and providing verified automated fixes.

##  Product Vision
AutoForge scans GitHub repositories, eliminates dead-code noise using AST reachability, ranks vulnerabilities via ML model prioritization, generates secure AI fixes using Gemini, and automatically opens Pull Requests — end-to-end without manual triage.

---

##  Phase 1 Architecture

```
GitHub Push ➔ Webhook Event ➔ Spring Boot Backend (Java 17) ➔ Redis Queue
│
┌───────────────────────────────────────────────────────────────────┘
▼
Background Workers:
├── Security Scanners (Semgrep + Checkov)
├── AST Reachability Analysis (tree-sitter)
├── ML Alert Prioritization (scikit-learn)
└── AI Fix Generation (Google Gemini 2.5 Flash)
│
▼
Automated GitHub Pull Request Creation
│
▼
React Dashboard (Live Logs, Heatmaps, PDF Reports)
```

---

##  Team Roles & Task Split

| Role | Member | Primary Responsibilities |
|---|---|---|
| **Backend & Auth Lead** | ** ** | Spring Boot core, PostgreSQL/JPA setup, Spring Security + JWT, User/Plan/Admin APIs |
| **GitHub & Scan Pipeline Engineer** | ** ** | GitHub Webhook receiver, signature verification, Semgrep/Checkov execution, Redis job queue |
| **AST / ML Engineer** | ** ** | tree-sitter reachability engine, call graph analysis, ML prioritization model (scikit-learn) |
| **AI Fix & Frontend Engineer** | ** ** | Gemini 2.5 Flash integration, automated PR engine, React + Vite dashboard, WebSockets |

---

##  5-Week Master Plan (Demo 1 Target)

| Wk |  (Backend / Auth) |  (GitHub / Scan) |  (AST / ML) |  (AI Fix / Frontend) |
|:---:|---|---|---|---|
| **1** | Spring Boot skeleton & project initialization | Study Semgrep/Checkov CLI & webhook architecture | Study tree-sitter & define reachability graph approach | Setup Gemini API access & React/Vite/Tailwind scaffold |
| **2** | JPA Entity classes, DB schema & ER diagram | Webhook receiver endpoint & signature verification | Prototype AST parsing on sample code repositories | React folder structure, routing & layout UI |
| **3** | Spring Security integration & DTO layer | CLI wrappers for Semgrep & Checkov execution | Build call graph reachability Proof-of-Concept | Login/Register UI pages & HTTP client setup |
| **4** | JWT token generation & protected routes | Wire Webhooks ➔ Scan Jobs ➔ Redis Queue | Integrate AST parser into the noise-reduction pipeline | Connect UI forms with backend JWT endpoints |
| **5** | User profile APIs & integration testing | End-to-end test: Push ➔ Webhook ➔ Job Enqueued | Rule-based priority stub (pre-ML placeholder) | Dashboard shell displaying user info & repo list |

---

##  Technology Stack

* **Backend:** Java 17, Spring Boot 3.x, Spring Security, Spring Data JPA
* **Database & Queue:** PostgreSQL, Redis
* **Scanners:** Semgrep, Checkov
* **AST & ML:** tree-sitter, Python, scikit-learn
* **AI Engine:** Google Gemini 2.5 Flash API
* **Frontend:** React, Vite, Tailwind CSS, WebSockets
* **DevOps:** Docker, Docker Compose, GitHub Actions / Webhooks
