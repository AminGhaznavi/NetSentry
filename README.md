<div align="center">
  <img src="https://img.shields.io/badge/NetSentry-Cybersecurity%20Dashboard-cyan?style=for-the-badge&logo=shield&logoColor=black" alt="NetSentry Logo">
  <p><em>A modern, multi-threaded network security scanner and reconnaissance web application built with Flask.</em></p>

  <p>
    <a href="https://AminGhaznavi.pythonanywhere.com" target="_blank"><b>🔗 Live Demo</b></a> •
    <a href="#-features"><b>Features</b></a> •
    <a href="#-tech-stack"><b>Tech Stack</b></a> •
    <a href="#-installation--running"><b>Installation</b></a>
  </p>
</div>

---

## 🛡️ About NetSentry

**NetSentry** is a lightweight yet powerful web-based security reconnaissance dashboard designed for developers, system administrators, and security enthusiasts. It combines essential network auditing tools into a sleek, glassmorphic dark-mode interface with zero page reloads.

---

## 🚀 Features

* **🔍 Multi-Threaded Port Scanner:** Rapidly scans TCP ports using a configurable thread pool to identify active services and open ports on a target host.
* **🔒 Security Headers Audit:** Inspects a target URL for critical modern defensive headers (such as HSTS, Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options) and evaluates an overall security grade.
* **🌐 DNS Records Recon:** Queries fundamental DNS records (A, AAAA, MX, NS, TXT) using robust DNS resolution libraries.
* **📍 IP Geolocation & ASN Intelligence:** Resolves targets to their respective IP addresses and extracts geolocation data, ISP, organization, and Autonomous System Number (ASN) details.
* **⚡ Modern UI/UX:** Built with a cyber-themed dark glassmorphism interface, responsive layouts for mobile and desktop devices, and seamless client-side tab switching.

---

## 💻 Tech Stack

* **Backend:** Python, Flask, ThreadPoolExecutor, dnspython
* **Frontend:** HTML5, CSS3, JavaScript (Vanilla ES6+), Responsive Design

---

## 🛠️ Installation & Running Locally

If you want to run NetSentry locally on your machine, follow these steps:

1. **Clone the repository:**
   `git clone https://github.com/AminGhaznavi/NetSentry.git`
   `cd NetSentry`

2. **Install dependencies:**
   `pip install -r requirements.txt`

3. **Run the application:**
   `python app.py`

4. **Open in your browser:**
   `Navigate to http://127.0.0.1:5000`

---

## 👤 Author

* **Amin Ghaznavi**
