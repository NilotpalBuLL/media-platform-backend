
# 🎬 Media Platform API (FastAPI)

A backend service where **admin users** can upload media metadata (video/audio) and generate **secure 10-minute streaming links**.  
This project demonstrates authentication with JWT, protected routes, and database modeling using FastAPI.

---

## 🚀 Features
- Secure **JWT-based authentication** (`/auth/signup`, `/auth/login`)
- Upload and manage **media metadata**
- Generate **secure 10-minute streaming URLs**
- Track **media view logs** (IP + timestamp)
- Built with **FastAPI** + **SQLAlchemy**

---

## 🛠️ Tech Stack
- **Python 3.9+**
- **FastAPI** (backend framework)
- **SQLite** (default DB, can replace with PostgreSQL/MySQL)
- **SQLAlchemy** (ORM)
- **JWT (PyJWT)** for authentication
- **Uvicorn** for ASGI server

---

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/media-platform.git
   cd media-platform
````

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate    # Linux/Mac
   .venv\Scripts\activate       # Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   Create a `.env` file in the root folder:

   ```ini
   SECRET_KEY=your_jwt_secret
   DATABASE_URL=sqlite:///./media.db
   ```

---

## ▶️ Run the Server

```bash
uvicorn app.main:app --reload
```

The API will be available at:
👉 `http://127.0.0.1:8000`

Interactive API Docs:
👉 `http://127.0.0.1:8000/docs`

---

## 📂 Database Schemas

**MediaAsset**

* `id`
* `title`
* `type` (video/audio)
* `file_url`
* `created_at`

**AdminUser**

* `id`
* `email`
* `hashed_password`
* `created_at`

**MediaViewLog**

* `media_id`
* `viewed_by_ip`
* `timestamp`

---

## 🔑 API Endpoints

### Auth

* `POST /auth/signup` → Register a new admin
* `POST /auth/login` → Login and get JWT token

### Media

* `POST /media` → Add new media metadata (**Requires Auth**)
* `GET /media/{id}/stream-url` → Get secure 10-minute streaming URL (**Requires Auth**)

---

## 🧪 Quick Test (using curl)

```bash
# Signup
curl -X POST "http://127.0.0.1:8000/auth/signup" \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "admin123"}'

# Login
curl -X POST "http://127.0.0.1:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "admin123"}'

# Use token in header
curl -X POST "http://127.0.0.1:8000/media" \
     -H "Authorization: Bearer <your_token>" \
     -H "Content-Type: application/json" \
     -d '{"title": "Sample Video", "type": "video", "file_url": "http://example.com/video.mp4"}'
```
