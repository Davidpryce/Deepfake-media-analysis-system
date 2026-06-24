"""
Complete Forensic Deepfake Detection System with Database Authentication
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import uvicorn
import uuid
import hashlib
import json
import os
from pathlib import Path
from jose import jwt, JWTError

# Import from database_config
from database_config import (
    get_db, User, Case, Evidence, ChainOfCustody, 
    AuditLog, SystemLog, hash_password, verify_password, 
    create_access_token, create_default_admin, get_user_by_username,
    create_system_log, create_audit_log, SessionLocal
)

# Create FastAPI app
app = FastAPI(title="Forensic Deepfake Detection System", version="2.0.0")

# Security
security = HTTPBearer()
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create directories
UPLOAD_DIR = Path("uploads")
REPORT_DIR = Path("reports")
UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

# ============================================
# AUTHENTICATION DEPENDENCIES
# ============================================

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get current user from JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account disabled")
    
    return user

async def get_current_admin(current_user: User = Depends(get_current_user)):
    """Check if user is admin"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# ============================================
# API ENDPOINTS
# ============================================

@app.post("/api/auth/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Login user and return JWT token"""
    
    # Find user
    user = get_user_by_username(db, username)
    
    if not user or not verify_password(password, user.hashed_password):
        create_audit_log(db, None, "LOGIN_FAILED", "auth", None, {"username": username})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    
    # Update last login
    user.last_login = datetime.utcnow()
    
    # Create token
    token = create_access_token({"user_id": user.id, "username": user.username})
    
    # Log successful login
    create_audit_log(db, user.id, "LOGIN_SUCCESS", "auth", None, {"username": user.username})
    create_system_log(db, "INFO", f"User {user.username} logged in", "auth", user.id)
    
    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@app.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    case_id: str = Form(""),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload and analyze file for deepfake detection"""
    
    # Generate evidence ID
    evidence_id = str(uuid.uuid4())
    
    # Save file
    file_path = UPLOAD_DIR / f"{evidence_id}_{file.filename}"
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Calculate file hash
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Find case if provided
    case = None
    if case_id:
        case = db.query(Case).filter(Case.case_id == case_id).first()
    
    # Simulate AI analysis
    import random
    is_fake = random.random() > 0.5
    confidence = random.uniform(0.7, 0.98)
    
    result = {
        "classification": "FAKE" if is_fake else "REAL",
        "confidence": confidence,
        "evidence_id": evidence_id
    }
    
    # Create evidence record
    evidence = Evidence(
        evidence_id=evidence_id,
        case_id=case.id if case else None,
        filename=file.filename,
        file_path=str(file_path),
        file_hash=file_hash,
        file_size=len(content),
        mime_type=file.content_type,
        classification=result["classification"],
        confidence_score=confidence,
        analysis_result=result,
        uploaded_by=current_user.id,
        analyzed_at=datetime.utcnow()
    )
    
    db.add(evidence)
    db.flush()
    
    # Add chain of custody
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        action="UPLOADED",
        performed_by=current_user.id,
        details={"filename": file.filename, "case_id": case_id}
    )
    db.add(custody)
    
    # Generate report
    report_path = REPORT_DIR / f"report_{evidence_id}.txt"
    with open(report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("FORENSIC DEEPFAKE ANALYSIS REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Report ID: {evidence_id}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"Filename: {file.filename}\n")
        f.write(f"Classification: {result['classification']}\n")
        f.write(f"Confidence: {result['confidence']:.2%}\n\n")
        f.write(f"Analyzed By: {current_user.username}\n")
    
    # Log analysis
    create_audit_log(db, current_user.id, "ANALYZE_EVIDENCE", "evidence", 
                     evidence_id, {"filename": file.filename, "result": result["classification"]})
    create_system_log(db, "INFO", f"Evidence analyzed: {evidence_id} - {result['classification']}", 
                      "analysis", current_user.id)
    
    db.commit()
    
    return {
        "success": True,
        "evidence_id": evidence_id,
        "classification": result["classification"],
        "confidence": confidence,
        "report_url": f"/api/download/{evidence_id}"
    }

@app.get("/api/download/{evidence_id}")
async def download_report(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download forensic report"""
    report_path = REPORT_DIR / f"report_{evidence_id}.txt"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    
    create_audit_log(db, current_user.id, "DOWNLOAD_REPORT", "evidence", evidence_id)
    
    return FileResponse(report_path, filename=f"forensic_report_{evidence_id}.txt")

@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""
    try:
        db.execute("SELECT 1")
        db_status = "connected"
    except:
        db_status = "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": db_status
    }

# ============================================
# HTML UI
# ============================================

UI_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Deepfake Detection System</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .login-container {
            background: white;
            max-width: 400px;
            margin: 100px auto;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .login-container h2 { text-align: center; margin-bottom: 30px; }
        .login-container input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .login-container button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        .navbar {
            background: white;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .logo { font-size: 24px; font-weight: bold; color: #667eea; }
        .nav-links a {
            margin-left: 20px;
            text-decoration: none;
            color: #333;
            cursor: pointer;
        }
        .upload-area {
            border: 2px dashed #ccc;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            cursor: pointer;
            margin: 20px 0;
        }
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        .result {
            margin-top: 20px;
            padding: 20px;
            border-radius: 10px;
        }
        .result.fake { background: #ffebee; border-left: 4px solid #f44336; }
        .result.real { background: #e8f5e9; border-left: 4px solid #4caf50; }
        .confidence-bar {
            background: #e0e0e0;
            border-radius: 10px;
            height: 30px;
            margin: 10px 0;
            overflow: hidden;
        }
        .confidence-fill {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        .fake .confidence-fill { background: #f44336; }
        .real .confidence-fill { background: #4caf50; }
    </style>
</head>
<body>
    <div id="loginPage" class="login-container">
        <h2>🔍 Forensic Deepfake System</h2>
        <input type="text" id="username" placeholder="Username" value="admin">
        <input type="password" id="password" placeholder="Password" value="Admin123!">
        <button onclick="login()">Login</button>
        <div id="errorMsg" style="color:red; text-align:center; margin-top:10px;"></div>
    </div>
    
    <div id="mainApp" style="display:none">
        <div class="navbar">
            <div class="logo">🔍 Forensic Deepfake System</div>
            <div class="nav-links">
                <a onclick="showPage('dashboard')">Dashboard</a>
                <a onclick="showPage('analysis')">Analysis</a>
                <span id="userInfo"></span>
                <a onclick="logout()">Logout</a>
            </div>
        </div>
        <div class="container">
            <div id="dashboardPage">
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    📁 Click to upload file for quick analysis
                </div>
                <input type="file" id="fileInput" style="display:none" onchange="quickAnalyze()">
                <div id="result"></div>
            </div>
            <div id="analysisPage" style="display:none">
                <h2>Upload Evidence</h2>
                <div class="upload-area" onclick="document.getElementById('analysisFile').click()">
                    📁 Click to upload
                </div>
                <input type="file" id="analysisFile" style="display:none">
                <button onclick="startAnalysis()">Start Analysis</button>
                <div id="analysisResult"></div>
            </div>
        </div>
    </div>
    
    <script>
        let token = null;
        
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            const response = await fetch('/api/auth/login', { method: 'POST', body: formData });
            const data = await response.json();
            
            if (data.success) {
                token = data.access_token;
                document.getElementById('loginPage').style.display = 'none';
                document.getElementById('mainApp').style.display = 'block';
                document.getElementById('userInfo').innerHTML = `👤 ${data.user.username} (${data.user.role})`;
            } else {
                document.getElementById('errorMsg').innerText = 'Login failed';
            }
        }
        
        async function logout() {
            token = null;
            document.getElementById('loginPage').style.display = 'block';
            document.getElementById('mainApp').style.display = 'none';
        }
        
        function showPage(page) {
            document.getElementById('dashboardPage').style.display = page === 'dashboard' ? 'block' : 'none';
            document.getElementById('analysisPage').style.display = page === 'analysis' ? 'block' : 'none';
        }
        
        async function quickAnalyze() {
            const file = document.getElementById('fileInput').files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });
            const data = await response.json();
            
            if (data.success) {
                const isFake = data.classification === 'FAKE';
                document.getElementById('result').innerHTML = `
                    <div class="result ${isFake ? 'fake' : 'real'}">
                        <h3>${isFake ? '⚠️ DEEPFAKE DETECTED' : '✅ AUTHENTIC'}</h3>
                        <p>Confidence: ${(data.confidence * 100).toFixed(1)}%</p>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${data.confidence * 100}%">
                                ${(data.confidence * 100).toFixed(1)}%
                            </div>
                        </div>
                        <a href="${data.report_url}" target="_blank">📄 Download Report</a>
                    </div>
                `;
            }
        }
        
        async function startAnalysis() {
            const file = document.getElementById('analysisFile').files[0];
            if (!file) { alert('Select a file'); return; }
            
            const formData = new FormData();
            formData.append('file', file);
            
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });
            const data = await response.json();
            
            if (data.success) {
                const isFake = data.classification === 'FAKE';
                document.getElementById('analysisResult').innerHTML = `
                    <div class="result ${isFake ? 'fake' : 'real'}">
                        <h3>${isFake ? '⚠️ DEEPFAKE DETECTED' : '✅ AUTHENTIC'}</h3>
                        <p>Confidence: ${(data.confidence * 100).toFixed(1)}%</p>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${data.confidence * 100}%">
                                ${(data.confidence * 100).toFixed(1)}%
                            </div>
                        </div>
                        <a href="${data.report_url}" target="_blank">📄 Download Report</a>
                    </div>
                `;
            }
        }
    </script>
</body>
</html>
"""

@app.get("/")
@app.get("/ui")
async def serve_ui():
    return HTMLResponse(UI_HTML)

# ============================================
# RUN THE APPLICATION
# ============================================

if __name__ == "__main__":
    # Create default admin user
    db = SessionLocal()
    create_default_admin(db)
    db.close()
    
    print("=" * 70)
    print("🔍 FORENSIC DEEPFAKE DETECTION SYSTEM")
    print("=" * 70)
    print(f"✓ Web UI: http://localhost:8000/ui")
    print(f"✓ API Docs: http://localhost:8000/docs")
    print("=" * 70)
    print("\n📝 Default Login: admin / Admin123!")
    print("=" * 70)
    
    uvicorn.run(app, host="0.0.0.0", port=8000)