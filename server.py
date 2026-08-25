import asyncio
import logging
import re
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any, Set
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Query
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
    ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin-secret-key")
    
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
    POLLING_INTERVAL = int(os.getenv("POLLING_INTERVAL", "5"))  # 5 seconds
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
        
        create_tables_query = """
        -- Main OTP requests table
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
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detected_at TIMESTAMP,
            timeout_at TIMESTAMP
        );
        
        -- OTP messages cache to prevent duplicates
        CREATE TABLE IF NOT EXISTS otp_messages_cache (
            id SERIAL PRIMARY KEY,
            message_id BIGINT UNIQUE NOT NULL,
            phone_number VARCHAR(20),
            otp_code TEXT,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Analytics table for tracking
        CREATE TABLE IF NOT EXISTS otp_analytics (
            id SERIAL PRIMARY KEY,
            transaction_id VARCHAR(50) REFERENCES otp_requests(transaction_id),
            phone_number VARCHAR(20),
            status VARCHAR(20),
            detection_time_seconds INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detected_at TIMESTAMP
        );
        
        -- Create indexes for better performance
        CREATE INDEX IF NOT EXISTS idx_otp_requests_status ON otp_requests(status);
        CREATE INDEX IF NOT EXISTS idx_otp_requests_created ON otp_requests(created_at);
        CREATE INDEX IF NOT EXISTS idx_otp_analytics_status ON otp_analytics(status);
        CREATE INDEX IF NOT EXISTS idx_otp_analytics_created ON otp_analytics(created_at);
        CREATE INDEX IF NOT EXISTS idx_otp_messages_cache_processed ON otp_messages_cache(processed_at);
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(create_tables_query)
                logger.info("Database tables created/verified")
        except Exception as e:
            logger.error(f"Table creation error: {str(e)}")
    
    async def save_request(self, request_data: dict):
        """Save OTP request to database with ON CONFLICT support"""
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
        ON CONFLICT (transaction_id) 
        DO UPDATE SET 
            status = 'active',
            timeout_at = NOW() + INTERVAL '5 minutes',
            session_string = $4,
            updated_at = CURRENT_TIMESTAMP
        """
        
        # Also insert into analytics
        analytics_query = """
        INSERT INTO otp_analytics (transaction_id, phone_number, status)
        VALUES ($1, $2, 'active')
        ON CONFLICT (transaction_id) DO NOTHING
        """
        
        try:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(
                        query,
                        str(request_data.get('transaction_id')),
                        request_data.get('purchase_code'),
                        request_data.get('phone_number'),
                        request_data.get('session_string'),
                        request_data.get('two_fa_password'),
                        request_data.get('bot_token'),
                        request_data.get('admin_telegram_id'),
                        request_data.get('channel_username'),
                        request_data.get('callback_url')
                    )
                    await conn.execute(
                        analytics_query,
                        str(request_data.get('transaction_id')),
                        request_data.get('phone_number')
                    )
                logger.info(f"Request saved for transaction: {request_data.get('transaction_id')}")
        except Exception as e:
            logger.error(f"Database save error: {str(e)}")
    
    async def is_message_processed(self, message_id: int) -> bool:
        """Check if a message has already been processed"""
        if not self.pool:
            return False
        
        query = "SELECT EXISTS(SELECT 1 FROM otp_messages_cache WHERE message_id = $1)"
        
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(query, message_id)
        except Exception as e:
            logger.error(f"Message check error: {str(e)}")
            return False
    
    async def mark_message_processed(self, message_id: int, phone_number: str, otp_code: str):
        """Mark a message as processed to prevent duplicates"""
        if not self.pool:
            return
        
        query = """
        INSERT INTO otp_messages_cache (message_id, phone_number, otp_code)
        VALUES ($1, $2, $3)
        ON CONFLICT (message_id) DO NOTHING
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, message_id, phone_number, otp_code)
        except Exception as e:
            logger.error(f"Message marking error: {str(e)}")
    
    async def cleanup_old_messages(self, hours: int = 24):
        """Clean up old processed messages"""
        if not self.pool:
            return
        
        query = "DELETE FROM otp_messages_cache WHERE processed_at < NOW() - ($1 * INTERVAL '1 hour')"
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, hours)
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    
    async def update_status(self, transaction_id: str, status: str, otp_code: Optional[str] = None):
        """Update OTP request status in database"""
        if not self.pool:
            return
        
        # Update main table
        query = """
        UPDATE otp_requests 
        SET status = $1::varchar, 
            otp_code = COALESCE($2::varchar, otp_code),
            detected_at = CASE WHEN $1::varchar = 'detected' THEN NOW() ELSE detected_at END,
            updated_at = CURRENT_TIMESTAMP
        WHERE transaction_id = $3::varchar
        """
        
        # Update analytics with detection time
        analytics_query = """
        UPDATE otp_analytics 
        SET status = $1::varchar,
            detected_at = CASE WHEN $1::varchar = 'detected' THEN NOW() ELSE detected_at END,
            detection_time_seconds = CASE 
                WHEN $1::varchar = 'detected' THEN 
                    EXTRACT(EPOCH FROM (NOW() - created_at))::INTEGER
                ELSE detection_time_seconds 
            END
        WHERE transaction_id = $2::varchar
        """
        
        try:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    await conn.execute(query, str(status), otp_code, str(transaction_id))
                    await conn.execute(analytics_query, str(status), str(transaction_id))
                logger.info(f"Status updated for {transaction_id}: {status}")
        except Exception as e:
            logger.error(f"Database update error: {str(e)}")
    
    async def get_request(self, transaction_id: str) -> Optional[dict]:
        """Get OTP request from database"""
        if not self.pool:
            return None
        
        query = "SELECT * FROM otp_requests WHERE transaction_id = $1::varchar"
        
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, str(transaction_id))
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Database query error: {str(e)}")
            return None
    
    async def get_analytics_summary(self) -> dict:
        """Get analytics summary"""
        if not self.pool:
            return {
                "total_requests": 0,
                "active_requests": 0,
                "detected_requests": 0,
                "timeout_requests": 0,
                "failed_requests": 0,
                "success_rate": 0,
                "average_detection_time": 0
            }
        
        query = """
        SELECT 
            COUNT(*) as total_requests,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_requests,
            COUNT(CASE WHEN status = 'detected' THEN 1 END) as detected_requests,
            COUNT(CASE WHEN status = 'timeout' THEN 1 END) as timeout_requests,
            COUNT(CASE WHEN status IN ('failed', 'unauthorized', 'cancelled') THEN 1 END) as failed_requests,
            ROUND(
                (COUNT(CASE WHEN status = 'detected' THEN 1 END)::FLOAT / 
                NULLIF(COUNT(*), 0) * 100)::numeric, 2
            ) as success_rate,
            ROUND(AVG(detection_time_seconds)::numeric, 2) as average_detection_time
        FROM otp_analytics
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        """
        
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query)
                return dict(row) if row else {}
        except Exception as e:
            logger.error(f"Analytics query error: {str(e)}")
            return {}
    
    async def get_recent_requests(self, limit: int = 20, status: Optional[str] = None) -> List[dict]:
        """Get recent OTP requests"""
        if not self.pool:
            return []
        
        query = """
        SELECT 
            transaction_id, purchase_code, phone_number, status,
            otp_code, created_at, detected_at, timeout_at
        FROM otp_requests
        """
        
        params = []
        if status:
            query += " WHERE status = $1::varchar"
            params.append(status)
        
        query += " ORDER BY created_at DESC LIMIT $2::integer"
        params.append(limit)
        
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, *params)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Recent requests query error: {str(e)}")
            return []
    
    async def get_hourly_stats(self, hours: int = 24) -> List[dict]:
        """Get hourly statistics"""
        if not self.pool:
            return []
        
        query = """
        SELECT 
            DATE_TRUNC('hour', created_at) as hour,
            COUNT(*) as total,
            COUNT(CASE WHEN status = 'detected' THEN 1 END) as detected,
            COUNT(CASE WHEN status = 'timeout' THEN 1 END) as timeout,
            ROUND(AVG(detection_time_seconds)::numeric, 2) as avg_detection_time
        FROM otp_analytics
        WHERE created_at >= NOW() - ($1::integer * INTERVAL '1 hour')
        GROUP BY DATE_TRUNC('hour', created_at)
        ORDER BY hour DESC
        """
        
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, hours)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Hourly stats query error: {str(e)}")
            return []

# ==================== CHANNEL POSTER ====================

class ChannelPoster:
    def __init__(self):
        self.bot_clients: Dict[str, Client] = {}
        self.last_used: Dict[str, datetime] = {}
        self.cleanup_task = None
    
    async def cleanup_idle_bots(self):
        """Clean up bot clients that haven't been used in 1 hour"""
        while True:
            await asyncio.sleep(3600)
            now = datetime.now()
            for bot_key, last_used in list(self.last_used.items()):
                if (now - last_used).total_seconds() > 3600:
                    if bot_key in self.bot_clients:
                        try:
                            await self.bot_clients[bot_key].stop()
                        except:
                            pass
                        del self.bot_clients[bot_key]
                    del self.last_used[bot_key]
                    logger.info(f"Cleaned up idle bot client: {bot_key}")
    
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
                    api_id=Config.TELEGRAM_API_ID,
                    api_hash=Config.TELEGRAM_API_HASH,
                    in_memory=True
                )
                await bot_client.start()
                self.bot_clients[bot_key] = bot_client
            else:
                bot_client = self.bot_clients[bot_key]
            
            # Update last used timestamp
            self.last_used[bot_key] = datetime.now()
            
            # Format phone number (hide middle digits)
            hidden_phone = self._mask_phone(phone_number)
            
            # Current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            date_only = datetime.now().strftime("%Y-%m-%d")
            time_only = datetime.now().strftime("%H:%M:%S")
            
            # Generate unique reference ID
            reference_id = f"OTP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
            
            # Channel message with professional template - Using Markdown
            channel_message = f"""
🔐 *OTP CODE DETECTED*
━━━━━━━━━━━━━━━━━━━

📱 *Phone:* `{hidden_phone}`
🔑 *Code:* `{otp_code}`
🌍 *Country:* {country_name}
📅 *Date:* {date_only}
🕐 *Time:* {time_only}

📋 *Ref:* `{reference_id}`

━━━━━━━━━━━━━━━━━━━
✅ Status: Successfully Detected
⚡ Speed: Instant
🔒 Security: Encrypted
━━━━━━━━━━━━━━━━━━━

_🤖 Automated Detection System_
"""
            
            # Send to channel with markdown parse mode
            await bot_client.send_message(
                channel_username,
                channel_message,
                parse_mode="Markdown"
            )
            
            # Admin message with full details
            admin_message = f"""
🔔 *OTP DETECTED - ADMIN ALERT*
━━━━━━━━━━━━━━━━━━━━━━

📱 *Full Phone Number:*
`{phone_number}`

🔐 *OTP Code:*
`{otp_code}`

🌍 *Country:* {country_name}

📅 *Date:* {date_only}
🕐 *Time:* {time_only}

📋 *Transaction ID:*
`{transaction_id}`

🎫 *Purchase Code:*
`{purchase_code}`

📇 *Reference ID:*
`{reference_id}`

━━━━━━━━━━━━━━━━━━━━━━
✅ *Status:* Successfully Detected
⚡ *Detection Time:* Instant
🔒 *Security:* Encrypted Connection
━━━━━━━━━━━━━━━━━━━━━━

_This is an admin-only message with full details_
"""
            
            # Send to admin with markdown parse mode
            try:
                await bot_client.send_message(
                    admin_telegram_id,
                    admin_message,
                    parse_mode="Markdown"
                )
            except Exception as e:
                logger.error(f"Admin message error: {str(e)}")
            
            logger.info(f"OTP posted to channel for {hidden_phone}")
            
        except Exception as e:
            logger.error(f"Channel posting error: {str(e)}")
            # Fallback: Try sending without parse mode
            try:
                await self._post_without_parse_mode(
                    bot_client, channel_username, admin_telegram_id,
                    phone_number, otp_code, country_name, transaction_id, purchase_code
                )
            except Exception as fallback_error:
                logger.error(f"Fallback posting also failed: {str(fallback_error)}")
    
    async def _post_without_parse_mode(self, bot_client, channel_username, admin_telegram_id,
                                       phone_number, otp_code, country_name, transaction_id, purchase_code):
        """Fallback method without any parse mode"""
        hidden_phone = self._mask_phone(phone_number)
        date_only = datetime.now().strftime("%Y-%m-%d")
        time_only = datetime.now().strftime("%H:%M:%S")
        reference_id = f"OTP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        
        channel_message = f"""
🔐 OTP CODE DETECTED
━━━━━━━━━━━━━━━━━━━

📱 Phone: {hidden_phone}
🔑 Code: {otp_code}
🌍 Country: {country_name}
📅 Date: {date_only}
🕐 Time: {time_only}

📋 Ref: {reference_id}

━━━━━━━━━━━━━━━━━━━
✅ Status: Successfully Detected
⚡ Speed: Instant
🔒 Security: Encrypted
━━━━━━━━━━━━━━━━━━━

🤖 Automated Detection System
"""
        
        await bot_client.send_message(channel_username, channel_message)
        
        admin_message = f"""
🔔 OTP DETECTED - ADMIN ALERT
━━━━━━━━━━━━━━━━━━━━━━

📱 Full Phone Number: {phone_number}
🔐 OTP Code: {otp_code}
🌍 Country: {country_name}
📅 Date: {date_only}
🕐 Time: {time_only}
📋 Transaction ID: {transaction_id}
🎫 Purchase Code: {purchase_code}
📇 Reference ID: {reference_id}
━━━━━━━━━━━━━━━━━━━━━━
✅ Status: Successfully Detected
⚡ Detection Time: Instant
🔒 Security: Encrypted Connection
━━━━━━━━━━━━━━━━━━━━━━
This is an admin-only message with full details
"""
        
        await bot_client.send_message(admin_telegram_id, admin_message)
        logger.info(f"OTP posted without parse mode for {hidden_phone}")
    
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
        self.processed_messages: Set[int] = set()  # In-memory cache for processed messages
        self._cleanup_lock = asyncio.Lock()
        self.stats = {
            "total_registered": 0,
            "total_detected": 0,
            "total_timeout": 0,
            "total_failed": 0
        }
        
    async def initialize(self):
        """Initialize database"""
        await self.db_manager.initialize()
        # Start cleanup task for idle bots
        asyncio.create_task(self.channel_poster.cleanup_idle_bots())
        # Start periodic cleanup of old messages
        asyncio.create_task(self._periodic_cleanup())
    
    async def _periodic_cleanup(self):
        """Periodically clean up old processed messages"""
        while True:
            await asyncio.sleep(3600)  # Every hour
            await self.db_manager.cleanup_old_messages(24)
            # Clear in-memory cache for old messages
            if len(self.processed_messages) > 1000:
                self.processed_messages.clear()
                logger.info("Cleared in-memory message cache")
    
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
                
                # Get initial last message ID to avoid processing old messages
                initial_last_id = 0
                try:
                    chat = await client.get_chat(Config.OTP_SENDER_ID)
                    async for message in client.get_chat_history(chat.id, limit=1):
                        initial_last_id = message.id
                        break
                except Exception as e:
                    logger.warning(f"Could not get initial message ID: {str(e)}")
                
                # Store client and session info
                session_id = str(uuid.uuid4())
                self.telegram_clients[session_id] = client
                
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
                    "otp_received": None,
                    "polling_task": None,
                    "last_message_id": initial_last_id,  # Store initial message ID
                    "processed_messages": set()  # Per-session processed messages
                }
                
                self.active_sessions[session_id] = session_info
                self.otp_requests[request.transaction_id] = session_info
                
                # Update stats
                self.stats["total_registered"] += 1
                
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
                
                # Start polling for OTP
                polling_task = asyncio.create_task(self.check_otp_loop(session_id))
                session_info["polling_task"] = polling_task
                
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
                self.stats["total_failed"] += 1
                raise HTTPException(500, f"Failed to register: {str(e)}")
    
    async def check_otp_loop(self, session_id: str):
        """Polling method with duplicate prevention"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        client = session_info["client"]
        last_message_id = session_info.get("last_message_id", 0)
        processed_messages = session_info.get("processed_messages", set())
        
        end_time = datetime.now() + timedelta(seconds=Config.OTP_TIMEOUT)
        
        logger.info(f"Started OTP polling for {session_info['phone_number']} from message ID: {last_message_id}")
        
        while datetime.now() < end_time:
            # Check if session still active
            if session_id not in self.active_sessions:
                logger.info(f"Session {session_id} no longer active, stopping polling")
                return
            
            if session_info["status"] != "active":
                logger.info(f"Session {session_id} status changed to {session_info['status']}, stopping polling")
                return
            
            try:
                # Get chat with Telegram (777000)
                chat = await client.get_chat(Config.OTP_SENDER_ID)
                
                # Get recent messages
                async for message in client.get_chat_history(chat.id, limit=5):
                    # Skip if we've already processed this message
                    if message.id <= last_message_id:
                        continue
                    
                    # Skip if already processed (in-memory check)
                    if message.id in processed_messages:
                        continue
                    
                    # Skip if already processed (database check)
                    if await self.db_manager.is_message_processed(message.id):
                        processed_messages.add(message.id)
                        continue
                    
                    # Update last message ID
                    last_message_id = message.id
                    session_info["last_message_id"] = last_message_id
                    
                    if not message.text:
                        continue
                    
                    text = message.text
                    logger.info(f"New message from 777000: {text[:50]}...")
                    
                    # Detect OTP pattern (5-6 digits)
                    match = re.search(r'\b(\d{5,6})\b', text)
                    if match:
                        otp = match.group(1)
                        logger.info(f"OTP DETECTED for {session_info['phone_number']}: {otp}")
                        
                        # Mark as processed
                        processed_messages.add(message.id)
                        self.processed_messages.add(message.id)
                        
                        # Save to database cache
                        await self.db_manager.mark_message_processed(
                            message.id, 
                            session_info['phone_number'], 
                            otp
                        )
                        
                        # Handle OTP detection
                        await self._handle_otp_detected(session_id, otp)
                        return
                    else:
                        # Mark non-OTP messages as processed too
                        processed_messages.add(message.id)
                        self.processed_messages.add(message.id)
                        
            except FloodWait as e:
                logger.warning(f"FloodWait: {e.x} seconds")
                await asyncio.sleep(min(e.x, 30))  # Cap wait time
            except Exception as e:
                logger.error(f"Polling error for {session_info['phone_number']}: {str(e)}")
            
            # Wait before next poll
            await asyncio.sleep(Config.POLLING_INTERVAL)
        
        logger.info(f"Polling timeout for {session_info['phone_number']}")
        return None  # Timeout
    
    async def _handle_otp_detected(self, session_id: str, otp_code: str):
        """Handle OTP detection - channel post + callback"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        # Prevent duplicate processing
        if session_info.get("otp_received"):
            logger.warning(f"OTP already received for {session_info['phone_number']}, skipping")
            return
        
        try:
            logger.info(f"Processing OTP for {session_info['phone_number']}: {otp_code}")
            
            # Update session info
            session_info["otp_received"] = otp_code
            session_info["status"] = "otp_detected"
            session_info["detected_at"] = datetime.now()
            
            # Update stats
            self.stats["total_detected"] += 1
            
            # Update database
            await self.db_manager.update_status(
                session_info["transaction_id"],
                "detected",
                otp_code
            )
            
            # Post to channel if endpoint config exists
            if session_info.get("endpoint_config"):
                endpoint = session_info["endpoint_config"]
                await self.channel_poster.post_otp_to_channel(
                    bot_token=endpoint.get("bot_token"),
                    channel_username=endpoint.get("channel_username"),
                    admin_telegram_id=endpoint.get("admin_telegram_id"),
                    phone_number=session_info["phone_number"],
                    otp_code=otp_code,
                    transaction_id=session_info["transaction_id"],
                    purchase_code=session_info.get("purchase_code", "")
                )
            
            # Send callback to main server
            await self._send_callback(session_info, otp_code, "detected")
            
            # Remove from active monitoring
            await self._cleanup_session(session_id)
            
        except Exception as e:
            logger.error(f"OTP detection handling error: {str(e)}")
    
    async def _handle_timeout(self, session_id: str):
        """Handle timeout - proper callback"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        try:
            logger.info(f"Handling timeout for {session_info['phone_number']}")
            
            # Update session status
            session_info["status"] = "timeout"
            
            # Update stats
            self.stats["total_timeout"] += 1
            
            # Update database
            await self.db_manager.update_status(
                session_info["transaction_id"],
                "timeout"
            )
            
            # Send timeout callback to main server
            await self._send_callback(session_info, None, "timeout")
            
            # Cleanup
            await self._cleanup_session(session_id)
            
        except Exception as e:
            logger.error(f"Timeout handling error: {str(e)}")
    
    async def _handle_disconnect(self, session_id: str):
        """Handle client disconnect"""
        session_info = self.active_sessions.get(session_id)
        if session_info and session_info["status"] == "active":
            logger.warning(f"Session disconnected for {session_info['phone_number']}")
            
            # Update stats
            self.stats["total_failed"] += 1
            
            # Update database
            await self.db_manager.update_status(
                session_info["transaction_id"],
                "unauthorized"
            )
            
            # Send unauthorized callback
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
                    logger.info(f"Callback sent successfully for {session_info['phone_number']} - Status: {status}")
                else:
                    logger.error(f"Callback failed with status {response.status_code}")
                    
        except Exception as e:
            logger.error(f"Callback error: {str(e)}")
    
    async def _schedule_timeout(self, session_id: str):
        """Schedule timeout for OTP monitoring"""
        await asyncio.sleep(Config.OTP_TIMEOUT)
        
        session_info = self.active_sessions.get(session_id)
        if session_info and session_info["status"] == "active":
            if session_info.get("otp_received") is None:  # Only timeout if no OTP received
                logger.info(f"Timeout for {session_info['phone_number']}")
                await self._handle_timeout(session_id)
    
    async def _cleanup_session(self, session_id: str):
        """Clean up session and stop client"""
        async with self._cleanup_lock:
            session_info = self.active_sessions.pop(session_id, None)
            if session_info:
                # Cancel polling task if exists
                if session_info.get("polling_task"):
                    session_info["polling_task"].cancel()
                
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
                
                logger.info(f"Session cleaned up: {session_id}")
    
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
                "purchase_code": session_info.get("purchase_code"),
                "last_message_id": session_info.get("last_message_id", 0)
            })
        return sessions
    
    def get_runtime_stats(self) -> dict:
        """Get runtime statistics"""
        return {
            **self.stats,
            "active_sessions": len(self.active_sessions),
            "available_slots": self.get_available_slots(),
            "max_concurrent": Config.MAX_CONCURRENT,
            "processed_messages": len(self.processed_messages),
            "success_rate": round(
                (self.stats["total_detected"] / max(1, self.stats["total_registered"])) * 100, 
                2
            )
        }

# ==================== FASTAPI APP ====================

otp_monitor = OTPMonitor()
server_start_time = datetime.now()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("OTP Catcher Server started")
    logger.info(f"Max concurrent sessions: {Config.MAX_CONCURRENT}")
    logger.info(f"OTP timeout: {Config.OTP_TIMEOUT} seconds")
    logger.info(f"Polling interval: {Config.POLLING_INTERVAL} seconds")
    logger.info(f"Monitoring sender ID: {Config.OTP_SENDER_ID}")
    logger.info("Duplicate prevention: ENABLED")
    
    # Initialize database
    await otp_monitor.initialize()
    
    yield
    
    # Shutdown
    logger.info("Shutting down OTP Catcher Server")
    # Clean up all sessions
    for session_id in list(otp_monitor.active_sessions.keys()):
        await otp_monitor._cleanup_session(session_id)
    
    # Close database pool
    if otp_monitor.db_manager.pool:
        await otp_monitor.db_manager.pool.close()

app = FastAPI(
    title="OTP Catcher Server",
    description="Server for catching OTP codes from Telegram (Sender ID: 777000) with duplicate prevention",
    version="2.3.0",
    lifespan=lifespan
)

# ==================== AUTH DEPENDENCIES ====================

async def verify_api_key(x_internal_key: str = Header(default="")):
    """Verify internal API key"""
    if x_internal_key != Config.INTERNAL_API_KEY:
        raise HTTPException(401, "Invalid API key")
    return True

async def verify_admin_key(x_admin_key: str = Header(default="")):
    """Verify admin API key"""
    if x_admin_key != Config.ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin key")
    return True

# ==================== PUBLIC ENDPOINTS ====================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "OTP Catcher Server",
        "status": "running",
        "version": "2.3.0",
        "timestamp": datetime.now().isoformat(),
        "monitoring": f"Sender ID {Config.OTP_SENDER_ID}",
        "method": "Polling with duplicate prevention",
        "uptime_seconds": int((datetime.now() - server_start_time).total_seconds())
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
        "polling_interval": Config.POLLING_INTERVAL,
        "monitoring_sender": Config.OTP_SENDER_ID,
        "detection_method": "polling",
        "duplicate_prevention": "enabled",
        "processed_messages": len(otp_monitor.processed_messages),
        "timestamp": datetime.now().isoformat()
    }

# ==================== OTP ENDPOINTS ====================

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

# ==================== ADMIN ANALYTICS ENDPOINTS ====================

@app.get("/api/admin/stats")
async def get_admin_stats(_: bool = Depends(verify_admin_key)):
    """Get comprehensive admin statistics"""
    try:
        # Get database analytics
        db_stats = await otp_monitor.db_manager.get_analytics_summary()
        
        # Get runtime stats
        runtime_stats = otp_monitor.get_runtime_stats()
        
        return {
            "server": {
                "uptime_seconds": int((datetime.now() - server_start_time).total_seconds()),
                "uptime_formatted": str(datetime.now() - server_start_time).split('.')[0],
                "started_at": server_start_time.isoformat(),
                "version": "2.3.0",
                "duplicate_prevention": "enabled"
            },
            "database": db_stats,
            "runtime": runtime_stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Admin stats error: {str(e)}")
        raise HTTPException(500, f"Failed to get stats: {str(e)}")

@app.get("/api/admin/requests")
async def get_recent_requests(
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    _: bool = Depends(verify_admin_key)
):
    """Get recent OTP requests with optional status filter"""
    try:
        requests = await otp_monitor.db_manager.get_recent_requests(limit, status)
        return {
            "total": len(requests),
            "requests": requests,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Recent requests error: {str(e)}")
        raise HTTPException(500, f"Failed to get requests: {str(e)}")

@app.get("/api/admin/hourly-stats")
async def get_hourly_stats(
    hours: int = Query(24, ge=1, le=168),
    _: bool = Depends(verify_admin_key)
):
    """Get hourly statistics"""
    try:
        stats = await otp_monitor.db_manager.get_hourly_stats(hours)
        return {
            "hours": hours,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Hourly stats error: {str(e)}")
        raise HTTPException(500, f"Failed to get hourly stats: {str(e)}")

@app.get("/api/admin/performance")
async def get_performance_metrics(_: bool = Depends(verify_admin_key)):
    """Get performance metrics"""
    try:
        db_stats = await otp_monitor.db_manager.get_analytics_summary()
        runtime_stats = otp_monitor.get_runtime_stats()
        
        return {
            "success_rate": db_stats.get("success_rate", 0),
            "average_detection_time_seconds": db_stats.get("average_detection_time", 0),
            "total_detected": runtime_stats.get("total_detected", 0),
            "total_timeout": runtime_stats.get("total_timeout", 0),
            "total_failed": runtime_stats.get("total_failed", 0),
            "active_sessions": runtime_stats.get("active_sessions", 0),
            "available_slots": runtime_stats.get("available_slots", 0),
            "processed_messages": runtime_stats.get("processed_messages", 0),
            "detection_efficiency": round(
                (runtime_stats.get("total_detected", 0) / 
                 max(1, runtime_stats.get("total_registered", 0))) * 100,
                2
            ),
            "duplicate_prevention": "enabled",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Performance metrics error: {str(e)}")
        raise HTTPException(500, f"Failed to get performance metrics: {str(e)}")

@app.get("/api/admin/dashboard")
async def get_admin_dashboard(_: bool = Depends(verify_admin_key)):
    """Get complete dashboard data"""
    try:
        # Get all data
        db_stats = await otp_monitor.db_manager.get_analytics_summary()
        runtime_stats = otp_monitor.get_runtime_stats()
        recent_requests = await otp_monitor.db_manager.get_recent_requests(10)
        hourly_stats = await otp_monitor.db_manager.get_hourly_stats(24)
        
        return {
            "summary": {
                **db_stats,
                **runtime_stats
            },
            "recent_requests": recent_requests,
            "hourly_stats": hourly_stats,
            "server_uptime": str(datetime.now() - server_start_time).split('.')[0],
            "duplicate_prevention": "enabled",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        raise HTTPException(500, f"Failed to get dashboard: {str(e)}")

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
