import asyncio
import logging
import re
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Set
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import uvicorn

# Telegram imports
from pyrogram import Client
from pyrogram.errors import (
    FloodWait,
    SessionExpired,
    UserDeactivated,
    UserDeactivatedBan,
    AuthKeyUnregistered,
    Unauthorized
)

# HTTP client
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
    TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", "0"))
    TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
    
    # Security
    INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "shared-secret-key")
    
    # Main server callback URL
    MAIN_SERVER_CALLBACK_URL = os.getenv(
        "MAIN_SERVER_CALLBACK_URL",
        "https://marketplace-server.onrender.com/api/otp/callback"
    )
    
    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "")
    
    # Server settings
    MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT", "10"))
    OTP_TIMEOUT = int(os.getenv("OTP_TIMEOUT", "300"))  # 5 minutes
    POLLING_INTERVAL = int(os.getenv("POLLING_INTERVAL", "3"))  # 3 seconds
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

class RegisterRequest(BaseModel):
    """Request to register account for OTP monitoring"""
    phone_number: str
    session_string: str
    two_fa_password: Optional[str] = None
    callback_url: Optional[str] = None
    transaction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Account info from main server
    account_id: Optional[str] = None
    buyer_username: Optional[str] = None
    buyer_id: Optional[str] = None
    endpoint_name: Optional[str] = None
    account_price: Optional[str] = None
    spam_status: Optional[str] = None
    account_info: Optional[Dict] = None
    bot_token: Optional[str] = None
    admin_telegram_id: Optional[int] = None
    channel_username: Optional[str] = None
    channel_id: Optional[int] = None
    
    @validator('phone_number')
    def validate_phone(cls, v):
        v = v.strip()
        if not re.match(r'^\+?[1-9]\d{1,14}$', v):
            raise ValueError('Invalid phone number format')
        return v
    
    @validator('session_string')
    def validate_session(cls, v):
        if len(v) < 50:
            raise ValueError('Invalid session string')
        return v


class OTPCallback(BaseModel):
    """Callback data sent to main server"""
    phone_number: str
    otp_code: Optional[str] = None
    status: str  # detected, expired, failed
    transaction_id: str
    account_id: Optional[str] = None
    buyer_username: Optional[str] = None
    buyer_id: Optional[str] = None
    endpoint_name: Optional[str] = None
    attempt_count: int = 0
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


# ==================== DATABASE MANAGER ====================

class DatabaseManager:
    """Manage OTP tracking database operations"""
    
    def __init__(self):
        self.pool: Optional[Pool] = None
    
    async def initialize(self):
        """Initialize database pool"""
        if not Config.DATABASE_URL:
            logger.warning("No DATABASE_URL set, running without database")
            return
            
        try:
            self.pool = await asyncpg.create_pool(
                Config.DATABASE_URL,
                min_size=1,
                max_size=10
            )
            await self.create_tables()
            logger.info("✅ Database initialized")
        except Exception as e:
            logger.error(f"Database init error: {e}")
            self.pool = None
    
    async def create_tables(self):
        """Create necessary tables"""
        if not self.pool:
            return
            
        query = """
        -- Active OTP tracking sessions
        CREATE TABLE IF NOT EXISTS otp_tracking (
            id SERIAL PRIMARY KEY,
            transaction_id VARCHAR(50) UNIQUE NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            account_id VARCHAR(50),
            buyer_username VARCHAR(100),
            buyer_id VARCHAR(50),
            endpoint_name VARCHAR(100),
            account_price VARCHAR(50),
            spam_status VARCHAR(50),
            account_info JSONB,
            status VARCHAR(20) DEFAULT 'active', -- active, detected, expired, failed
            otp_code TEXT,
            attempt_count INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            detected_at TIMESTAMP,
            expired_at TIMESTAMP
        );
        
        -- Processed messages cache to prevent duplicates
        CREATE TABLE IF NOT EXISTS processed_messages (
            id SERIAL PRIMARY KEY,
            message_id BIGINT UNIQUE NOT NULL,
            phone_number VARCHAR(20),
            otp_code TEXT,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_tracking_status ON otp_tracking(status);
        CREATE INDEX IF NOT EXISTS idx_tracking_created ON otp_tracking(created_at);
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query)
                logger.info("✅ Database tables ready")
        except Exception as e:
            logger.error(f"Table creation error: {e}")
    
    async def save_tracking(self, data: dict):
        """Save or update tracking record"""
        if not self.pool:
            return
            
        query = """
        INSERT INTO otp_tracking (
            transaction_id, phone_number, account_id, buyer_username, buyer_id,
            endpoint_name, account_price, spam_status, account_info,
            status, attempt_count, expired_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9,
            'active', $10, NOW() + INTERVAL '5 minutes'
        )
        ON CONFLICT (transaction_id) 
        DO UPDATE SET 
            status = 'active',
            attempt_count = otp_tracking.attempt_count + 1,
            expired_at = NOW() + INTERVAL '5 minutes'
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    query,
                    data.get('transaction_id'),
                    data.get('phone_number'),
                    data.get('account_id'),
                    data.get('buyer_username'),
                    data.get('buyer_id'),
                    data.get('endpoint_name'),
                    data.get('account_price'),
                    data.get('spam_status'),
                    data.get('account_info_json'),
                    1  # attempt count
                )
                logger.info(f"✅ Tracking saved: {data.get('transaction_id')}")
        except Exception as e:
            logger.error(f"Save tracking error: {e}")
    
    async def update_status(self, transaction_id: str, status: str, otp_code: Optional[str] = None):
        """Update tracking status"""
        if not self.pool:
            return
            
        query = """
        UPDATE otp_tracking 
        SET status = $1,
            otp_code = COALESCE($2, otp_code),
            detected_at = CASE WHEN $1 = 'detected' THEN NOW() ELSE detected_at END,
            expired_at = CASE WHEN $1 = 'expired' THEN NOW() ELSE expired_at END
        WHERE transaction_id = $3
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, status, otp_code, transaction_id)
                logger.info(f"✅ Status updated: {transaction_id} → {status}")
        except Exception as e:
            logger.error(f"Update status error: {e}")
    
    async def is_message_processed(self, message_id: int) -> bool:
        """Check if message already processed"""
        if not self.pool:
            return False
            
        query = "SELECT EXISTS(SELECT 1 FROM processed_messages WHERE message_id = $1)"
        
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval(query, message_id)
        except:
            return False
    
    async def mark_message_processed(self, message_id: int, phone_number: str, otp_code: str):
        """Mark message as processed"""
        if not self.pool:
            return
            
        query = """
        INSERT INTO processed_messages (message_id, phone_number, otp_code)
        VALUES ($1, $2, $3)
        ON CONFLICT (message_id) DO NOTHING
        """
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, message_id, phone_number, otp_code)
        except Exception as e:
            logger.error(f"Mark message error: {e}")
    
    async def get_tracking(self, transaction_id: str) -> Optional[dict]:
        """Get tracking record"""
        if not self.pool:
            return None
            
        query = "SELECT * FROM otp_tracking WHERE transaction_id = $1"
        
        try:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, transaction_id)
                return dict(row) if row else None
        except:
            return None
    
    async def delete_tracking(self, transaction_id: str):
        """Delete tracking after successful OTP detection"""
        if not self.pool:
            return
            
        query = "DELETE FROM otp_tracking WHERE transaction_id = $1"
        
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, transaction_id)
                logger.info(f"✅ Tracking deleted: {transaction_id}")
        except Exception as e:
            logger.error(f"Delete tracking error: {e}")


# ==================== CHANNEL POSTER ====================

class ChannelPoster:
    """Post OTP messages to Telegram channels"""
    
    def __init__(self):
        self.bot_clients: Dict[str, Client] = {}
        self.last_used: Dict[str, datetime] = {}
    
    def _get_bot_key(self, bot_token: str, channel: str) -> str:
        """Generate unique bot key"""
        return hashlib.md5(f"{bot_token}_{channel}".encode()).hexdigest()[:20]
    
    async def _get_bot_client(self, bot_token: str, channel: str) -> Optional[Client]:
        """Get or create bot client"""
        bot_key = self._get_bot_key(bot_token, channel)
        
        if bot_key in self.bot_clients:
            self.last_used[bot_key] = datetime.now()
            return self.bot_clients[bot_key]
        
        try:
            client = Client(
                name=f"bot_{bot_key}",
                bot_token=bot_token,
                api_id=Config.TELEGRAM_API_ID,
                api_hash=Config.TELEGRAM_API_HASH,
                in_memory=True
            )
            await client.start()
            self.bot_clients[bot_key] = client
            self.last_used[bot_key] = datetime.now()
            logger.info(f"✅ Bot client created: {bot_key}")
            return client
        except Exception as e:
            logger.error(f"Bot client creation error: {e}")
            return None
    
    def _mask_phone(self, phone: str) -> str:
        """Mask middle digits of phone number"""
        if len(phone) <= 6:
            return phone
        return f"{phone[:3]}*****{phone[-2:]}"
    
    async def post_otp(self, config: dict, data: dict):
        """Post OTP message to channel and admin"""
        if not config.get('bot_token') or not (config.get('channel_username') or config.get('channel_id')):
            logger.warning("Missing bot token or channel info, skipping channel post")
            return
        
        bot_token = config['bot_token']
        channel = config.get('channel_username') or str(config.get('channel_id'))
        
        bot_client = await self._get_bot_client(bot_token, channel)
        if not bot_client:
            return
        
        # Prepare message data
        hidden_phone = self._mask_phone(data['phone_number'])
        otp_code = data['otp_code']
        buyer_username = data.get('buyer_username', 'Unknown')
        buyer_id = data.get('buyer_id', 'Unknown')
        endpoint_name = data.get('endpoint_name', 'Unknown')
        account_price = data.get('account_price', 'N/A')
        spam_status = data.get('spam_status', 'Unknown')
        transaction_id = data.get('transaction_id', '')
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        time_str = datetime.now().strftime("%H:%M:%S")
        ref_id = f"OTP-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        
        # Channel message
        channel_msg = f"""
🔐 **OTP CODE DETECTED**
━━━━━━━━━━━━━━━━━━━

📱 **Phone:** `{hidden_phone}`
🔑 **Code:** `{otp_code}`
👤 **Buyer:** {buyer_username} (ID: {buyer_id})
📱 **App:** {endpoint_name}

💰 **Price:** {account_price}
🛡️ **Spam:** {spam_status}

📅 **Date:** {date_str}
🕐 **Time:** {time_str}
📋 **Ref:** `{ref_id}`

━━━━━━━━━━━━━━━━━━━
✅ **Purchase Successful**
━━━━━━━━━━━━━━━━━━━

_🤖 Automated OTP Detection_
"""
        
        # Admin message with full details
        admin_msg = f"""
🔔 **OTP DETECTED - ADMIN ALERT**
━━━━━━━━━━━━━━━━━━━━━━

📱 **Full Phone:** `{data['phone_number']}`
🔐 **OTP Code:** `{otp_code}`
👤 **Buyer:** {buyer_username} (ID: {buyer_id})
📱 **Endpoint:** {endpoint_name}
💰 **Price:** {account_price}
🛡️ **Spam:** {spam_status}

📋 **TRX ID:** `{transaction_id}`
📇 **Ref ID:** `{ref_id}`

📅 **Date:** {date_str}
🕐 **Time:** {time_str}

━━━━━━━━━━━━━━━━━━━━━━
✅ **Status:** Successfully Detected
🔒 **Security:** Encrypted
━━━━━━━━━━━━━━━━━━━━━━

_Admin-only full details_
"""
        
        try:
            # Send to channel
            await bot_client.send_message(channel, channel_msg, parse_mode="Markdown")
            logger.info(f"✅ OTP posted to channel for {hidden_phone}")
        except Exception as e:
            logger.error(f"Channel post error: {e}")
            # Fallback without markdown
            try:
                await bot_client.send_message(channel, channel_msg.replace('**', '').replace('`', ''))
            except:
                pass
        
        # Send to admin if configured
        if config.get('admin_telegram_id'):
            try:
                await bot_client.send_message(config['admin_telegram_id'], admin_msg, parse_mode="Markdown")
            except Exception as e:
                logger.error(f"Admin message error: {e}")
                try:
                    await bot_client.send_message(
                        config['admin_telegram_id'], 
                        admin_msg.replace('**', '').replace('`', '')
                    )
                except:
                    pass


# ==================== OTP MONITOR ====================

class OTPMonitor:
    """Main OTP monitoring and detection system"""
    
    def __init__(self):
        self.active_sessions: Dict[str, dict] = {}
        self.transaction_map: Dict[str, str] = {}  # transaction_id -> session_id
        self.semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT)
        self.db = DatabaseManager()
        self.poster = ChannelPoster()
        self.processed_messages: Set[int] = set()
        self._cleanup_lock = asyncio.Lock()
        self.message_lock = asyncio.Lock()
        
        # Stats
        self.stats = {
            "total_attempts": 0,
            "total_detected": 0,
            "total_expired": 0,
            "total_failed": 0
        }
    
    async def initialize(self):
        """Initialize system"""
        await self.db.initialize()
        # Start message cache cleanup
        asyncio.create_task(self._cleanup_loop())
        logger.info("✅ OTP Monitor initialized")
    
    async def _cleanup_loop(self):
        """Periodic cleanup"""
        while True:
            await asyncio.sleep(1800)  # 30 minutes
            if len(self.processed_messages) > 500:
                self.processed_messages.clear()
                logger.info("Cleared message cache")
    
    async def register_account(self, request: RegisterRequest) -> dict:
        """Register account for OTP monitoring"""
        async with self.semaphore:
            client = None
            try:
                # Increment attempt counter
                self.stats["total_attempts"] += 1
                
                # Create Telegram client
                client = Client(
                    name=f"session_{request.phone_number}_{int(time.time())}",
                    api_id=Config.TELEGRAM_API_ID,
                    api_hash=Config.TELEGRAM_API_HASH,
                    session_string=request.session_string,
                    in_memory=True
                )
                
                # Connect
                await client.start()
                logger.info(f"✅ Connected: {request.phone_number}")
                
                # Handle 2FA if needed
                if request.two_fa_password:
                    try:
                        await client.check_password(request.two_fa_password)
                    except Exception as e:
                        await client.stop()
                        raise HTTPException(400, f"2FA password incorrect: {str(e)}")
                
                # Get initial message ID to avoid old messages
                initial_last_id = 0
                try:
                    chat = await client.get_chat(Config.OTP_SENDER_ID)
                    async for message in client.get_chat_history(chat.id, limit=1):
                        initial_last_id = message.id
                        break
                except Exception as e:
                    logger.warning(f"Could not get initial message ID: {e}")
                
                # Create session
                session_id = str(uuid.uuid4())
                session_info = {
                    "session_id": session_id,
                    "phone_number": request.phone_number,
                    "client": client,
                    "registered_at": datetime.now(),
                    "callback_url": request.callback_url or Config.MAIN_SERVER_CALLBACK_URL,
                    "transaction_id": request.transaction_id,
                    "account_id": request.account_id,
                    "buyer_username": request.buyer_username,
                    "buyer_id": request.buyer_id,
                    "endpoint_name": request.endpoint_name,
                    "account_price": request.account_price,
                    "spam_status": request.spam_status,
                    "account_info": request.account_info,
                    "bot_token": request.bot_token,
                    "admin_telegram_id": request.admin_telegram_id,
                    "channel_username": request.channel_username,
                    "channel_id": request.channel_id,
                    "status": "active",
                    "otp_received": None,
                    "polling_task": None,
                    "timeout_task": None,
                    "last_message_id": initial_last_id,
                    "processed_messages": set()
                }
                
                self.active_sessions[session_id] = session_info
                self.transaction_map[request.transaction_id] = session_id
                
                # Save to database
                await self.db.save_tracking({
                    "transaction_id": request.transaction_id,
                    "phone_number": request.phone_number,
                    "account_id": request.account_id,
                    "buyer_username": request.buyer_username,
                    "buyer_id": request.buyer_id,
                    "endpoint_name": request.endpoint_name,
                    "account_price": request.account_price,
                    "spam_status": request.spam_status,
                    "account_info_json": request.account_info
                })
                
                # Start polling and timeout tasks
                polling_task = asyncio.create_task(self._poll_otp(session_id))
                timeout_task = asyncio.create_task(self._schedule_timeout(session_id))
                session_info["polling_task"] = polling_task
                session_info["timeout_task"] = timeout_task
                
                return {
                    "success": True,
                    "session_id": session_id,
                    "message": "Account registered for OTP monitoring",
                    "timeout_at": (datetime.now() + timedelta(seconds=Config.OTP_TIMEOUT)).isoformat()
                }
                
            except HTTPException:
                if client:
                    await client.stop()
                raise
            except Exception as e:
                self.stats["total_failed"] += 1
                if client:
                    try:
                        await client.stop()
                    except:
                        pass
                logger.error(f"Registration error: {e}")
                raise HTTPException(500, f"Failed to register: {str(e)}")
    
    async def _poll_otp(self, session_id: str):
        """Poll for OTP messages"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        client = session_info["client"]
        last_message_id = session_info["last_message_id"]
        processed_messages = session_info["processed_messages"]
        
        end_time = datetime.now() + timedelta(seconds=Config.OTP_TIMEOUT)
        
        logger.info(f"🔄 Polling started: {session_info['phone_number']} from msg ID: {last_message_id}")
        
        while datetime.now() < end_time:
            # Check if session still active
            if session_id not in self.active_sessions or session_info["status"] != "active":
                return
            
            try:
                chat = await client.get_chat(Config.OTP_SENDER_ID)
                
                async for message in client.get_chat_history(chat.id, limit=5):
                    # Skip old messages
                    if message.id <= last_message_id:
                        continue
                    
                    # Check duplicates
                    async with self.message_lock:
                        if message.id in processed_messages or message.id in self.processed_messages:
                            continue
                        
                        # Check database
                        if await self.db.is_message_processed(message.id):
                            processed_messages.add(message.id)
                            self.processed_messages.add(message.id)
                            continue
                        
                        # Mark as processed
                        processed_messages.add(message.id)
                        self.processed_messages.add(message.id)
                        last_message_id = message.id
                        session_info["last_message_id"] = last_message_id
                    
                    if not message.text:
                        continue
                    
                    text = message.text
                    logger.info(f"📩 Message from 777000: {text[:50]}...")
                    
                    # Extract OTP (5-6 digits)
                    match = re.search(r'\b(\d{5,6})\b', text)
                    if match:
                        otp = match.group(1)
                        logger.info(f"🎯 OTP DETECTED: {otp}")
                        
                        await self.db.mark_message_processed(message.id, session_info['phone_number'], otp)
                        await self._handle_detection(session_id, otp)
                        return
                        
            except FloodWait as e:
                logger.warning(f"FloodWait: {e.x}s")
                await asyncio.sleep(min(e.x, 30))
            except Exception as e:
                logger.error(f"Polling error: {e}")
            
            await asyncio.sleep(Config.POLLING_INTERVAL)
        
        logger.info(f"⏰ Polling timeout: {session_info['phone_number']}")
    
    async def _handle_detection(self, session_id: str, otp_code: str):
        """Handle OTP detection"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        if session_info.get("otp_received"):
            return
        
        try:
            # Update session
            session_info["otp_received"] = otp_code
            session_info["status"] = "detected"
            session_info["detected_at"] = datetime.now()
            
            # Update stats
            self.stats["total_detected"] += 1
            
            # 1. POST TO CHANNEL FIRST
            await self.poster.post_otp({
                "bot_token": session_info.get("bot_token"),
                "channel_username": session_info.get("channel_username"),
                "channel_id": session_info.get("channel_id"),
                "admin_telegram_id": session_info.get("admin_telegram_id")
            }, {
                "phone_number": session_info["phone_number"],
                "otp_code": otp_code,
                "buyer_username": session_info.get("buyer_username"),
                "buyer_id": session_info.get("buyer_id"),
                "endpoint_name": session_info.get("endpoint_name"),
                "account_price": session_info.get("account_price"),
                "spam_status": session_info.get("spam_status"),
                "transaction_id": session_info["transaction_id"]
            })
            
            # 2. SEND CALLBACK TO MAIN SERVER
            await self._send_callback(session_info, otp_code, "detected")
            
            # 3. DELETE FROM DATABASE (successful)
            await self.db.delete_tracking(session_info["transaction_id"])
            
            # 4. CLEANUP
            await self._cleanup_session(session_id)
            
        except Exception as e:
            logger.error(f"Detection handling error: {e}")
    
    async def _handle_expired(self, session_id: str):
        """Handle timeout/expired"""
        session_info = self.active_sessions.get(session_id)
        if not session_info:
            return
        
        try:
            session_info["status"] = "expired"
            self.stats["total_expired"] += 1
            
            # Update database as expired (keep for retry)
            await self.db.update_status(session_info["transaction_id"], "expired")
            
            # Send callback
            await self._send_callback(session_info, None, "expired")
            
            # Cleanup session
            await self._cleanup_session(session_id)
            
        except Exception as e:
            logger.error(f"Expired handling error: {e}")
    
    async def _send_callback(self, session_info: dict, otp_code: Optional[str], status: str):
        """Send callback to main server"""
        callback = OTPCallback(
            phone_number=session_info["phone_number"],
            otp_code=otp_code,
            status=status,
            transaction_id=session_info["transaction_id"],
            account_id=session_info.get("account_id"),
            buyer_username=session_info.get("buyer_username"),
            buyer_id=session_info.get("buyer_id"),
            endpoint_name=session_info.get("endpoint_name"),
            attempt_count=self.stats["total_attempts"]
        )
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    session_info["callback_url"],
                    json=callback.dict(),
                    headers={
                        "X-Internal-Key": Config.INTERNAL_API_KEY,
                        "Content-Type": "application/json"
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.info(f"✅ Callback sent: {session_info['phone_number']} → {status}")
                else:
                    logger.error(f"Callback failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Callback error: {e}")
    
    async def _schedule_timeout(self, session_id: str):
        """Schedule timeout"""
        await asyncio.sleep(Config.OTP_TIMEOUT)
        
        session_info = self.active_sessions.get(session_id)
        if session_info and session_info["status"] == "active" and not session_info.get("otp_received"):
            await self._handle_expired(session_id)
    
    async def _cleanup_session(self, session_id: str):
        """Clean up session"""
        async with self._cleanup_lock:
            session_info = self.active_sessions.pop(session_id, None)
            if session_info:
                # Cancel tasks
                for task_key in ["polling_task", "timeout_task"]:
                    task = session_info.get(task_key)
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except:
                            pass
                
                # Stop client
                client = session_info["client"]
                try:
                    await client.stop()
                except:
                    pass
                
                # Remove from maps
                self.transaction_map.pop(session_info["transaction_id"], None)
                
                logger.info(f"✅ Session cleaned: {session_id}")
    
    def get_available_slots(self) -> int:
        """Get available slots"""
        active = len([s for s in self.active_sessions.values() if s["status"] == "active"])
        return max(0, Config.MAX_CONCURRENT - active)


# ==================== FASTAPI APP ====================

otp_monitor = OTPMonitor()
server_start_time = datetime.now()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🚀 OTP Catcher Server starting...")
    logger.info(f"Max concurrent: {Config.MAX_CONCURRENT}")
    logger.info(f"OTP timeout: {Config.OTP_TIMEOUT}s")
    logger.info(f"Polling interval: {Config.POLLING_INTERVAL}s")
    
    await otp_monitor.initialize()
    
    yield
    
    # Shutdown
    logger.info("🔧 Shutting down...")
    for session_id in list(otp_monitor.active_sessions.keys()):
        await otp_monitor._cleanup_session(session_id)
    
    if otp_monitor.db.pool:
        await otp_monitor.db.pool.close()
    
    logger.info("✅ Shutdown complete")

app = FastAPI(
    title="OTP Catcher Server",
    description="OTP detection from Telegram (777000)",
    version="3.0.0",
    lifespan=lifespan
)

# ==================== AUTH ====================

async def verify_api_key(x_internal_key: str = Header(default="")):
    """Verify internal API key"""
    if x_internal_key != Config.INTERNAL_API_KEY:
        raise HTTPException(401, "Invalid API key")
    return True

# ==================== ENDPOINTS ====================

@app.get("/")
async def root():
    return {
        "service": "OTP Catcher Server",
        "status": "running",
        "version": "3.0.0",
        "uptime_seconds": int((datetime.now() - server_start_time).total_seconds())
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "available_slots": otp_monitor.get_available_slots(),
        "max_concurrent": Config.MAX_CONCURRENT,
        "active_sessions": len(otp_monitor.active_sessions),
        "total_detected": otp_monitor.stats["total_detected"],
        "total_expired": otp_monitor.stats["total_expired"],
        "total_attempts": otp_monitor.stats["total_attempts"]
    }

@app.post("/api/otp/register")
async def register_account(request: RegisterRequest, _: bool = Depends(verify_api_key)):
    """Register account for OTP monitoring"""
    try:
        if otp_monitor.get_available_slots() <= 0:
            raise HTTPException(429, "No available slots")
        
        result = await otp_monitor.register_account(request)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(500, f"Failed: {str(e)}")

@app.get("/api/otp/sessions")
async def get_sessions(_: bool = Depends(verify_api_key)):
    """Get active sessions"""
    sessions = []
    for session_info in otp_monitor.active_sessions.values():
        sessions.append({
            "phone_number": session_info["phone_number"],
            "status": session_info["status"],
            "transaction_id": session_info["transaction_id"],
            "registered_at": session_info["registered_at"].isoformat()
        })
    
    return {
        "sessions": sessions,
        "total": len(sessions),
        "available_slots": otp_monitor.get_available_slots()
    }

@app.delete("/api/otp/session/{transaction_id}")
async def cancel_session(transaction_id: str, _: bool = Depends(verify_api_key)):
    """Cancel active session"""
    session_id = otp_monitor.transaction_map.get(transaction_id)
    if session_id:
        await otp_monitor._cleanup_session(session_id)
        await otp_monitor.db.update_status(transaction_id, "failed")
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
    logger.error(f"Unhandled: {exc}")
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
        reload=False
    )
