#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import secrets
import plotly.express as px
from datetime import datetime
import time
import os
from mac_vendor_lookup import MacLookup

# ============================================
# CLOUD-READY DATABASE PATH
# ============================================
# This finds the database in the SAME folder as this script.
# Works on Streamlit Cloud and locally.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flow_data.db')

# ============================================
# DEVICE DETECTION (IEEE OUI DATABASE)
# ============================================
mac_lookup = MacLookup()

KNOWN_DEVICES = {
    '46:12:5a': 'MacBook (Apple)',
    '28:bb:b2': 'Infinix Phone (Android)',
    'b0:be:83': 'MacBook Pro (Apple)',
    '94:25:33': 'Huawei Device (Android)',
    '00:0c:29': 'Ubuntu VM (Linux)',
    '1a:00:07': 'MacBook (macOS)',
    'a6:da:fa': 'iPhone (iOS)',
}

def detect_device(ip_address, mac_address=None, dhcp_vendor=None):
    if dhcp_vendor and dhcp_vendor != '' and dhcp_vendor != 'None':
        return dhcp_vendor

    if mac_address and mac_address != '':
        clean_mac = mac_address.replace(':', '').upper()
        for prefix, device in KNOWN_DEVICES.items():
            prefix_clean = prefix.replace(':', '').upper()
            if clean_mac.startswith(prefix_clean):
                return device

    if mac_address and mac_address != '':
        try:
            vendor = mac_lookup.lookup(mac_address)
            return vendor
        except KeyError:
            return 'Unregistered Device'
        except Exception:
            pass

    if ip_address:
        if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return 'Local Device'
        return 'External'

    return 'Unknown'

# ============================================
# IP HASHING FOR USER VIEW
# ============================================
def hash_ip(ip_address):
    if not ip_address or ip_address == '':
        return 'Unknown'
    return hashlib.sha256(ip_address.encode()).hexdigest()[:16]

def display_ip(ip_address, is_admin):
    if is_admin:
        return ip_address
    return hash_ip(ip_address)

# ============================================
# DATABASE CONNECTION HELPER
# ============================================
def get_db_connection(max_retries=5):
    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(DB_PATH, timeout=15.0)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=15000;")
            return conn
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < max_retries - 1:
                time.sleep(0.5)
                continue
            raise
    raise Exception("Could not connect to database after retries")

# ============================================
# AUTHENTICATION FUNCTIONS
# ============================================
def init_auth_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except:
        pass
    
    # Create default admin if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((salt + 'admin123').encode()).hexdigest()
        c.execute('INSERT INTO users (username, password_hash, salt, created_at, role) VALUES (?,?,?,?,?)',
                 ('admin', password_hash, salt, datetime.now().isoformat(), 'admin'))
    conn.commit()
    conn.close()

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def verify_user(username, password):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT salt, password_hash, role FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result:
            salt, password_hash, role = result
            if hash_password(password, salt) == password_hash:
                return True, role
    except Exception:
        pass
    return False, None

def create_user(username, password, role='user'):
    if len(username) < 3:
        return False, "Username too short"
    if len(password) < 6:
        return False, "Password too short"
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if c.fetchone()[0] > 0:
            conn.close()
            return False, "Username exists"
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)
        c.execute('INSERT INTO users (username, password_hash, salt, created_at, role) VALUES (?,?,?,?,?)',
                 (username, password_hash, salt, datetime.now().isoformat(), role))
        conn.commit()
        conn.close()
        return True, "Account created!"
    except Exception as e:
        return False, f"Error: {e}"

def get_user_role(username):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT role FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else 'user'
    except:
        return 'user'

def get_all_users():
    for attempt in range(5):
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT username, created_at, role FROM users")
            users = c.fetchall()
            conn.close()
            return users
        except sqlite3.OperationalError as e:
            if "locked" in str(e) and attempt < 4:
                time.sleep(0.5)
                continue
            return []
    return []

def delete_user(username):
    if username == 'admin':
        return False, "Cannot delete default admin"
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True, "User deleted"
    except Exception as e:
        return False, f"Error: {e}"

# ============================================
# DATA MANAGEMENT FUNCTIONS
# ============================================
def clear_all_data():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM flows")
        conn.commit()
        conn.close()
        return True, "✅ All data cleared!"
    except Exception as e:
        return False, f"❌ Error: {e}"

def clear_anomalies_only():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("DELETE FROM alerts")
        c.execute("UPDATE flows SET is_anomaly = 0, detected = NULL")
        conn.commit()
        conn.close()
        return True, "✅ Anomalies cleared!"
    except Exception as e:
        return False, f"❌ Error: {e}"

# ============================================
# LOGIN PAGE
# ============================================
def show_login():
    st.set_page_config(page_title="Login - Network Security Monitor", page_icon="🔐", layout="centered")
    st.markdown("""
    <style>
    .stApp { background: linear-gradient(135deg, #0a0e1a 0%, #1a2a4a 50%, #0a0e1a 100%); }
    .login-box { max-width: 400px; margin: 0 auto; padding: 40px; background: rgba(255,255,255,0.05); border-radius: 16px; border: 1px solid rgba(255,255,255,0.08); backdrop-filter: blur(10px); margin-top: 15vh; text-align: center; }
    .login-box h1 { color: white; font-size: 2rem; margin-bottom: 4px; }
    .login-box p { color: rgba(255,255,255,0.5); margin-bottom: 30px; }
    .login-icon { font-size: 4rem; margin-bottom: 10px; }
    footer { display: none !important; }
    #MainMenu { display: none !important; }
    .stDeployButton { display: none !important; }
    </style>
    """, unsafe_allow_html=True)
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown('<div class="login-icon">🛡️</div>', unsafe_allow_html=True)
    st.markdown('<h1>Network Security Monitor</h1>', unsafe_allow_html=True)
    st.markdown('<p>Privacy-Preserving Anomaly Detection with Device ID</p>', unsafe_allow_html=True)
    
    if st.session_state.get('show_signup', False):
        st.markdown("---")
        st.markdown("### 📝 Create Account")
        st.info("👤 New users get VIEW-ONLY access.")
        new_user = st.text_input("Username", placeholder="min 3 chars", key="su")
        new_pass = st.text_input("Password", type="password", placeholder="min 6 chars", key="sp")
        new_confirm = st.text_input("Confirm Password", type="password", key="sc")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Create Account", use_container_width=True):
                if new_pass != new_confirm:
                    st.error("Passwords don't match")
                elif new_user and new_pass:
                    ok, msg = create_user(new_user, new_pass, 'user')
                    if ok:
                        st.success(msg)
                        st.balloons()
                        st.session_state['show_signup'] = False
                        st.rerun()
                    else:
                        st.error(msg)
                else:
                    st.warning("Fill all fields")
        with c2:
            if st.button("⬅️ Back to Login", use_container_width=True):
                st.session_state['show_signup'] = False
                st.rerun()
    else:
        username = st.text_input("Username", placeholder="Enter username")
        password = st.text_input("Password", type="password", placeholder="Enter password")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔓 Login", use_container_width=True):
                if username and password:
                    ok, role = verify_user(username, password)
                    if ok:
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username
                        st.session_state['role'] = role
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials")
                else:
                    st.warning("Enter both fields")
        with c2:
            if st.button("📝 Sign Up", use_container_width=True):
                st.session_state['show_signup'] = True
                st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

# ============================================
# DASHBOARD
# ============================================
def show_dashboard():
    st.set_page_config(page_title="Network Security Monitor", page_icon="🛡️", layout="wide")
    username = st.session_state.get('username', 'admin')
    is_admin = (get_user_role(username) == 'admin')
    
    st.markdown("""
    <style>
    .stApp { background: #0a0e1a; }
    .main-header {
        background: linear-gradient(135deg, #0a1628 0%, #1a2a4a 30%, #2a3a5a 60%, #1a2a4a 100%);
        padding: 25px 35px; border-radius: 16px; color: white; text-align: center; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.08);
    }
    .main-header h1 { font-size: 2.2rem; font-weight: 800; margin: 0; }
    .main-header h1 span { color: #64b5f6; }
    .main-header p { opacity: 0.85; margin: 8px 0 0 0; }
    .main-header .badge {
        display: inline-block; background: rgba(100,181,246,0.15); border: 1px solid rgba(100,181,246,0.25);
        padding: 4px 16px; border-radius: 20px; font-size: 0.75rem; color: #64b5f6; margin-top: 8px;
    }
    .glass-card {
        background: rgba(255,255,255,0.04); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.06);
        border-radius: 16px; padding: 20px 24px; height: 100%;
    }
    .glass-card .metric-value { font-size: 2.4rem; font-weight: 700; color: #ffffff; }
    .glass-card .metric-label { font-size: 0.8rem; color: rgba(255,255,255,0.5); text-transform: uppercase; letter-spacing: 1.5px; }
    .status-healthy { display: inline-block; background: rgba(45,255,100,0.12); border: 1px solid rgba(45,255,100,0.25); padding: 6px 18px; border-radius: 20px; color: #2dff64; font-weight: 600; }
    .status-alert { display: inline-block; background: rgba(255,68,68,0.15); border: 1px solid rgba(255,68,68,0.3); padding: 6px 18px; border-radius: 20px; color: #ff4444; font-weight: 600; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    .alert-card { background: rgba(255,68,68,0.06); border-left: 3px solid #ff4444; padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; }
    .alert-card .time { font-size: 0.7rem; color: rgba(255,255,255,0.4); }
    .alert-card .detail { font-size: 0.85rem; color: #ffffff; font-weight: 500; }
    .alert-card .device { font-size: 0.75rem; color: #ffaa00; font-weight: 600; }
    .alert-card .ip { font-size: 0.75rem; color: rgba(255,255,255,0.5); font-family: monospace; }
    .live-dot { display: inline-block; width: 8px; height: 8px; background: #2dff64; border-radius: 50%; animation: live-pulse 1.2s infinite; margin-right: 6px; }
    @keyframes live-pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.3; transform: scale(0.7); } }
    .role-admin { background: rgba(255,170,0,0.15); border: 1px solid rgba(255,170,0,0.3); padding: 2px 12px; border-radius: 12px; color: #ffaa00; font-size: 0.7rem; font-weight: 600; }
    .role-user { background: rgba(100,181,246,0.10); border: 1px solid rgba(100,181,246,0.2); padding: 2px 12px; border-radius: 12px; color: #64b5f6; font-size: 0.7rem; font-weight: 600; }
    .privacy-badge { background: rgba(100,181,246,0.10); border: 1px solid rgba(100,181,246,0.2); padding: 8px 14px; border-radius: 8px; color: #64b5f6; font-size: 0.75rem; text-align: center; margin-bottom: 12px; }
    footer { display: none !important; }
    #MainMenu { display: none !important; }
    .stDeployButton { display: none !important; }
    </style>
    """, unsafe_allow_html=True)
    
    with st.sidebar:
        role_badge = '<span class="role-admin">👑 Admin</span>' if is_admin else '<span class="role-user">👤 User</span>'
        st.markdown(f"""
        <div style="background: rgba(100,181,246,0.08); border: 1px solid rgba(100,181,246,0.1); border-radius: 8px; padding: 12px; text-align: center; margin-bottom: 16px;">
            <div style="color: #64b5f6; font-weight: 600;">👤 {username}</div>
            <div style="margin-top: 4px;">{role_badge}</div>
        </div>
        """, unsafe_allow_html=True)
        
        if not is_admin:
            st.markdown("""
            <div class="privacy-badge">
                🔒 Privacy Mode<br>
                <span style="font-size: 0.65rem; opacity: 0.7;">IPs are hashed</span>
            </div>
            """, unsafe_allow_html=True)
            
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state['logged_in'] = False
            st.session_state['username'] = ''
            st.session_state['role'] = ''
            st.rerun()
        
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center;">
            <div style="font-size: 2.8rem;">🛡️</div>
            <div style="color: #64b5f6; font-weight: 700;">Network Security</div>
            <div style="color: rgba(255,255,255,0.3); font-size: 0.7rem;">Anomaly Detection System</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        refresh_rate = st.slider("🔄 Refresh", 3, 30, 5)
        
        if is_admin:
            st.markdown("---")
            st.markdown("""
            <div style="color: rgba(255,255,255,0.3); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
                👑 Admin Panel
            </div>
            """, unsafe_allow_html=True)
            
            users = get_all_users()
            if users:
                user_data = [{'Username': u[0], 'Role': '👑 Admin' if u[2] == 'admin' else '👤 User'} for u in users]
                st.dataframe(pd.DataFrame(user_data), use_container_width=True, hide_index=True)
            
            st.markdown("**➕ Add User**")
            new_user = st.text_input("Username", key="au", placeholder="Enter username")
            new_pass = st.text_input("Password", type="password", key="ap", placeholder="Enter password")
            new_role = st.selectbox("Role", ['user', 'admin'], key="ar")
            if st.button("➕ Create", use_container_width=True):
                if new_user and new_pass:
                    ok, msg = create_user(new_user, new_pass, new_role)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
                else:
                    st.warning("Fill all fields")
            
            user_list = [u[0] for u in users if u[0] != 'admin']
            if user_list:
                del_user = st.selectbox("Select user", user_list, key="du")
                if st.button("🗑️ Delete", use_container_width=True):
                    ok, msg = delete_user(del_user)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            
            st.markdown("---")
            st.markdown("""
            <div style="color: rgba(255,255,255,0.3); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
                🗑️ Data Management
            </div>
            """, unsafe_allow_html=True)
            
            c1, c2 = st.columns(2)
            with c1:
                if st.button("🧹 Clear All", use_container_width=True):
                    ok, msg = clear_all_data()
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            with c2:
                if st.button("🚨 Clear Anomalies", use_container_width=True):
                    ok, msg = clear_anomalies_only()
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
        else:
            st.markdown("---")
            st.markdown("""
            <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; padding: 16px; text-align: center;">
                <div style="font-size: 2rem; opacity: 0.3;">🔒</div>
                <div style="color: rgba(255,255,255,0.3); font-size: 0.8rem; font-weight: 600;">View-Only Mode</div>
                <div style="color: rgba(255,255,255,0.15); font-size: 0.65rem; margin-top: 4px;">Contact admin for full access</div>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown("---")
        st.markdown(f"""
        <div style="color: rgba(255,255,255,0.2); font-size: 0.6rem; text-align: center;">
            <span class="live-dot"></span> Live Monitoring<br>
            Privacy-Preserving • ML-Powered
        </div>
        """, unsafe_allow_html=True)
        
        status_placeholder = st.empty()

    def get_data():
        for attempt in range(5):
            try:
                conn = get_db_connection()
                stats = pd.read_sql_query("""
                    SELECT 
                        COUNT(*) as total_flows,
                        SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count,
                        AVG(byte_count) as avg_bytes
                    FROM flows
                """, conn)
                alerts = pd.read_sql_query("""
                    SELECT f.timestamp, f.src_ip, f.dst_ip, f.src_mac, f.dhcp_vendor, f.packet_count, f.byte_count, a.severity
                    FROM alerts a JOIN flows f ON a.flow_id = f.id
                    ORDER BY a.timestamp DESC LIMIT 20
                """, conn)
                timeline = pd.read_sql_query("""
                    SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
                    FROM flows WHERE is_anomaly = 1
                    AND timestamp > datetime('now', '-24 hours')
                    GROUP BY hour ORDER BY hour
                """, conn)
                recent = pd.read_sql_query("""
                    SELECT timestamp, src_ip, dst_ip, src_mac, dst_mac, dhcp_vendor, packet_count, byte_count
                    FROM flows ORDER BY id DESC LIMIT 15
                """, conn)
                conn.close()
                if stats.empty:
                    return None, None, None, None
                return stats.iloc[0], alerts, timeline, recent
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < 4:
                    time.sleep(1.0)
                    continue
                return None, None, None, None
            except Exception:
                return None, None, None, None
        return None, None, None, None

    placeholder = st.empty()

    while True:
        with placeholder.container():
            stats, alerts, timeline, recent = get_data()
            
            if stats is None:
                st.warning("⏳ Waiting for data... Make sure the collector is running.")
                time.sleep(3)
                continue
            
            st.markdown("""
            <div class="main-header">
                <h1>🛡️ Network <span>Security</span> Monitor</h1>
                <p>Privacy-Preserving Anomaly Detection with Device Identification</p>
                <div class="badge">⚡ Real-time • ML-Powered • Privacy First • DHCP Fingerprinting</div>
            </div>
            """, unsafe_allow_html=True)
            
            anomaly_count = int(stats['anomaly_count']) if stats['anomaly_count'] is not None else 0
            total_flows = int(stats['total_flows']) if stats['total_flows'] is not None else 0
            avg_bytes = float(stats['avg_bytes']) if stats['avg_bytes'] is not None else 0
            
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.markdown(f"""<div class="glass-card"><div class="metric-label">📊 Total Flows</div><div class="metric-value">{total_flows:,}</div></div>""", unsafe_allow_html=True)
            with c2:
                color = "#ff4444" if anomaly_count > 0 else "#2dff64"
                st.markdown(f"""<div class="glass-card"><div class="metric-label">🚨 Anomalies</div><div class="metric-value" style="color: {color}">{anomaly_count}</div></div>""", unsafe_allow_html=True)
            with c3:
                st.markdown(f"""<div class="glass-card"><div class="metric-label">📦 Avg Packet Size</div><div class="metric-value">{avg_bytes:,.0f}</div></div>""", unsafe_allow_html=True)
            with c4:
                status_text = "🔴 Alert" if anomaly_count > 0 else "🟢 Healthy"
                status_class = "status-alert" if anomaly_count > 0 else "status-healthy"
                st.markdown(f"""<div class="glass-card"><div class="metric-label">📈 System Status</div><div style="margin-top: 4px;"><span class="{status_class}">{status_text}</span></div></div>""", unsafe_allow_html=True)
            
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown("**📈 Anomaly Timeline (24h)**")
                if not timeline.empty:
                    fig = px.bar(timeline, x='hour', y='count', color='count', color_continuous_scale=['#1a2a4a', '#ffaa00', '#ff4444'])
                    fig.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font_color='rgba(255,255,255,0.6)', height=300, margin=dict(l=20, r=20, t=20, b=20), showlegend=False)
                    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                else:
                    st.info("No anomalies in last 24 hours")
            
            with c2:
                st.markdown("**🔴 Recent Alerts**")
                if not alerts.empty:
                    for _, alert in alerts.head(5).iterrows():
                        mac = alert.get('src_mac', None) if 'src_mac' in alert else None
                        dhcp = alert.get('dhcp_vendor', None) if 'dhcp_vendor' in alert else None
                        device = detect_device(alert['src_ip'], mac, dhcp)
                        src_display = display_ip(alert['src_ip'], is_admin)
                        dst_display = display_ip(alert['dst_ip'], is_admin)
                        st.markdown(f"""
                        <div class="alert-card">
                            <div class="time">🚨 {alert['timestamp'][11:19]}</div>
                            <div class="detail">{src_display} → {dst_display}</div>
                            <div class="device">{device}</div>
                            <div class="ip">{alert['packet_count']} packets • {alert['byte_count']:,} bytes</div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("✅ No alerts")
            
            st.markdown("---")
            st.markdown("**📋 Recent Network Flows with Device Detection**")
            
            if recent is not None and not recent.empty:
                df = recent.head(8).copy()
                df['timestamp'] = df['timestamp'].str[11:19]
                df['Device'] = df.apply(lambda row: detect_device(row['src_ip'], row['src_mac'], row.get('dhcp_vendor')), axis=1)
                df['src'] = df['src_ip'].apply(lambda x: display_ip(x, is_admin))
                df['dst'] = df['dst_ip'].apply(lambda x: display_ip(x, is_admin))
                df = df[['timestamp', 'src', 'dst', 'Device', 'packet_count', 'byte_count']]
                df.columns = ['Time', 'Source', 'Destination', 'Device', 'Packets', 'Bytes']
                st.dataframe(df, use_container_width=True, hide_index=True)
                if not is_admin:
                    st.caption("🔒 IP addresses are hashed for privacy. Only administrators can view real IP addresses.")
            else:
                st.info("No flows yet")
        
        if stats is not None and stats['anomaly_count'] is not None:
            anomaly_count = int(stats['anomaly_count'])
            if anomaly_count > 0:
                status_placeholder.markdown(f"""<div style="background: rgba(255,68,68,0.08); border: 1px solid rgba(255,68,68,0.15); border-radius: 8px; padding: 12px; text-align: center;"><div style="color: #ff4444; font-weight: 700;">⚠️ {anomaly_count} Threats</div></div>""", unsafe_allow_html=True)
            else:
                status_placeholder.markdown(f"""<div style="background: rgba(45,255,100,0.06); border: 1px solid rgba(45,255,100,0.1); border-radius: 8px; padding: 12px; text-align: center;"><div style="color: #2dff64; font-weight: 700;">✅ Clean</div></div>""", unsafe_allow_html=True)
        
        time.sleep(refresh_rate)
        st.rerun()

# ============================================
# MAIN APP
# ============================================
init_auth_db()

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = ''
if 'role' not in st.session_state:
    st.session_state['role'] = 'user'

if st.session_state['logged_in']:
    show_dashboard()
else:
    show_login()
