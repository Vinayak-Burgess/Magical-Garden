"""
================================================================================
 MAGICAL GARDEN  v2.1.0
 A fully offline, encrypted password manager with Tokyo Night glassmorphism UI
--------------------------------------------------------------------------------
 Motto: "Bridging the gap between secure systems and aesthetic design."

 Requirements:
     pip install PySide6 cryptography

 Run:
     python magical_garden.py

 100% offline. No network calls. No telemetry. All data lives next to this
 file as an encrypted blob (garden.enc) plus its key-verification file
 (sunlight.key), and two small plaintext preference/config files that never
 contain secrets.

 SECURITY NOTE: there is no password-recovery backdoor. If sunlight.key is
 lost or deleted, a new master password can NEVER decrypt the old garden.enc
 (a different password derives a completely different encryption key). The
 app will refuse to silently treat that situation as a "fresh install."
================================================================================
"""


import sys
import os
import json
import base64
import secrets
import string
import time
import math
import re
import csv
import uuid
import struct
import tempfile
from datetime import datetime

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Missing dependency 'cryptography'. Install it with:\n    pip install cryptography")
    sys.exit(1)

try:
    from PySide6.QtCore import (
        Qt, QTimer, Signal, QRectF, QRect, QSize, QPropertyAnimation, QEasingCurve,
        QPoint, Property, QMimeData, QByteArray,
    )
    from PySide6.QtGui import QColor, QPainter, QPen, QFont
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
        QVBoxLayout, QHBoxLayout, QGridLayout, QLayout, QFrame, QStackedWidget,
        QScrollArea, QComboBox, QSlider, QCheckBox, QButtonGroup, QMessageBox,
        QFileDialog, QInputDialog, QSizePolicy, QSpacerItem, QProgressBar,
        QGraphicsDropShadowEffect, QDialog, QTextEdit,
    )
except ImportError:
    print("Missing dependency 'PySide6'. Install it with:\n    pip install PySide6")
    sys.exit(1)


# =========================================================================== #
#  FILE MAP - read this first if you're new to the codebase
# =========================================================================== #
#   1. STORAGE FILES / CRYPTO ENGINE   - file paths + PBKDF2/Fernet encryption
#   2. PASSWORD SCORING / GENERATION   - strength meter math, password creator
#   3. THEME PALETTES / STYLESHEET     - all colors + the QSS builder
#   4. FLOW LAYOUT                     - the wrapping-row layout used for tag
#                                         chips, pills, and the Vault grid
#   5. SMALL REUSABLE WIDGETS          - Card, ToggleSwitch, Badge, etc.
#   6. AuthPage                        - setup / unlock / recovery screen
#   7. Sidebar                         - left-hand navigation
#   8. EntryDialog / EntryListDialog   - the Add/Edit modal + drill-down list
#   9. EntryCard                       - a single credential card in the Vault
#  10. VaultPage / DashboardPage       - the two main content screens
#  11. GeneratorPage / SettingsPage    - password generator + all preferences
#  12. TutorialPage / LicensePage      - static help/info screens
#  13. MainAppShell / MagicalGardenApp - wires everything together, owns the
#                                         session key and the auto-lock timer
# =========================================================================== #


# =========================================================================== #
#  STORAGE FILES  (all local, all offline)
# =========================================================================== #
#  Everything the app reads or writes lives NEXT TO THIS SCRIPT (not wherever
#  the terminal happened to be when it was launched), split into two folders:
#    vault/   - garden.enc + sunlight.key   (sensitive - back these up together)
#    config/  - preferences + generator settings (not sensitive, no secrets)
#  Both folders are created automatically the first time the app runs.
# =========================================================================== #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "vault")
CONFIG_DIR = os.path.join(BASE_DIR, "config")

GARDEN_FILE = os.path.join(VAULT_DIR, "garden.enc")
SUNLIGHT_KEY_FILE = os.path.join(VAULT_DIR, "sunlight.key")
GENERATOR_CONFIG_FILE = os.path.join(CONFIG_DIR, "generator_config.json")
PREFERENCES_FILE = os.path.join(CONFIG_DIR, "user_preferences.json")


def ensure_data_dirs():
    """Creates vault/ and config/ if they don't exist yet. Called once at
    startup (see the bottom of this file) - every read/write below also
    re-creates its own folder defensively, in case it gets deleted while the
    app is running."""
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)


ensure_data_dirs()

DEFAULT_GEN_CONFIG = {
    "length": 20,
    "use_uppercase": True,
    "use_lowercase": True,
    "use_digits": True,
    "use_symbols": True,
    "exclude_ambiguous": False,
}

DEFAULT_PREFERENCES = {
    "theme": "Midnight",               # the currently active palette name (THEMES)
    "last_dark_theme": "Midnight",     # remembers your accent color while in Light mode
    "font_size": "Medium",
    "vault_view_mode": "Grid",         # "Grid" | "List" - how Vault entries are laid out
    "default_page": "dashboard",       # which page opens right after unlocking
    "auto_lock_enabled": True,
    "auto_lock_timeout_min": 15,
    "clipboard_auto_clear": True,
    "clipboard_clear_delay_sec": 30,
    "last_unlocked_iso": "",
}

FONT_SIZES = {"Small": 9, "Medium": 10, "Large": 11, "X-Large": 13}
FONT_SCALES = {"Small": 0.9, "Medium": 1.0, "Large": 1.14, "X-Large": 1.3}

TAGLINE = "Bridging the gap between secure systems and aesthetic design."


# =========================================================================== #
#  UI TUNABLES  -  change these instead of hunting through the page code
# =========================================================================== #
#  A handful of numbers that show up in more than one place, or that you're
#  likely to want to tweak (card sizing, animation speed, timings), pulled up
#  here so the app stays easy to adjust without spelunking through layout
#  code buried inside a specific page class.
# =========================================================================== #

SIDEBAR_WIDTH = 250                 # px, left navigation column
VAULT_GRID_CARD_WIDTH = 400         # px, fixed card width used in Vault "Grid" view
ENTRY_CARD_MARGIN = 20              # px, inner padding of each Vault entry card
ENTRY_CARD_SPACING = 10             # px, vertical gap between rows inside a card
VAULT_ROW_GAP = 14                  # px, gap between entry cards in the Vault list
DIALOG_ANIMATION_MS = 190           # fade+rise duration when a modal opens
TOGGLE_ANIMATION_MS = 150           # slide duration for the on/off switches
AUTO_SAVE_DEBOUNCE_MS = 250         # delay after the last slider tick before writing to disk
AUTO_LOCK_POLL_MS = 2000            # how often the inactivity timer checks the clock


# =========================================================================== #
#  JSON HELPERS
# =========================================================================== #

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                merged = default.copy()
                merged.update(data)
                return merged
        except Exception:
            pass
    return default.copy()


def save_json(path, data):
    """Atomic write: dump to a temp file in the same folder, then rename it
    over the real file in one step, so an interrupted write can never leave
    a half-written/corrupt config file behind."""

    dir_name = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(dir_name, exist_ok=True)
    last_error = None
    for attempt in range(5):
        try:
            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                json.dump(data, tf, indent=4)
                temp_name = tf.name
            os.replace(temp_name, path)
            return True
        except PermissionError as e:
            last_error = e
            time.sleep(0.1 * (attempt + 1))
    print(f"Warning: could not save '{path}' after several attempts: {last_error}")
    return False


# =========================================================================== #
#  CRYPTO ENGINE  (PBKDF2-HMAC-SHA256, 600k iterations + Fernet AES128-CBC/HMAC)
# =========================================================================== #

def vault_exists() -> bool:
    return os.path.exists(GARDEN_FILE)


def key_exists() -> bool:
    return os.path.exists(SUNLIGHT_KEY_FILE)


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_sunlight_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def initialize_garden_key(master_password: str):
    ensure_data_dirs()
    salt = generate_salt()
    key = derive_sunlight_key(master_password, salt)
    fernet = Fernet(key)
    verification = fernet.encrypt(b"GARDEN_BLOOM_VERIFIED")
    with open(SUNLIGHT_KEY_FILE, "wb") as f:
        f.write(salt + verification)
    return key


def verify_sunlight_key(master_password: str):
    if not key_exists():
        return None
    with open(SUNLIGHT_KEY_FILE, "rb") as f:
        content = f.read()
    salt, verification = content[:16], content[16:]
    try:
        key = derive_sunlight_key(master_password, salt)
        fernet = Fernet(key)
        if fernet.decrypt(verification) == b"GARDEN_BLOOM_VERIFIED":
            return key
    except (InvalidToken, Exception):
        return None
    return None


def load_garden_vault(key: bytes) -> dict:
    default_vault = {"entries": {}}
    if key is None or not vault_exists():
        return default_vault
    try:
        fernet = Fernet(key)
        with open(GARDEN_FILE, "rb") as f:
            encrypted_data = f.read()
        if not encrypted_data:
            return default_vault
        data = json.loads(fernet.decrypt(encrypted_data).decode("utf-8"))
        if "entries" not in data or not isinstance(data["entries"], dict):
            data["entries"] = {}
        return data
    except Exception:
        return default_vault


def save_garden_vault(data: dict, key: bytes) -> bool:
    """Same atomic-write-with-retry approach as save_json() above, but for
    the encrypted vault blob. Returns True/False so callers that promise the
    user "saved!" can actually check that it happened."""
    if key is None:
        return False
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(json.dumps(data, indent=4).encode("utf-8"))
    dir_name = os.path.dirname(os.path.abspath(GARDEN_FILE)) or "."
    os.makedirs(dir_name, exist_ok=True)
    last_error = None
    for attempt in range(5):
        try:
            with tempfile.NamedTemporaryFile("wb", dir=dir_name, delete=False) as tf:
                tf.write(encrypted_data)
                temp_name = tf.name
            os.replace(temp_name, GARDEN_FILE)
            return True
        except PermissionError as e:
            last_error = e
            time.sleep(0.1 * (attempt + 1))
    print(f"Warning: could not save the vault after several attempts: {last_error}")
    return False


def wipe_vault_files():
    """Used ONLY by the explicit, typed-confirmation recovery flow in AuthPage.
    Never called implicitly - see the security note at the top of this file."""
    for path in (GARDEN_FILE, SUNLIGHT_KEY_FILE):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


# =========================================================================== #
#  PASSWORD SCORING / ENTROPY / GENERATION
# =========================================================================== #

AMBIGUOUS_CHARS = "O0Il1|"
SYMBOL_SET = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"


def password_strength_score(pwd: str) -> int:
    """0..5 heuristic score driving the Petal Bloom meter."""
    score = 0
    if len(pwd) >= 8:
        score += 1
    if len(pwd) >= 14:
        score += 1
    if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd):
        score += 1
    if any(c.isdigit() for c in pwd):
        score += 1
    if any(c in string.punctuation for c in pwd):
        score += 1
    return score


def strength_bucket(score: int):
    """Returns (label, color_key) for a 0..5 score."""
    if score >= 5:
        return "Strong", "green"
    if score == 4:
        return "Good", "primary"
    if score == 3:
        return "Fair", "amber"
    return "Weak", "red"


def estimate_entropy_bits(cfg: dict) -> float:
    pool = 0
    if cfg.get("use_uppercase", True):
        pool += 26
    if cfg.get("use_lowercase", True):
        pool += 26
    if cfg.get("use_digits", True):
        pool += 10
    if cfg.get("use_symbols", True):
        pool += len(SYMBOL_SET)
    if cfg.get("exclude_ambiguous", False):
        pool = max(1, pool - len(set(AMBIGUOUS_CHARS)))
    if pool <= 1:
        return 0.0
    return cfg.get("length", 20) * math.log2(pool)


def entropy_strength(bits: float):
    if bits < 40:
        return "Weak", "red"
    if bits < 60:
        return "Fair", "amber"
    if bits < 80:
        return "Good", "primary"
    if bits < 100:
        return "Strong", "green"
    return "Very Strong", "green"


def generate_password(cfg: dict) -> str:
    charset = ""
    if cfg.get("use_uppercase", True):
        charset += string.ascii_uppercase
    if cfg.get("use_lowercase", True):
        charset += string.ascii_lowercase
    if cfg.get("use_digits", True):
        charset += string.digits
    if cfg.get("use_symbols", True):
        charset += SYMBOL_SET
    if cfg.get("exclude_ambiguous", False):
        for ch in AMBIGUOUS_CHARS:
            charset = charset.replace(ch, "")
    if not charset:
        charset = string.ascii_letters + string.digits
    length = max(4, int(cfg.get("length", 20)))
    return "".join(secrets.choice(charset) for _ in range(length))


def compute_vault_stats(entries: dict) -> dict:
    """Single source of truth for every derived number shown on the Dashboard."""
    total = len(entries)
    favorites = sum(1 for e in entries.values() if e.get("favorite"))
    bucket_counts = {"Strong": 0, "Good": 0, "Fair": 0, "Weak": 0}
    bucket_members = {"Strong": [], "Good": [], "Fair": [], "Weak": []}
    pass_map = {}
    for eid, e in entries.items():
        pwd = e.get("password", "")
        score = password_strength_score(pwd)
        label, _ = strength_bucket(score)
        bucket_counts[label] += 1
        bucket_members[label].append(eid)
        if pwd:
            pass_map.setdefault(pwd, []).append(eid)
    reused_groups = {pwd: ids for pwd, ids in pass_map.items() if len(ids) > 1}
    reused_count = sum(len(ids) for ids in reused_groups.values())
    weak_at_risk = bucket_counts["Weak"] + bucket_counts["Fair"]
    strong_count = bucket_counts["Strong"] + bucket_counts["Good"]
    if total == 0:
        health = 100
    else:
        penalty = bucket_counts["Weak"] * 15 + bucket_counts["Fair"] * 8 + reused_count * 10
        health = max(0, 100 - penalty)
    tag_counts = {}
    for e in entries.values():
        for t in e.get("tags", []):
            tag_counts[t] = tag_counts.get(t, 0) + 1
    return {
        "total": total, "favorites": favorites, "bucket_counts": bucket_counts,
        "bucket_members": bucket_members, "reused_groups": reused_groups,
        "reused_count": reused_count, "weak_at_risk": weak_at_risk,
        "strong_count": strong_count, "health": health, "tag_counts": tag_counts,
    }


# =========================================================================== #
#  THEME PALETTES
# =========================================================================== #

THEMES = {
    "Midnight": {"bg": "#13141c", "surface": "#1e2030", "input": "#272a3f", "border": "#3b4261",
                 "primary": "#7aa2f7", "secondary": "#bb9af7", "green": "#9ece6a", "red": "#f7768e",
                 "amber": "#e0af68", "cyan": "#7dcfff", "text": "#c0caf5", "muted": "#737aa2",
                 "on_primary": "#0b1220", "light": False},
    "Aurora": {"bg": "#161320", "surface": "#211c2f", "input": "#2b2440", "border": "#443a5c",
               "primary": "#bb9af7", "secondary": "#7aa2f7", "green": "#9ece6a", "red": "#f7768e",
               "amber": "#e0af68", "cyan": "#7dcfff", "text": "#e0ceff", "muted": "#8b7fae",
               "on_primary": "#140f24", "light": False},
    "Crimson": {"bg": "#1a1114", "surface": "#241a1e", "input": "#2f2226", "border": "#4a2e33",
                "primary": "#f7768e", "secondary": "#e0af68", "green": "#9ece6a", "red": "#f7768e",
                "amber": "#e0af68", "cyan": "#7dcfff", "text": "#f0d3d9", "muted": "#a4818a",
                "on_primary": "#1a1114", "light": False},
    "Ocean": {"bg": "#0e1620", "surface": "#152230", "input": "#1c2d3f", "border": "#2e4a63",
              "primary": "#7dcfff", "secondary": "#7aa2f7", "green": "#9ece6a", "red": "#f7768e",
              "amber": "#e0af68", "cyan": "#7dcfff", "text": "#c9e6ff", "muted": "#6f93ac",
              "on_primary": "#08131c", "light": False},
    "Forest": {"bg": "#0e1712", "surface": "#15221a", "input": "#1c2e22", "border": "#2c4a35",
               "primary": "#9ece6a", "secondary": "#7dcfff", "green": "#9ece6a", "red": "#f7768e",
               "amber": "#e0af68", "cyan": "#7dcfff", "text": "#cfe8c9", "muted": "#75946f",
               "on_primary": "#0c1710", "light": False},
    "Light": {"bg": "#eef0f4", "surface": "#ffffff", "input": "#f4f5f8", "border": "#d1d5db",
              "primary": "#3b82f6", "secondary": "#8b5cf6", "green": "#10b981", "red": "#ef4444",
              "amber": "#f59e0b", "cyan": "#0ea5e9", "text": "#0f172a", "muted": "#64748b",
              "on_primary": "#ffffff", "light": True},
}

THEME_ORDER = ["Midnight", "Aurora", "Crimson", "Ocean", "Forest", "Light"]
DARK_THEME_ORDER = ["Midnight", "Aurora", "Crimson", "Ocean", "Forest"]

AVATAR_COLOR_KEYS = ["primary", "secondary", "green", "amber", "cyan", "red"]


class Palette:
    data = THEMES["Midnight"]

    @classmethod
    def get(cls, key, fallback="#7aa2f7"):
        return cls.data.get(key, fallback)


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    c = QColor(hex_color)
    return f"rgba({c.red()},{c.green()},{c.blue()},{alpha})"


def shade(hex_color: str, factor: int) -> str:
    c = QColor(hex_color)
    return c.lighter(factor).name() if factor >= 100 else c.darker(int(10000 / factor)).name()


# =========================================================================== #
#  STYLESHEET BUILDER
# =========================================================================== #

def build_stylesheet(p: dict, scale: float = 1.0) -> str:
    tpl = """
    QWidget { color: __TEXT__; font-family: "Segoe UI", "Ubuntu", sans-serif; }
    QMainWindow, #Root { background-color: __BG__; }
    QToolTip { background-color: __SURFACE__; color: __TEXT__; border: 1px solid __BORDER__; padding: 5px; border-radius: 6px; }

    QFrame#Card { background-color: __SURFACE__; border: 1px solid __BORDER__; border-radius: 20px; }
    QFrame#Card[hoverable="true"]:hover { border: 1px solid __PRIMARY__; }
    QFrame#CardFlat { background-color: __INPUT__; border: 1px solid __BORDER__; border-radius: 16px; }
    QFrame#Sidebar { background-color: __SURFACE__; border-right: 1px solid __BORDER__; }
    QFrame#Pill { background-color: __INPUT__; border: 1px solid __BORDER__; border-radius: 23px; }
    QFrame#DangerZone { background-color: __RED_SOFT__; border: 1px solid __RED__; border-radius: 18px; }

    QDialog { background-color: __SURFACE__; }
    QTextEdit {
        background-color: __INPUT__; border: 1px solid __BORDER__; border-radius: 12px;
        padding: 8px; color: __TEXT__; font-size: 13px;
    }
    QTextEdit:focus { border: 1px solid __PRIMARY__; }

    QLineEdit#PillEdit { background: transparent; border: none; color: __TEXT__; font-size: 14px; padding: 0px; }

    QLineEdit, QComboBox {
        background-color: __INPUT__; border: 1px solid __BORDER__; border-radius: 12px;
        padding: 9px 12px; color: __TEXT__; font-size: 13px; selection-background-color: __PRIMARY__;
    }
    QLineEdit:focus, QComboBox:focus { border: 1px solid __PRIMARY__; }
    QLineEdit:disabled { color: __MUTED__; }
    QComboBox::drop-down { border: none; width: 26px; }
    QComboBox QAbstractItemView {
        background-color: __SURFACE__; color: __TEXT__; border: 1px solid __BORDER__;
        selection-background-color: __PRIMARY_SOFT__; selection-color: __PRIMARY__; outline: none; padding: 4px;
    }

    QPushButton { border: none; outline: none; }

    /* Gradient primary action - a callback to the original "Unlock Vault"
       button style, used for the single most important action on a screen. */
    QPushButton#PrimaryButton {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 __PRIMARY__, stop:1 __SECONDARY__);
        color: __ON_PRIMARY__; border-radius: 20px;
        font-weight: 700; padding: 11px 18px; font-size: 13px;
    }
    QPushButton#PrimaryButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 __PRIMARY_HOVER__, stop:1 __SECONDARY__);
    }
    QPushButton#PrimaryButton:disabled { background: __BORDER__; color: __MUTED__; }

    QPushButton#SuccessButton {
        background-color: __GREEN__; color: __ON_PRIMARY__; border-radius: 20px;
        font-weight: 700; padding: 11px 18px; font-size: 13px;
    }
    QPushButton#SuccessButton:hover { background-color: __GREEN_HOVER__; }

    QPushButton#DangerButton {
        background-color: transparent; color: __RED__; border: 1.5px solid __RED__;
        border-radius: 16px; padding: 8px 14px; font-weight: 700; font-size: 12px;
    }
    QPushButton#DangerButton:hover { background-color: __RED_SOFT__; }
    QPushButton#DangerButton:disabled { color: __MUTED__; border: 1.5px solid __BORDER__; }

    QPushButton#DangerSolidButton {
        background-color: __RED__; color: #ffffff; border-radius: 20px; font-weight: 700; padding: 10px 18px;
    }
    QPushButton#DangerSolidButton:hover { background-color: __RED_HOVER__; }
    QPushButton#DangerSolidButton:disabled { background-color: __BORDER__; color: __MUTED__; }

    QPushButton#GhostButton {
        background-color: transparent; color: __TEXT__; border-radius: 14px; padding: 9px 14px;
        text-align: left; font-size: 13px;
    }
    QPushButton#GhostButton:hover { background-color: __INPUT__; }

    QPushButton#LinkButton {
        background-color: transparent; color: __PRIMARY__; font-weight: 700; font-size: 12px;
        text-align: left; padding: 2px;
    }
    QPushButton#LinkButton:hover { color: __PRIMARY_HOVER__; text-decoration: underline; }

    QPushButton#NavButton {
        background-color: transparent; color: __MUTED__; border-radius: 14px; padding: 11px 14px;
        text-align: left; font-size: 14px;
    }
    QPushButton#NavButton:hover { background-color: __INPUT__; color: __TEXT__; }
    QPushButton#NavButton[active="true"] { background-color: __PRIMARY_SOFT__; color: __PRIMARY__; font-weight: 700; }

    QPushButton#IconButton {
        background-color: __INPUT__; border-radius: 16px; color: __MUTED__; font-size: 13px; border: 1px solid __BORDER__;
        padding: 6px 10px;
    }
    QPushButton#IconButton:hover { background-color: __BORDER__; color: __TEXT__; }
    QPushButton#IconButtonFlat {
        background-color: transparent; border-radius: 15px; color: __MUTED__; font-size: 14px;
    }
    QPushButton#IconButtonFlat:hover { background-color: __BORDER__; color: __TEXT__; }

    QPushButton#Chip {
        background-color: __INPUT__; color: __MUTED__; border-radius: 16px; padding: 8px 16px;
        font-size: 12px; font-weight: 700; border: 1px solid __BORDER__;
    }
    QPushButton#Chip:checked { background-color: __PRIMARY_SOFT__; color: __PRIMARY__; border: 1px solid __PRIMARY__; }

    /* Grid / List view switch on the Vault page */
    QPushButton#ViewToggle {
        background-color: __INPUT__; color: __MUTED__; border: 1px solid __BORDER__;
        border-radius: 12px; font-size: 15px; padding: 6px;
    }
    QPushButton#ViewToggle:checked { background-color: __PRIMARY__; color: __ON_PRIMARY__; border: 1px solid __PRIMARY__; }

    QPushButton#SettingsTab { background-color: transparent; color: __MUTED__; border-radius: 14px; padding: 10px 16px; font-weight: 700; font-size: 13px; }
    QPushButton#SettingsTab:checked { background-color: __PRIMARY__; color: __ON_PRIMARY__; }

    QPushButton#ThemeCard { background-color: __CARDFLAT__; border: 1.5px solid __BORDER__; border-radius: 16px; padding: 6px; }
    QPushButton#ThemeCard:checked { border: 1.5px solid __GREEN__; }

    QPushButton#SizeCard { background-color: __CARDFLAT__; border: 1.5px solid __BORDER__; border-radius: 14px; padding: 10px; color: __TEXT__; font-weight: 700; }
    QPushButton#SizeCard:checked { border: 1.5px solid __GREEN__; color: __GREEN__; }

    QPushButton#FavStar { background: transparent; font-size: 17px; border: none; }
    QPushButton#TagPillClose { background: transparent; color: __MUTED__; border-radius: 8px; font-size: 10px; font-weight: 800; }
    QPushButton#TagPillClose:hover { background: __BORDER__; color: __TEXT__; }

    QLabel#EntryPasswordMask {
        background-color: __INPUT__; border: 1px solid __BORDER__; border-radius: 12px;
        padding: 9px 12px; font-family: Consolas, monospace; font-size: 13px; letter-spacing: 2px;
    }

    QLabel#BrandTitle { font-size: 20px; font-weight: 800; color: __PRIMARY__; }
    QLabel#BrandVersion { font-size: 11px; color: __MUTED__; }
    QLabel#PageTitle { font-size: 24px; font-weight: 800; color: __TEXT__; }
    QLabel#PageSubtitle { font-size: 13px; color: __MUTED__; }
    QLabel#SectionTitle { font-size: 16px; font-weight: 800; color: __TEXT__; }
    QLabel#CardLabel { font-size: 15px; font-weight: 700; color: __TEXT__; }
    QLabel#Muted { color: __MUTED__; font-size: 12px; }
    QLabel#FieldLabel { color: __MUTED__; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
    QLabel#MetricValue { font-size: 26px; font-weight: 800; }
    QLabel#GaugeCenter { font-size: 26px; font-weight: 800; }

    QScrollArea { border: none; background: transparent; }
    QScrollArea > QWidget > QWidget { background: transparent; }
    QScrollBar:vertical { background: transparent; width: 9px; margin: 2px; }
    QScrollBar::handle:vertical { background: __BORDER__; border-radius: 4px; min-height: 30px; }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
    QScrollBar:horizontal { background: transparent; height: 0px; }

    QSlider::groove:horizontal { height: 6px; background: __INPUT__; border-radius: 3px; }
    QSlider::sub-page:horizontal { background: __PRIMARY__; border-radius: 3px; }
    QSlider::add-page:horizontal { background: __INPUT__; border-radius: 3px; }
    QSlider::handle:horizontal {
        background: __PRIMARY__; width: 16px; height: 16px; margin: -6px 0; border-radius: 8px; border: 2px solid __SURFACE__;
    }

    QProgressBar { background: __INPUT__; border-radius: 5px; border: none; text-align: center; color: transparent; }
    QProgressBar::chunk { border-radius: 5px; }

    QMessageBox { background-color: __SURFACE__; }
    QMessageBox QLabel { color: __TEXT__; }
    QInputDialog { background-color: __SURFACE__; }
    """
    # Every literal "font-size: Npx" in the template above is scaled uniformly
    # here - this is what makes Settings -> UI & Theme -> Font Size actually
    # change anything, instead of being overridden by hardcoded pixel sizes.
    def _scale_px(match):
        return f"font-size: {max(8, round(int(match.group(1)) * scale))}px"

    css = re.sub(r"font-size:\s*(\d+)px", _scale_px, tpl)
    css = css.replace("__BG__", p["bg"])
    css = css.replace("__SURFACE__", p["surface"])
    css = css.replace("__INPUT__", p["input"])
    css = css.replace("__CARDFLAT__", p["input"])
    css = css.replace("__BORDER__", p["border"])
    css = css.replace("__PRIMARY_HOVER__", shade(p["primary"], 112 if not p["light"] else 90))
    css = css.replace("__GREEN_HOVER__", shade(p["green"], 112 if not p["light"] else 90))
    css = css.replace("__RED_HOVER__", shade(p["red"], 112 if not p["light"] else 90))
    css = css.replace("__PRIMARY_SOFT__", hex_to_rgba(p["primary"], 0.16))
    css = css.replace("__RED_SOFT__", hex_to_rgba(p["red"], 0.12))
    css = css.replace("__PRIMARY__", p["primary"])
    css = css.replace("__SECONDARY__", p["secondary"])
    css = css.replace("__GREEN__", p["green"])
    css = css.replace("__RED__", p["red"])
    css = css.replace("__AMBER__", p["amber"])
    css = css.replace("__CYAN__", p["cyan"])
    css = css.replace("__TEXT__", p["text"])
    css = css.replace("__MUTED__", p["muted"])
    css = css.replace("__ON_PRIMARY__", p["on_primary"])
    return css


def apply_shadow(widget, color="#000000", blur=28, alpha=90, y=6):
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    c = QColor(color)
    c.setAlpha(alpha)
    eff.setColor(c)
    eff.setOffset(0, y)
    widget.setGraphicsEffect(eff)


# =========================================================================== #
#  FLOW LAYOUT  
# =========================================================================== #

class FlowLayout(QLayout):
    """A QLayout that lays child widgets left-to-right and wraps to a new row
    once it runs out of horizontal space - like CSS 'flex-wrap'. Qt has no
    built-in equivalent. This is what lets tag chips, category filters, and
    the Vault's grid view resize cleanly instead of overlapping or clipping
    when the window is resized. See also make_flow_container() below, which
    is the version of this you should actually reach for in page code."""

    def __init__(self, parent=None, margin=0, hspacing=8, vspacing=8):
        super().__init__(parent)
        self._hspacing = hspacing
        self._vspacing = vspacing
        self._items = []
        self.setContentsMargins(margin, margin, margin, margin)

    def addItem(self, item):
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):
        if 0 <= index < len(self._items):
            return self._items[index]
        return None

    def takeAt(self, index):
        if 0 <= index < len(self._items):
            return self._items.pop(index)
        return None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self):
        return True

    def heightForWidth(self, width):
        return self._do_layout(QRect(0, 0, width, 0), True)

    def setGeometry(self, rect):
        super().setGeometry(rect)
        self._do_layout(rect, False)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        size += QSize(margins.left() + margins.right(), margins.top() + margins.bottom())
        return size

    def _do_layout(self, rect, test_only):
        left, top, right, bottom = self.getContentsMargins()
        effective = rect.adjusted(left, top, -right, -bottom)
        x = effective.x()
        y = effective.y()
        line_height = 0
        for item in self._items:
            hint = item.sizeHint()
            next_x = x + hint.width() + self._hspacing
            if next_x - self._hspacing > effective.right() and line_height > 0:
                x = effective.x()
                y = y + line_height + self._vspacing
                next_x = x + hint.width() + self._hspacing
                line_height = 0
            if not test_only:
                item.setGeometry(QRect(x, y, hint.width(), hint.height()))
            x = next_x
            line_height = max(line_height, hint.height())
        return (y + line_height) - rect.y() + bottom


def make_flow_container(margin=0, hspacing=8, vspacing=8):
    """A QWidget with a FlowLayout that actually reports its wrapped, multi-row
    height to whatever layout it sits inside. Without explicitly turning on
    heightForWidth here, a plain QWidget always reports hasHeightForWidth=False,
    so the parent QVBoxLayout squashes it to a single-row sizeHint and every
    chip/tag/pill row after the first ends up overlapping instead of wrapping.
    This one fix is what makes tag chips and category filters actually visible
    and clickable."""
    container = QWidget()
    FlowLayout(container, margin=margin, hspacing=hspacing, vspacing=vspacing)
    sp = container.sizePolicy()
    sp.setHeightForWidth(True)
    container.setSizePolicy(sp)
    return container


# =========================================================================== #
#  SMALL REUSABLE WIDGETS
# =========================================================================== #

class Card(QFrame):
    """The app's one basic 'panel' shape: rounded corners + a soft shadow.
    Every card-like surface in the app (dashboard tiles, the vault list, the
    settings panels) is one of these. Pass flat=True for a plain nested
    surface without its own shadow, used INSIDE another Card so the two
    shadows don't stack up. Pass shadow=False to keep the normal "Card" look
    (surface color + border) but skip the QGraphicsDropShadowEffect entirely -
    used by EntryCard, since a real vault can contain dozens of cards and a
    drop-shadow effect on every single one measurably slows down scrolling
    and resizing (each one is its own offscreen render pass for Qt)."""

    def __init__(self, flat=False, shadow=None, parent=None):
        super().__init__(parent)
        self.setObjectName("CardFlat" if flat else "Card")
        if shadow is None:
            shadow = not flat
        if shadow:
            apply_shadow(self, blur=26, alpha=70, y=4)


class ToggleSwitch(QCheckBox):
    """Custom-painted iOS-style pill toggle with an animated sliding knob."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(46, 26)
        self.setText("")
        self._knob_pos = 1.0 if self.isChecked() else 0.0
        self._anim = None
        self.toggled.connect(self._animate_to)

    def hitButton(self, pos):
        return self.rect().contains(pos)

    def sync_visual(self):
        self._knob_pos = 1.0 if self.isChecked() else 0.0
        self.update()

    def _get_knob_pos(self):
        return self._knob_pos

    def _set_knob_pos(self, value):
        self._knob_pos = value
        self.update()

    knob_pos = Property(float, _get_knob_pos, _set_knob_pos)

    def _animate_to(self, checked):
        anim = QPropertyAnimation(self, b"knob_pos", self)
        anim.setDuration(150)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.setStartValue(self._knob_pos)
        anim.setEndValue(1.0 if checked else 0.0)
        anim.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        self._anim = anim

    @staticmethod
    def _blend(c1: QColor, c2: QColor, t: float) -> QColor:
        t = max(0.0, min(1.0, t))
        return QColor(
            int(c1.red() + (c2.red() - c1.red()) * t),
            int(c1.green() + (c2.green() - c1.green()) * t),
            int(c1.blue() + (c2.blue() - c1.blue()) * t),
        )

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(1, 1, -1, -1)
        off_color = QColor(Palette.get("border"))
        on_color = QColor(Palette.get("primary"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._blend(off_color, on_color, self._knob_pos))
        painter.drawRoundedRect(rect, rect.height() / 2, rect.height() / 2)
        knob_d = rect.height() - 6
        travel = rect.width() - knob_d - 6
        x = rect.left() + 3 + travel * self._knob_pos
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(int(x), int(rect.top() + 3), int(knob_d), int(knob_d))


class CircularGauge(QWidget):
    """Security-score ring - value in [0, 1]."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._value = 0.0
        self._color_key = "primary"
        self.setMinimumSize(110, 110)

    def set_value(self, value: float, color_key: str = "primary"):
        self._value = max(0.0, min(1.0, value))
        self._color_key = color_key
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(self.width(), self.height()) - 16
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        pen_w = max(8, int(side * 0.1))
        inner = rect.adjusted(pen_w / 2, pen_w / 2, -pen_w / 2, -pen_w / 2)

        bg_pen = QPen(QColor(Palette.get("border")))
        bg_pen.setWidth(pen_w)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(inner, 0, 360 * 16)

        fg_pen = QPen(QColor(Palette.get(self._color_key)))
        fg_pen.setWidth(pen_w)
        fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(fg_pen)
        span = int(-360 * self._value * 16)
        painter.drawArc(inner, 90 * 16, span)


class StrengthBar(QWidget):
    """Five-segment Petal Bloom strength meter."""

    def __init__(self, segments=5, parent=None):
        super().__init__(parent)
        self._segments = segments
        self._filled = 0
        self._color_key = "red"
        self.setFixedHeight(8)
        self.setMinimumWidth(80)

    def set_score(self, score: int, color_key: str):
        self._filled = max(0, min(self._segments, score))
        self._color_key = color_key
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gap = 4
        seg_w = (self.width() - gap * (self._segments - 1)) / self._segments
        fill_color = QColor(Palette.get(self._color_key))
        empty_color = QColor(Palette.get("border"))
        for i in range(self._segments):
            x = i * (seg_w + gap)
            rect = QRectF(x, 0, seg_w, self.height())
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill_color if i < self._filled else empty_color)
            painter.drawRoundedRect(rect, self.height() / 2, self.height() / 2)


class Badge(QLabel):
    """A small rounded pill of colored text (e.g. the 'Strong'/'Weak'
    strength label, or a tag shown on a Vault card). Not clickable - see
    clickable_badge() further down for the interactive version used for the
    'Reused' warning."""

    def __init__(self, text, color_key="primary", parent=None):
        super().__init__(text, parent)
        self.set_color_key(color_key)

    def set_color_key(self, color_key):
        bg = hex_to_rgba(Palette.get(color_key), 0.18)
        fg = Palette.get(color_key)
        self.setStyleSheet(
            f"background-color:{bg}; color:{fg}; border-radius:10px; padding:3px 10px; "
            f"font-size:11px; font-weight:700;"
        )


class TagPill(QFrame):
    """A removable tag chip used inside the Add/Edit Entry dialog."""
    removed = Signal(str)

    def __init__(self, tag, parent=None):
        super().__init__(parent)
        self.tag = tag
        self.setStyleSheet(
            f"background-color:{hex_to_rgba(Palette.get('primary'), 0.16)}; border-radius:12px;"
        )
        h = QHBoxLayout(self)
        h.setContentsMargins(10, 3, 5, 3)
        h.setSpacing(4)
        lbl = QLabel(tag)
        lbl.setStyleSheet(f"color:{Palette.get('primary')}; font-size:12px; font-weight:700; background:transparent;")
        h.addWidget(lbl)
        x_btn = QPushButton("\u2715")
        x_btn.setObjectName("TagPillClose")
        x_btn.setFixedSize(16, 16)
        x_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        x_btn.clicked.connect(lambda: self.removed.emit(self.tag))
        h.addWidget(x_btn)


class PasswordField(QFrame):
    """A pill-shaped field with an embedded show/hide eye and optional generate bolt."""

    textChanged = Signal(str)

    def __init__(self, placeholder="", show_generate=False, gen_callback=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Pill")
        self.setFixedHeight(46)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 6, 0)
        lay.setSpacing(4)

        self.edit = QLineEdit()
        self.edit.setObjectName("PillEdit")
        self.edit.setPlaceholderText(placeholder)
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.textChanged.connect(self.textChanged.emit)
        lay.addWidget(self.edit, 1)

        self.eye_btn = QPushButton("\U0001F441")
        self.eye_btn.setObjectName("IconButtonFlat")
        self.eye_btn.setFixedSize(32, 32)
        self.eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.eye_btn.setAutoDefault(False)  # never let this hijack Enter inside a QDialog
        self.eye_btn.clicked.connect(self._toggle_visibility)
        lay.addWidget(self.eye_btn)

        self.gen_btn = None
        if show_generate:
            self.gen_btn = QPushButton("\u26A1")
            self.gen_btn.setObjectName("IconButtonFlat")
            self.gen_btn.setFixedSize(32, 32)
            self.gen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.gen_btn.setAutoDefault(False)
            if gen_callback:
                self.gen_btn.clicked.connect(gen_callback)
            lay.addWidget(self.gen_btn)

    def _toggle_visibility(self):
        if self.edit.echoMode() == QLineEdit.EchoMode.Password:
            self.edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.eye_btn.setText("\U0001F648")
        else:
            self.edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.eye_btn.setText("\U0001F441")

    def text(self):
        return self.edit.text()

    def setText(self, t):
        self.edit.setText(t)


def avatar_for(name: str) -> QLabel:
    letters = "".join(w[0] for w in name.split()[:2]).upper() or "?"
    idx = sum(ord(c) for c in name) % len(AVATAR_COLOR_KEYS) if name else 0
    color_key = AVATAR_COLOR_KEYS[idx]
    lbl = QLabel(letters[:2])
    lbl.setFixedSize(44, 44)
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setStyleSheet(
        f"background-color:{Palette.get(color_key)}; color:#0b1220; border-radius:12px; "
        f"font-weight:800; font-size:15px;"
    )
    return lbl


def make_pill_input(placeholder=""):
    edit = QLineEdit()
    edit.setPlaceholderText(placeholder)
    edit.setFixedHeight(46)
    edit.setStyleSheet("border-radius: 23px; padding-left: 16px;")
    return edit


def clear_layout(layout):
    """Removes every widget from a layout, hiding each one immediately before
    scheduling it for deletion."""
    while layout.count():
        item = layout.takeAt(0)
        w = item.widget()
        if w:
            w.hide()
            w.deleteLater()


def h_spacer():
    return QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)


def v_spacer():
    return QSpacerItem(0, 0, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)


def confirm(parent, title, text) -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.Warning)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    return box.exec() == QMessageBox.StandardButton.Yes


def info(parent, title, text):
    QMessageBox.information(parent, title, text)


def warn(parent, title, text):
    QMessageBox.warning(parent, title, text)


def error(parent, title, text):
    QMessageBox.critical(parent, title, text)


def copy_to_clipboard_privately(text: str):
    """Copies `text` to the clipboard - and, on Windows, tells the OS not to
    keep it around anywhere else."""
    clipboard = QApplication.clipboard()
    mime = QMimeData()
    mime.setText(text)
    if sys.platform == "win32":
        exclude = QByteArray(struct.pack("<i", 0))
        mime.setData("CanIncludeInClipboardHistory", exclude)
        mime.setData("CanUploadToCloudClipboard", exclude)
    clipboard.setMimeData(mime)


class Toast(QLabel):
    """A small, self-dismissing pill notification that floats over the
    bottom of the window. Used to confirm clipboard copies - a background
    timer silently clearing the clipboard later is otherwise invisible and
    easy to distrust ("is this actually working?"), so every copy now says
    out loud exactly when it will be cleared."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(False)
        self.hide()
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)

    def show_message(self, text, duration_ms=2600):
        self.setStyleSheet(
            f"background-color:{Palette.get('surface')}; color:{Palette.get('text')}; "
            f"border:1px solid {Palette.get('border')}; border-radius:18px; "
            f"padding:10px 22px; font-weight:700; font-size:12px;"
        )
        self.setText(text)
        self.adjustSize()
        parent_rect = self.parentWidget().rect()
        x = (parent_rect.width() - self.width()) // 2
        y = parent_rect.height() - self.height() - 28
        self.move(max(0, x), max(0, y))
        self.show()
        self.raise_()
        self._timer.start(duration_ms)


# =========================================================================== #
#  AUTH PAGE  (setup / unlock / recovery)
# =========================================================================== #

class AuthPage(QWidget):
    """The screen shown before the vault is unlocked. It has three distinct
    modes, decided fresh every time refresh() runs by looking at which files
    exist on disk:
      - "setup"    - no key file, no vault yet -> let the user choose a
                     master password for the very first time.
      - "unlock"   - a key file exists -> ask for the master password and
                     verify it.
      - "recovery" - a vault file exists but its key file is missing/deleted
                     -> refuse to quietly start over (see the security note
                     at the top of this file); the only way forward is an
                     explicit, typed-out confirmation to erase and start
                     fresh."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.stack = QStackedWidget()
        outer.addWidget(self.stack)

        # ---------------- normal setup / unlock card ----------------
        self.card = Card()
        self.card.setFixedWidth(480)
        apply_shadow(self.card, blur=40, alpha=110)
        v = QVBoxLayout(self.card)
        v.setContentsMargins(40, 46, 40, 40)
        v.setSpacing(4)

        sprout = QLabel("\U0001F331")
        sprout.setStyleSheet("font-size: 44px;")
        sprout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(sprout)

        title_lbl = QLabel("Magical Garden")
        title_lbl.setObjectName("PageTitle")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("font-size: 26px; margin-top: 8px;")
        v.addWidget(title_lbl)

        version_lbl = QLabel("v2.1.0 \u00B7 Zero-telemetry")
        version_lbl.setObjectName("Muted")
        version_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(version_lbl)

        tagline_lbl = QLabel(TAGLINE)
        tagline_lbl.setObjectName("Muted")
        tagline_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline_lbl.setWordWrap(True)
        tagline_lbl.setStyleSheet(f"font-style: italic; color:{Palette.get('primary')};")
        v.addWidget(tagline_lbl)
        v.addSpacing(20)

        self.prompt_lbl = QLabel("Plant Sunlight Key  \U0001F33B")
        self.prompt_lbl.setObjectName("SectionTitle")
        self.prompt_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(self.prompt_lbl)
        v.addSpacing(14)

        self.pwd_field = PasswordField(placeholder="Enter master password...")
        self.pwd_field.edit.returnPressed.connect(self._on_submit)
        v.addWidget(self.pwd_field)
        v.addSpacing(18)

        self.action_btn = QPushButton("\U0001F513 Unlock Vault")
        self.action_btn.setObjectName("PrimaryButton")
        self.action_btn.setFixedHeight(48)
        self.action_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.action_btn.clicked.connect(self._on_submit)
        v.addWidget(self.action_btn)
        v.addSpacing(18)

        footer_lbl = QLabel("Offline-first \u00B7 E2E encrypted \u00B7 Open source")
        footer_lbl.setObjectName("Muted")
        footer_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(footer_lbl)
        self.stack.addWidget(self.card)

        # ---------------- recovery-required card ----------------
        self.recovery_card = Card()
        self.recovery_card.setFixedWidth(520)
        apply_shadow(self.recovery_card, blur=40, alpha=110)
        rv = QVBoxLayout(self.recovery_card)
        rv.setContentsMargins(40, 40, 40, 36)
        rv.setSpacing(8)

        warn_ic = QLabel("\u26A0\uFE0F")
        warn_ic.setStyleSheet("font-size: 40px;")
        warn_ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rv.addWidget(warn_ic)

        rtitle = QLabel("Vault Key Missing")
        rtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        rtitle.setStyleSheet(f"font-size: 22px; font-weight: 800; color:{Palette.get('red')};")
        rv.addWidget(rtitle)
        rv.addSpacing(8)

        rbody = QLabel(
            "sunlight.key was not found, but an encrypted vault (garden.enc) still exists on disk.\n\n"
            "For your security, Magical Garden never allows a vault to be unlocked by simply setting "
            "a new password \u2014 the encryption key cannot be regenerated from a password alone "
            "without the original key file. If sunlight.key is missing, the existing vault cannot be "
            "recovered.\n\n"
            "You may erase the old vault and start completely fresh, but this will permanently destroy "
            "every entry currently stored."
        )
        rbody.setWordWrap(True)
        rbody.setObjectName("Muted")
        rv.addWidget(rbody)
        rv.addSpacing(14)

        self.erase_confirm_edit = make_pill_input("Type ERASE to confirm")
        self.erase_confirm_edit.textChanged.connect(self._update_erase_btn)
        rv.addWidget(self.erase_confirm_edit)
        rv.addSpacing(12)

        self.erase_btn = QPushButton("\U0001F5D1 Erase Vault && Start Fresh")
        self.erase_btn.setObjectName("DangerSolidButton")
        self.erase_btn.setFixedHeight(46)
        self.erase_btn.setEnabled(False)
        self.erase_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.erase_btn.clicked.connect(self._do_erase)
        rv.addWidget(self.erase_btn)
        self.stack.addWidget(self.recovery_card)

        self.mode = "setup"

    def refresh(self):
        if key_exists():
            self.mode = "unlock"
        elif vault_exists():
            self.mode = "recovery"
        else:
            self.mode = "setup"

        if self.mode == "recovery":
            self.erase_confirm_edit.setText("")
            self.stack.setCurrentWidget(self.recovery_card)
            return

        self.stack.setCurrentWidget(self.card)
        self.pwd_field.setText("")
        self.pwd_field.edit.setFocus()
        if self.mode == "setup":
            self.prompt_lbl.setText("Plant Sunlight Key  \U0001F33B")
            self.action_btn.setText("\U0001F513 Initialize Vault")
        else:
            self.prompt_lbl.setText("Unlock Vault  \U0001F511")
            self.action_btn.setText("\U0001F513 Unlock Vault")

    def _update_erase_btn(self, text):
        self.erase_btn.setEnabled(text.strip() == "ERASE")

    def _do_erase(self):
        if not confirm(self, "Erase Vault", "This will permanently delete every stored entry. Continue?"):
            return
        wipe_vault_files()
        self.refresh()

    def _on_submit(self):
        pwd = self.pwd_field.text().strip()
        if self.mode == "setup":
            if vault_exists() or key_exists():
                # Defense in depth: never silently (re-)initialize over existing files.
                self.refresh()
                return
            if len(pwd) < 6:
                warn(self, "Weak Key", "Sunlight Key must be at least 6 characters.")
                return
            key = initialize_garden_key(pwd)
            self.app_window.on_unlocked(key)
        else:
            key = verify_sunlight_key(pwd)
            if not key:
                error(self, "Access Denied", "Invalid Sunlight Key.")
                return
            self.app_window.on_unlocked(key)


# =========================================================================== #
#  SIDEBAR
# =========================================================================== #

class Sidebar(QFrame):
    """Left-hand navigation: brand header, the nav button list (Settings is
    deliberately last, just above Lock Vault - it's not a page you visit
    often), and the Lock Vault button. Purely a "dumb" view: every click just
    calls back into MagicalGardenApp.navigate()/lock_vault()."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.setObjectName("Sidebar")
        self.setFixedWidth(SIDEBAR_WIDTH)

        v = QVBoxLayout(self)
        v.setContentsMargins(18, 24, 18, 20)
        v.setSpacing(4)

        brand = QHBoxLayout()
        sprout = QLabel("\U0001F331")
        sprout.setStyleSheet("font-size: 26px;")
        brand.addWidget(sprout)
        brand_txt = QVBoxLayout()
        brand_txt.setSpacing(0)
        t = QLabel("Magical Garden")
        t.setObjectName("BrandTitle")
        t.setStyleSheet("font-size: 16px;")
        v_lbl = QLabel("v2.1.0")
        v_lbl.setObjectName("BrandVersion")
        brand_txt.addWidget(t)
        brand_txt.addWidget(v_lbl)
        brand.addLayout(brand_txt)
        brand.addStretch(1)
        v.addLayout(brand)

        tagline_lbl = QLabel(TAGLINE)
        tagline_lbl.setWordWrap(True)
        tagline_lbl.setStyleSheet(f"font-size: 10px; font-style: italic; color:{Palette.get('muted')}; padding: 2px 2px 0 2px;")
        v.addWidget(tagline_lbl)
        v.addSpacing(16)

        self.nav_buttons = {}
        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)

        for key, label, icon in [
            ("dashboard", "Dashboard", "\U0001F4CA"),
            ("vault", "Vault", "\U0001F338"),
            ("generator", "Generator", "\u26A1"),
            ("tags", "Tags", "\U0001F3F7"),
            ("tutorial", "Tutorial", "\U0001F4D6"),
            ("license", "License", "\U0001F4C4"),
            ("settings", "Settings", "\u2699\uFE0F"),
        ]:
            btn = QPushButton(f"  {icon}   {label}")
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setFixedHeight(44)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, k=key: self.app_window.navigate(k))
            self.btn_group.addButton(btn)
            self.nav_buttons[key] = btn
            v.addWidget(btn)

        v.addItem(v_spacer())

        self.lock_btn = QPushButton("\U0001F512 Lock Vault")
        self.lock_btn.setObjectName("DangerSolidButton")
        self.lock_btn.setFixedHeight(44)
        self.lock_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.lock_btn.clicked.connect(self.app_window.lock_vault)
        v.addWidget(self.lock_btn)

    def set_active(self, key):
        for k, btn in self.nav_buttons.items():
            active = (k == key)
            btn.setChecked(active)
            btn.setProperty("active", "true" if active else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)


# =========================================================================== #
#  ADD / EDIT ENTRY DIALOG
# =========================================================================== #

class AnimatedDialog(QDialog):
    """QDialog with a subtle fade + rise-in animation on open - shared by every
    modal in the app (Add/Edit Entry, drill-down lists) for a consistent,
    less abrupt feel than Qt's default instant-appear dialogs."""

    def showEvent(self, event):
        super().showEvent(event)
        if getattr(self, "_opened_once", False):
            return
        self._opened_once = True
        start_geo = self.geometry()
        start_geo.moveTop(start_geo.top() + 18)
        end_geo = self.geometry()

        self.setWindowOpacity(0.0)
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade_anim.setDuration(190)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.setGeometry(start_geo)
        self._rise_anim = QPropertyAnimation(self, b"geometry", self)
        self._rise_anim.setDuration(190)
        self._rise_anim.setStartValue(start_geo)
        self._rise_anim.setEndValue(end_geo)
        self._rise_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._fade_anim.start()
        self._rise_anim.start()


class EntryDialog(AnimatedDialog):
    """The Add/Edit Entry modal. Used for both jobs - entry_id=None means
    "creating a new entry"; passing an existing id + its data means "editing
    it". Handles its own tag-pill UI (type + Enter to add, click X to
    remove) and live strength meter, then writes straight to the vault file
    on Save."""

    def __init__(self, app_window, entry_id=None, entry=None, parent=None):
        super().__init__(parent)
        self.app_window = app_window
        self.entry_id = entry_id
        self.is_new = entry_id is None
        entry = entry or {}
        self.tags = list(entry.get("tags", []))

        self.setWindowTitle("Add Entry" if self.is_new else "Edit Entry")
        self.setModal(True)
        self.setMinimumWidth(560)

        v = QVBoxLayout(self)
        v.setContentsMargins(28, 26, 28, 22)
        v.setSpacing(4)

        head = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        t = QLabel("Add Entry" if self.is_new else "Edit Entry")
        t.setStyleSheet("font-size: 20px; font-weight: 800;")
        title_col.addWidget(t)
        sub = QLabel("Add new credentials" if self.is_new else "Update credentials")
        sub.setObjectName("Muted")
        title_col.addWidget(sub)
        head.addLayout(title_col)
        head.addItem(h_spacer())
        close_btn = QPushButton("\u2715")
        close_btn.setObjectName("IconButtonFlat")
        close_btn.setFixedSize(28, 28)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setAutoDefault(False)
        close_btn.clicked.connect(self.reject)
        head.addWidget(close_btn)
        v.addLayout(head)
        v.addSpacing(14)

        row1 = QHBoxLayout()
        row1.setSpacing(14)
        col1 = QVBoxLayout()
        col1.addWidget(self._label("\U0001F310 WEBSITE NAME"))
        self.name_edit = make_pill_input("e.g. GitHub")
        self.name_edit.setText(entry.get("name", ""))
        col1.addWidget(self.name_edit)
        row1.addLayout(col1, 1)
        col2 = QVBoxLayout()
        col2.addWidget(self._label("URL (OPTIONAL)"))
        self.url_edit = make_pill_input("https://example.com")
        self.url_edit.setText(entry.get("url", ""))
        col2.addWidget(self.url_edit)
        row1.addLayout(col2, 1)
        v.addLayout(row1)
        v.addSpacing(10)

        v.addWidget(self._label("\U0001F464 USERNAME / EMAIL"))
        self.user_edit = make_pill_input("username or email")
        self.user_edit.setText(entry.get("username", ""))
        v.addWidget(self.user_edit)
        v.addSpacing(10)

        v.addWidget(self._label("\U0001F512 PASSWORD"))
        pwd_row = QHBoxLayout()
        self.pwd_field = PasswordField(placeholder="enter password", show_generate=True,
                                        gen_callback=self._generate)
        self.pwd_field.setText(entry.get("password", ""))
        self.pwd_field.textChanged.connect(self._update_strength)
        pwd_row.addWidget(self.pwd_field, 1)
        self.strength_lbl = QLabel("")
        self.strength_lbl.setFixedWidth(64)
        self.strength_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pwd_row.addWidget(self.strength_lbl)
        v.addLayout(pwd_row)
        self.strength_bar = StrengthBar()
        v.addWidget(self.strength_bar)
        v.addSpacing(10)

        v.addWidget(self._label("\U0001F3F7 TAGS"))
        self.tag_input = make_pill_input("type a tag and press Enter (comma-separated OK)")
        self.tag_input.returnPressed.connect(self._add_tag_from_input)
        v.addWidget(self.tag_input)
        self.tags_wrap = make_flow_container(margin=6, hspacing=6, vspacing=6)
        v.addWidget(self.tags_wrap)
        v.addSpacing(6)

        v.addWidget(self._label("NOTES"))
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlainText(entry.get("notes", ""))
        self.notes_edit.setFixedHeight(64)
        v.addWidget(self.notes_edit)
        v.addSpacing(10)

        self.fav_check = QCheckBox("Mark as Favorite")
        self.fav_check.setChecked(entry.get("favorite", False))
        v.addWidget(self.fav_check)
        v.addSpacing(16)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("GhostButton")
        cancel_btn.setStyleSheet(f"border: 1px solid {Palette.get('border')}; border-radius: 20px;")
        cancel_btn.setFixedHeight(46)
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.setAutoDefault(False)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn, 1)
        save_btn = QPushButton("Add Entry" if self.is_new else "Save Changes")
        save_btn.setObjectName("PrimaryButton")
        save_btn.setFixedHeight(46)
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.setAutoDefault(False)
        save_btn.setDefault(False)
        save_btn.clicked.connect(self._save)
        btn_row.addWidget(save_btn, 2)
        v.addLayout(btn_row)

        self._render_tags()
        self._update_strength(entry.get("password", ""))

    def _label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("FieldLabel")
        return lbl

    def _generate(self):
        self.pwd_field.setText(generate_password(self.app_window.gen_config))

    def _update_strength(self, _text=None):
        pwd = self.pwd_field.text()
        score = password_strength_score(pwd)
        label, color_key = strength_bucket(score)
        self.strength_bar.set_score(score, color_key)
        self.strength_lbl.setText(label)
        self.strength_lbl.setStyleSheet(f"color:{Palette.get(color_key)}; font-weight:800;")

    def _add_tag_from_input(self):
        raw = self.tag_input.text().strip().lower()
        self.tag_input.setText("")
        for t in raw.split(","):
            t = t.strip()
            if t and t not in self.tags:
                self.tags.append(t)
        self._render_tags()

    def _remove_tag(self, tag):
        self.tags = [t for t in self.tags if t != tag]
        self._render_tags()

    def _render_tags(self):
        layout = self.tags_wrap.layout()
        clear_layout(layout)
        for t in self.tags:
            pill = TagPill(t)
            pill.removed.connect(self._remove_tag)
            layout.addWidget(pill)

    def _save(self):
        name = self.name_edit.text().strip()
        password = self.pwd_field.text().strip()
        if not name or not password:
            warn(self, "Incomplete Entry", "Website Name and Password are required.")
            return
        data = load_garden_vault(self.app_window.session_key)
        now_str = datetime.now().isoformat()
        eid = self.entry_id or uuid.uuid4().hex
        existing = data["entries"].get(eid, {})
        data["entries"][eid] = {
            "name": name,
            "url": self.url_edit.text().strip(),
            "username": self.user_edit.text().strip(),
            "password": password,
            "tags": list(self.tags),
            "notes": self.notes_edit.toPlainText().strip(),
            "favorite": self.fav_check.isChecked(),
            "created_at": existing.get("created_at", now_str),
            "updated_at": now_str,
        }
        if not save_garden_vault(data, self.app_window.session_key):
            error(self, "Save Failed", "Could not write to the vault file. Please try again.")
            return
        self.accept()


class EntryListDialog(AnimatedDialog):
    """Read-only drill-down list used by clickable Dashboard stats."""

    def __init__(self, app_window, title, entry_ids, entries, parent=None):
        super().__init__(parent)
        self.app_window = app_window
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(480)
        self.setMinimumHeight(360)

        v = QVBoxLayout(self)
        v.setContentsMargins(24, 22, 24, 22)
        head = QHBoxLayout()
        t = QLabel(title)
        t.setStyleSheet("font-size: 17px; font-weight: 800;")
        head.addWidget(t)
        head.addItem(h_spacer())
        close_btn = QPushButton("\u2715")
        close_btn.setObjectName("IconButtonFlat")
        close_btn.setFixedSize(26, 26)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.setAutoDefault(False)
        close_btn.clicked.connect(self.reject)
        head.addWidget(close_btn)
        v.addLayout(head)
        v.addSpacing(10)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setSpacing(8)

        seen = set()
        shown = 0
        for eid in entry_ids:
            if eid in seen:
                continue
            seen.add(eid)
            e = entries.get(eid)
            if not e:
                continue
            shown += 1
            row = QPushButton()
            row.setObjectName("GhostButton")
            row.setStyleSheet(f"border: 1px solid {Palette.get('border')}; border-radius: 14px;")
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(12, 10, 12, 10)
            name_lbl = QLabel(e.get("name", ""))
            name_lbl.setStyleSheet("font-weight: 700;")
            rl.addWidget(name_lbl)
            user_lbl = QLabel(e.get("username", ""))
            user_lbl.setObjectName("Muted")
            rl.addWidget(user_lbl)
            rl.addItem(h_spacer())
            score = password_strength_score(e.get("password", ""))
            label, color_key = strength_bucket(score)
            rl.addWidget(Badge(label, color_key))
            row.clicked.connect(lambda checked, name=e.get("name", ""): self._goto(name))
            hl.addWidget(row)

        if shown == 0:
            empty = QLabel("Nothing to show.")
            empty.setObjectName("Muted")
            hl.addWidget(empty)
        hl.addItem(v_spacer())
        scroll.setWidget(holder)
        v.addWidget(scroll)

    def _goto(self, name):
        self.app_window.pending_vault_search = name
        self.accept()
        self.app_window.navigate("vault")


# =========================================================================== #
#  ENTRY CARD  (Vault list row)
# =========================================================================== #

def clickable_badge(text, color_key, tooltip=""):
    btn = QPushButton(text)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    if tooltip:
        btn.setToolTip(tooltip)
    bg = hex_to_rgba(Palette.get(color_key), 0.18)
    bg_hover = hex_to_rgba(Palette.get(color_key), 0.32)
    fg = Palette.get(color_key)
    btn.setStyleSheet(
        f"QPushButton {{ background-color:{bg}; color:{fg}; border-radius:10px; padding:3px 10px; "
        f"font-size:11px; font-weight:700; border: none; }} "
        f"QPushButton:hover {{ background-color:{bg_hover}; }}"
    )
    return btn


class EntryCard(Card):
    """A single credential 'card' shown in the Vault. It is fully self-
    contained: it reads the user's Grid/List preference itself, so the page
    that creates it (VaultPage) doesn't need to know those details - it just
    drops the card into whichever container fits the current view mode."""

    def __init__(self, entry_id, entry, app_window, on_change, reused_with=None, on_show_reused=None, parent=None):
        super().__init__(flat=False, shadow=False, parent=parent)
        self.entry_id = entry_id
        self.entry = entry
        self.app_window = app_window
        self.on_change = on_change
        self.reused_with = reused_with or []
        self.on_show_reused = on_show_reused
        self._revealed = False
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.setProperty("hoverable", "true")
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)

        if app_window.prefs.get("vault_view_mode", "Grid") == "Grid":
            self.setFixedWidth(VAULT_GRID_CARD_WIDTH)  # fixed width lets FlowLayout wrap cards into columns

        v = QVBoxLayout(self)
        v.setContentsMargins(ENTRY_CARD_MARGIN, ENTRY_CARD_MARGIN - 4, ENTRY_CARD_MARGIN, ENTRY_CARD_MARGIN - 4)
        v.setSpacing(ENTRY_CARD_SPACING)

        top = QHBoxLayout()
        top.setSpacing(12)
        top.addWidget(avatar_for(entry.get("name", "?")))

        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        name_row = QHBoxLayout()
        name_row.setSpacing(6)
        name_lbl = QLabel(entry.get("name", ""))
        name_lbl.setObjectName("CardLabel")
        name_row.addWidget(name_lbl)
        if entry.get("url"):
            globe = QLabel("\U0001F310")
            globe.setStyleSheet("font-size: 12px;")
            name_row.addWidget(globe)
        name_row.addItem(h_spacer())
        title_col.addLayout(name_row)
        user_lbl = QLabel(entry.get("username", ""))
        user_lbl.setObjectName("Muted")
        title_col.addWidget(user_lbl)
        top.addLayout(title_col, 1)

        is_fav = entry.get("favorite", False)
        self.fav_btn = QPushButton("\u2605" if is_fav else "\u2606")
        self.fav_btn.setObjectName("FavStar")
        self.fav_btn.setStyleSheet(
            f"color:{Palette.get('amber') if is_fav else Palette.get('muted')}; font-size: 18px; background: transparent;"
        )
        self.fav_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.fav_btn.setFixedSize(28, 28)
        self.fav_btn.clicked.connect(self._toggle_favorite)
        top.addWidget(self.fav_btn)

        score = password_strength_score(entry.get("password", ""))
        label, color_key = strength_bucket(score)
        top.addWidget(Badge(label, color_key))

        if self.reused_with:
            reused_btn = clickable_badge(
                f"\U0001F501 Reused \u00D7{len(self.reused_with) + 1}", "red",
                tooltip="This password is also used elsewhere - click to see where"
            )
            reused_btn.clicked.connect(self._show_reused)
            top.addWidget(reused_btn)
        v.addLayout(top)

        pwd_row = QHBoxLayout()
        self.pwd_lbl = QLabel()
        self.pwd_lbl.setObjectName("EntryPasswordMask")
        pwd_row.addWidget(self.pwd_lbl, 1)
        eye_btn = QPushButton("\U0001F441")
        eye_btn.setObjectName("IconButton")
        eye_btn.setFixedSize(34, 34)
        eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        eye_btn.clicked.connect(self._toggle_reveal)
        pwd_row.addWidget(eye_btn)
        copy_pwd_btn = QPushButton("\u29C9")
        copy_pwd_btn.setObjectName("IconButton")
        copy_pwd_btn.setFixedSize(34, 34)
        copy_pwd_btn.setToolTip("Copy password")
        copy_pwd_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_pwd_btn.clicked.connect(
            lambda: self.app_window.copy_with_autoclear(entry.get("password", ""), f"Password for {entry.get('name', '')}")
        )
        pwd_row.addWidget(copy_pwd_btn)
        v.addLayout(pwd_row)
        self._update_pwd_label()

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        tags_wrap = make_flow_container(margin=0, hspacing=6, vspacing=6)
        for t in entry.get("tags", []):
            tags_wrap.layout().addWidget(Badge(t, "secondary"))
        bottom.addWidget(tags_wrap, 1)

        dup_btn = QPushButton("\u29C9")
        dup_btn.setObjectName("IconButtonFlat")
        dup_btn.setFixedSize(30, 30)
        dup_btn.setToolTip("Duplicate entry")
        dup_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        dup_btn.clicked.connect(self._duplicate)
        bottom.addWidget(dup_btn)

        edit_btn = QPushButton("\u270E")
        edit_btn.setObjectName("IconButtonFlat")
        edit_btn.setFixedSize(30, 30)
        edit_btn.setToolTip("Edit entry")
        edit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        edit_btn.clicked.connect(self._open_edit)
        bottom.addWidget(edit_btn)

        del_btn = QPushButton("\U0001F5D1")
        del_btn.setObjectName("IconButtonFlat")
        del_btn.setFixedSize(30, 30)
        del_btn.setToolTip("Delete entry")
        del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        del_btn.clicked.connect(self._delete)
        bottom.addWidget(del_btn)

        v.addLayout(bottom)

    def _update_pwd_label(self):
        pwd = self.entry.get("password", "")
        if self._revealed:
            self.pwd_lbl.setText(pwd)
        else:
            self.pwd_lbl.setText("\u2022" * min(len(pwd), 24) if pwd else "")

    def _toggle_reveal(self):
        self._revealed = not self._revealed
        self._update_pwd_label()

    def _show_reused(self):
        if self.on_show_reused:
            self.on_show_reused([self.entry_id] + self.reused_with)

    def _toggle_favorite(self):
        data = load_garden_vault(self.app_window.session_key)
        if self.entry_id in data["entries"]:
            data["entries"][self.entry_id]["favorite"] = not data["entries"][self.entry_id].get("favorite", False)
            save_garden_vault(data, self.app_window.session_key)
        self.on_change()

    def _open_edit(self):
        dlg = EntryDialog(self.app_window, entry_id=self.entry_id, entry=self.entry)
        if dlg.exec():
            self.on_change()

    def _duplicate(self):
        data = load_garden_vault(self.app_window.session_key)
        source = data["entries"].get(self.entry_id, dict(self.entry))
        now_str = datetime.now().isoformat()
        new_entry = dict(source)
        new_entry["name"] = f"{source.get('name', '')} (copy)"
        new_entry["favorite"] = False
        new_entry["created_at"] = now_str
        new_entry["updated_at"] = now_str
        data["entries"][uuid.uuid4().hex] = new_entry
        save_garden_vault(data, self.app_window.session_key)
        self.on_change()

    def _delete(self):
        if not confirm(self, "Delete Entry", f"Permanently delete '{self.entry.get('name', '')}'? This cannot be undone."):
            return
        data = load_garden_vault(self.app_window.session_key)
        if self.entry_id in data["entries"]:
            del data["entries"][self.entry_id]
            save_garden_vault(data, self.app_window.session_key)
        self.on_change()


# =========================================================================== #
#  VAULT PAGE
# =========================================================================== #

class VaultPage(QWidget):
    """The main credential browser: search, tag-filter chips, a Grid/List
    toggle, and the actual list of EntryCards grouped into Favorites / All
    entries. Nothing here mutates the vault directly - all edits go through
    EntryDialog or EntryCard's own quick actions, which call back into
    self.refresh() when they're done."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.active_tag = "All"
        self.entries = {}

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        head = QHBoxLayout()
        title = QLabel("\U0001F33A Vault")
        title.setObjectName("PageTitle")
        head.addWidget(title)
        head.addItem(h_spacer())

        # Grid / List is a real, persisted user preference - this is the
        # "control how you want your space to look" toggle.
        self.view_group = QButtonGroup(self)
        self.view_group.setExclusive(True)
        self.grid_btn = QPushButton("\u25A6")
        self.grid_btn.setObjectName("ViewToggle")
        self.grid_btn.setCheckable(True)
        self.grid_btn.setFixedSize(38, 38)
        self.grid_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.grid_btn.setToolTip("Grid view")
        self.grid_btn.clicked.connect(lambda: self._set_view_mode("Grid"))
        self.list_btn = QPushButton("\u2261")
        self.list_btn.setObjectName("ViewToggle")
        self.list_btn.setCheckable(True)
        self.list_btn.setFixedSize(38, 38)
        self.list_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.list_btn.setToolTip("List view")
        self.list_btn.clicked.connect(lambda: self._set_view_mode("List"))
        self.view_group.addButton(self.grid_btn)
        self.view_group.addButton(self.list_btn)
        head.addWidget(self.grid_btn)
        head.addWidget(self.list_btn)
        head.addSpacing(6)

        add_btn = QPushButton("+ Add Entry")
        add_btn.setObjectName("SuccessButton")
        add_btn.setFixedHeight(42)
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self._add_entry)
        head.addWidget(add_btn)
        root.addLayout(head)

        self.subtitle = QLabel("")
        self.subtitle.setObjectName("PageSubtitle")
        root.addWidget(self.subtitle)

        search_row = QHBoxLayout()
        search_row.setSpacing(10)
        self.search_edit = make_pill_input("\U0001F50D  Search websites, usernames, tags...")
        self.search_edit.textChanged.connect(self._apply_filters)
        search_row.addWidget(self.search_edit, 1)
        self.clear_search_btn = QPushButton("\u2715 Clear")
        self.clear_search_btn.setObjectName("GhostButton")
        self.clear_search_btn.setStyleSheet(f"border: 1px solid {Palette.get('border')}; border-radius: 16px;")
        self.clear_search_btn.setFixedHeight(46)
        self.clear_search_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_search_btn.clicked.connect(self._clear_search)
        search_row.addWidget(self.clear_search_btn)
        root.addLayout(search_row)

        self.chip_container = make_flow_container(margin=0, hspacing=8, vspacing=8)
        root.addWidget(self.chip_container)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.list_holder = QWidget()
        self.list_layout = QVBoxLayout(self.list_holder)
        self.list_layout.setSpacing(14)
        self.list_layout.setContentsMargins(2, 2, 2, 10)
        self.scroll.setWidget(self.list_holder)
        root.addWidget(self.scroll, 1)

        self.footer_lbl = QLabel("")
        self.footer_lbl.setObjectName("Muted")
        self.footer_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self.footer_lbl)

    def refresh(self):
        data = load_garden_vault(self.app_window.session_key)
        self.entries = data.get("entries", {})

        view_mode = self.app_window.prefs.get("vault_view_mode", "Grid")
        self.grid_btn.setChecked(view_mode == "Grid")
        self.list_btn.setChecked(view_mode == "List")

        pending_tag = getattr(self.app_window, "pending_vault_tag", None)
        pending_search = getattr(self.app_window, "pending_vault_search", None)
        if pending_tag is not None:
            self.active_tag = pending_tag
            self.app_window.pending_vault_tag = None
        if pending_search is not None:
            self.search_edit.blockSignals(True)
            self.search_edit.setText(pending_search)
            self.search_edit.blockSignals(False)
            self.app_window.pending_vault_search = None

        all_tags = sorted({t for e in self.entries.values() for t in e.get("tags", [])})
        self.subtitle.setText(f"{len(self.entries)} entries across {len(all_tags)} tags")

        if self.active_tag not in (["All"] + all_tags):
            self.active_tag = "All"

        chip_layout = self.chip_container.layout()
        clear_layout(chip_layout)
        self.chip_group = QButtonGroup(self)
        self.chip_group.setExclusive(True)
        for cat in ["All"] + all_tags:
            chip = QPushButton(("\U0001F310 " if cat == "All" else "") + cat)
            chip.setObjectName("Chip")
            chip.setCheckable(True)
            chip.setChecked(cat == self.active_tag)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda checked, c=cat: self._set_tag(c))
            self.chip_group.addButton(chip)
            chip_layout.addWidget(chip)

        self._apply_filters()

    def _set_tag(self, tag):
        self.active_tag = tag
        if tag == "All":
            self.search_edit.blockSignals(True)
            self.search_edit.setText("")
            self.search_edit.blockSignals(False)
        self._apply_filters()

    def _clear_search(self):
        """Reset both the search box and the tag filter in one click."""
        self.active_tag = "All"
        self.search_edit.blockSignals(True)
        self.search_edit.setText("")
        self.search_edit.blockSignals(False)
        self.refresh()

    def _set_view_mode(self, mode):
        """Persist the user's Grid/List choice immediately and re-render."""
        self.app_window.prefs["vault_view_mode"] = mode
        self.app_window.save_prefs()
        self.grid_btn.setChecked(mode == "Grid")
        self.list_btn.setChecked(mode == "List")
        self._apply_filters()

    def _apply_filters(self):
        query = self.search_edit.text().strip().lower()
        filtered = {}
        for eid, e in self.entries.items():
            if self.active_tag != "All" and self.active_tag not in e.get("tags", []):
                continue
            haystack = " ".join([e.get("name", ""), e.get("username", ""), " ".join(e.get("tags", []))]).lower()
            if query and query not in haystack:
                continue
            filtered[eid] = e
        self._render_list(filtered)

    def _render_list(self, filtered):
        """Rebuilds the visible entry cards from scratch every time filters,
        search text, or the view mode changes. In Grid mode each section
        (Favorites / All entries) gets its own FlowLayout container so fixed-
        width cards wrap into columns; in List mode cards simply stack full-
        width in a plain vertical layout - both share the exact same
        EntryCard, just arranged differently."""
        clear_layout(self.list_layout)

        self.list_layout.setSpacing(VAULT_ROW_GAP)
        grid_mode = self.app_window.prefs.get("vault_view_mode", "Grid") == "Grid"

        pass_groups = {}
        for eid, e in self.entries.items():
            pwd = e.get("password", "")
            if pwd:
                pass_groups.setdefault(pwd, []).append(eid)

        favorites = {eid: e for eid, e in filtered.items() if e.get("favorite")}
        rest = {eid: e for eid, e in filtered.items() if not e.get("favorite")}

        def add_section(title, items):
            if not items:
                return
            if title:
                hdr = QLabel(title)
                hdr.setStyleSheet("font-size: 14px; font-weight: 800; margin-top: 4px;")
                self.list_layout.addWidget(hdr)

            # Grid mode: cards go into a wrapping FlowLayout container.
            # List mode: cards go straight into the page's own vertical layout.
            target_container = make_flow_container(margin=0, hspacing=14, vspacing=14) if grid_mode else None
            if target_container:
                self.list_layout.addWidget(target_container)

            for eid, e in sorted(items.items(), key=lambda kv: kv[1].get("name", "").lower()):
                group = pass_groups.get(e.get("password", ""), [eid])
                reused_with = [i for i in group if i != eid] if len(group) > 1 else []
                card = EntryCard(eid, e, self.app_window, self.refresh,
                                  reused_with=reused_with, on_show_reused=self._show_reused_group)
                if target_container:
                    target_container.layout().addWidget(card)
                else:
                    self.list_layout.addWidget(card)

        add_section("\u2B50 Favorites" if favorites else None, favorites)
        add_section("All entries" if favorites else None, rest)

        if not filtered:
            empty = QLabel("No entries match your search. Try a different filter, or add a new entry.")
            empty.setObjectName("Muted")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.list_layout.addWidget(empty)
        self.list_layout.addItem(v_spacer())

        self.footer_lbl.setText(f"{len(filtered)} of {len(self.entries)} entries")

    def _add_entry(self):
        dlg = EntryDialog(self.app_window, entry_id=None, entry=None)
        if dlg.exec():
            self.refresh()

    def _show_reused_group(self, ids):
        dlg = EntryListDialog(self.app_window, "Entries Sharing This Password", ids, self.entries, self)
        dlg.exec()


# =========================================================================== #
#  TAGS PAGE
# =========================================================================== #
#  Tag management used to be a tab buried inside Settings. It now lives here
#  as its own first-class page (with a Sidebar entry) because tags are core,
#  everyday vault content - renaming/deleting them deserves the same visible
#  home as the Vault itself, not a corner of a preferences screen.
# =========================================================================== #

class TagsPage(QWidget):
    """Lists every tag in use across the vault with a live entry count, and
    lets the user rename a tag everywhere at once, delete it everywhere at
    once, or jump straight to the Vault pre-filtered to that tag."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        title = QLabel("\U0001F3F7 Tags")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        subtitle = QLabel("Rename or delete a tag everywhere at once, or jump to it in the Vault")
        subtitle.setObjectName("PageSubtitle")
        root.addWidget(subtitle)
        root.addSpacing(10)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.holder = QWidget()
        self.list_layout = QVBoxLayout(self.holder)
        self.list_layout.setSpacing(10)
        self.list_layout.setContentsMargins(2, 2, 2, 10)
        self.scroll.setWidget(self.holder)
        root.addWidget(self.scroll, 1)

    def refresh(self):
        clear_layout(self.list_layout)
        data = load_garden_vault(self.app_window.session_key)
        entries = data.get("entries", {})
        tag_counts = {}
        for e in entries.values():
            for t in e.get("tags", []):
                tag_counts[t] = tag_counts.get(t, 0) + 1

        if not tag_counts:
            empty_card = Card(flat=True)
            ev = QVBoxLayout(empty_card)
            ev.setContentsMargins(20, 30, 20, 30)
            ev.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ic = QLabel("\U0001F3F7")
            ic.setStyleSheet("font-size: 32px;")
            ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ev.addWidget(ic)
            empty = QLabel("No tags yet - add one or more tags to any entry from the Vault.")
            empty.setObjectName("Muted")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ev.addWidget(empty)
            self.list_layout.addWidget(empty_card)
            self.list_layout.addItem(v_spacer())
            return

        for tag, count in sorted(tag_counts.items()):
            row = Card()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(20, 14, 20, 14)
            rl.setSpacing(12)

            badge = Badge(tag, "primary")
            rl.addWidget(badge)
            count_lbl = QLabel(f"{count} entr{'y' if count == 1 else 'ies'}")
            count_lbl.setObjectName("Muted")
            rl.addWidget(count_lbl)
            rl.addItem(h_spacer())

            view_btn = QPushButton("View in Vault")
            view_btn.setObjectName("IconButton")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.clicked.connect(lambda checked, tg=tag: self._goto_vault(tg))
            rl.addWidget(view_btn)

            rename_btn = QPushButton("Rename")
            rename_btn.setObjectName("IconButton")
            rename_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            rename_btn.clicked.connect(lambda checked, tg=tag: self._rename_tag(tg))
            rl.addWidget(rename_btn)

            del_btn = QPushButton("Delete")
            del_btn.setObjectName("DangerButton")
            del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            del_btn.clicked.connect(lambda checked, tg=tag: self._delete_tag(tg))
            rl.addWidget(del_btn)

            self.list_layout.addWidget(row)
        self.list_layout.addItem(v_spacer())

    def _goto_vault(self, tag):
        self.app_window.pending_vault_tag = tag
        self.app_window.navigate("vault")

    def _rename_tag(self, tag):
        new_name, ok = QInputDialog.getText(self, "Rename Tag", f"Rename '{tag}' to:", text=tag)
        new_name = new_name.strip().lower()
        if not ok or not new_name or new_name == tag:
            return
        data = load_garden_vault(self.app_window.session_key)
        for e in data.get("entries", {}).values():
            tags = e.get("tags", [])
            if tag in tags:
                e["tags"] = sorted({new_name if t == tag else t for t in tags})
        save_garden_vault(data, self.app_window.session_key)
        self.refresh()

    def _delete_tag(self, tag):
        if not confirm(self, "Delete Tag", f"Remove tag '{tag}' from all entries? "
                                            f"The entries themselves are not affected."):
            return
        data = load_garden_vault(self.app_window.session_key)
        for e in data.get("entries", {}).values():
            e["tags"] = [t for t in e.get("tags", []) if t != tag]
        save_garden_vault(data, self.app_window.session_key)
        self.refresh()


# =========================================================================== #
#  DASHBOARD PAGE
# =========================================================================== #

class DashboardPage(QWidget):
    """The at-a-glance security overview: the health gauge, the four mini
    stats, the strength breakdown bars, "Recently Modified", and the Tags
    panel. Every number here is computed fresh from the live vault on each
    refresh() via compute_vault_stats() - nothing is cached - and several of
    them (the Weak/At Risk tile, each strength-breakdown row, the reused-
    passwords notice) are clickable, opening an EntryListDialog that shows
    exactly which entries are involved rather than just a bare count."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        outer.addWidget(self.scroll)
        self.inner = QWidget()
        self.scroll.setWidget(self.inner)
        self.v = QVBoxLayout(self.inner)
        self.v.setContentsMargins(2, 2, 2, 2)
        self.v.setSpacing(18)

    def refresh(self):
        clear_layout(self.v)

        prefs = self.app_window.prefs
        data = load_garden_vault(self.app_window.session_key)
        entries = data.get("entries", {})
        stats = compute_vault_stats(entries)

        head = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(0)
        t = QLabel("Dashboard")
        t.setObjectName("PageTitle")
        title_col.addWidget(t)
        sub = QLabel("Security overview & quick access")
        sub.setObjectName("PageSubtitle")
        title_col.addWidget(sub)
        head.addLayout(title_col)
        head.addItem(h_spacer())
        add_btn = QPushButton("+ Add Entry")
        add_btn.setObjectName("SuccessButton")
        add_btn.setFixedHeight(42)
        add_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        add_btn.clicked.connect(self._add_entry)
        head.addWidget(add_btn)
        self.v.addLayout(head)

        last_unlock = prefs.get("last_unlocked_iso", "")
        if last_unlock:
            try:
                dt = datetime.fromisoformat(last_unlock)
                same_day = dt.date() == datetime.now().date()
                when = f"today at {dt.strftime('%I:%M %p').lstrip('0')}" if same_day else \
                    f"on {dt.strftime('%b %d')} at {dt.strftime('%I:%M %p').lstrip('0')}"
                sub2 = QLabel(f"Vault last unlocked {when}.")
                sub2.setObjectName("Muted")
                self.v.addWidget(sub2)
            except Exception:
                pass

        top_row = QHBoxLayout()
        top_row.setSpacing(16)

        gauge_card = Card()
        gc = QVBoxLayout(gauge_card)
        gc.setContentsMargins(20, 20, 20, 20)
        health = stats["health"]
        color_key = "green" if health >= 80 else ("amber" if health >= 50 else "red")
        gauge = CircularGauge()
        gauge.setFixedSize(120, 120)
        gauge.set_value(health / 100.0, color_key)
        gauge_center = QVBoxLayout(gauge)
        gauge_center.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gv = QLabel(str(health))
        gv.setObjectName("GaugeCenter")
        gv.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gv.setStyleSheet(f"color:{Palette.get(color_key)};")
        gt = QLabel("/ 100")
        gt.setObjectName("Muted")
        gt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        gauge_center.addWidget(gv)
        gauge_center.addWidget(gt)
        gc.addWidget(gauge, 0, Qt.AlignmentFlag.AlignCenter)
        gc.addSpacing(8)
        score_lbl = QLabel("Security Score")
        score_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_lbl.setStyleSheet("font-weight: 800;")
        gc.addWidget(score_lbl)
        status_txt = "Excellent" if health >= 80 else ("Needs attention" if health < 50 else "Fair")
        status_lbl = QLabel(status_txt)
        status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_lbl.setObjectName("Muted")
        gc.addWidget(status_lbl)
        top_row.addWidget(gauge_card, 1)

        grid = QGridLayout()
        grid.setSpacing(14)

        def mini_stat(icon, value, title, color_key_inner, onclick=None):
            card = Card(flat=True)
            if onclick:
                card.setCursor(Qt.CursorShape.PointingHandCursor)
            cv = QVBoxLayout(card)
            cv.setContentsMargins(16, 14, 16, 14)
            cv.setSpacing(6)
            ic_box = QLabel(icon)
            ic_box.setFixedSize(38, 38)
            ic_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ic_box.setStyleSheet(
                f"font-size: 16px; background-color:{hex_to_rgba(Palette.get(color_key_inner), 0.16)}; "
                f"border-radius: 10px;"
            )
            cv.addWidget(ic_box)
            val = QLabel(str(value))
            val.setObjectName("MetricValue")
            cv.addWidget(val)
            ttl = QLabel(title)
            ttl.setObjectName("Muted")
            cv.addWidget(ttl)
            if onclick:
                card.mousePressEvent = lambda event: onclick()
            return card

        grid.addWidget(mini_stat("\U0001F512", stats["total"], "Total Passwords", "primary"), 0, 0)
        grid.addWidget(mini_stat("\u2B50", stats["favorites"], "Favorites", "amber"), 0, 1)
        grid.addWidget(mini_stat("\u26A0\uFE0F", stats["weak_at_risk"], "Weak / At Risk", "red",
                                  onclick=lambda: self._show_bucket(["Weak", "Fair"])), 1, 0)
        grid.addWidget(mini_stat("\U0001F6E1\uFE0F", stats["strong_count"], "Strong Passwords", "green"), 1, 1)
        top_row.addLayout(grid, 2)
        self.v.addLayout(top_row)

        breakdown_card = Card()
        bv = QVBoxLayout(breakdown_card)
        bv.setContentsMargins(24, 20, 24, 20)
        bv_title = QLabel("Password Strength Breakdown")
        bv_title.setObjectName("SectionTitle")
        bv.addWidget(bv_title)
        bv.addSpacing(10)
        max_count = max(1, stats["total"])
        for label, ck in [("Strong", "green"), ("Good", "primary"), ("Fair", "amber"), ("Weak", "red")]:
            row_wrap = QFrame()
            row_wrap.setCursor(Qt.CursorShape.PointingHandCursor)
            row_h = QHBoxLayout(row_wrap)
            row_h.setContentsMargins(0, 4, 0, 4)
            lbl = QLabel(label)
            lbl.setFixedWidth(60)
            lbl.setStyleSheet(f"color:{Palette.get(ck)}; font-weight: 700;")
            row_h.addWidget(lbl)
            bar = QProgressBar()
            bar.setRange(0, max_count)
            bar.setValue(stats["bucket_counts"][label])
            bar.setFixedHeight(8)
            bar.setTextVisible(False)
            bar.setStyleSheet(f"QProgressBar::chunk {{ background-color:{Palette.get(ck)}; }}")
            row_h.addWidget(bar, 1)
            count_lbl = QLabel(str(stats["bucket_counts"][label]))
            count_lbl.setFixedWidth(20)
            row_h.addWidget(count_lbl)
            row_wrap.mousePressEvent = lambda event, l=label: self._show_bucket([l])
            bv.addWidget(row_wrap)

        if stats["reused_count"] > 0:
            bv.addSpacing(8)
            reused_btn = QPushButton(f"\U0001F501 {stats['reused_count']} passwords reused across multiple entries \u2014 Review")
            reused_btn.setObjectName("LinkButton")
            reused_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            reused_btn.clicked.connect(self._show_reused)
            bv.addWidget(reused_btn)
        self.v.addWidget(breakdown_card)

        bottom_row = QHBoxLayout()
        bottom_row.setSpacing(16)

        recent_card = Card()
        rv = QVBoxLayout(recent_card)
        rv.setContentsMargins(24, 20, 24, 20)
        rhead = QHBoxLayout()
        rtitle = QLabel("Recently Modified")
        rtitle.setObjectName("SectionTitle")
        rhead.addWidget(rtitle)
        rhead.addItem(h_spacer())
        view_all = QPushButton("View all \u2192")
        view_all.setObjectName("LinkButton")
        view_all.setCursor(Qt.CursorShape.PointingHandCursor)
        view_all.clicked.connect(lambda: self.app_window.navigate("vault"))
        rhead.addWidget(view_all)
        rv.addLayout(rhead)
        rv.addSpacing(6)
        recent = sorted(entries.items(), key=lambda kv: kv[1].get("updated_at", ""), reverse=True)[:5]
        if not recent:
            empty = QLabel("No entries yet. Add your first one!")
            empty.setObjectName("Muted")
            rv.addWidget(empty)
        for eid, e in recent:
            row = QPushButton()
            row.setObjectName("GhostButton")
            row.setCursor(Qt.CursorShape.PointingHandCursor)
            rl = QHBoxLayout(row)
            rl.setContentsMargins(8, 6, 8, 6)
            name_lbl = QLabel(e.get("name", ""))
            name_lbl.setStyleSheet("font-weight: 700;")
            rl.addWidget(name_lbl)
            rl.addItem(h_spacer())
            date_lbl = QLabel(self._fmt_date(e.get("updated_at", "")))
            date_lbl.setObjectName("Muted")
            rl.addWidget(date_lbl)
            row.clicked.connect(lambda checked, i=eid, ent=e: self._edit_entry(i, ent))
            rv.addWidget(row)
        rv.addItem(v_spacer())
        bottom_row.addWidget(recent_card, 1)

        tags_card = Card()
        tv = QVBoxLayout(tags_card)
        tv.setContentsMargins(24, 20, 24, 20)
        ttitle = QLabel("\U0001F3F7 Tags")
        ttitle.setObjectName("SectionTitle")
        tv.addWidget(ttitle)
        tv.addSpacing(8)
        tag_wrap = make_flow_container(margin=0, hspacing=8, vspacing=8)
        for tag, count in sorted(stats["tag_counts"].items()):
            btn = QPushButton(f"{tag}  {count}")
            btn.setObjectName("Chip")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, tg=tag: self._goto_tag(tg))
            tag_wrap.layout().addWidget(btn)
        if not stats["tag_counts"]:
            none_lbl = QLabel("No tags yet.")
            none_lbl.setObjectName("Muted")
            tag_wrap.layout().addWidget(none_lbl)
        tv.addWidget(tag_wrap)
        tv.addItem(v_spacer())
        gen_btn = QPushButton("\u26A1 Open Generator \u2192")
        gen_btn.setObjectName("GhostButton")
        gen_btn.setStyleSheet(f"border: 1px solid {Palette.get('border')}; border-radius: 16px;")
        gen_btn.setFixedHeight(42)
        gen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        gen_btn.clicked.connect(lambda: self.app_window.navigate("generator"))
        tv.addWidget(gen_btn)
        bottom_row.addWidget(tags_card, 1)
        self.v.addLayout(bottom_row)

        attention = stats["weak_at_risk"]
        if attention > 0:
            banner = QFrame()
            banner.setObjectName("DangerZone")
            bl = QVBoxLayout(banner)
            bl.setContentsMargins(20, 16, 20, 16)
            bt = QLabel(f"\u26A0\uFE0F {attention} password{'s' if attention != 1 else ''} need attention")
            bt.setStyleSheet(f"color:{Palette.get('red')}; font-weight: 800;")
            bl.addWidget(bt)
            bd = QLabel("Weak or fair passwords were found. Update them to improve your security score.")
            bd.setObjectName("Muted")
            bd.setWordWrap(True)
            bl.addWidget(bd)
            review_btn = QPushButton("Review in Vault \u2192")
            review_btn.setObjectName("LinkButton")
            review_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            review_btn.clicked.connect(lambda: self.app_window.navigate("vault"))
            bl.addWidget(review_btn)
            self.v.addWidget(banner)

        self.v.addItem(v_spacer())

    def _fmt_date(self, iso_str):
        try:
            return datetime.fromisoformat(iso_str).strftime("%b %d, %Y")
        except Exception:
            return ""

    def _add_entry(self):
        dlg = EntryDialog(self.app_window, entry_id=None, entry=None)
        if dlg.exec():
            self.refresh()

    def _edit_entry(self, eid, entry):
        dlg = EntryDialog(self.app_window, entry_id=eid, entry=entry)
        if dlg.exec():
            self.refresh()

    def _show_bucket(self, labels):
        data = load_garden_vault(self.app_window.session_key)
        entries = data.get("entries", {})
        ids = [eid for eid, e in entries.items()
               if strength_bucket(password_strength_score(e.get("password", "")))[0] in labels]
        dlg = EntryListDialog(self.app_window, " / ".join(labels) + " Passwords", ids, entries, self)
        dlg.exec()

    def _show_reused(self):
        data = load_garden_vault(self.app_window.session_key)
        entries = data.get("entries", {})
        stats = compute_vault_stats(entries)
        ids = [eid for group in stats["reused_groups"].values() for eid in group]
        dlg = EntryListDialog(self.app_window, "Reused Passwords", ids, entries, self)
        dlg.exec()

    def _goto_tag(self, tag):
        self.app_window.pending_vault_tag = tag
        self.app_window.navigate("vault")


# =========================================================================== #
#  GENERATOR PAGE
# =========================================================================== #

class GeneratorPage(QWidget):

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        self.history = []

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(20)

        left = QVBoxLayout()
        left.setSpacing(16)

        title = QLabel("\u26A1 Seed Generator")
        title.setObjectName("PageTitle")
        left.addWidget(title)
        subtitle = QLabel("Grow cryptographically strong passwords from secure entropy")
        subtitle.setObjectName("PageSubtitle")
        left.addWidget(subtitle)

        result_card = Card()
        rc_v = QVBoxLayout(result_card)
        rc_v.setContentsMargins(26, 24, 26, 24)
        self.result_lbl = QLabel("")
        self.result_lbl.setStyleSheet("font-size: 22px; font-family: Consolas, monospace; letter-spacing: 1px;")
        self.result_lbl.setWordWrap(True)
        rc_v.addWidget(self.result_lbl)
        rc_v.addSpacing(20)

        meta_row = QHBoxLayout()
        self.entropy_badge = Badge("~0 bits", "green")
        meta_row.addWidget(self.entropy_badge)
        self.entropy_desc = QLabel("Estimated Entropy \u00B7 Weak")
        self.entropy_desc.setObjectName("Muted")
        meta_row.addWidget(self.entropy_desc)
        meta_row.addItem(h_spacer())
        copy_btn = QPushButton("Copy")
        copy_btn.setObjectName("PrimaryButton")
        copy_btn.setFixedHeight(38)
        copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        copy_btn.clicked.connect(self._copy_current)
        meta_row.addWidget(copy_btn)
        regen_btn = QPushButton("\u21BB Regenerate")
        regen_btn.setObjectName("GhostButton")
        regen_btn.setStyleSheet(f"border: 1px solid {Palette.get('border')}; border-radius: 19px;")
        regen_btn.setFixedHeight(38)
        regen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        regen_btn.clicked.connect(self._generate)
        meta_row.addWidget(regen_btn)
        rc_v.addLayout(meta_row)
        left.addWidget(result_card)

        params_card = Card()
        pc_v = QVBoxLayout(params_card)
        pc_v.setContentsMargins(26, 22, 26, 22)
        pc_v.setSpacing(14)
        params_title = QLabel("PARAMETERS")
        params_title.setObjectName("FieldLabel")
        pc_v.addWidget(params_title)

        len_row = QHBoxLayout()
        len_row.addWidget(QLabel("Length"))
        len_row.addItem(h_spacer())
        self.len_val_lbl = QLabel("20")
        self.len_val_lbl.setStyleSheet(f"color:{Palette.get('primary')}; font-weight: 800; font-size: 16px;")
        len_row.addWidget(self.len_val_lbl)
        pc_v.addLayout(len_row)

        self.len_slider = QSlider(Qt.Orientation.Horizontal)
        self.len_slider.setRange(8, 64)
        self.len_slider.valueChanged.connect(self._on_length_changed)
        pc_v.addWidget(self.len_slider)
        range_row = QHBoxLayout()
        range_row.addWidget(QLabel("8"))
        range_row.addItem(h_spacer())
        range_row.addWidget(QLabel("64"))
        pc_v.addLayout(range_row)
        pc_v.addSpacing(6)

        self.toggle_widgets = {}

        def toggle_row(label_text, key, sub=None):
            row = QHBoxLayout()
            text_col = QVBoxLayout()
            text_col.setSpacing(0)
            lbl = QLabel(label_text)
            lbl.setStyleSheet("font-weight: 600;")
            text_col.addWidget(lbl)
            if sub:
                sub_lbl = QLabel(sub)
                sub_lbl.setObjectName("Muted")
                text_col.addWidget(sub_lbl)
            row.addLayout(text_col)
            row.addItem(h_spacer())
            sw = ToggleSwitch()
            sw.toggled.connect(lambda checked, k=key: self._on_toggle(k, checked))
            self.toggle_widgets[key] = sw
            row.addWidget(sw)
            pc_v.addLayout(row)

        toggle_row("Uppercase A\u2013Z", "use_uppercase")
        toggle_row("Lowercase a\u2013z", "use_lowercase")
        toggle_row("Digits 0\u20139", "use_digits")
        toggle_row("Symbols !@#$...", "use_symbols")
        toggle_row("Exclude Ambiguous", "exclude_ambiguous", "Removes O, 0, I, 1, l")

        pc_v.addSpacing(10)
        gen_btn = QPushButton("\u2728 Generate New Seed")
        gen_btn.setObjectName("PrimaryButton")
        gen_btn.setFixedHeight(48)
        gen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        gen_btn.clicked.connect(self._generate)
        pc_v.addWidget(gen_btn)

        left.addWidget(params_card)
        left.addItem(v_spacer())
        root.addLayout(left, 3)

        right = QVBoxLayout()
        harvest_card = Card()
        hc_v = QVBoxLayout(harvest_card)
        hc_v.setContentsMargins(22, 20, 22, 20)
        hc_title = QLabel("\U0001F33F RECENT HARVEST")
        hc_title.setObjectName("FieldLabel")
        hc_v.addWidget(hc_title)
        hc_v.addSpacing(10)
        self.harvest_list_layout = QVBoxLayout()
        self.harvest_list_layout.setSpacing(8)
        hc_v.addLayout(self.harvest_list_layout)
        self.harvest_empty_lbl = QLabel("Generate a seed\nto see history")
        self.harvest_empty_lbl.setObjectName("Muted")
        self.harvest_empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hc_v.addWidget(self.harvest_empty_lbl)
        hc_v.addItem(v_spacer())
        right.addWidget(harvest_card)
        root.addLayout(right, 1)

        self.current_password = ""

    def refresh(self):
        cfg = self.app_window.gen_config
        self.len_slider.blockSignals(True)
        self.len_slider.setValue(cfg.get("length", 20))
        self.len_slider.blockSignals(False)
        self.len_val_lbl.setText(str(cfg.get("length", 20)))
        for key, sw in self.toggle_widgets.items():
            sw.blockSignals(True)
            sw.setChecked(cfg.get(key, False))
            sw.blockSignals(False)
            sw.sync_visual()
        self._generate()

    def _on_length_changed(self, value):
        self.app_window.gen_config["length"] = value
        self.len_val_lbl.setText(str(value))
        self.app_window.save_gen_config()
        self._generate()

    def _on_toggle(self, key, checked):
        self.app_window.gen_config[key] = checked
        self.app_window.save_gen_config()
        self._generate()

    def _generate(self):
        cfg = self.app_window.gen_config
        pwd = generate_password(cfg)
        self.current_password = pwd
        self.result_lbl.setText(pwd)
        bits = estimate_entropy_bits(cfg)
        label, color_key = entropy_strength(bits)
        self.entropy_badge.setText(f"~{int(bits)} bits")
        self.entropy_badge.set_color_key(color_key)
        self.entropy_desc.setText(f"Estimated Entropy \u00B7 {label}")
        self._push_history(pwd)

    def _push_history(self, pwd):
        self.history.insert(0, pwd)
        self.history = self.history[:5]
        clear_layout(self.harvest_list_layout)
        self.harvest_empty_lbl.setVisible(len(self.history) == 0)
        for pwd_h in self.history:
            row = Card(flat=True)
            rh = QHBoxLayout(row)
            rh.setContentsMargins(10, 8, 10, 8)
            masked = pwd_h[:3] + "\u2022" * max(0, len(pwd_h) - 6) + pwd_h[-3:] if len(pwd_h) > 6 else pwd_h
            lbl = QLabel(masked)
            lbl.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
            rh.addWidget(lbl, 1)
            copy_btn = QPushButton("\U0001F4CB")
            copy_btn.setObjectName("IconButtonFlat")
            copy_btn.setFixedSize(26, 26)
            copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            copy_btn.clicked.connect(lambda checked, p=pwd_h: self.app_window.copy_with_autoclear(p, "Generated password"))
            rh.addWidget(copy_btn)
            self.harvest_list_layout.addWidget(row)

    def _copy_current(self):
        if self.current_password:
            self.app_window.copy_with_autoclear(self.current_password, "Generated password")


# =========================================================================== #
#  SETTINGS PAGE
# =========================================================================== #

class SettingsPage(QWidget):
    """Everything the user can configure, in four tabs: Appearance/Theme,
    Security (auto-lock + clipboard), Master Key (re-encrypt with a new
    password), and Data (CSV export/import + the "erase everything" danger
    zone). Tag management used to live here too - it's now its own page
    (TagsPage) since tags are everyday content, not a preference."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)

        title = QLabel("\u2699\uFE0F Settings")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        subtitle = QLabel("Customize your garden environment")
        subtitle.setObjectName("PageSubtitle")
        root.addWidget(subtitle)

        tabs_card = Card()
        tabs_h = QHBoxLayout(tabs_card)
        tabs_h.setContentsMargins(8, 8, 8, 8)
        tabs_h.setSpacing(4)
        self.tab_group = QButtonGroup(self)
        self.tab_group.setExclusive(True)
        self.tab_buttons = {}
        for key, label in [("ui", "\U0001F3A8 UI & Theme"), ("security", "\U0001F6E1 Security"),
                            ("masterkey", "\U0001F511 Master Key"), ("data", "\U0001F4BE Data")]:
            btn = QPushButton(label)
            btn.setObjectName("SettingsTab")
            btn.setCheckable(True)
            btn.setFixedHeight(40)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, k=key: self._switch_tab(k))
            self.tab_group.addButton(btn)
            self.tab_buttons[key] = btn
            tabs_h.addWidget(btn, 1)
        root.addWidget(tabs_card)

        self.stack = QStackedWidget()
        self.pages = {
            "ui": self._build_ui_tab(),
            "security": self._build_security_tab(),
            "masterkey": self._build_masterkey_tab(),
            "data": self._build_data_tab(),
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        root.addWidget(self.stack, 1)

        self.current_tab = "ui"

    # ------------------------------ UI & THEME TAB ------------------------------ #
    def _build_ui_tab(self):
        card = Card()
        v = QVBoxLayout(card)
        v.setContentsMargins(26, 24, 26, 24)
        v.setSpacing(10)

        mode_title = QLabel("\U0001F313 Appearance")
        mode_title.setObjectName("SectionTitle")
        v.addWidget(mode_title)
        v.addSpacing(6)
        mode_row = QHBoxLayout()
        mode_row.setSpacing(12)
        self.mode_group = QButtonGroup(self)
        self.mode_group.setExclusive(True)
        self.dark_mode_btn = QPushButton("\U0001F319  Dark")
        self.dark_mode_btn.setObjectName("SizeCard")
        self.dark_mode_btn.setCheckable(True)
        self.dark_mode_btn.setFixedHeight(48)
        self.dark_mode_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.dark_mode_btn.clicked.connect(self._activate_dark_mode)
        self.light_mode_btn = QPushButton("\u2600\uFE0F  Light")
        self.light_mode_btn.setObjectName("SizeCard")
        self.light_mode_btn.setCheckable(True)
        self.light_mode_btn.setFixedHeight(48)
        self.light_mode_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.light_mode_btn.clicked.connect(lambda: self.app_window.apply_theme("Light"))
        self.mode_group.addButton(self.dark_mode_btn)
        self.mode_group.addButton(self.light_mode_btn)
        mode_row.addWidget(self.dark_mode_btn, 1)
        mode_row.addWidget(self.light_mode_btn, 1)
        v.addLayout(mode_row)
        v.addSpacing(18)

        theme_title = QLabel("\U0001F3A8 Accent Color")
        theme_title.setObjectName("SectionTitle")
        v.addWidget(theme_title)
        v.addSpacing(6)

        theme_grid = QGridLayout()
        theme_grid.setSpacing(14)
        self.theme_group = QButtonGroup(self)
        self.theme_group.setExclusive(True)
        self.theme_buttons = {}
        for i, name in enumerate(DARK_THEME_ORDER):
            pal = THEMES[name]
            btn = QPushButton()
            btn.setObjectName("ThemeCard")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setFixedHeight(96)
            bl = QVBoxLayout(btn)
            bl.setContentsMargins(6, 6, 6, 6)
            swatch = QFrame()
            swatch.setFixedHeight(46)
            swatch.setStyleSheet(
                f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {pal['bg']}, stop:1 {pal['surface']}); "
                f"border-radius: 10px;"
            )
            swatch_l = QVBoxLayout(swatch)
            swatch_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            dot = QLabel()
            dot.setFixedSize(22, 22)
            dot.setStyleSheet(f"background-color:{pal['primary']}; border-radius:11px; border: 2px solid white;")
            swatch_l.addWidget(dot)
            bl.addWidget(swatch)
            name_lbl = QLabel(name)
            name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_lbl.setStyleSheet("font-weight: 700; font-size: 12px; margin-top: 4px;")
            bl.addWidget(name_lbl)
            btn.clicked.connect(lambda checked, n=name: self.app_window.apply_theme(n))
            self.theme_group.addButton(btn)
            self.theme_buttons[name] = btn
            theme_grid.addWidget(btn, i // 5, i % 5)
        v.addLayout(theme_grid)
        v.addSpacing(18)

        font_title = QLabel("Aa Font Size")
        font_title.setObjectName("SectionTitle")
        v.addWidget(font_title)
        v.addSpacing(6)
        font_row = QHBoxLayout()
        font_row.setSpacing(12)
        self.font_group = QButtonGroup(self)
        self.font_group.setExclusive(True)
        self.font_buttons = {}
        for size_name in ["Small", "Medium", "Large", "X-Large"]:
            btn = QPushButton(f"Aa\n{size_name}")
            btn.setObjectName("SizeCard")
            btn.setCheckable(True)
            btn.setFixedHeight(70)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, s=size_name: self.app_window.apply_font_size(s))
            self.font_group.addButton(btn)
            self.font_buttons[size_name] = btn
            font_row.addWidget(btn, 1)
        v.addLayout(font_row)
        v.addSpacing(18)

        # --- Which page greets the user right after unlocking. -------------
        page_title = QLabel("\U0001F3E0 Default Page on Unlock")
        page_title.setObjectName("SectionTitle")
        v.addWidget(page_title)
        v.addSpacing(6)
        self.default_page_combo = QComboBox()
        self.default_page_combo.addItem("Dashboard", "dashboard")
        self.default_page_combo.addItem("Vault", "vault")
        self.default_page_combo.addItem("Generator", "generator")
        self.default_page_combo.setFixedHeight(42)
        self.default_page_combo.currentIndexChanged.connect(self._on_default_page_changed)
        v.addWidget(self.default_page_combo)
        v.addItem(v_spacer())
        return card

    def _activate_dark_mode(self):
        """The Dark button doesn't pick one specific palette - it restores
        whichever dark accent color the user had selected last."""
        self.app_window.apply_theme(self.app_window.prefs.get("last_dark_theme", "Midnight"))

    def _on_default_page_changed(self, index):
        value = self.default_page_combo.itemData(index)
        if value:
            self.app_window.prefs["default_page"] = value
            self.app_window.save_prefs()

    # ------------------------------ SECURITY TAB ------------------------------ #
    def _build_security_tab(self):
        card = Card()
        v = QVBoxLayout(card)
        v.setContentsMargins(26, 24, 26, 24)
        v.setSpacing(4)
        title = QLabel("Security Settings")
        title.setObjectName("SectionTitle")
        v.addWidget(title)
        v.addSpacing(10)

        def row_with_toggle(label, sub, initial, on_toggle):
            row = QHBoxLayout()
            col = QVBoxLayout()
            col.setSpacing(2)
            l = QLabel(label)
            l.setStyleSheet("font-weight: 700;")
            col.addWidget(l)
            s = QLabel(sub)
            s.setObjectName("Muted")
            s.setWordWrap(True)
            col.addWidget(s)
            row.addLayout(col, 1)
            sw = ToggleSwitch()
            sw.setChecked(initial)
            sw.toggled.connect(on_toggle)
            row.addWidget(sw)
            v.addLayout(row)
            v.addSpacing(14)
            return sw

        prefs = self.app_window.prefs
        self.autolock_sw = row_with_toggle(
            "Auto-lock Vault", "Automatically lock after a period of inactivity",
            prefs.get("auto_lock_enabled", True), self._on_autolock_toggle)

        v.addWidget(QLabel("Auto-lock Timeout"))
        timeout_row = QHBoxLayout()
        self.timeout_slider = QSlider(Qt.Orientation.Horizontal)
        self.timeout_slider.setRange(1, 60)
        self.timeout_slider.setValue(prefs.get("auto_lock_timeout_min", 15))
        self.timeout_slider.valueChanged.connect(self._on_timeout_changed)
        timeout_row.addWidget(self.timeout_slider, 1)
        self.timeout_lbl = QLabel(f"{prefs.get('auto_lock_timeout_min', 15)} min")
        self.timeout_lbl.setStyleSheet(f"color:{Palette.get('primary')}; font-weight: 700;")
        timeout_row.addWidget(self.timeout_lbl)
        v.addLayout(timeout_row)
        v.addSpacing(18)

        self.clipclear_sw = row_with_toggle(
            "Clipboard Auto-clear", "Automatically clear passwords copied to clipboard",
            prefs.get("clipboard_auto_clear", True), self._on_clipclear_toggle)

        v.addWidget(QLabel("Clipboard Clear Delay"))
        delay_row = QHBoxLayout()
        self.delay_slider = QSlider(Qt.Orientation.Horizontal)
        self.delay_slider.setRange(5, 120)
        self.delay_slider.setValue(prefs.get("clipboard_clear_delay_sec", 30))
        self.delay_slider.valueChanged.connect(self._on_delay_changed)
        delay_row.addWidget(self.delay_slider, 1)
        self.delay_lbl = QLabel(f"{prefs.get('clipboard_clear_delay_sec', 30)} sec")
        self.delay_lbl.setStyleSheet(f"color:{Palette.get('primary')}; font-weight: 700;")
        delay_row.addWidget(self.delay_lbl)
        v.addLayout(delay_row)
        v.addItem(v_spacer())
        return card

    def _on_autolock_toggle(self, checked):
        self.app_window.prefs["auto_lock_enabled"] = checked
        self.app_window.save_prefs()

    def _on_timeout_changed(self, value):
        self.app_window.prefs["auto_lock_timeout_min"] = value
        self.timeout_lbl.setText(f"{value} min")
        self.app_window.save_prefs()

    def _on_clipclear_toggle(self, checked):
        self.app_window.prefs["clipboard_auto_clear"] = checked
        self.app_window.save_prefs()

    def _on_delay_changed(self, value):
        self.app_window.prefs["clipboard_clear_delay_sec"] = value
        self.delay_lbl.setText(f"{value} sec")
        self.app_window.save_prefs()

    # ------------------------------ MASTER KEY TAB ------------------------------ #
    def _build_masterkey_tab(self):
        card = Card()
        v = QVBoxLayout(card)
        v.setContentsMargins(26, 24, 26, 24)
        v.setSpacing(6)
        title = QLabel("Re-encrypt Database")
        title.setObjectName("SectionTitle")
        v.addWidget(title)
        desc = QLabel("Change your master key. All vault entries will be re-encrypted using the new "
                       "password. Your current session remains active.")
        desc.setObjectName("Muted")
        desc.setWordWrap(True)
        v.addWidget(desc)
        v.addSpacing(18)

        v.addWidget(self._field_label("NEW MASTER KEY"))
        self.new_key_field = PasswordField(placeholder="Enter new master password...")
        v.addWidget(self.new_key_field)
        v.addSpacing(12)

        v.addWidget(self._field_label("CONFIRM NEW KEY"))
        self.confirm_key_edit = QLineEdit()
        self.confirm_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_key_edit.setPlaceholderText("Confirm new master password...")
        self.confirm_key_edit.setFixedHeight(46)
        v.addWidget(self.confirm_key_edit)
        v.addSpacing(18)

        reencrypt_btn = QPushButton("\U0001F512 Re-encrypt Database")
        reencrypt_btn.setObjectName("PrimaryButton")
        reencrypt_btn.setFixedHeight(48)
        reencrypt_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reencrypt_btn.clicked.connect(self._reencrypt)
        v.addWidget(reencrypt_btn)
        v.addItem(v_spacer())
        return card

    def _field_label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("FieldLabel")
        return lbl

    def _reencrypt(self):
        new_pwd = self.new_key_field.text().strip()
        confirm_pwd = self.confirm_key_edit.text().strip()
        if len(new_pwd) < 6:
            warn(self, "Weak Key", "New master key must be at least 6 characters.")
            return
        if new_pwd != confirm_pwd:
            warn(self, "Mismatch", "The two keys do not match.")
            return
        if not confirm(self, "Re-encrypt Database",
                        "This will re-encrypt your entire vault with the new master key. Continue?"):
            return
        current_data = load_garden_vault(self.app_window.session_key)
        new_key = initialize_garden_key(new_pwd)
        save_garden_vault(current_data, new_key)
        self.app_window.session_key = new_key
        self.new_key_field.setText("")
        self.confirm_key_edit.setText("")
        info(self, "Success", "Vault re-encrypted with new master key.")

    # ------------------------------ DATA TAB ------------------------------ #
    def _build_data_tab(self):
        card = Card()
        v = QVBoxLayout(card)
        v.setContentsMargins(26, 24, 26, 24)
        v.setSpacing(6)
        title = QLabel("Data Management")
        title.setObjectName("SectionTitle")
        v.addWidget(title)
        desc = QLabel("Export a backup of your vault or import from a previous backup. "
                       "The live vault file is AES/Fernet encrypted at rest.")
        desc.setObjectName("Muted")
        desc.setWordWrap(True)
        v.addWidget(desc)
        v.addSpacing(18)

        io_row = QHBoxLayout()
        io_row.setSpacing(16)

        export_card = Card(flat=True)
        export_card.setCursor(Qt.CursorShape.PointingHandCursor)
        ev = QVBoxLayout(export_card)
        ev.setContentsMargins(20, 24, 20, 24)
        ev.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic1 = QLabel("\U0001F4E4")
        ic1.setStyleSheet("font-size: 26px;")
        ic1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(ic1)
        t1 = QLabel("Export CSV")
        t1.setStyleSheet(f"font-weight: 800; color:{Palette.get('primary')};")
        t1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(t1)
        s1 = QLabel("Download vault backup")
        s1.setObjectName("Muted")
        s1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ev.addWidget(s1)
        export_card.mousePressEvent = lambda event: self._export_csv()
        io_row.addWidget(export_card, 1)

        import_card = Card(flat=True)
        import_card.setCursor(Qt.CursorShape.PointingHandCursor)
        iv = QVBoxLayout(import_card)
        iv.setContentsMargins(20, 24, 20, 24)
        iv.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic2 = QLabel("\U0001F4E5")
        ic2.setStyleSheet("font-size: 26px;")
        ic2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        iv.addWidget(ic2)
        t2 = QLabel("Import CSV")
        t2.setStyleSheet(f"font-weight: 800; color:{Palette.get('secondary')};")
        t2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        iv.addWidget(t2)
        s2 = QLabel("Restore from a backup file")
        s2.setObjectName("Muted")
        s2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        iv.addWidget(s2)
        import_card.mousePressEvent = lambda event: self._import_csv()
        io_row.addWidget(import_card, 1)

        v.addLayout(io_row)
        v.addSpacing(20)

        danger = QFrame()
        danger.setObjectName("DangerZone")
        dv = QVBoxLayout(danger)
        dv.setContentsMargins(20, 18, 20, 18)
        dtitle = QLabel("\u26A0 Danger Zone")
        dtitle.setStyleSheet(f"color:{Palette.get('red')}; font-weight: 800; font-size: 14px;")
        dv.addWidget(dtitle)
        ddesc = QLabel("Permanently delete all vault entries. This action cannot be undone "
                        "and all entries will be lost.")
        ddesc.setObjectName("Muted")
        ddesc.setWordWrap(True)
        dv.addWidget(ddesc)
        dv.addSpacing(10)
        clear_btn = QPushButton("\U0001F5D1 Clear All Data")
        clear_btn.setObjectName("DangerSolidButton")
        clear_btn.setFixedHeight(40)
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_all_data)
        dv.addWidget(clear_btn, 0, Qt.AlignmentFlag.AlignLeft)
        v.addWidget(danger)
        v.addItem(v_spacer())
        return card

    def _export_csv(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Vault", "garden_backup.csv", "CSV Files (*.csv)")
        if not file_path:
            return
        vault_data = load_garden_vault(self.app_window.session_key)
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Name", "URL", "Username", "Password", "Tags", "Notes", "Favorite",
                                  "Created At", "Updated At"])
                for e in vault_data.get("entries", {}).values():
                    writer.writerow([
                        e.get("name", ""), e.get("url", ""), e.get("username", ""), e.get("password", ""),
                        ",".join(e.get("tags", [])), e.get("notes", ""), e.get("favorite", False),
                        e.get("created_at", ""), e.get("updated_at", ""),
                    ])
            info(self, "Exported", "Vault exported to CSV successfully.")
        except Exception as e:
            error(self, "Export Failed", str(e))

    def _import_csv(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Vault", "", "CSV Files (*.csv)")
        if not file_path:
            return
        vault_data = load_garden_vault(self.app_window.session_key)
        now_str = datetime.now().isoformat()
        count = 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 4 and row[0].strip():
                        name = row[0].strip()
                        url = row[1] if len(row) > 1 else ""
                        user = row[2] if len(row) > 2 else ""
                        pwd = row[3] if len(row) > 3 else ""
                        tags = [t.strip().lower() for t in row[4].split(",")] if len(row) > 4 and row[4].strip() else []
                        notes = row[5] if len(row) > 5 else ""
                        favorite = row[6].strip().lower() in ("true", "1", "yes") if len(row) > 6 else False
                        eid = uuid.uuid4().hex
                        vault_data["entries"][eid] = {
                            "name": name, "url": url, "username": user, "password": pwd,
                            "tags": [t for t in tags if t], "notes": notes, "favorite": favorite,
                            "created_at": now_str, "updated_at": now_str,
                        }
                        count += 1
            save_garden_vault(vault_data, self.app_window.session_key)
            info(self, "Imported", f"Successfully imported {count} entries into the vault.")
            self.app_window.refresh_current_page()
        except Exception as e:
            error(self, "Import Failed", str(e))

    def _clear_all_data(self):
        if not confirm(self, "Clear All Data",
                        "This will permanently delete every entry in your vault. This cannot be undone. Continue?"):
            return
        data = {"entries": {}}
        save_garden_vault(data, self.app_window.session_key)
        info(self, "Vault Cleared", "All vault entries have been deleted.")
        self.app_window.refresh_current_page()

    def _switch_tab(self, key):
        self.current_tab = key
        self.stack.setCurrentWidget(self.pages[key])

    def refresh(self):
        for key, btn in self.tab_buttons.items():
            btn.setChecked(key == self.current_tab)
        current_theme = self.app_window.prefs.get("theme", "Midnight")
        is_light = THEMES.get(current_theme, THEMES["Midnight"])["light"]
        self.dark_mode_btn.setChecked(not is_light)
        self.light_mode_btn.setChecked(is_light)
        for name, btn in self.theme_buttons.items():
            btn.setChecked(name == current_theme)
        for name, btn in self.font_buttons.items():
            btn.setChecked(name == self.app_window.prefs.get("font_size", "Medium"))
        current_default_page = self.app_window.prefs.get("default_page", "dashboard")
        idx = self.default_page_combo.findData(current_default_page)
        if idx >= 0:
            self.default_page_combo.blockSignals(True)
            self.default_page_combo.setCurrentIndex(idx)
            self.default_page_combo.blockSignals(False)


# =========================================================================== #
#  TUTORIAL PAGE  &  LICENSE PAGE 
# =========================================================================== #

TUTORIAL_STEPS = [
    ("\U0001F331", "Step 1", "The Garden Metaphor",
     "Magical Garden uses botanical terms for your credentials. Your whole password collection is a "
     "Garden, and each saved login is an Entry \u2014 the seed of your digital access."),
    ("\U0001F3F7\uFE0F", "Step 2", "Tags, Not Folders",
     "Instead of rigid categories, every entry can carry any number of free-form tags (work, dev, "
     "personal...). Filter the Vault by tag, and rename or delete tags globally from Settings \u2192 Tags."),
    ("\U0001F338", "Step 3", "The Vault Workspace",
     "The Vault lists every entry with its strength badge and tags. Search, filter by tag, star your "
     "favorites, and use the pencil, copy, and trash icons on each card to edit, copy, or remove it."),
    ("\U0001F339", "Step 4", "Strength & Petal Bloom",
     "Every password gets a live strength meter \u2014 from red (Weak) through amber (Fair) and blue "
     "(Good) to green (Strong) \u2014 both while typing in the Add/Edit dialog and on each Vault card."),
    ("\u26A1", "Step 5", "Seed Generator",
     "The Generator creates cryptographically random passwords using Python's 'secrets' module (a "
     "CSPRNG). Adjust length (8\u201364 chars), toggle character sets, and exclude ambiguous characters."),
    ("\U0001F4CA", "Step 6", "Dashboard Insights",
     "The Dashboard shows your overall Security Score plus a strength breakdown. Click any bucket, or "
     "the reused-passwords notice, to see exactly which entries need attention."),
    ("\U0001F511", "Step 7", "Master Key Security",
     "Your Master Key unlocks everything and is never stored \u2014 only a PBKDF2-HMAC-SHA256 hash "
     "(600,000 iterations) lives locally. If sunlight.key is ever lost or deleted, the vault cannot be "
     "recovered by design; there is no backdoor."),
]

LICENSE_TEXT = (
    "Magical Garden v2.1.0\n\n"
    "This application is provided for personal password management purposes. It runs entirely offline: "
    "no analytics, no network calls, and no external services are contacted at any point.\n\n"
    "Your master password is never written to disk. Only a salted PBKDF2-HMAC-SHA256 derivation (600,000 "
    "iterations) is used to unlock a Fernet (AES-128-CBC + HMAC-SHA256) encrypted vault file stored next "
    "to this program.\n\n"

    "By design there is no password-recovery backdoor: if sunlight.key is lost, deleted, or corrupted, "
    "the existing garden.enc vault cannot be decrypted by simply setting a new password. The application "
    "will instead require an explicit, typed confirmation before an old vault can be erased and a new "
    "one created.\n\n"
    "You are responsible for backing up garden.enc and sunlight.key together, and for remembering your "
    "Master Key.\n\n"

    "THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT" 
    "NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND"
    "NONINFRINGEMENT." 
    "IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY"
    "CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,"
    "ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN"
    "THE SOFTWARE.\n\n"

    "Copyright (c) 2026 Vinayak Burgess\n\n"
    "Bridging the gap between secure systems and aesthetic design."
)


class TutorialPage(QWidget):
    """A static, scrollable walkthrough (TUTORIAL_STEPS below) explaining the
    app's vocabulary and how the security model works. No live data, no
    state - refresh() is a no-op."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)
        title = QLabel("\U0001F4D6 Tutorial")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        sub = QLabel("Learn how Magical Garden keeps your passwords safe")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)
        root.addSpacing(6)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.setSpacing(12)
        for icon, step, t, body in TUTORIAL_STEPS:
            card = Card(flat=True)
            cv = QHBoxLayout(card)
            cv.setContentsMargins(18, 16, 18, 16)
            cv.setSpacing(16)
            ic = QLabel(icon)
            ic.setStyleSheet("font-size: 22px;")
            ic.setFixedSize(40, 40)
            ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cv.addWidget(ic)
            col = QVBoxLayout()
            col.setSpacing(4)
            hr = QHBoxLayout()
            hr.addWidget(Badge(step, "primary"))
            hl_lbl = QLabel(t)
            hl_lbl.setStyleSheet("font-weight: 800; font-size: 14px;")
            hr.addWidget(hl_lbl)
            hr.addItem(h_spacer())
            col.addLayout(hr)
            body_lbl = QLabel(body)
            body_lbl.setWordWrap(True)
            body_lbl.setObjectName("Muted")
            col.addWidget(body_lbl)
            cv.addLayout(col, 1)
            hl.addWidget(card)
        hl.addItem(v_spacer())
        scroll.setWidget(holder)
        root.addWidget(scroll, 1)

    def refresh(self):
        pass


class LicensePage(QWidget):
    """Static legal/data-handling text (LICENSE_TEXT below). No live data,
    no state - refresh() is a no-op."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)
        title = QLabel("\U0001F4C4 License")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        sub = QLabel("Legal information and data-handling policy")
        sub.setObjectName("PageSubtitle")
        root.addWidget(sub)
        root.addSpacing(6)

        card = Card()
        cv = QVBoxLayout(card)
        cv.setContentsMargins(26, 24, 26, 24)
        lbl = QLabel(LICENSE_TEXT)
        lbl.setWordWrap(True)
        lbl.setObjectName("Muted")
        cv.addWidget(lbl)
        root.addWidget(card)
        root.addItem(v_spacer())

    def refresh(self):
        pass


# =========================================================================== #
#  MAIN APPLICATION SHELL & WINDOW
# =========================================================================== #

class MainAppShell(QWidget):
    """Sidebar + routed content. Rebuilt fresh on every theme change so that
    every single widget always reflects the currently active Palette."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        self.sidebar = Sidebar(app_window)
        h.addWidget(self.sidebar)

        content_wrap = QWidget()
        cv = QVBoxLayout(content_wrap)
        cv.setContentsMargins(30, 26, 30, 26)

        self.stack = QStackedWidget()
        self.pages = {
            "dashboard": DashboardPage(app_window),
            "vault": VaultPage(app_window),
            "tags": TagsPage(app_window),
            "generator": GeneratorPage(app_window),
            "settings": SettingsPage(app_window),
            "tutorial": TutorialPage(app_window),
            "license": LicensePage(app_window),
        }
        for p in self.pages.values():
            self.stack.addWidget(p)
        cv.addWidget(self.stack)
        h.addWidget(content_wrap, 1)

    def navigate(self, key):
        self.sidebar.set_active(key)
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        page.refresh()


class MagicalGardenApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.prefs = load_json(PREFERENCES_FILE, DEFAULT_PREFERENCES)
        self.gen_config = load_json(GENERATOR_CONFIG_FILE, DEFAULT_GEN_CONFIG)

        self.session_key = None
        self.last_activity_time = time.time()
        self.current_route = "dashboard"
        self.pending_vault_tag = None
        self.pending_vault_search = None

        self.setWindowTitle("Magical Garden \u2014 v2.1.0")
        self.resize(1440, 880)
        self.setMinimumSize(1080, 680)

        self.central = QStackedWidget()
        self.central.setObjectName("Root")
        self.setCentralWidget(self.central)

        self.auth_page = AuthPage(self)
        self.central.addWidget(self.auth_page)

        self.shell = None  # built lazily after first unlock

        # Floats on top of self.central regardless of which page is active -
        # see copy_with_autoclear() below for why this exists.
        self._toast = Toast(self.central)

        self.apply_theme(self.prefs.get("theme", "Midnight"), first_load=True)
        self.apply_font_size(self.prefs.get("font_size", "Medium"), first_load=True)

        self.central.setCurrentWidget(self.auth_page)
        self.auth_page.refresh()

        # Inactivity + auto-lock loop
        QApplication.instance().installEventFilter(self)
        self.lock_timer = QTimer(self)
        self.lock_timer.timeout.connect(self._check_auto_lock)
        self.lock_timer.start(AUTO_LOCK_POLL_MS)

        # Debounced background saves - see save_prefs()/save_gen_config() below
        # for why these exist (short version: a Windows crash from writing
        # the same tiny file dozens of times a second while dragging a
        # slider). Both timers are single-shot and simply (re)start on every
        # call, so only the LAST change in a burst actually hits disk.
        self._prefs_save_timer = QTimer(self)
        self._prefs_save_timer.setSingleShot(True)
        self._prefs_save_timer.timeout.connect(lambda: save_json(PREFERENCES_FILE, self.prefs))
        self._gen_save_timer = QTimer(self)
        self._gen_save_timer.setSingleShot(True)
        self._gen_save_timer.timeout.connect(lambda: save_json(GENERATOR_CONFIG_FILE, self.gen_config))

    # ------------------------------ THEME / FONT ------------------------------ #

    def _current_scale(self):
        return FONT_SCALES.get(self.prefs.get("font_size", "Medium"), 1.0)

    def apply_theme(self, name, first_load=False):
        """Switch the active palette. Also remembers the last DARK accent
        chosen (Midnight/Aurora/Crimson/Ocean/Forest) separately from the
        current theme, so toggling Light -> Dark in Settings restores
        whichever accent you had before, instead of always resetting to
        Midnight."""
        if name not in THEMES:
            name = "Midnight"
        self.prefs["theme"] = name
        if not THEMES[name]["light"]:
            self.prefs["last_dark_theme"] = name
        Palette.data = THEMES[name]
        QApplication.instance().setStyleSheet(build_stylesheet(THEMES[name], scale=self._current_scale()))
        if not first_load:
            self.save_prefs()
            if self.session_key is not None:
                self._rebuild_shell()

    def apply_font_size(self, size_name, first_load=False):
        if size_name not in FONT_SIZES:
            size_name = "Medium"
        self.prefs["font_size"] = size_name
        font = QFont("Segoe UI", FONT_SIZES[size_name])
        QApplication.instance().setFont(font)
        theme_name = self.prefs.get("theme", "Midnight")
        QApplication.instance().setStyleSheet(build_stylesheet(THEMES[theme_name], scale=self._current_scale()))
        if not first_load:
            self.save_prefs()
            if self.session_key is not None:
                self._rebuild_shell()

    def save_prefs(self):
        self._prefs_save_timer.start(AUTO_SAVE_DEBOUNCE_MS)

    def save_gen_config(self):
        """See save_prefs() above - same debounce, for the Generator's own
        settings file (used while dragging the password-length slider)."""
        self._gen_save_timer.start(AUTO_SAVE_DEBOUNCE_MS)

    # ------------------------------ AUTH / SESSION ------------------------------ #

    def on_unlocked(self, key):
        self.session_key = key
        self.last_activity_time = time.time()
        self.prefs["last_unlocked_iso"] = datetime.now().isoformat()
        self.save_prefs()
        # Respect the user's "Default Page on Unlock" choice from Settings.
        self.current_route = self.prefs.get("default_page", "dashboard")
        self._rebuild_shell()

    def _rebuild_shell(self):
        old_shell = self.shell
        self.shell = MainAppShell(self)
        self.central.addWidget(self.shell)
        self.central.setCurrentWidget(self.shell)
        if old_shell is not None:
            self.central.removeWidget(old_shell)
            old_shell.deleteLater()
        self.shell.navigate(self.current_route)

    def lock_vault(self):
        self.session_key = None
        if self.prefs.get("clipboard_auto_clear", True):
            QApplication.clipboard().clear()
        self.current_route = "dashboard"
        self.central.setCurrentWidget(self.auth_page)
        self.auth_page.refresh()

    def navigate(self, key):
        self.current_route = key
        if self.shell:
            self.shell.navigate(key)

    def refresh_current_page(self):
        if self.shell:
            self.shell.navigate(self.current_route)

    # ------------------------------ CLIPBOARD ------------------------------ #

    def copy_with_autoclear(self, text, label):
        if not text:
            return
        copy_to_clipboard_privately(text)
        if self.prefs.get("clipboard_auto_clear", True):
            delay_sec = int(self.prefs.get("clipboard_clear_delay_sec", 30))
            QTimer.singleShot(delay_sec * 1000, lambda t=text: self._clear_clipboard_if_unchanged(t))
            self.show_toast(f"\U0001F4CB {label} copied \u2014 clipboard clears in {delay_sec}s")
        else:
            self.show_toast(f"\U0001F4CB {label} copied")

    def show_toast(self, message):
        self._toast.show_message(message)

    def _clear_clipboard_if_unchanged(self, text):
        cb = QApplication.clipboard()
        if cb.text() == text:
            cb.clear()

    # ------------------------------ AUTO-LOCK ------------------------------ #

    def eventFilter(self, obj, event):
        if event.type() in (event.Type.MouseMove, event.Type.MouseButtonPress,
                             event.Type.KeyPress, event.Type.Wheel):
            self.last_activity_time = time.time()
        return super().eventFilter(obj, event)

    def _check_auto_lock(self):
        if self.session_key and self.prefs.get("auto_lock_enabled", True):
            timeout_sec = int(self.prefs.get("auto_lock_timeout_min", 15)) * 60
            if time.time() - self.last_activity_time > timeout_sec:
                self.lock_vault()
                info(self, "Vault Locked", "Locked automatically due to inactivity.")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._toast.isVisible():
            self._toast.show_message(self._toast.text(), duration_ms=self._toast._timer.remainingTime())

    def closeEvent(self, event):
        # Flush any pending debounced saves immediately instead of letting
        # them get lost if the app closes mid-debounce-window (e.g. the user
        # quits within ~250ms of moving a settings slider).
        if self._prefs_save_timer.isActive():
            self._prefs_save_timer.stop()
            save_json(PREFERENCES_FILE, self.prefs)
        if self._gen_save_timer.isActive():
            self._gen_save_timer.stop()
            save_json(GENERATOR_CONFIG_FILE, self.gen_config)
        if self.prefs.get("clipboard_auto_clear", True):
            QApplication.clipboard().clear()
        event.accept()


# =========================================================================== #
#  ENTRY POINT
# =========================================================================== #

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Magical Garden")
    window = MagicalGardenApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
