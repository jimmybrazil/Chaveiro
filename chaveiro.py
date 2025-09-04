#!/usr/bin/env python3
# Chaveiro — Gerenciador de Senhas
# Desenvolvido por Thiago Freitas

import os
import sys
import sqlite3
import secrets
import string
import base64
import hmac
import io
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Ícone: vamos gerar um PNG moderno em azul-prussiano usando Pillow
try:
    from PIL import Image, ImageDraw, ImageFilter
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


APP_NAME = "ChaveiroTF"

# Paleta
PRUSSIAN = "#003153"        # azul prussiano
PRUSSIAN_2 = "#0B3C5D"      # variação
ACCENT = PRUSSIAN
ACCENT_HOVER = "#0B4A73"
DANGER = "#e76f51"
DANGER_HOVER = "#d4553b"
MUTED = "#444444"
MUTED_HOVER = "#333333"


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_app_dir():
    home = str(Path.home())
    if sys.platform == "win32":
        base = os.getenv("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return os.path.join(base, APP_NAME)
    elif sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
        return os.path.join(base, APP_NAME)
    else:
        base = os.path.join(home, ".local", "share")
        return os.path.join(base, APP_NAME.lower())


def get_assets_dir():
    return os.path.join(get_app_dir(), "assets")


def resource_path(rel_path):
    # Compatibilidade com PyInstaller
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, rel_path)


def _hex_to_rgb(h):
    h = h.strip().lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _blend_rgb(c1, c2, t):
    return tuple(int(c1[i] * (1 - t) + c2[i] * t) for i in range(3))


def generate_prussian_icon(path, size=512):
    if not PIL_AVAILABLE:
        return False
    size = int(size)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    c_top = _hex_to_rgb(PRUSSIAN_2)
    c_bot = _hex_to_rgb(PRUSSIAN)

    # Fundo em gradiente
    bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bg_draw = ImageDraw.Draw(bg)
    for y in range(size):
        t = y / (size - 1)
        col = _blend_rgb(c_top, c_bot, t)
        bg_draw.line((0, y, size, y), fill=(col[0], col[1], col[2], 255))

    # Máscara arredondada para o fundo
    mask = Image.new("L", (size, size), 0)
    mask_draw = ImageDraw.Draw(mask)
    radius = int(size * 0.22)
    mask_draw.rounded_rectangle((0, 0, size, size), radius=radius, fill=255)

    # Sombra do fundo
    shadow_mask = mask.filter(ImageFilter.GaussianBlur(radius=int(size * 0.035)))
    shadow = Image.new("RGBA", (size, size), (0, 0, 0, 90))
    shadow_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    shadow_img.paste(shadow, (0, int(size * 0.018)), shadow_mask)

    rounded_bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    rounded_bg.paste(bg, (0, 0), mask)

    base = Image.alpha_composite(shadow_img, rounded_bg)

    d = ImageDraw.Draw(base)

    # Corpo do cadeado (branco com cantos arredondados)
    body_w = int(size * 0.5)
    body_h = int(size * 0.36)
    body_x0 = int((size - body_w) / 2)
    body_y0 = int(size * 0.42)
    body_x1 = body_x0 + body_w
    body_y1 = body_y0 + body_h
    body_radius = int(size * 0.065)
    d.rounded_rectangle((body_x0, body_y0, body_x1, body_y1),
                        radius=body_radius, fill=(255, 255, 255, 248))

    # Alça (arco)
    arc_x0 = int(size * 0.32)
    arc_y0 = int(size * 0.25)
    arc_x1 = int(size * 0.68)
    arc_y1 = int(size * 0.62)
    arc_width = int(size * 0.075)
    d.arc((arc_x0, arc_y0, arc_x1, arc_y1),
          start=210, end=-30, fill=(255, 255, 255, 255), width=arc_width)

    # Fechadura (olho e haste)
    cx = size // 2
    cy = int(body_y0 + body_h * 0.52)
    r = int(size * 0.05)
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=_hex_to_rgb(PRUSSIAN))

    stem_w = int(size * 0.065)
    stem_h = int(size * 0.16)
    stem_radius = int(stem_w * 0.35)
    d.rounded_rectangle((cx - stem_w // 2, cy, cx + stem_w // 2, cy + stem_h),
                        radius=stem_radius, fill=_hex_to_rgb(PRUSSIAN))

    # Brilho sutil
    gloss = Image.new("RGBA", (size, size), (255, 255, 255, 0))
    gd = ImageDraw.Draw(gloss)
    gd.polygon([
        (int(size * 0.10), int(size * 0.35)),
        (int(size * 0.25), int(size * 0.12)),
        (int(size * 0.62), int(size * 0.09)),
        (int(size * 0.90), int(size * 0.22)),
        (int(size * 0.86), int(size * 0.28)),
        (int(size * 0.60), int(size * 0.30)),
        (int(size * 0.25), int(size * 0.40)),
        (int(size * 0.10), int(size * 0.38)),
    ], fill=(255, 255, 255, 22))
    gloss = gloss.filter(ImageFilter.GaussianBlur(radius=int(size * 0.015)))

    final_img = Image.alpha_composite(base, gloss)
    final_img.save(path, format="PNG")
    return True


def ensure_assets():
    """Gera e retorna o caminho do ícone PNG (azul-prussiano)."""
    assets_dir = get_assets_dir()
    os.makedirs(assets_dir, exist_ok=True)
    icon_path = os.path.join(assets_dir, "chaveiro.png")

    if not os.path.exists(icon_path):
        try:
            ok = generate_prussian_icon(icon_path, size=512)
            if not ok:
                # fallback: cria um PNG 1x1 azul-prussiano
                if PIL_AVAILABLE:
                    Image.new("RGBA", (1, 1), _hex_to_rgb(PRUSSIAN)).save(icon_path, format="PNG")
                else:
                    # PNG 1x1 azul #003153 em base64 (caso extremo sem Pillow)
                    tiny_png_b64 = (
                        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMA"
                        "ASsJTYQAAAAASUVORK5CYII="
                    )
                    with open(icon_path, "wb") as f:
                        f.write(base64.b64decode(tiny_png_b64))
        except Exception:
            pass

    return icon_path


class Vault:
    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._fernet = None
        self.initialize_db()

    def initialize_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            """)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password_enc BLOB NOT NULL,
                    notes_enc BLOB,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

    def is_initialized(self):
        cur = self.conn.execute("SELECT value FROM meta WHERE key='master_hash'")
        return cur.fetchone() is not None

    def set_meta_blob(self, key, blob):
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, blob))

    def set_meta_text(self, key, text):
        self.set_meta_blob(key, text.encode("utf-8"))

    def get_meta_blob(self, key):
        cur = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,))
        row = cur.fetchone()
        return row[0] if row else None

    def get_meta_text(self, key):
        b = self.get_meta_blob(key)
        return b.decode("utf-8") if b else None

    def _pbkdf2(self, pwd: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
        return kdf.derive(pwd)

    def _derive_fernet(self, master_password: str) -> Fernet:
        kdf_salt = self.get_meta_blob("kdf_salt")
        iterations = int(self.get_meta_text("iterations") or "390000")
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=kdf_salt, iterations=iterations)
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
        return Fernet(key)

    def set_master(self, master_password: str):
        iterations = 390000
        auth_salt = secrets.token_bytes(16)
        kdf_salt = secrets.token_bytes(16)
        master_hash = self._pbkdf2(master_password.encode(), auth_salt, iterations)

        self.set_meta_blob("auth_salt", auth_salt)
        self.set_meta_blob("kdf_salt", kdf_salt)
        self.set_meta_blob("master_hash", master_hash)
        self.set_meta_text("iterations", str(iterations))
        self.set_meta_text("created_at", now_iso())
        self.set_meta_text("version", "1")

        self._fernet = self._derive_fernet(master_password)
        return True

    def unlock(self, master_password: str):
        auth_salt = self.get_meta_blob("auth_salt")
        iterations = int(self.get_meta_text("iterations") or "390000")
        stored_hash = self.get_meta_blob("master_hash")
        if not auth_salt or not stored_hash:
            raise RuntimeError("Cofre mal inicializado.")
        test_hash = self._pbkdf2(master_password.encode(), auth_salt, iterations)
        if not hmac.compare_digest(stored_hash, test_hash):
            return False
        self._fernet = self._derive_fernet(master_password)
        return True

    def lock(self):
        self._fernet = None

    def require_unlocked(self):
        if self._fernet is None:
            raise RuntimeError("Cofre não desbloqueado.")

    def add_entry(self, service, username, password, notes=""):
        self.require_unlocked()
        now = now_iso()
        f = self._fernet
        p_blob = f.encrypt(password.encode("utf-8"))
        n_blob = f.encrypt((notes or "").encode("utf-8"))
        with self.conn:
            self.conn.execute("""
                INSERT INTO entries(service, username, password_enc, notes_enc, created_at, updated_at)
                VALUES(?,?,?,?,?,?)
            """, (service, username, p_blob, n_blob, now, now))

    def update_entry(self, entry_id, service, username, password, notes):
        self.require_unlocked()
        now = now_iso()
        f = self._fernet
        p_blob = f.encrypt(password.encode("utf-8"))
        n_blob = f.encrypt((notes or "").encode("utf-8"))
        with self.conn:
            self.conn.execute("""
                UPDATE entries SET service=?, username=?, password_enc=?, notes_enc=?, updated_at=?
                WHERE id=?
            """, (service, username, p_blob, n_blob, now, entry_id))

    def delete_entry(self, entry_id):
        with self.conn:
            self.conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))

    def list_entries(self, search=None):
        if search:
            like = f"%{search.strip()}%"
            cur = self.conn.execute("""
                SELECT id, service, username, updated_at FROM entries
                WHERE service LIKE ? OR username LIKE ?
                ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC
            """, (like, like))
        else:
            cur = self.conn.execute("""
                SELECT id, service, username, updated_at FROM entries
                ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC
            """)
        rows = cur.fetchall()
        return [{"id": r[0], "service": r[1], "username": r[2], "updated_at": r[3]} for r in rows]

    def get_entry(self, entry_id):
        self.require_unlocked()
        cur = self.conn.execute("""
            SELECT id, service, username, password_enc, notes_enc, created_at, updated_at
            FROM entries WHERE id=?
        """, (entry_id,))
        row = cur.fetchone()
        if not row:
            return None
        f = self._fernet
        password = f.decrypt(row[3]).decode("utf-8")
        notes = f.decrypt(row[4]).decode("utf-8") if row[4] is not None else ""
        return {
            "id": row[0],
            "service": row[1],
            "username": row[2],
            "password": password,
            "notes": notes,
            "created_at": row[5],
            "updated_at": row[6],
        }

    def get_password(self, entry_id):
        self.require_unlocked()
        cur = self.conn.execute("SELECT password_enc FROM entries WHERE id=?", (entry_id,))
        row = cur.fetchone()
        if not row:
            return None
        return self._fernet.decrypt(row[0]).decode("utf-8")


class EntryModal(ctk.CTkToplevel):
    def __init__(self, master, vault: Vault, on_saved, entry=None):
        super().__init__(master)
        self.title("Entrada do Cofre")
        self.geometry("520x540")
        self.resizable(False, False)
        self.vault = vault
        self.on_saved = on_saved
        self.entry = entry
        self.show_password = False

        title = "Nova entrada" if self.entry is None else "Editar entrada"
        ctk.CTkLabel(self, text=f"🔐 {title}", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(16, 6))

        form = ctk.CTkFrame(self, corner_radius=12)
        form.pack(fill="both", expand=True, padx=16, pady=8)

        # Campos
        self.service_var = ctk.StringVar(value=self.entry["service"] if self.entry else "")
        self.username_var = ctk.StringVar(value=self.entry["username"] if self.entry else "")
        self.password_var = ctk.StringVar(value=self.entry["password"] if self.entry else "")
        self.notes_text = ctk.CTkTextbox(form, height=140)

        if self.entry:
            self.notes_text.insert("1.0", self.entry.get("notes", ""))

        ctk.CTkLabel(form, text="Serviço").pack(anchor="w", padx=12, pady=(12, 2))
        self.service_entry = ctk.CTkEntry(form, textvariable=self.service_var, placeholder_text="Ex.: Gmail")
        self.service_entry.pack(fill="x", padx=12, pady=2)

        ctk.CTkLabel(form, text="Usuário").pack(anchor="w", padx=12, pady=(8, 2))
        self.username_entry = ctk.CTkEntry(form, textvariable=self.username_var, placeholder_text="email@exemplo.com")
        self.username_entry.pack(fill="x", padx=12, pady=2)

        pw_row = ctk.CTkFrame(form)
        pw_row.pack(fill="x", padx=12, pady=8)
        ctk.CTkLabel(pw_row, text="Senha").pack(side="left")
        self.toggle_pw_btn = ctk.CTkButton(pw_row, text="👁️ Mostrar", width=100, fg_color=MUTED, hover_color=MUTED_HOVER, command=self.toggle_password)
        self.toggle_pw_btn.pack(side="right", padx=(6, 0))
        self.gen_pw_btn = ctk.CTkButton(pw_row, text="⚙️ Gerar", width=80, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.open_generator)
        self.gen_pw_btn.pack(side="right", padx=6)

        self.password_entry = ctk.CTkEntry(form, textvariable=self.password_var, show="•", placeholder_text="Senha forte")
        self.password_entry.pack(fill="x", padx=12)

        ctk.CTkLabel(form, text="Notas").pack(anchor="w", padx=12, pady=(10, 4))
        self.notes_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        btns = ctk.CTkFrame(self)
        btns.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(btns, text="Salvar", fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.save).pack(side="right")
        ctk.CTkButton(btns, text="Cancelar", fg_color="transparent", hover=False, command=self.destroy).pack(side="right", padx=8)

        self.service_entry.focus_set()

    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.configure(show="" if self.show_password else "•")
        self.toggle_pw_btn.configure(text="🙈 Ocultar" if self.show_password else "👁️ Mostrar")

    def open_generator(self):
        GeneratorModal(self, self.password_var)

    def save(self):
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        notes = self.notes_text.get("1.0", "end").strip()

        if not service:
            messagebox.showwarning("Atenção", "Informe o nome do serviço.")
            return
        if not username:
            messagebox.showwarning("Atenção", "Informe o usuário.")
            return
        if len(password) < 8:
            if not messagebox.askyesno("Senha curta", "A senha tem menos de 8 caracteres. Deseja continuar?"):
                return

        try:
            if self.entry is None:
                self.vault.add_entry(service, username, password, notes)
            else:
                self.vault.update_entry(self.entry["id"], service, username, password, notes)
            self.on_saved()
            self.destroy()
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível salvar: {e}")


class GeneratorModal(ctk.CTkToplevel):
    def __init__(self, master, target_var: ctk.StringVar):
        super().__init__(master)
        self.title("Gerador de Senhas")
        self.geometry("420x380")
        self.resizable(False, False)
        self.target_var = target_var

        ctk.CTkLabel(self, text="🔧 Gerar senha forte", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(16, 8))

        frame = ctk.CTkFrame(self, corner_radius=12)
        frame.pack(fill="both", expand=True, padx=16, pady=8)

        self.length_var = tk.IntVar(value=16)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        row = ctk.CTkFrame(frame)
        row.pack(fill="x", padx=12, pady=(12, 6))
        ctk.CTkLabel(row, text="Tamanho:").pack(side="left")
        self.len_slider = ctk.CTkSlider(row, from_=8, to=64, number_of_steps=56, command=lambda v: self.length_var.set(int(float(v))))
        self.len_slider.set(16)
        self.len_slider.pack(side="left", fill="x", expand=True, padx=10)
        self.len_val = ctk.CTkLabel(row, textvariable=self.length_var)
        self.len_val.pack(side="left")

        ctk.CTkCheckBox(frame, text="Letras minúsculas (a-z)", variable=self.use_lower).pack(anchor="w", padx=12, pady=2)
        ctk.CTkCheckBox(frame, text="Letras maiúsculas (A-Z)", variable=self.use_upper).pack(anchor="w", padx=12, pady=2)
        ctk.CTkCheckBox(frame, text="Dígitos (0-9)", variable=self.use_digits).pack(anchor="w", padx=12, pady=2)
        ctk.CTkCheckBox(frame, text="Símbolos (!@#$...)", variable=self.use_symbols).pack(anchor="w", padx=12, pady=2)

        self.result_var = ctk.StringVar(value="")
        ctk.CTkLabel(frame, text="Prévia:").pack(anchor="w", padx=12, pady=(10, 2))
        self.preview = ctk.CTkEntry(frame, textvariable=self.result_var)
        self.preview.pack(fill="x", padx=12)

        btns = ctk.CTkFrame(self)
        btns.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(btns, text="Gerar", fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.generate).pack(side="right")
        ctk.CTkButton(btns, text="Usar", fg_color="transparent", command=self.use).pack(side="right", padx=8)

        self.generate()

    def generate(self):
        length = self.length_var.get()
        pool = ""
        if self.use_lower.get():
            pool += string.ascii_lowercase
        if self.use_upper.get():
            pool += string.ascii_uppercase
        if self.use_digits.get():
            pool += string.digits
        if self.use_symbols.get():
            pool += "!@#$%^&*()-_=+[]{};:,.?/\\|~"

        if not pool:
            pool = string.ascii_letters + string.digits

        # Garante diversidade mínima
        while True:
            pwd = "".join(secrets.choice(pool) for _ in range(length))
            if (not self.use_lower.get() or any(c.islower() for c in pwd)) \
               and (not self.use_upper.get() or any(c.isupper() for c in pwd)) \
               and (not self.use_digits.get() or any(c.isdigit() for c in pwd)) \
               and (not self.use_symbols.get() or any(c in "!@#$%^&*()-_=+[]{};:,.?/\\|~" for c in pwd)):
                break

        self.result_var.set(pwd)

    def use(self):
        self.target_var.set(self.result_var.get())
        self.destroy()


class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, vault: Vault, on_unlocked):
        super().__init__(master)
        self.vault = vault
        self.on_unlocked = on_unlocked
        self.mode = "setup" if not self.vault.is_initialized() else "login"

        self.pack(fill="both", expand=True)
        self.build_ui()

    def build_ui(self):
        for w in self.winfo_children():
            w.destroy()

        container = ctk.CTkFrame(self, corner_radius=16)
        container.place(relx=0.5, rely=0.5, anchor="center")
        container.configure(width=560, height=420)

        content = ctk.CTkFrame(container, fg_color="transparent")
        content.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(content, text="🔐 Chaveiro", font=ctk.CTkFont(size=28, weight="bold")).pack(pady=(8, 0))
        ctk.CTkLabel(content, text="Gerenciador de Senhas", font=ctk.CTkFont(size=14)).pack(pady=(0, 12))
        ctk.CTkLabel(content, text="Desenvolvido por Thiago Freitas", font=ctk.CTkFont(size=12, slant="italic")).pack(pady=(0, 16))

        if self.mode == "setup":
            ctk.CTkLabel(content, text="Crie sua senha mestra", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(4, 8))
            self.pw1 = ctk.CTkEntry(content, show="•", width=340, placeholder_text="Senha mestra (mín. 8 chars)")
            self.pw2 = ctk.CTkEntry(content, show="•", width=340, placeholder_text="Confirmar senha mestra")
            self.pw1.pack(pady=6)
            self.pw2.pack(pady=6)

            show_row = ctk.CTkFrame(content, fg_color="transparent")
            show_row.pack(pady=(4, 12))
            self.show_pw_var = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(show_row, text="Mostrar senhas", variable=self.show_pw_var,
                            command=self.toggle_show_setup).pack()

            ctk.CTkButton(content, text="Criar Cofre", width=180, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.create_vault).pack(pady=10)
        else:
            ctk.CTkLabel(content, text="Desbloqueie seu cofre", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(4, 8))
            self.pw_login = ctk.CTkEntry(content, show="•", width=340, placeholder_text="Senha mestra")
            self.pw_login.pack(pady=6)

            show_row = ctk.CTkFrame(content, fg_color="transparent")
            show_row.pack(pady=(4, 12))
            self.show_login_var = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(show_row, text="Mostrar senha", variable=self.show_login_var,
                            command=self.toggle_show_login).pack()

            ctk.CTkButton(content, text="Desbloquear", width=180, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.unlock).pack(pady=10)

        # Tema
        theme_row = ctk.CTkFrame(content, fg_color="transparent")
        theme_row.pack(pady=(20, 0))
        ctk.CTkLabel(theme_row, text="Tema: ").pack(side="left", padx=(0, 6))
        self.theme_menu = ctk.CTkOptionMenu(theme_row, values=["Sistema", "Claro", "Escuro"],
                                            command=self.change_theme)
        self.theme_menu.set("Escuro")
        self.theme_menu.pack(side="left")

    def toggle_show_setup(self):
        show = "" if self.show_pw_var.get() else "•"
        self.pw1.configure(show=show)
        self.pw2.configure(show=show)

    def toggle_show_login(self):
        show = "" if self.show_login_var.get() else "•"
        self.pw_login.configure(show=show)

    def change_theme(self, choice):
        mapping = {"Sistema": "System", "Claro": "Light", "Escuro": "Dark"}
        ctk.set_appearance_mode(mapping.get(choice, "Dark"))

    def create_vault(self):
        p1 = self.pw1.get()
        p2 = self.pw2.get()
        if len(p1) < 8:
            messagebox.showwarning("Atenção", "Use ao menos 8 caracteres na senha mestra.")
            return
        if p1 != p2:
            messagebox.showwarning("Atenção", "As senhas não coincidem.")
            return
        try:
            self.vault.set_master(p1)
            messagebox.showinfo("Pronto", "Cofre criado com sucesso!")
            self.on_unlocked()
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao criar cofre: {e}")

    def unlock(self):
        p = self.pw_login.get()
        try:
            ok = self.vault.unlock(p)
            if ok:
                self.on_unlocked()
            else:
                messagebox.showerror("Erro", "Senha mestra incorreta.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao desbloquear: {e}")

    def reset(self):
        self.mode = "login" if self.vault.is_initialized() else "setup"
        self.build_ui()


class MainFrame(ctk.CTkFrame):
    def __init__(self, master, vault: Vault, on_lock):
        super().__init__(master)
        self.vault = vault
        self.on_lock = on_lock
        self.search_var = ctk.StringVar()
        self.toast_label = None
        self.toast_job = None

        self.pack(fill="both", expand=True)
        self.build_ui()

    def build_ui(self):
        for w in self.winfo_children():
            w.destroy()

        header = ctk.CTkFrame(self, corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text="🔐 Chaveiro", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=16, pady=10)
        ctk.CTkLabel(header, text="Desenvolvido por Thiago Freitas", font=ctk.CTkFont(size=12, slant="italic")).pack(side="left", padx=8, pady=10)

        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=16, pady=10)

        self.search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var, placeholder_text="Pesquisar por serviço ou usuário...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_list())

        ctk.CTkButton(toolbar, text="+ Nova entrada", fg_color=ACCENT, hover_color=ACCENT_HOVER, command=self.open_new).pack(side="left", padx=4)
        ctk.CTkButton(toolbar, text="Bloquear", fg_color=MUTED, hover_color=MUTED_HOVER, command=self.lock).pack(side="right", padx=(8,0))

        theme_menu = ctk.CTkOptionMenu(toolbar, values=["Sistema", "Claro", "Escuro"], command=self.change_theme)
        theme_menu.set("Escuro")
        theme_menu.pack(side="right", padx=8)

        self.list_area = ctk.CTkScrollableFrame(self, corner_radius=12)
        self.list_area.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        footer = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        footer.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkLabel(footer, text="💾 Seus dados ficam criptografados localmente | Tema ajustável | Desenvolvido por Thiago Freitas").pack(side="left")

        self.refresh_list()

    def change_theme(self, choice):
        mapping = {"Sistema": "System", "Claro": "Light", "Escuro": "Dark"}
        ctk.set_appearance_mode(mapping.get(choice, "Dark"))

    def open_new(self):
        EntryModal(self, self.vault, on_saved=self.refresh_list)

    def open_edit(self, entry_id):
        entry = self.vault.get_entry(entry_id)
        if not entry:
            messagebox.showerror("Erro", "Entrada não encontrada.")
            return
        EntryModal(self, self.vault, on_saved=self.refresh_list, entry=entry)

    def lock(self):
        self.vault.lock()
        self.on_lock()

    def copy_password(self, entry_id):
        pwd = self.vault.get_password(entry_id)
        if not pwd:
            messagebox.showerror("Erro", "Não foi possível obter a senha.")
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.show_toast("Senha copiada para a área de transferência (será limpa em 15s).")
        # Limpa após 15s se ainda for a mesma
        self.after(15000, lambda: self.safe_clear_clipboard(pwd))

    def safe_clear_clipboard(self, expected):
        try:
            current = self.clipboard_get()
            if current == expected:
                self.clipboard_clear()
        except Exception:
            pass

    def confirm_delete(self, entry_id, title):
        if messagebox.askyesno("Confirmar exclusão", f"Excluir a entrada '{title}'? Esta ação não pode ser desfeita."):
            try:
                self.vault.delete_entry(entry_id)
                self.refresh_list()
                self.show_toast("Entrada excluída.")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível excluir: {e}")

    def show_toast(self, text):
        if self.toast_label:
            self.toast_label.destroy()
            self.toast_label = None
        if self.toast_job:
            try:
                self.after_cancel(self.toast_job)
            except Exception:
                pass

        self.toast_label = ctk.CTkLabel(self, text=text, fg_color=ACCENT, text_color="white", corner_radius=8, padx=10, pady=6)
        self.toast_label.place(relx=0.5, rely=1.0, anchor="s", y=-10)
        self.toast_job = self.after(2500, lambda: self.toast_label.destroy())

    def refresh_list(self):
        for child in self.list_area.winfo_children():
            child.destroy()

        items = self.vault.list_entries(self.search_var.get())
        if not items:
            ctk.CTkLabel(self.list_area, text="Nenhuma entrada encontrada. Clique em “+ Nova entrada” para começar.",
                         font=ctk.CTkFont(size=13)).pack(pady=14)
            return

        for item in items:
            row = ctk.CTkFrame(self.list_area, corner_radius=10)
            row.pack(fill="x", padx=8, pady=6)

            left = ctk.CTkFrame(row, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True, padx=10, pady=8)
            ctk.CTkLabel(left, text=item["service"], font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(left, text=f"{item['username']} • Atualizado: {item['updated_at']}", font=ctk.CTkFont(size=12)).pack(anchor="w")

            actions = ctk.CTkFrame(row, fg_color="transparent")
            actions.pack(side="right", padx=10)
            ctk.CTkButton(actions, text="Copiar", width=80, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=lambda i=item["id"]: self.copy_password(i)).pack(side="left", padx=4)
            ctk.CTkButton(actions, text="Editar", width=80, fg_color=ACCENT, hover_color=ACCENT_HOVER, command=lambda i=item["id"]: self.open_edit(i)).pack(side="left", padx=4)
            ctk.CTkButton(actions, text="Excluir", width=80, fg_color=DANGER, hover_color=DANGER_HOVER,
                          command=lambda i=item["id"], t=item["service"]: self.confirm_delete(i, t)).pack(side="left", padx=4)


class PasswordManagerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        # Tema escuro por padrão + tema base escuro
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("dark-blue")  # base escura; botões usam nosso ACCENT

        self.title("🔐 Chaveiro — Gerenciador de Senhas")
        self.geometry("1024x640")
        self.minsize(900, 560)

        # Ícone moderno (azul-prussiano) gerado automaticamente
        try:
            icon_path = ensure_assets()
            self._icon_img = tk.PhotoImage(file=icon_path)
            self.iconphoto(True, self._icon_img)
        except Exception:
            pass

        db_path = os.path.join(get_app_dir(), "vault.db")
        self.vault = Vault(db_path)

        self.login_frame = LoginFrame(self, self.vault, on_unlocked=self.on_unlocked)
        self.main_frame = None

    def on_unlocked(self):
        if self.login_frame:
            self.login_frame.pack_forget()
            self.login_frame.destroy()
            self.login_frame = None
        self.main_frame = MainFrame(self, self.vault, on_lock=self.on_lock)

    def on_lock(self):
        if self.main_frame:
            self.main_frame.pack_forget()
            self.main_frame.destroy()
            self.main_frame = None
        self.login_frame = LoginFrame(self, self.vault, on_unlocked=self.on_unlocked)


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()