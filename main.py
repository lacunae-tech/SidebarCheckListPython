# sidebar_checklist.py
# Windows 11 / Python 3.9
# Spec: Sidebar resident checklist (v1.1)
#
# Notes:
# - Uses AppBar (SHAppBarMessage) via ctypes to reserve workspace ("not overlapped").
# - GUI via tkinter.
# - settings.json is mandatory; checklist.json optional (or fetched via API with cache).
#
# Optional deps for toast:
#   pip install winotify
#   (fallback to tkinter messagebox if not installed)

import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time
import traceback
import unicodedata
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import tkinter as tk
from tkinter import ttk, messagebox


# -----------------------------
# Constants / Globals
# -----------------------------
APP_NAME = "SidebarChecklist"
SETTINGS_FILE = "settings.json"
CHECKLIST_FILE = "checklist.json"
CACHE_FILE = "checklist.cache.json"
MAX_FILE_BYTES = 5 * 1024 * 1024
CACHE_TTL_SECONDS = 12 * 60 * 60

ABE_RIGHT = 2
ABM_NEW = 0x00000000
ABM_REMOVE = 0x00000001
ABM_QUERYPOS = 0x00000002
ABM_SETPOS = 0x00000003

SM_REMOTESESSION = 0x1000

WM_DISPLAYCHANGE = 0x007E
WM_SETTINGCHANGE = 0x001A
WM_DPICHANGED = 0x02E0

GWL_WNDPROC = -4

user32 = ctypes.windll.user32
shell32 = ctypes.windll.shell32
kernel32 = ctypes.windll.kernel32

_old_wndproc = None
_appbar_msg_id = None


# -----------------------------
# DPI awareness (best effort)
# -----------------------------
def set_dpi_awareness():
    # Prefer Per-monitor v2 if available (Windows 10+)
    try:
        AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = ctypes.c_void_p(-4)
        user32.SetProcessDpiAwarenessContext(AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
        return
    except Exception:
        pass
    # Fallback: system DPI aware
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass


# -----------------------------
# Windows structures for AppBar / Monitors
# -----------------------------
class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG),
                ("top", wt.LONG),
                ("right", wt.LONG),
                ("bottom", wt.LONG)]


class APPBARDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HWND),
        ("uCallbackMessage", wt.UINT),
        ("uEdge", wt.UINT),
        ("rc", RECT),
        ("lParam", wt.LPARAM),
    ]


class MONITORINFOEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("rcMonitor", RECT),
        ("rcWork", RECT),
        ("dwFlags", wt.DWORD),
        ("szDevice", wt.WCHAR * 32),
    ]


MONITORINFOF_PRIMARY = 0x00000001


def file_size_ok(path: str) -> bool:
    try:
        return os.path.getsize(path) <= MAX_FILE_BYTES
    except OSError:
        return True


def read_json_file_strict(path: str):
    # Enforce 5MB before reading
    if os.path.exists(path):
        if not file_size_ok(path):
            raise ValueError(f"File too large (>5MB): {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def jst_now_iso():
    # JST (+09:00)
    jst = timezone(timedelta(hours=9))
    return datetime.now(jst).isoformat(timespec="seconds")


def jst_today_filename():
    jst = timezone(timedelta(hours=9))
    d = datetime.now(jst).date()
    return d.strftime("%Y-%m-%d") + ".json"


def show_toast(title: str, msg: str):
    # Best effort toast; fallback to messagebox
    try:
        from winotify import Notification, audio
        toast = Notification(app_id=APP_NAME, title=title, msg=msg, duration="short")
        toast.set_audio(audio.Default, loop=False)
        toast.show()
        return
    except Exception:
        pass
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast(title, msg, duration=4, threaded=True)
        return
    except Exception:
        pass
    # Fallback
    try:
        messagebox.showinfo(title, msg)
    except Exception:
        pass


def is_remote_session() -> bool:
    try:
        return bool(user32.GetSystemMetrics(SM_REMOTESESSION))
    except Exception:
        return False


# -----------------------------
# Monitor enumeration
# -----------------------------
def enum_monitors():
    monitors = []

    MONITORENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HMONITOR, wt.HDC, ctypes.POINTER(RECT), wt.LPARAM)

    def _cb(hmon, hdc, lprc, lparam):
        mi = MONITORINFOEXW()
        mi.cbSize = ctypes.sizeof(MONITORINFOEXW)
        if user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            monitors.append({
                "hmon": hmon,
                "monitor": (mi.rcMonitor.left, mi.rcMonitor.top, mi.rcMonitor.right, mi.rcMonitor.bottom),
                "is_primary": bool(mi.dwFlags & MONITORINFOF_PRIMARY),
                "device": mi.szDevice,
            })
        return True

    cb = MONITORENUMPROC(_cb)
    user32.EnumDisplayMonitors(0, 0, cb, 0)
    # Sort: primary first, then others
    monitors.sort(key=lambda m: (not m["is_primary"], m["device"]))
    return monitors


def get_target_monitor_rect(target: str):
    mons = enum_monitors()
    if not mons:
        # Fallback to a reasonable default
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        return (0, 0, w, h), False

    has_sub = len(mons) >= 2
    if target == "sub" and has_sub:
        m = mons[1]
    else:
        m = mons[0]
    return m["monitor"], has_sub


# -----------------------------
# Single instance via mutex
# -----------------------------
def ensure_single_instance():
    name = f"Global\\{APP_NAME}_Mutex_v1_1"
    kernel32.CreateMutexW.restype = wt.HANDLE
    h = kernel32.CreateMutexW(None, False, name)
    if not h:
        return True  # cannot create; allow
    err = kernel32.GetLastError()
    ERROR_ALREADY_EXISTS = 183
    if err == ERROR_ALREADY_EXISTS:
        return False
    return True


# -----------------------------
# AppBar wrapper
# -----------------------------
def appbar_register(hwnd: int):
    global _appbar_msg_id
    if _appbar_msg_id is None:
        _appbar_msg_id = user32.RegisterWindowMessageW("SidebarChecklistAppBarMessage")

    abd = APPBARDATA()
    abd.cbSize = ctypes.sizeof(APPBARDATA)
    abd.hWnd = wt.HWND(hwnd)
    abd.uCallbackMessage = _appbar_msg_id
    shell32.SHAppBarMessage(ABM_NEW, ctypes.byref(abd))


def appbar_unregister(hwnd: int):
    abd = APPBARDATA()
    abd.cbSize = ctypes.sizeof(APPBARDATA)
    abd.hWnd = wt.HWND(hwnd)
    shell32.SHAppBarMessage(ABM_REMOVE, ctypes.byref(abd))


def appbar_setpos(hwnd: int, monitor_rect, width_px: int):
    """
    Reserve space on the right edge using AppBar.
    Returns final rect (left, top, right, bottom) decided by OS.
    """
    (ml, mt, mr, mb) = monitor_rect
    desired = RECT()
    desired.left = mr - width_px
    desired.right = mr
    desired.top = mt
    desired.bottom = mb

    abd = APPBARDATA()
    abd.cbSize = ctypes.sizeof(APPBARDATA)
    abd.hWnd = wt.HWND(hwnd)
    abd.uEdge = ABE_RIGHT
    abd.rc = desired

    # Ask OS to adjust, then set
    shell32.SHAppBarMessage(ABM_QUERYPOS, ctypes.byref(abd))
    shell32.SHAppBarMessage(ABM_SETPOS, ctypes.byref(abd))

    r = abd.rc
    return (r.left, r.top, r.right, r.bottom)


# -----------------------------
# Checklist source / cache
# -----------------------------
def validate_checklist_json(obj):
    if not isinstance(obj, dict):
        raise ValueError("checklist.json root must be object")
    lists = obj.get("lists")
    if lists is None or not isinstance(lists, list):
        raise ValueError("checklist.json must have lists[]")
    # Empty lists is allowed (handled by UI)
    seen = set()
    for l in lists:
        if not isinstance(l, dict):
            raise ValueError("lists[] must be object")
        lid = l.get("id")
        if not isinstance(lid, str) or not lid:
            raise ValueError("lists[].id must be string")
        if lid in seen:
            raise ValueError("lists[].id duplicated")
        seen.add(lid)
        items = l.get("items")
        if items is None or not isinstance(items, list):
            raise ValueError("lists[].items must be list (can be empty)")
        for it in items:
            if not isinstance(it, str):
                raise ValueError("lists[].items[] must be string")
    return True


def read_cache_if_valid(cache_path: str):
    if not os.path.exists(cache_path):
        return None
    if not file_size_ok(cache_path):
        return None
    try:
        obj = read_json_file_strict(cache_path)
        fetched_at = obj.get("fetched_at")
        data = obj.get("data")
        if not isinstance(fetched_at, str) or data is None:
            return None
        # Parse iso (best effort)
        try:
            dt = datetime.fromisoformat(fetched_at)
        except Exception:
            return None
        age = datetime.now(dt.tzinfo or timezone.utc) - dt
        if age.total_seconds() <= CACHE_TTL_SECONDS:
            validate_checklist_json(data)
            return data
        return None
    except Exception:
        return None


def fetch_checklist_via_api(base_url: str, api_key: str, timeout_ms: int):
    headers = {
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/1.1",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key

    req = Request(base_url, headers=headers, method="GET")
    timeout_s = max(0.5, timeout_ms / 1000.0)

    with urlopen(req, timeout=timeout_s) as resp:
        raw = resp.read()

    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("API response too large (>5MB)")
    try:
        txt = raw.decode("utf-8")
    except Exception:
        txt = raw.decode("utf-8", errors="replace")

    data = json.loads(txt)
    validate_checklist_json(data)
    return data


def load_checklist(settings: dict, app_dir: str):
    """
    Returns tuple: (status, data, error_message)
    status:
      - "ok"
      - "missing"  (treat as no checklist)
      - "json_error"
    """
    api = settings.get("api", {}) or {}
    enabled = bool(api.get("enabled", False))

    # Determine local file path
    checklist_path = (settings.get("checklist", {}) or {}).get("path", "") or ""
    if not checklist_path:
        checklist_path = os.path.join(app_dir, CHECKLIST_FILE)
    else:
        # Allow relative
        if not os.path.isabs(checklist_path):
            checklist_path = os.path.join(app_dir, checklist_path)

    cache_path = os.path.join(app_dir, CACHE_FILE)

    if enabled:
        base_url = str(api.get("base_url", "") or "").strip()
        api_key = str(api.get("api_key", "") or "")
        timeout_ms = int(api.get("timeout_ms", 3000) or 3000)

        try:
            data = fetch_checklist_via_api(base_url, api_key, timeout_ms)
            # Write cache
            wrapper = {"fetched_at": jst_now_iso(), "data": data}
            # Enforce cache size by checking serialized length (best effort)
            s = json.dumps(wrapper, ensure_ascii=False)
            if len(s.encode("utf-8")) <= MAX_FILE_BYTES:
                write_json_atomic(cache_path, wrapper)
            return "ok", data, ""
        except Exception:
            # Fallback to cache if valid
            cached = read_cache_if_valid(cache_path)
            if cached is not None:
                return "ok", cached, ""
            # No cache: behave like checklist missing (per spec 11.3-4)
            return "missing", None, ""

    # Local mode
    if not os.path.exists(checklist_path):
        return "missing", None, ""
    try:
        data = read_json_file_strict(checklist_path)
        validate_checklist_json(data)
        return "ok", data, ""
    except Exception:
        return "json_error", None, "JSONファイルエラー"


# -----------------------------
# Settings load/save
# -----------------------------
def clamp_int(v, lo, hi, default):
    try:
        x = int(v)
    except Exception:
        return default
    return max(lo, min(hi, x))


def normalize_settings(settings: dict, has_sub: bool):
    # sidebar width clamp
    window = settings.setdefault("window", {})
    window["sidebar_width_px"] = clamp_int(window.get("sidebar_width_px", 400), 280, 900, 400)

    # target monitor
    disp = settings.setdefault("display", {})
    t = disp.get("target_monitor", "main")
    if t not in ("main", "sub"):
        t = "main"
    if t == "sub" and not has_sub:
        t = "main"
    disp["target_monitor"] = t

    # selection
    sel = settings.setdefault("selection", {})
    if not isinstance(sel.get("selected_list_id", ""), str):
        sel["selected_list_id"] = ""

    # checklist ui
    cl = settings.setdefault("checklist", {})
    cl["font_size"] = clamp_int(cl.get("font_size", 22), 10, 48, 22)
    cl["checkbox_size"] = clamp_int(cl.get("checkbox_size", 16), 12, 30, 16)
    if not isinstance(cl.get("save_path", ""), str):
        cl["save_path"] = ""
    if not isinstance(cl.get("path", ""), str):
        cl["path"] = ""

    # api
    api = settings.setdefault("api", {})
    api["enabled"] = bool(api.get("enabled", False))
    if not isinstance(api.get("base_url", ""), str):
        api["base_url"] = ""
    if not isinstance(api.get("api_key", ""), str):
        api["api_key"] = ""
    api["timeout_ms"] = clamp_int(api.get("timeout_ms", 3000), 500, 20000, 3000)

    return settings


def load_settings_or_exit(app_dir: str):
    path = os.path.join(app_dir, SETTINGS_FILE)
    try:
        if not os.path.exists(path):
            raise FileNotFoundError("settings.json not found")
        if not file_size_ok(path):
            raise ValueError("settings.json too large (>5MB)")
        settings = read_json_file_strict(path)
        if not isinstance(settings, dict):
            raise ValueError("settings.json must be object")
        # Need monitor info to normalize
        _, has_sub = get_target_monitor_rect(settings.get("display", {}).get("target_monitor", "main"))
        normalize_settings(settings, has_sub)
        # Write back normalized (optional)
        write_json_atomic(path, settings)
        return settings
    except Exception:
        messagebox.showerror("JSONファイルエラー", "JSONファイルエラー")
        sys.exit(1)


def save_settings(app_dir: str, settings: dict):
    path = os.path.join(app_dir, SETTINGS_FILE)
    # size guard: if settings.json already too large, treat as fatal in spec,
    # but at runtime we just attempt overwrite (still stays small normally).
    write_json_atomic(path, settings)


# -----------------------------
# UI Components (Scrollable list)
# -----------------------------
class ScrollableFrame(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)

        self.inner.bind("<Configure>", self._on_frame_configure)
        self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.canvas.configure(yscrollcommand=self.vsb.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")

        # Mouse wheel scroll
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_frame_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_mousewheel(self, event):
        try:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass


# -----------------------------
# Main App
# -----------------------------
class SidebarChecklistApp:
    def __init__(self, root: tk.Tk, app_dir: str):
        self.root = root
        self.app_dir = app_dir

        self.settings = load_settings_or_exit(app_dir)

        # State
        self.checklist_data = None
        self.current_list = None
        self.item_vars = []  # list of (text, tk.BooleanVar)
        self.filtered_indices = []
        self.last_good_geometry = None
        self.reposition_after_id = None

        # Build UI
        self.root.title("サイドバー常駐チェックリスト")
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.root.bind("<Alt-F4>", lambda e: self.on_exit())

        self.root.resizable(False, False)
        self.root.attributes("-topmost", not is_remote_session())

        # Layout
        self.header = ttk.Frame(root)
        self.header.pack(side="top", fill="x", padx=8, pady=6)

        # Row 1: dropdown
        row1 = ttk.Frame(self.header)
        row1.pack(side="top", fill="x", pady=(0, 4))
        self.list_var = tk.StringVar()
        self.list_combo = ttk.Combobox(row1, textvariable=self.list_var, state="readonly")
        self.list_combo.pack(side="left", fill="x", expand=True)
        self.list_combo.bind("<<ComboboxSelected>>", self.on_list_selected)

        # Row 2: search
        row2 = ttk.Frame(self.header)
        row2.pack(side="top", fill="x", pady=(0, 4))
        ttk.Label(row2, text="検索").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(row2, textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.search_var.trace_add("write", lambda *args: self.apply_filter())
        self.search_entry.bind("<KeyRelease>", lambda event: self.apply_filter())

        # Row 3: buttons
        row3 = ttk.Frame(self.header)
        row3.pack(side="top", fill="x")

        self.save_btn = ttk.Button(row3, text="保存", command=self.on_save)
        self.save_btn.pack(side="left")

        self.refresh_btn = ttk.Button(row3, text="リフレッシュ", command=self.on_refresh)
        self.refresh_btn.pack(side="left", padx=(6, 0))

        # Monitor toggle
        self.monitor_main_btn = ttk.Button(row3, text="メイン", command=lambda: self.set_monitor("main"))
        self.monitor_sub_btn = ttk.Button(row3, text="サブ", command=lambda: self.set_monitor("sub"))
        self.monitor_main_btn.pack(side="right")
        self.monitor_sub_btn.pack(side="right", padx=(0, 6))

        # Separator
        ttk.Separator(root, orient="horizontal").pack(side="top", fill="x")

        # Body
        self.body = ttk.Frame(root)
        self.body.pack(side="top", fill="both", expand=True)

        self.error_label = ttk.Label(self.body, text="", anchor="center", justify="center")
        self.error_label.pack_forget()

        self.scroll = ScrollableFrame(self.body)
        self.scroll.pack(side="top", fill="both", expand=True)

        # Bind configure for move prevention / reposition
        self.root.bind("<Configure>", self.on_configure)

        # Initialize
        self.load_checklists_and_render()

        # AppBar register after window created
        self.root.after(50, self.init_appbar)

        # Periodic: enforce topmost based on RDP and keep position
        self.root.after(1000, self.periodic_enforce)

    # -------------------------
    # App lifecycle
    # -------------------------
    def init_appbar(self):
        try:
            hwnd = self.root.winfo_id()
            appbar_register(hwnd)
            self.apply_appbar_and_geometry()
        except Exception:
            # If AppBar fails, still show window
            pass

    def on_exit(self):
        try:
            hwnd = self.root.winfo_id()
            appbar_unregister(hwnd)
        except Exception:
            pass
        self.root.destroy()

    # -------------------------
    # Loading / rendering
    # -------------------------
    def load_checklists_and_render(self):
        status, data, err = load_checklist(self.settings, self.app_dir)
        if status == "missing":
            self.checklist_data = None
            self.show_error("チェックリストが存在しません")
            self.update_monitor_buttons()
            self.apply_appbar_and_geometry()
            return
        if status == "json_error":
            self.checklist_data = None
            self.show_error("JSONファイルエラー")
            self.update_monitor_buttons()
            self.apply_appbar_and_geometry()
            return

        self.checklist_data = data
        lists = data.get("lists", [])
        if not lists:
            self.show_error("チェックリストが存在しません")
            self.populate_list_dropdown([])
            self.update_monitor_buttons()
            self.apply_appbar_and_geometry()
            return

        # Populate dropdown
        self.populate_list_dropdown(lists)

        # Select list (with fallback)
        wanted_id = (self.settings.get("selection", {}) or {}).get("selected_list_id", "")
        selected = None
        for l in lists:
            if l.get("id") == wanted_id:
                selected = l
                break
        if selected is None:
            selected = lists[0]
            # Silent fallback (no UI error), update settings to keep consistent
            self.settings["selection"]["selected_list_id"] = selected.get("id", "")
            save_settings(self.app_dir, self.settings)

        self.set_current_list(selected)

        # Clear error and render items
        self.hide_error()
        self.render_items()

        self.update_monitor_buttons()
        self.apply_appbar_and_geometry()

    def populate_list_dropdown(self, lists):
        names = []
        self._list_id_by_name = {}
        for l in lists:
            name = l.get("name", l.get("id", ""))
            # Ensure unique displayed names in combobox
            base = name
            i = 2
            while name in self._list_id_by_name:
                name = f"{base} ({i})"
                i += 1
            self._list_id_by_name[name] = l.get("id", "")
            names.append(name)

        self._all_list_names = names
        self.list_combo["values"] = names

    def set_current_list(self, lobj):
        self.current_list = lobj
        # Set combobox selection by id
        target_id = lobj.get("id", "")
        for name, lid in self._list_id_by_name.items():
            if lid == target_id:
                self.list_var.set(name)
                break

    def render_items(self):
        # Clear old widgets
        for child in self.scroll.inner.winfo_children():
            child.destroy()

        self.item_vars = []
        items = self.current_list.get("items", []) if self.current_list else []
        font_size = int((self.settings.get("checklist", {}) or {}).get("font_size", 22))
        checkbox_size = int((self.settings.get("checklist", {}) or {}).get("checkbox_size", 16))

        style = ttk.Style()
        style.configure("Checklist.TCheckbutton", font=("", font_size))
        style.configure("Checklist.TLabel", font=("", font_size))

        for idx, text in enumerate(items):
            row = ttk.Frame(self.scroll.inner)
            row.pack(side="top", fill="x", padx=8, pady=6)

            var = tk.BooleanVar(value=False)

            cb = ttk.Checkbutton(row, variable=var, style="Checklist.TCheckbutton")
            cb.pack(side="left", anchor="n")

            # Text label with wrap. Indent is naturally aligned because label starts after checkbox.
            lbl = ttk.Label(
                row,
                text=text,
                style="Checklist.TLabel",
                wraplength=self.settings["window"]["sidebar_width_px"] - 80,
                justify="left"
            )
            lbl.pack(side="left", fill="x", expand=True, padx=(10, 0))

            # Allow clicking text to toggle
            lbl.bind("<Button-1>", lambda e, v=var: v.set(not v.get()))

            # Store
            self.item_vars.append((text, var, row))

        self.apply_filter()

    def apply_filter(self):
        q = self.normalize_search_text(self.search_var.get())
        all_names = getattr(self, "_all_list_names", [])
        if q:
            filtered = [
                name for name in all_names
                if q in self.normalize_search_text(name)
            ]
        else:
            filtered = all_names
        self.list_combo["values"] = filtered

    @staticmethod
    def normalize_search_text(value):
        text = "" if value is None else str(value)
        return unicodedata.normalize("NFKC", text).casefold().strip()

    def show_error(self, msg: str):
        # Hide list
        self.scroll.pack_forget()
        self.error_label.configure(text=msg)
        self.error_label.pack(side="top", fill="both", expand=True, padx=12, pady=12)

    def hide_error(self):
        self.error_label.pack_forget()
        self.scroll.pack(side="top", fill="both", expand=True)

    # -------------------------
    # Events
    # -------------------------
    def on_list_selected(self, event=None):
        if not self.checklist_data:
            return
        name = self.list_var.get()
        lid = self._list_id_by_name.get(name, "")
        # Find list
        lists = self.checklist_data.get("lists", [])
        selected = None
        for l in lists:
            if l.get("id") == lid:
                selected = l
                break
        if selected is None:
            # silent fallback to first
            if lists:
                selected = lists[0]
        if selected is None:
            return

        self.set_current_list(selected)

        # Save immediately per spec
        self.settings["selection"]["selected_list_id"] = selected.get("id", "")
        save_settings(self.app_dir, self.settings)

        self.render_items()

    def on_refresh(self):
        self.load_checklists_and_render()

    def set_monitor(self, target: str):
        # Update setting and save immediately per spec
        _, has_sub = get_target_monitor_rect(target)
        if target == "sub" and not has_sub:
            target = "main"

        self.settings["display"]["target_monitor"] = target
        save_settings(self.app_dir, self.settings)

        self.update_monitor_buttons()
        self.apply_appbar_and_geometry()

    def update_monitor_buttons(self):
        _, has_sub = get_target_monitor_rect(self.settings.get("display", {}).get("target_monitor", "main"))
        t = self.settings["display"]["target_monitor"]

        # Disable if no sub
        if has_sub:
            self.monitor_sub_btn.state(["!disabled"])
        else:
            self.monitor_sub_btn.state(["disabled"])
            if t == "sub":
                self.settings["display"]["target_monitor"] = "main"
                save_settings(self.app_dir, self.settings)

        # Make active button unclickable
        if t == "main":
            self.monitor_main_btn.state(["disabled"])
            self.monitor_sub_btn.state(["!disabled"] if has_sub else ["disabled"])
        else:
            self.monitor_sub_btn.state(["disabled"])
            self.monitor_main_btn.state(["!disabled"])

    def on_save(self):
        if not self.current_list:
            return

        save_dir = (self.settings.get("checklist", {}) or {}).get("save_path", "") or ""
        if not save_dir:
            save_dir = self.app_dir
        else:
            if not os.path.isabs(save_dir):
                save_dir = os.path.join(self.app_dir, save_dir)

        os.makedirs(save_dir, exist_ok=True)
        path = os.path.join(save_dir, jst_today_filename())

        # Size guard: if existing file too large, abort with toast
        if os.path.exists(path) and not file_size_ok(path):
            show_toast("保存失敗", "サイズ超過のため保存できません")
            return

        entry = {
            "id": self.current_list.get("id", ""),
            "timestamp": jst_now_iso(),
            "items": [{"text": t, "is_checked": bool(v.get())} for (t, v, _row) in self.item_vars],
            "checklist_version": str((self.checklist_data or {}).get("version", "1.0")),
        }

        try:
            if os.path.exists(path):
                data = read_json_file_strict(path)
                if not isinstance(data, list):
                    # If invalid format, treat as json error and do not overwrite
                    show_toast("保存失敗", "JSONファイルエラー")
                    return
            else:
                data = []

            data.append(entry)

            # Enforce max size before writing (best effort by serialization)
            s = json.dumps(data, ensure_ascii=False, indent=2)
            if len(s.encode("utf-8")) > MAX_FILE_BYTES:
                show_toast("保存失敗", "サイズ超過のため保存できません")
                return

            write_json_atomic(path, data)
            show_toast("保存完了", "チェック状態を保存しました")
        except Exception:
            show_toast("保存失敗", "JSONファイルエラー")

    # -------------------------
    # Geometry / AppBar / Move prevention
    # -------------------------
    def apply_appbar_and_geometry(self):
        try:
            width = int(self.settings["window"]["sidebar_width_px"])
            target = self.settings["display"]["target_monitor"]
            mon_rect, has_sub = get_target_monitor_rect(target)
            normalize_settings(self.settings, has_sub)

            hwnd = self.root.winfo_id()

            # Reserve and get final rect
            (l, t, r, b) = appbar_setpos(hwnd, mon_rect, width)
            height = b - t

            # Apply geometry
            self.root.geometry(f"{width}x{height}+{l}+{t}")
            self.last_good_geometry = (width, height, l, t)
        except Exception:
            # AppBar failure: fallback to right edge on target monitor, no reservation
            try:
                width = int(self.settings["window"]["sidebar_width_px"])
                target = self.settings["display"]["target_monitor"]
                (ml, mt, mr, mb), _ = get_target_monitor_rect(target)
                height = mb - mt
                l = mr - width
                self.root.geometry(f"{width}x{height}+{l}+{mt}")
                self.last_good_geometry = (width, height, l, mt)
            except Exception:
                pass

    def debounce_reposition(self):
        if self.reposition_after_id is not None:
            try:
                self.root.after_cancel(self.reposition_after_id)
            except Exception:
                pass
        self.reposition_after_id = self.root.after(250, self._do_reposition_once)

    def _do_reposition_once(self):
        self.reposition_after_id = None
        self.apply_appbar_and_geometry()

    def on_configure(self, event=None):
        # Prevent moving: if user drags, we snap back (debounced).
        # Also respond to environment changes
        self.debounce_reposition()

    def periodic_enforce(self):
        # Enforce topmost based on RDP
        try:
            self.root.attributes("-topmost", not is_remote_session())
        except Exception:
            pass
        # Also enforce geometry if drifted
        try:
            if self.last_good_geometry:
                w, h, x, y = self.last_good_geometry
                # If moved significantly, snap back
                curx = self.root.winfo_x()
                cury = self.root.winfo_y()
                if abs(curx - x) > 2 or abs(cury - y) > 2:
                    self.apply_appbar_and_geometry()
        except Exception:
            pass
        self.root.after(1000, self.periodic_enforce)


def main():
    set_dpi_awareness()

    if not ensure_single_instance():
        messagebox.showinfo("起動済み", "既に起動しています。")
        return

    app_dir = os.path.abspath(os.path.dirname(sys.argv[0]))

    root = tk.Tk()

    # Create and run
    SidebarChecklistApp(root, app_dir)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # As a last resort, show something without crashing silently
        try:
            messagebox.showerror("エラー", "予期しないエラーが発生しました。\n\n" + traceback.format_exc())
        except Exception:
            pass
        raise
