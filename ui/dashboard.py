from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from app_utils.locked_apps_repository import (
    list_locked_apps,
    lock_apps,
    unlock_all_apps,
    unlock_apps,
)
from app_utils.logger import logger
from app_utils.paths import APP_DISPLAY_NAME
from app_utils.software_inventory import (
    InventoryApp,
    build_software_inventory,
    is_valid_executable,
    normalize_path,
)
from security.auth_manager import (
    change_master_password,
    get_master_password_policy_hint,
    is_master_password_set,
    setup_master_password,
    validate_master_password_strength,
)
from ui.password_prompt import prompt_for_master_password

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys
from PIL import Image, ImageDraw, ImageTk

# Enable DPI awareness to ensure native crisp rendering of Tkinter and High-DPI support
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

BI_RGB = 0
DIB_RGB_COLORS = 0
DI_NORMAL = 0x0003
SHGFI_ICON = 0x000000100
SHGFI_SMALLICON = 0x000000001
SHGFI_LARGEICON = 0x000000000

shell32 = ctypes.windll.shell32
user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32


class SHFILEINFOW(ctypes.Structure):
    _fields_ = [
        ("hIcon", wintypes.HICON),
        ("iIcon", ctypes.c_int),
        ("dwAttributes", wintypes.DWORD),
        ("szDisplayName", wintypes.WCHAR * 260),
        ("szTypeName", wintypes.WCHAR * 80),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class RGBQUAD(ctypes.Structure):
    _fields_ = [
        ("rgbBlue", ctypes.c_ubyte),
        ("rgbGreen", ctypes.c_ubyte),
        ("rgbRed", ctypes.c_ubyte),
        ("rgbReserved", ctypes.c_ubyte),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", RGBQUAD * 1),
    ]


def _icon_size_flags(size: tuple[int, int]) -> int:
    # Always request the LARGEICON from the shell to capture maximum detail, avoiding blurry 16x16 scaling
    return SHGFI_LARGEICON


def _extract_shell_icon_handle(path: str, size: tuple[int, int]) -> int | None:
    file_info = SHFILEINFOW()
    flags = SHGFI_ICON | _icon_size_flags(size)
    result = shell32.SHGetFileInfoW(
        path,
        0,
        ctypes.byref(file_info),
        ctypes.sizeof(file_info),
        flags,
    )
    if result and file_info.hIcon:
        return int(file_info.hIcon)
    return None


def _extract_private_icon_handle(path: str, size: tuple[int, int]) -> int | None:
    hicon = wintypes.HICON()
    extracted = shell32.PrivateExtractIconsW(
        path,
        0,
        size[0],
        size[1],
        ctypes.byref(hicon),
        None,
        1,
        0,
    )
    if extracted > 0 and hicon.value:
        return int(hicon.value)
    return None


def _extract_fallback_icon_handle(path: str) -> int | None:
    hicon_large = wintypes.HICON()
    hicon_small = wintypes.HICON()
    extracted = shell32.ExtractIconExW(
        ctypes.c_wchar_p(path),
        0,
        ctypes.byref(hicon_large),
        ctypes.byref(hicon_small),
        1,
    )
    if extracted <= 0:
        return None

    preferred = hicon_large.value or hicon_small.value
    if not preferred:
        if hicon_large.value:
            user32.DestroyIcon(hicon_large)
        if hicon_small.value:
            user32.DestroyIcon(hicon_small)
        return None

    unused = hicon_small.value if preferred == hicon_large.value else hicon_large.value
    if unused:
        user32.DestroyIcon(wintypes.HICON(unused))
    return int(preferred)


def _hicon_to_image(hicon: int, size: tuple[int, int]) -> Image.Image | None:
    width, height = size
    screen_dc = user32.GetDC(None)
    if not screen_dc:
        return None

    mem_dc = gdi32.CreateCompatibleDC(screen_dc)
    if not mem_dc:
        user32.ReleaseDC(None, screen_dc)
        return None

    bitmap_info = BITMAPINFO()
    bitmap_info.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bitmap_info.bmiHeader.biWidth = width
    bitmap_info.bmiHeader.biHeight = -height
    bitmap_info.bmiHeader.biPlanes = 1
    bitmap_info.bmiHeader.biBitCount = 32
    bitmap_info.bmiHeader.biCompression = BI_RGB

    bits = ctypes.c_void_p()
    dib = gdi32.CreateDIBSection(
        mem_dc,
        ctypes.byref(bitmap_info),
        DIB_RGB_COLORS,
        ctypes.byref(bits),
        None,
        0,
    )
    if not dib or not bits:
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(None, screen_dc)
        return None

    old_bitmap = gdi32.SelectObject(mem_dc, dib)
    try:
        ctypes.memset(bits, 0, width * height * 4)
        if not user32.DrawIconEx(
            mem_dc, 0, 0, hicon, width, height, 0, None, DI_NORMAL
        ):
            return None
        pixel_data = ctypes.string_at(bits, width * height * 4)
    finally:
        if old_bitmap:
            gdi32.SelectObject(mem_dc, old_bitmap)
        gdi32.DeleteObject(dib)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(None, screen_dc)

    return Image.frombuffer(
        "RGBA", (width, height), pixel_data, "raw", "BGRA", 0, 1
    ).copy()


def extract_icon_from_exe(
    path: str, size: tuple[int, int] = (24, 24)
) -> Image.Image | None:
    if not path or not os.path.exists(path):
        return None

    # Try extracting high-resolution icons directly from the executable first
    # High-quality downsampling (Lanczos) from 64x64 or 48x48 yields beautifully sharp, crisp output
    for candidate_size in ((64, 64), (48, 48), (32, 32)):
        hicon: int | None = None
        try:
            hicon = _extract_private_icon_handle(path, candidate_size)
            if hicon:
                img = _hicon_to_image(hicon, candidate_size)
                if img:
                    resample = getattr(Image, "Resampling", Image).LANCZOS
                    return img.resize(size, resample)
        except Exception:
            pass
        finally:
            if hicon:
                user32.DestroyIcon(wintypes.HICON(hicon))

    # Fallback to standard shell/fallback extraction at 32x32 to guarantee maximum sharpness
    hicon: int | None = None
    try:
        hicon = _extract_shell_icon_handle(
            path, (32, 32)
        ) or _extract_fallback_icon_handle(path)
        if hicon:
            img = _hicon_to_image(hicon, (32, 32))
            if img:
                resample = getattr(Image, "Resampling", Image).LANCZOS
                return img.resize(size, resample)
    except Exception:
        pass
    finally:
        if hicon:
            user32.DestroyIcon(wintypes.HICON(hicon))

    return None


def get_app_icon(
    path: str, app_name: str, size: tuple[int, int] = (24, 24)
) -> ImageTk.PhotoImage:
    if path and os.path.exists(path):
        img = None
        if path.lower().endswith((".png", ".jpg", ".jpeg", ".bmp")):
            try:
                with Image.open(path) as image:
                    resample = getattr(Image, "Resampling", Image).LANCZOS
                    img = image.convert("RGBA").resize(size, resample)
            except Exception:
                pass
        else:
            img = extract_icon_from_exe(path, size=size)

        if img is not None:
            return ImageTk.PhotoImage(img)

    # Fallback premium icon
    img = Image.new("RGBA", size, color=(255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    colors = [
        (31, 111, 235),
        (15, 118, 110),
        (225, 29, 72),
        (147, 51, 234),
        (217, 119, 6),
        (5, 150, 105),
    ]
    color = colors[hash(app_name) % len(colors)]
    draw.rounded_rectangle([0, 0, size[0] - 1, size[1] - 1], radius=4, fill=color)

    letter = (app_name.strip() or "A")[0].upper()
    w, h = size
    draw.text((w / 2, h / 2), letter, fill=(255, 255, 255), anchor="mm")
    return ImageTk.PhotoImage(img)


def _resolve_asset_path(filename: str) -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "assets" / filename
    return Path(__file__).resolve().parent.parent / "assets" / filename


def load_dashboard_logo(size: tuple[int, int] = (84, 84)) -> ImageTk.PhotoImage | None:
    logo_path = _resolve_asset_path("dashboard_logo.png")
    if not logo_path.exists():
        return None

    try:
        with Image.open(logo_path) as image:
            resample = getattr(Image, "Resampling", Image).LANCZOS
            prepared = image.convert("RGBA").resize(size, resample)
        return ImageTk.PhotoImage(prepared)
    except Exception as exc:
        logger.warning("Failed to load dashboard logo from %s: %s", logo_path, exc)
        return None


def filter_displayable_inventory_rows(
    inventory: list[InventoryApp],
) -> list[InventoryApp]:
    return [app for app in inventory if app.path or app.is_locked]


class Dashboard(tk.Toplevel):
    def __init__(self, master: tk.Misc | None = None, controller=None):
        super().__init__(master=master)
        self.controller = controller
        self.title(APP_DISPLAY_NAME)
        self.geometry("1080x640")
        self.minsize(900, 520)
        self.configure(bg="#f4f7fb")

        self.icon_cache: dict[str, ImageTk.PhotoImage] = {}
        self.header_logo_image: ImageTk.PhotoImage | None = None
        self.search_var = tk.StringVar()
        self.status_filter_var = tk.StringVar(value="All")
        self.inventory_rows: list[InventoryApp] = []
        self.displayed_rows: list[InventoryApp] = []
        self.tree_index: dict[str, InventoryApp] = {}
        self.refresh_results: queue.Queue = queue.Queue()
        self._refresh_token = 0
        self._refresh_in_progress = False

        self._configure_tree_style()
        self.create_widgets()

        self.search_var.trace_add("write", lambda *_args: self.apply_search_filter())
        self.after(150, self._poll_refresh_results)
        self.after(100, self.bootstrap_dashboard)

    def _configure_tree_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Inventory.Treeview", rowheight=28, font=("Segoe UI", 10))
        style.configure(
            "Inventory.Treeview.Heading",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 6),
        )
        style.configure(
            "Filter.TCombobox",
            padding=4,
            arrowsize=14,
            borderwidth=1,
            fieldbackground="#ffffff",
            background="#ffffff",
            foreground="#1f2a37",
            bordercolor="#000000",
            lightcolor="#ffffff",
            darkcolor="#ffffff",
            arrowcolor="#000000",
            focuscolor="#ffffff",
        )
        style.map(
            "Filter.TCombobox",
            fieldbackground=[
                ("readonly", "#ffffff"),
                ("disabled", "#edf2f7"),
            ],
            background=[
                ("readonly", "#ffffff"),
                ("disabled", "#edf2f7"),
            ],
            bordercolor=[
                ("focus readonly", "#000000"),
                ("readonly", "#000000"),
                ("disabled", "#c7d3e0"),
            ],
            lightcolor=[
                ("focus readonly", "#ffffff"),
                ("readonly", "#ffffff"),
                ("disabled", "#edf2f7"),
            ],
            darkcolor=[
                ("focus readonly", "#ffffff"),
                ("readonly", "#ffffff"),
                ("disabled", "#edf2f7"),
            ],
            foreground=[
                ("readonly", "#1f2a37"),
                ("disabled", "#7b8794"),
            ],
            selectbackground=[("readonly", "#ffffff")],
            selectforeground=[("readonly", "#1f2a37")],
            focuscolor=[
                ("focus", "#ffffff"),
                ("readonly", "#ffffff"),
            ],
            arrowcolor=[
                ("readonly", "#000000"),
                ("disabled", "#94a3b8"),
            ],
        )

    def create_widgets(self):
        outer = tk.Frame(self, bg="#f4f7fb")
        outer.pack(fill=tk.BOTH, expand=True, padx=18, pady=18)

        header = tk.Frame(outer, bg="#f4f7fb")
        header.pack(fill=tk.X, pady=(0, 14))

        title_row = tk.Frame(header, bg="#f4f7fb")
        title_row.pack(fill=tk.X)

        brand_block = tk.Frame(title_row, bg="#f4f7fb")
        brand_block.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.header_logo_image = load_dashboard_logo(size=(88, 88))
        if self.header_logo_image is not None:
            tk.Label(
                brand_block,
                image=self.header_logo_image,
                bg="#f4f7fb",
            ).pack(side=tk.LEFT, padx=(0, 10), pady=(0, 0))

        title_text_block = tk.Frame(brand_block, bg="#f4f7fb")
        title_text_block.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=(3, 0))

        tk.Label(
            title_text_block,
            text="Security Dashboard",
            font=("Segoe UI", 16, "bold"),
            bg="#f4f7fb",
            fg="#1f2a37",
        ).pack(anchor=tk.W)

        self.settings_button = tk.Menubutton(
            title_row,
            text="\u2699",
            font=("Segoe UI Symbol", 16),
            bg="#f4f7fb",
            fg="#1f2a37",
            activebackground="#e7eef8",
            activeforeground="#1f2a37",
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
            padx=6,
            pady=0,
            cursor="hand2",
        )
        self.settings_menu = tk.Menu(self.settings_button, tearoff=0)
        self.settings_menu.add_command(
            label="View Audit Log",
            command=self.show_audit_log_dialog,
        )
        self.settings_menu.add_command(
            label="Recover Password",
            command=self.show_recovery_dialog,
        )
        self.settings_menu.add_command(
            label="Reset Password",
            command=self.show_reset_password_dialog,
        )
        self.settings_menu.add_command(
            label="Unlock All Applications",
            command=self.unlock_all_locked_applications,
        )
        self.settings_button.configure(menu=self.settings_menu)
        self.settings_button.pack(side=tk.RIGHT, anchor=tk.E)

        self.refresh_button = tk.Button(
            title_row,
            text="Refresh",
            width=12,
            command=self.refresh_inventory,
            bg="#e7eef8",
            fg="#1f3a5f",
            relief=tk.FLAT,
            cursor="hand2",
        )
        self.refresh_button.pack(side=tk.RIGHT, padx=(0, 8), anchor=tk.E)

        tk.Label(
            title_text_block,
            text="Secure, monitor, and manage protected applications from one unified dashboard.",
            font=("Segoe UI", 10),
            bg="#f4f7fb",
            fg="#5b6470",
            justify=tk.LEFT,
            wraplength=620,
        ).pack(anchor=tk.W, pady=(2, 0))

        toolbar = tk.Frame(outer, bg="#f4f7fb")
        toolbar.pack(fill=tk.X, pady=(0, 12))

        search_card = tk.Frame(toolbar, bg="#ffffff", bd=1, relief=tk.SOLID)
        search_card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12))

        self.search_var.set("Search...")
        self.search_entry = tk.Entry(
            search_card,
            textvariable=self.search_var,
            font=("Segoe UI", 10),
            relief=tk.FLAT,
            bg="#ffffff",
            fg="#888888",
        )
        self.search_entry.pack(fill=tk.X, padx=12, pady=6)

        self.search_entry.bind("<FocusIn>", self._on_search_focus_in)
        self.search_entry.bind("<FocusOut>", self._on_search_focus_out)

        actions = tk.Frame(toolbar, bg="#f4f7fb")
        actions.pack(side=tk.RIGHT)

        self.custom_path_button = tk.Button(
            toolbar,
            text="Custom Path",
            width=14,
            command=self.lock_custom_path,
            bg="#f4f0ff",
            fg="#4b2e83",
            relief=tk.FLAT,
            cursor="hand2",
        )
        self.custom_path_button.pack(side=tk.LEFT, padx=(0, 8))

        self.lock_button = tk.Button(
            actions,
            text="Lock Selected",
            width=14,
            command=self.lock_selected_apps,
            bg="#1f6feb",
            fg="#ffffff",
            relief=tk.FLAT,
        )
        self.lock_button.pack(side=tk.LEFT, padx=4)

        self.unlock_button = tk.Button(
            actions,
            text="Unlock Selected",
            width=14,
            command=self.unlock_selected_apps,
            bg="#0f766e",
            fg="#ffffff",
            relief=tk.FLAT,
        )
        self.unlock_button.pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="Loading software inventory...")
        self.summary_var = tk.StringVar(value="")

        status_bar = tk.Frame(outer, bg="#f4f7fb")
        status_bar.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            status_bar,
            textvariable=self.status_var,
            font=("Segoe UI", 10),
            bg="#f4f7fb",
            fg="#1f2a37",
        ).pack(side=tk.LEFT)

        status_actions = tk.Frame(status_bar, bg="#f4f7fb")
        status_actions.pack(side=tk.RIGHT)

        filter_group = tk.Frame(status_actions, bg="#f4f7fb")
        filter_group.pack(side=tk.LEFT, padx=(0, 14))

        tk.Label(
            filter_group,
            text="Filter:",
            font=("Segoe UI", 10, "bold"),
            bg="#f4f7fb",
            fg="#1f2a37",
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.filter_combo = ttk.Combobox(
            filter_group,
            textvariable=self.status_filter_var,
            values=("All", "Locked", "Unlocked"),
            state="readonly",
            width=12,
            style="Filter.TCombobox",
            takefocus=False,
        )
        self.filter_combo.pack(side=tk.LEFT)
        self.filter_combo.bind("<<ComboboxSelected>>", self._on_status_filter_changed)

        tk.Label(
            status_actions,
            textvariable=self.summary_var,
            font=("Segoe UI", 10, "bold"),
            bg="#f4f7fb",
            fg="#3b556f",
        ).pack(side=tk.LEFT)

        tree_card = tk.Frame(outer, bg="#ffffff", bd=1, relief=tk.SOLID)
        tree_card.pack(fill=tk.BOTH, expand=True)

        columns = ("status", "path")
        self.tree = ttk.Treeview(
            tree_card,
            columns=columns,
            show="tree headings",
            selectmode="extended",
            style="Inventory.Treeview",
        )
        self.tree.heading("#0", text="Name")
        self.tree.heading("status", text="Status")
        self.tree.heading("path", text="Path")

        self.tree.column("#0", width=280, anchor=tk.W, stretch=False)
        self.tree.column("status", width=110, anchor=tk.CENTER, stretch=False)
        self.tree.column("path", width=604, anchor=tk.W)

        self.tree.tag_configure("locked", background="#fdecec")
        self.tree.tag_configure("unlocked", background="#eef8f0")
        self.tree.tag_configure("missing_path", foreground="#9a6700")

        y_scroll = ttk.Scrollbar(tree_card, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(
            tree_card, orient=tk.HORIZONTAL, command=self.tree.xview
        )
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        tree_card.grid_rowconfigure(0, weight=1)
        tree_card.grid_columnconfigure(0, weight=1)

    def _on_search_focus_in(self, event):
        if self.search_var.get() == "Search...":
            self.search_var.set("")
            self.search_entry.config(fg="#000000")

    def _on_search_focus_out(self, event):
        if not self.search_var.get().strip():
            self.search_var.set("Search...")
            self.search_entry.config(fg="#888888")

    def _on_status_filter_changed(self, _event=None):
        self.apply_search_filter()

    def _status_filter_label(self) -> str:
        value = self.status_filter_var.get().strip()
        return value if value in {"All", "Locked", "Unlocked"} else "All"

    def _status_filter_key(self) -> str:
        labels = {
            "All": "all",
            "Locked": "locked",
            "Unlocked": "unlocked",
        }
        return labels.get(self._status_filter_label(), "all")

    def bootstrap_dashboard(self):
        if not is_master_password_set():
            self.show_setup_password_dialog()
        self.refresh_inventory()

    def _center_child_dialog(self, dialog: tk.Toplevel) -> None:
        try:
            dialog.tk.call("tk", "PlaceWindow", dialog._w, "center")
            return
        except Exception:
            pass

        dialog.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - dialog.winfo_width()) // 2
        y = self.winfo_y() + (self.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _fit_dialog_to_content(
        self,
        dialog: tk.Toplevel,
        *,
        min_width: int = 0,
        min_height: int = 0,
    ) -> None:
        dialog.update_idletasks()
        width = max(dialog.winfo_reqwidth(), min_width)
        height = max(dialog.winfo_reqheight(), min_height)
        dialog.geometry(f"{width}x{height}")
        self._center_child_dialog(dialog)

    def show_setup_password_dialog(self):
        from app_utils.paths import get_project_root
        
        dialog = tk.Toplevel(self)
        dialog.title("Initial Setup")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#ffffff")
        dialog.resizable(False, False)
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        
        main_container = tk.Frame(dialog, bg="#ffffff")
        main_container.pack(fill=tk.BOTH, expand=True, padx=48, pady=(24, 32))

        # Logo
        try:
            logo_path = get_project_root() / "assets" / "dashboard_logo.png"
            img = Image.open(logo_path).resize((64, 64), Image.Resampling.LANCZOS)
            self._setup_logo = ImageTk.PhotoImage(img)
            logo_lbl = tk.Label(main_container, image=self._setup_logo, bg="#ffffff")
            logo_lbl.pack(pady=(0, 16))
        except Exception:
            pass

        # Headers
        tk.Label(
            main_container,
            text=f"Welcome to {APP_DISPLAY_NAME}",
            font=("Segoe UI", 16, "bold"),
            bg="#ffffff",
            fg="#1f2a37",
        ).pack(pady=(0, 4))
        tk.Label(
            main_container,
            text="Set the master password used for unlocking\nand dashboard changes.",
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#4b5563",
            justify=tk.CENTER
        ).pack(pady=(0, 20))

        # Policy Box
        policy_frame = tk.Frame(main_container, bg="#faf8ff", highlightbackground="#e9e3ff", highlightthickness=1)
        policy_frame.pack(fill=tk.X, pady=(0, 20))
        
        policy_inner = tk.Frame(policy_frame, bg="#faf8ff")
        policy_inner.pack(padx=16, pady=12)
        tk.Label(
            policy_inner,
            text="🛡\ufe0f Use at least 12 characters and include all of these:\nuppercase letters, lowercase letters, numbers, and symbols.",
            font=("Segoe UI", 9),
            bg="#faf8ff",
            fg="#5b21b6",
            justify=tk.CENTER
        ).pack()

        # Helper to create input fields
        def create_input_field(parent, label_text, placeholder_text):
            tk.Label(
                parent, text=label_text, font=("Segoe UI", 9), bg="#ffffff", fg="#374151"
            ).pack(anchor=tk.W, pady=(0, 6))
            
            field_frame = tk.Frame(parent, bg="#ffffff", highlightbackground="#d1d5db", highlightthickness=1)
            field_frame.pack(fill=tk.X, pady=(0, 16))
            
            # Left icon (Lock)
            tk.Label(field_frame, text="\U0001f512", font=("Segoe UI", 10), bg="#ffffff", fg="#9ca3af").pack(side=tk.LEFT, padx=12)
            
            entry_var = tk.StringVar()
            entry = tk.Entry(field_frame, textvariable=entry_var, font=("Segoe UI", 10), show="*", bd=0, highlightthickness=0, bg="#ffffff", fg="#111827", insertbackground="#111827")
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
            
            # Placeholder logic
            def on_focus_in(e):
                if entry_var.get() == placeholder_text:
                    entry.delete(0, tk.END)
                    entry.config(fg="#111827", show="*")
            def on_focus_out(e):
                if not entry_var.get():
                    entry.insert(0, placeholder_text)
                    entry.config(fg="#9ca3af", show="")
            
            entry.insert(0, placeholder_text)
            entry.config(fg="#9ca3af", show="")
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
            
            # Eye toggle
            eye_lbl = tk.Label(field_frame, text="\U0001f441\ufe0f", font=("Segoe UI", 11), bg="#ffffff", fg="#6b7280", cursor="hand2")
            eye_lbl.pack(side=tk.RIGHT, padx=12)
            
            def toggle_eye(e):
                if entry_var.get() != placeholder_text:
                    current_show = entry.cget("show")
                    entry.config(show="" if current_show == "*" else "*")
            eye_lbl.bind("<Button-1>", toggle_eye)
            
            return entry, entry_var

        pwd_entry, pwd_var = create_input_field(main_container, "Master Password", "Enter master password")
        confirm_entry, confirm_var = create_input_field(main_container, "Re-enter Password", "Confirm master password")

        def save_password(event=None):
            # Clean placeholders
            if pwd_var.get() == "Enter master password": pwd_entry.delete(0, tk.END)
            if confirm_var.get() == "Confirm master password": confirm_entry.delete(0, tk.END)
            
            password = pwd_entry.get()
            confirmation = confirm_entry.get()
            validation_error = validate_master_password_strength(password)
            if validation_error:
                messagebox.showerror("Weak Password", validation_error, parent=dialog)
                pwd_entry.focus_set()
                return
            if password != confirmation:
                messagebox.showerror("Password Mismatch", "The passwords do not match.", parent=dialog)
                confirm_entry.focus_set()
                return
            success, result = setup_master_password(password)
            if success:
                recovery_key = result
                dialog.grab_release()
                dialog.destroy()
                self._show_recovery_key_dialog(recovery_key)
                return
            messagebox.showerror("Error", result, parent=dialog)

        # Save Button
        save_btn = tk.Button(
            main_container,
            text="\U0001f512 Save Password",
            font=("Segoe UI", 10, "bold"),
            bg="#5b21b6",
            fg="#ffffff",
            activebackground="#4c1d95",
            activeforeground="#ffffff",
            bd=0,
            cursor="hand2",
            command=save_password
        )
        save_btn.pack(fill=tk.X, pady=(12, 0), ipady=8)

        pwd_entry.bind("<Return>", lambda _e: confirm_entry.focus_set())
        confirm_entry.bind("<Return>", save_password)

        dialog.after(100, pwd_entry.focus_set)
        self._fit_dialog_to_content(dialog, min_width=520, min_height=580)

    def _show_recovery_key_dialog(self, recovery_key: str):
        dialog = tk.Toplevel(self)
        dialog.title("Recovery Key")
        dialog.geometry("480x320")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#ffffff")
        dialog.resizable(False, False)

        self._center_child_dialog(dialog)

        tk.Label(
            dialog,
            text="Save Your Recovery Key",
            font=("Segoe UI", 12, "bold"),
            bg="#ffffff",
            fg="#d97706",
        ).pack(pady=(16, 8))

        tk.Label(
            dialog,
            text="This key is the ONLY way to reset your password if forgotten.\n"
            "Store it in a safe place (password manager, printed copy, etc.).\n"
            "It will NOT be shown again.",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#5b6470",
            justify=tk.CENTER,
        ).pack(pady=(0, 12))

        key_frame = tk.Frame(dialog, bg="#fef3c7", bd=2, relief=tk.SOLID)
        key_frame.pack(fill=tk.X, padx=24, pady=8)

        key_label = tk.Label(
            key_frame,
            text=recovery_key,
            font=("Consolas", 14, "bold"),
            bg="#fef3c7",
            fg="#92400e",
        )
        key_label.pack(pady=12)

        def copy_key():
            self.clipboard_clear()
            self.clipboard_append(recovery_key)
            self.update()
            messagebox.showinfo(
                "Copied", "Recovery key copied to clipboard.", parent=dialog
            )

        tk.Button(
            dialog,
            text="Copy to Clipboard",
            command=copy_key,
            width=20,
            bg="#d97706",
            fg="#ffffff",
            relief=tk.FLAT,
        ).pack(pady=8)

        acknowledged = [False]

        def confirm_acknowledge():
            acknowledged[0] = True
            dialog.destroy()

        tk.Button(
            dialog,
            text="I Have Saved This Key",
            command=confirm_acknowledge,
            width=20,
            bg="#1f6feb",
            fg="#ffffff",
            relief=tk.FLAT,
        ).pack(pady=(0, 14))

        dialog.protocol("WM_DELETE_WINDOW", confirm_acknowledge)
        self.wait_window(dialog)
        if not acknowledged[0]:
            self._show_recovery_key_dialog(recovery_key)

    def show_recovery_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Password Recovery")
        dialog.geometry("440x300")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#ffffff")
        dialog.resizable(False, False)

        self._center_child_dialog(dialog)

        tk.Label(
            dialog,
            text="Recover Account Access",
            font=("Segoe UI", 12, "bold"),
            bg="#ffffff",
            fg="#1f2a37",
        ).pack(pady=(16, 8))

        tk.Label(
            dialog,
            text="Enter your recovery key and a new password.",
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#5b6470",
        ).pack(pady=(0, 10))

        tk.Label(
            dialog,
            text="Recovery Key",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#5b6470",
        ).pack(anchor=tk.W, padx=24)
        key_entry = tk.Entry(dialog, width=34)
        key_entry.pack(pady=(4, 8), padx=24)

        tk.Label(
            dialog,
            text="New Password",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#5b6470",
        ).pack(anchor=tk.W, padx=24)
        new_entry = tk.Entry(dialog, show="*", width=34)
        new_entry.pack(pady=(4, 8), padx=24)

        tk.Label(
            dialog,
            text="Confirm New Password",
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#5b6470",
        ).pack(anchor=tk.W, padx=24)
        confirm_entry = tk.Entry(dialog, show="*", width=34)
        confirm_entry.pack(pady=(4, 12), padx=24)

        def submit_recovery():
            from security.auth_manager import reset_password_with_recovery_key

            recovery_key = key_entry.get().strip()
            new_password = new_entry.get()
            validation_error = validate_master_password_strength(new_password)
            if validation_error:
                messagebox.showerror("Weak Password", validation_error, parent=dialog)
                new_entry.focus_set()
                new_entry.select_range(0, tk.END)
                return
            if new_password != confirm_entry.get():
                messagebox.showerror(
                    "Password Mismatch",
                    "The new passwords do not match.",
                    parent=dialog,
                )
                confirm_entry.focus_set()
                confirm_entry.select_range(0, tk.END)
                return

            success, result = reset_password_with_recovery_key(
                recovery_key, new_password
            )
            if success:
                new_recovery_key = result
                dialog.destroy()
                self._show_recovery_key_dialog(new_recovery_key)
                messagebox.showinfo(
                    "Success",
                    "Password reset successfully. A new recovery key has been generated.",
                    parent=self,
                )
                return

            messagebox.showerror("Error", result, parent=dialog)

        button_row = tk.Frame(dialog, bg="#ffffff")
        button_row.pack(pady=(6, 14))

        tk.Button(
            button_row,
            text="Reset Password",
            width=16,
            command=submit_recovery,
            bg="#1f6feb",
            fg="#ffffff",
            relief=tk.FLAT,
        ).pack(side=tk.LEFT, padx=6)
        tk.Button(
            button_row,
            text="Cancel",
            width=12,
            command=dialog.destroy,
            bg="#e7eef8",
            fg="#1f3a5f",
            relief=tk.FLAT,
        ).pack(side=tk.LEFT, padx=6)

        key_entry.focus_set()
        key_entry.bind("<Return>", lambda _event: new_entry.focus_set())
        new_entry.bind("<Return>", lambda _event: confirm_entry.focus_set())
        confirm_entry.bind("<Return>", lambda _event: submit_recovery())
        self._fit_dialog_to_content(dialog, min_width=440, min_height=340)

    def show_reset_password_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Reset Password")
        dialog.geometry("420x280")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#ffffff")
        dialog.resizable(False, False)

        tk.Label(
            dialog,
            text="Reset Master Password",
            font=("Segoe UI", 12, "bold"),
            bg="#ffffff",
            fg="#1f2a37",
        ).pack(pady=(18, 8))
        tk.Label(
            dialog,
            text="Enter your current password and the new password.",
            font=("Segoe UI", 10),
            bg="#ffffff",
            fg="#5b6470",
        ).pack(pady=(0, 10))
        tk.Label(
            dialog,
            text=get_master_password_policy_hint(),
            font=("Segoe UI", 9),
            bg="#ffffff",
            fg="#6b7280",
            wraplength=340,
            justify=tk.CENTER,
        ).pack(pady=(0, 8))

        form = tk.Frame(dialog, bg="#ffffff")
        form.pack(padx=20, fill=tk.X)

        tk.Label(
            form, text="Previous Password", font=("Segoe UI", 10), bg="#ffffff"
        ).pack(anchor=tk.W)
        previous_entry = tk.Entry(form, show="*", width=34)
        previous_entry.pack(fill=tk.X, pady=(4, 10))

        tk.Label(form, text="New Password", font=("Segoe UI", 10), bg="#ffffff").pack(
            anchor=tk.W
        )
        new_entry = tk.Entry(form, show="*", width=34)
        new_entry.pack(fill=tk.X, pady=(4, 10))

        tk.Label(
            form, text="Confirm New Password", font=("Segoe UI", 10), bg="#ffffff"
        ).pack(anchor=tk.W)
        confirm_entry = tk.Entry(form, show="*", width=34)
        confirm_entry.pack(fill=tk.X, pady=(4, 10))

        def submit_password_change():
            new_password = new_entry.get()
            validation_error = validate_master_password_strength(new_password)
            if validation_error:
                messagebox.showerror("Weak Password", validation_error, parent=dialog)
                new_entry.focus_set()
                new_entry.select_range(0, tk.END)
                return
            if new_password != confirm_entry.get():
                messagebox.showerror(
                    "Password Mismatch",
                    "The new passwords do not match.",
                    parent=dialog,
                )
                confirm_entry.focus_set()
                confirm_entry.select_range(0, tk.END)
                return
            success, message = change_master_password(
                previous_entry.get(),
                new_password,
            )
            if success:
                self.status_var.set("Master password updated successfully.")
                messagebox.showinfo("Success", message, parent=dialog)
                dialog.destroy()
                return

            messagebox.showerror("Error", message, parent=dialog)
            previous_entry.focus_set()
            previous_entry.select_range(0, tk.END)

        button_row = tk.Frame(dialog, bg="#ffffff")
        button_row.pack(pady=(6, 14))

        tk.Button(
            button_row,
            text="Update Password",
            width=16,
            command=submit_password_change,
            bg="#1f6feb",
            fg="#ffffff",
            relief=tk.FLAT,
        ).pack(side=tk.LEFT, padx=6)
        tk.Button(
            button_row,
            text="Cancel",
            width=12,
            command=dialog.destroy,
            bg="#e7eef8",
            fg="#1f3a5f",
            relief=tk.FLAT,
        ).pack(side=tk.LEFT, padx=6)

        previous_entry.bind("<Return>", lambda _event: new_entry.focus_set())
        new_entry.bind("<Return>", lambda _event: confirm_entry.focus_set())
        confirm_entry.bind("<Return>", lambda _event: submit_password_change())
        previous_entry.focus_set()
        self._fit_dialog_to_content(dialog, min_width=420, min_height=340)

    def show_audit_log_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Security Audit Log")
        dialog.geometry("720x480")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg="#ffffff")
        dialog.resizable(True, True)

        self._center_child_dialog(dialog)

        tk.Label(
            dialog,
            text="Security Audit Log",
            font=("Segoe UI", 12, "bold"),
            bg="#ffffff",
            fg="#1f2a37",
        ).pack(pady=(12, 8))

        tree_frame = tk.Frame(dialog, bg="#ffffff")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)

        columns = ("timestamp", "event", "details")
        tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        tree.heading("timestamp", text="Timestamp")
        tree.heading("event", text="Event")
        tree.heading("details", text="Details")
        tree.column("timestamp", width=180, anchor=tk.W)
        tree.column("event", width=180, anchor=tk.W)
        tree.column("details", width=320, anchor=tk.W)

        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=y_scroll.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        try:
            from config.config_manager import get_connection

            conn = get_connection()
            try:
                rows = conn.execute(
                    "SELECT timestamp, event_type, details FROM security_logs ORDER BY id DESC LIMIT 500"
                ).fetchall()
                for row in rows:
                    tree.insert(
                        "",
                        "end",
                        values=(
                            str(row["timestamp"] or ""),
                            str(row["event_type"] or ""),
                            str(row["details"] or ""),
                        ),
                    )
            finally:
                conn.close()
        except Exception as exc:
            logger.error("Failed to load audit log: %s", exc)
            messagebox.showerror(
                "Error", "Failed to load audit log entries.", parent=dialog
            )

        def export_log():
            try:
                from tkinter import filedialog

                save_path = filedialog.asksaveasfilename(
                    parent=dialog,
                    title="Export Audit Log",
                    defaultextension=".csv",
                    filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt")],
                )
                if not save_path:
                    return
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write("Timestamp,Event,Details\n")
                    for item in tree.get_children():
                        values = tree.item(item, "values")
                        escaped = [
                            '"' + str(v).replace('"', '""') + '"'
                            if "," in str(v)
                            else str(v)
                            for v in values
                        ]
                        f.write(",".join(escaped) + "\n")
                messagebox.showinfo(
                    "Success", f"Audit log exported to {save_path}", parent=dialog
                )
            except Exception as exc:
                logger.error("Failed to export audit log: %s", exc)
                messagebox.showerror(
                    "Error", "Failed to export audit log.", parent=dialog
                )

        btn_frame = tk.Frame(dialog, bg="#ffffff")
        btn_frame.pack(fill=tk.X, padx=16, pady=(0, 12))

        tk.Button(
            btn_frame,
            text="Export CSV",
            width=14,
            command=export_log,
            bg="#1f6feb",
            fg="#ffffff",
            relief=tk.FLAT,
        ).pack(side=tk.LEFT)
        tk.Button(
            btn_frame,
            text="Close",
            width=12,
            command=dialog.destroy,
            bg="#e7eef8",
            fg="#1f3a5f",
            relief=tk.FLAT,
        ).pack(side=tk.RIGHT)

    def unlock_all_locked_applications(self):
        locked_apps = list_locked_apps()
        if not locked_apps:
            messagebox.showinfo(
                "Nothing to Unlock",
                "There are no locked applications to unlock.",
                parent=self,
            )
            return

        if not prompt_for_master_password(
            self,
            title="Unlock All Applications",
            message="Enter the master password to unlock all applications.",
            action_label="Unlock All",
        ):
            return

        try:
            changed = unlock_all_apps()
            logger.info("Unlocked all applications from settings. Count: %s", changed)
            self.status_var.set(f"Unlocked all applications ({changed} removed).")
            self.refresh_inventory()
        except Exception as exc:
            logger.error(f"Error unlocking all applications: {exc}")
            messagebox.showerror(
                "Error", "Failed to unlock all applications.", parent=self
            )

    def lock_custom_path(self):
        selected_path = filedialog.askopenfilename(
            parent=self,
            title="Select an executable to lock",
            filetypes=[("Executable Files", "*.exe")],
        )
        if not selected_path:
            return

        normalized_path = normalize_path(selected_path)
        if not is_valid_executable(normalized_path):
            messagebox.showerror(
                "Invalid File",
                "Please select a valid .exe file.",
                parent=self,
            )
            return

        if not prompt_for_master_password(
            self,
            title="Lock Custom Path",
            message="Enter the master password to lock the selected application.",
            action_label="Lock",
        ):
            return

        custom_app = InventoryApp(
            display_name=os.path.splitext(os.path.basename(normalized_path))[0]
            or os.path.basename(normalized_path),
            executable_name=os.path.basename(normalized_path),
            path=normalized_path,
            icon_path=normalized_path,
            is_locked=False,
            sources=("custom_path",),
        )

        try:
            changed = lock_apps([custom_app])
            if changed:
                logger.info("Locked custom path application: %s", normalized_path)
                self.status_var.set(
                    f"Locked custom application: {custom_app.executable_name}"
                )
            else:
                self.status_var.set(
                    f"Application already locked: {custom_app.executable_name}"
                )
                messagebox.showinfo(
                    "Already Locked",
                    "That application is already in the locked list.",
                    parent=self,
                )
            self.refresh_inventory()
        except ValueError as exc:
            logger.error("Rejected insecure custom lock rule: %s", exc)
            messagebox.showerror("Cannot Lock Application", str(exc), parent=self)
        except Exception as exc:
            logger.error(f"Error locking custom path application: {exc}")
            messagebox.showerror(
                "Error", "Failed to lock the selected application.", parent=self
            )

    def refresh_inventory(self):
        if self._refresh_in_progress:
            return

        self._refresh_in_progress = True
        self._refresh_token += 1
        refresh_token = self._refresh_token

        self.status_var.set("Refreshing installed software inventory...")
        self._set_buttons_enabled(False)

        worker = threading.Thread(
            target=self._refresh_inventory_worker,
            args=(refresh_token,),
            daemon=True,
        )
        worker.start()

    def _refresh_inventory_worker(self, refresh_token: int):
        try:
            locked_apps = list_locked_apps()
            inventory = build_software_inventory(locked_apps)
            self.refresh_results.put((refresh_token, inventory, None))
        except Exception as exc:
            logger.error(f"Error refreshing inventory: {exc}")
            self.refresh_results.put((refresh_token, None, exc))

    def _poll_refresh_results(self):
        try:
            while True:
                refresh_token, inventory, error = self.refresh_results.get_nowait()
                self._apply_inventory_results(refresh_token, inventory, error)
        except queue.Empty:
            pass

        if self.winfo_exists():
            self.after(150, self._poll_refresh_results)

    def _apply_inventory_results(self, refresh_token: int, inventory, error):
        if not self.winfo_exists() or refresh_token != self._refresh_token:
            return

        self._refresh_in_progress = False
        self._set_buttons_enabled(True)

        if error is not None:
            self.status_var.set("Inventory refresh failed. See logs for details.")
            messagebox.showerror(
                "Error", "Failed to refresh software inventory.", parent=self
            )
            return

        self.icon_cache.clear()
        self.inventory_rows = filter_displayable_inventory_rows(list(inventory or []))
        self.apply_search_filter()

    def apply_search_filter(self):
        raw_query = self._sanitize_query(self.search_var.get())
        query = "" if raw_query == "Search..." else raw_query.casefold()
        status_filter = self._status_filter_key()

        filtered_rows = self.inventory_rows
        if status_filter == "locked":
            filtered_rows = [app for app in filtered_rows if app.is_locked]
        elif status_filter == "unlocked":
            filtered_rows = [app for app in filtered_rows if not app.is_locked]

        if not query:
            self.displayed_rows = list(filtered_rows)
        else:
            self.displayed_rows = [
                app for app in filtered_rows if self._matches_query(app, query)
            ]

        self._render_tree()
        self._update_summary()

    def _sanitize_query(self, value: str) -> str:
        trimmed = str(value or "").strip()
        printable = "".join(ch for ch in trimmed if ch.isprintable())
        return printable[:120]

    def _matches_query(self, app: InventoryApp, query: str) -> bool:
        haystack = " ".join(
            [
                app.status,
                app.display_name,
                app.executable_name,
                app.path,
                " ".join(app.sources),
            ]
        ).casefold()
        return query in haystack

    def _render_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.tree_index.clear()

        for index, app in enumerate(self.displayed_rows):
            item_id = f"app-{index}"
            self.tree_index[item_id] = app

            icon_source = app.icon_path or app.path
            icon_key = f"{app.dedupe_key}|{icon_source.casefold()}"
            if icon_key not in self.icon_cache:
                self.icon_cache[icon_key] = get_app_icon(
                    icon_source, app.display_name, size=(24, 24)
                )

            photo_image = self.icon_cache[icon_key]

            self.tree.insert(
                "",
                "end",
                iid=item_id,
                text=f"  {app.display_name}",
                image=photo_image,
                values=(
                    app.status,
                    app.path or "Path unavailable",
                ),
                tags=self._row_tags(app),
            )

        if not self.displayed_rows:
            filter_label = self._status_filter_label().casefold()
            if filter_label == "all":
                self.status_var.set("No applications match the current filter.")
            else:
                self.status_var.set(
                    f"No {filter_label} applications match the current filter."
                )
        else:
            filter_label = self._status_filter_label().casefold()
            noun = "applications" if len(self.displayed_rows) != 1 else "application"
            if filter_label == "all":
                self.status_var.set(f"Showing {len(self.displayed_rows)} {noun}.")
            else:
                self.status_var.set(
                    f"Showing {len(self.displayed_rows)} {filter_label} {noun}."
                )

    def _row_tags(self, app: InventoryApp) -> tuple[str, ...]:
        tags = ["locked" if app.is_locked else "unlocked"]
        if not app.path:
            tags.append("missing_path")
        return tuple(tags)

    def _update_summary(self):
        locked_count = sum(1 for app in self.inventory_rows if app.is_locked)
        total_count = len(self.inventory_rows)
        self.summary_var.set(f"{locked_count} locked / {total_count} total")

    def _selected_apps(self) -> list[InventoryApp]:
        selected_items = self.tree.selection()
        return [
            self.tree_index[item_id]
            for item_id in selected_items
            if item_id in self.tree_index
        ]

    def lock_selected_apps(self):
        selected_apps = [app for app in self._selected_apps() if not app.is_locked]
        if not selected_apps:
            messagebox.showinfo(
                "Nothing to Lock",
                "Select one or more unlocked applications first.",
                parent=self,
            )
            return

        if not prompt_for_master_password(
            self,
            title="Lock Applications",
            message="Enter the master password to lock the selected applications.",
            action_label="Lock",
        ):
            return

        try:
            changed = lock_apps(selected_apps)
            logger.info("Locked %s applications from dashboard.", changed)
            self.status_var.set(f"Locked {changed} application(s).")
            self.refresh_inventory()
        except ValueError as exc:
            logger.error("Rejected insecure lock request: %s", exc)
            messagebox.showerror("Cannot Lock Application", str(exc), parent=self)
        except Exception as exc:
            logger.error(f"Error locking apps: {exc}")
            messagebox.showerror(
                "Error", "Failed to lock selected applications.", parent=self
            )

    def unlock_selected_apps(self):
        selected_apps = [app for app in self._selected_apps() if app.is_locked]
        if not selected_apps:
            messagebox.showinfo(
                "Nothing to Unlock",
                "Select one or more locked applications first.",
                parent=self,
            )
            return

        if not prompt_for_master_password(
            self,
            title="Unlock Applications",
            message="Enter the master password to unlock the selected applications.",
            action_label="Unlock",
        ):
            return

        try:
            changed = unlock_apps(selected_apps)
            logger.info("Unlocked %s applications from dashboard.", changed)
            self.status_var.set(f"Unlocked {changed} application(s).")
            self.refresh_inventory()
        except Exception as exc:
            logger.error(f"Error unlocking apps: {exc}")
            messagebox.showerror(
                "Error", "Failed to unlock selected applications.", parent=self
            )

    def _set_buttons_enabled(self, enabled: bool):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.refresh_button.config(state=state)
        self.custom_path_button.config(state=state)
        self.lock_button.config(state=state)
        self.unlock_button.config(state=state)
        self.filter_combo.config(state="readonly" if enabled else "disabled")
        self.settings_button.config(state=state)


if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    app = Dashboard(root)
    root.mainloop()
