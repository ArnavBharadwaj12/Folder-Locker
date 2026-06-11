import ctypes
import os
import queue
import shutil
import sys
import threading
import time
from tkinter import filedialog
from tkinter import BooleanVar
from tkinter import Menu
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import StringVar
from tkinter import TclError
from tkinter import ttk

import customtkinter as ctk

import main as backend


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


APP_VERSION = "7.0.0"
APP_NAME = "Folder Locker"
APP_AUTHOR = "Arnav"
APP_USER_MODEL_ID = "arnav.folderlocker.v7"


def resource_path(relative_path):
    """Return an absolute resource path for source and PyInstaller builds."""
    base_dir = getattr(
        sys,
        "_MEIPASS",
        os.path.dirname(os.path.abspath(__file__))
    )
    return os.path.abspath(os.path.join(base_dir, relative_path))


ICON_FILE = resource_path(os.path.join("Assets", "icon.ico"))
STARTUP_DIAGNOSTIC_LOG = backend.STARTUP_DIAGNOSTIC_LOG


DEFAULT_SETTINGS = {
    "open_maximized_on_startup": False,
    "remember_window_size": True,
    "confirm_before_lock_folder": True,
    "confirm_before_unlock_folder": True,
    "confirm_before_remove_folder": True,
    "theme": "Dark",
    "window_geometry": "1100x700",
}


class Theme:
    """Central dark theme colors for a consistent professional UI."""

    BACKGROUND = "#0f172a"
    SURFACE = "#111827"
    SURFACE_RAISED = "#1f2937"
    BORDER = "#334155"
    TEXT = "#f8fafc"
    MUTED_TEXT = "#94a3b8"
    PRIMARY = "#2563eb"
    PRIMARY_HOVER = "#1d4ed8"
    DANGER = "#dc2626"
    DANGER_HOVER = "#b91c1c"
    SUCCESS = "#22c55e"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"
    SIDEBAR = "#0b1220"

    @classmethod
    def apply_mode(cls, theme_name):
        """Update shared colors for the selected application theme."""
        if str(theme_name).lower() == "light":
            cls.BACKGROUND = "#f8fafc"
            cls.SURFACE = "#ffffff"
            cls.SURFACE_RAISED = "#e2e8f0"
            cls.BORDER = "#cbd5e1"
            cls.TEXT = "#0f172a"
            cls.MUTED_TEXT = "#475569"
            cls.PRIMARY = "#2563eb"
            cls.PRIMARY_HOVER = "#1d4ed8"
            cls.DANGER = "#dc2626"
            cls.DANGER_HOVER = "#b91c1c"
            cls.SUCCESS = "#16a34a"
            cls.WARNING = "#d97706"
            cls.ERROR = "#dc2626"
            cls.SIDEBAR = "#e2e8f0"
            ctk.set_appearance_mode("light")
            return

        cls.BACKGROUND = "#0f172a"
        cls.SURFACE = "#111827"
        cls.SURFACE_RAISED = "#1f2937"
        cls.BORDER = "#334155"
        cls.TEXT = "#f8fafc"
        cls.MUTED_TEXT = "#94a3b8"
        cls.PRIMARY = "#2563eb"
        cls.PRIMARY_HOVER = "#1d4ed8"
        cls.DANGER = "#dc2626"
        cls.DANGER_HOVER = "#b91c1c"
        cls.SUCCESS = "#22c55e"
        cls.WARNING = "#f59e0b"
        cls.ERROR = "#ef4444"
        cls.SIDEBAR = "#0b1220"
        ctk.set_appearance_mode("dark")


BUTTON_ICONS = {
    "Add Folder": "+",
    "Remove Folder": "-",
    "Refresh": "↻",
    "Hide Folder": "◐",
    "Unhide Folder": "◑",
    "Lock Folder": "🔒",
    "Unlock Folder": "🔓",
    "Change Password": "●",
    "Activity Log": "☰",
    "Backup Database": "B",
    "Restore Database": "R",
    "Export Activity Log": "T",
    "Settings": "*",
    "About": "ℹ",
    "Exit": "×",
}


def load_app_config():
    """Load config.json and merge missing app settings."""
    backend.ensure_project_files()

    try:
        with open(backend.CONFIG_FILE, "r", encoding="utf-8") as config_file:
            config_data = backend.json.load(config_file)
    except (OSError, backend.json.JSONDecodeError):
        config_data = {}

    if not isinstance(config_data, dict):
        config_data = {}

    changed = False

    if config_data.get("app_name") != APP_NAME:
        config_data["app_name"] = APP_NAME
        changed = True

    if config_data.get("version") != APP_VERSION:
        config_data["version"] = APP_VERSION
        changed = True

    if "locked_folders_directory" not in config_data:
        config_data["locked_folders_directory"] = "Locked Folders"
        changed = True

    settings = config_data.get("settings")

    if not isinstance(settings, dict):
        settings = {}
        config_data["settings"] = settings
        changed = True

    for key, value in DEFAULT_SETTINGS.items():
        if key not in settings:
            settings[key] = value
            changed = True

    if settings.get("theme") not in ("Dark", "Light"):
        settings["theme"] = DEFAULT_SETTINGS["theme"]
        changed = True

    if changed:
        save_app_config(config_data)

    return config_data


def save_app_config(config_data):
    """Persist config.json with the application settings."""
    with open(backend.CONFIG_FILE, "w", encoding="utf-8") as config_file:
        backend.json.dump(config_data, config_file, indent=4)


def friendly_error_message(action):
    """Return a clear user-facing error without technical traceback details."""
    return (
        f"{action} could not be completed. "
        "Please check the selected file or folder and try again."
    )


def migrate_password_if_needed(connection, password, stored_record):
    """Preserve backend password migration behavior during GUI checks."""
    if not (
        backend.password_storage_supports_pbkdf2(connection)
        and backend.password_record_needs_migration(
            stored_record["password_salt"],
            stored_record["password_algorithm"],
            stored_record["password_iterations"]
        )
    ):
        return

    (
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    ) = backend.hash_password(password)

    backend.save_password_hash(
        connection,
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    )


class LoginFrame(ctk.CTkFrame):
    """Centered login screen for the Folder Locker GUI."""

    STATUS_COLORS = {
        "neutral": Theme.MUTED_TEXT,
        "orange": Theme.WARNING,
        "red": Theme.ERROR,
        "green": Theme.SUCCESS,
    }

    def __init__(self, master, login_callback):
        super().__init__(master, fg_color="transparent")
        self.login_callback = login_callback

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.configure(fg_color=Theme.BACKGROUND)

        self.card = ctk.CTkFrame(
            self,
            width=460,
            corner_radius=10,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1
        )
        self.card.grid(row=0, column=0, padx=40, pady=40)
        self.card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            self.card,
            text=APP_NAME,
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=34, weight="bold")
        )
        title.grid(row=0, column=0, padx=40, pady=(40, 8), sticky="ew")

        subtitle = ctk.CTkLabel(
            self.card,
            text=f"Version {APP_VERSION}",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=14)
        )
        subtitle.grid(row=1, column=0, padx=40, pady=(0, 28), sticky="ew")

        self.password_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Enter master password",
            show="*",
            height=44,
            fg_color=Theme.SURFACE_RAISED,
            border_color=Theme.BORDER,
            text_color=Theme.TEXT
        )
        self.password_entry.grid(
            row=2,
            column=0,
            padx=40,
            pady=(0, 18),
            sticky="ew"
        )
        self.password_entry.bind("<Return>", self._handle_enter_key)

        self.login_button = ctk.CTkButton(
            self.card,
            text="Login",
            height=44,
            fg_color=Theme.PRIMARY,
            hover_color=Theme.PRIMARY_HOVER,
            font=ctk.CTkFont(size=15, weight="bold"),
            command=self._handle_login
        )
        self.login_button.grid(
            row=3,
            column=0,
            padx=40,
            pady=(0, 18),
            sticky="ew"
        )

        self.status_label = ctk.CTkLabel(
            self.card,
            text="Ready to login",
            font=ctk.CTkFont(size=14),
            text_color=self.STATUS_COLORS["neutral"],
            justify="center"
        )
        self.status_label.grid(
            row=4,
            column=0,
            padx=40,
            pady=(0, 40),
            sticky="ew"
        )

    def focus_password_entry(self):
        """Place the cursor in the password box."""
        self.password_entry.focus_set()

    def clear_password(self):
        """Remove the typed password after an unsuccessful login."""
        self.password_entry.delete(0, "end")
        self.focus_password_entry()

    def set_status(self, message, status_type="neutral"):
        """Update the inline login status message."""
        self.status_label.configure(
            text=message,
            text_color=self.STATUS_COLORS[status_type]
        )

    def set_login_enabled(self, enabled):
        """Enable or disable the password field and login button."""
        state = "normal" if enabled else "disabled"
        self.password_entry.configure(state=state)
        self.login_button.configure(state=state)

        if enabled:
            self.focus_password_entry()

    def _handle_enter_key(self, _event):
        """Submit the form when the user presses Enter."""
        self._handle_login()

    def _handle_login(self):
        """Send the entered password to the main application."""
        password = self.password_entry.get()
        self.login_callback(password)



class FirstRunSetupFrame(ctk.CTkFrame):
    """Full-screen first-run setup screen shown when no master password exists."""

    STATUS_COLORS = {
        "neutral": Theme.MUTED_TEXT,
        "error": Theme.ERROR,
        "success": Theme.SUCCESS,
    }

    def __init__(self, master, setup_callback):
        super().__init__(master, fg_color="transparent")
        self.setup_callback = setup_callback

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.configure(fg_color=Theme.BACKGROUND)

        self.card = ctk.CTkFrame(
            self,
            width=480,
            corner_radius=12,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1,
        )
        self.card.grid(row=0, column=0, padx=40, pady=40)
        self.card.grid_columnconfigure(0, weight=1)

        # ── Badge row ──────────────────────────────────────────────────
        badge = ctk.CTkFrame(
            self.card,
            width=56,
            height=56,
            corner_radius=28,
            fg_color=Theme.PRIMARY,
        )
        badge.grid(row=0, column=0, padx=40, pady=(36, 0))
        badge.grid_propagate(False)
        badge.grid_columnconfigure(0, weight=1)
        badge.grid_rowconfigure(0, weight=1)
        ctk.CTkLabel(
            badge,
            text="🔐",
            font=ctk.CTkFont(size=22),
        ).grid(row=0, column=0)

        # ── Title ──────────────────────────────────────────────────────
        ctk.CTkLabel(
            self.card,
            text="Welcome to Folder Locker",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=26, weight="bold"),
        ).grid(row=1, column=0, padx=40, pady=(14, 4), sticky="ew")

        ctk.CTkLabel(
            self.card,
            text="Create a master password to get started",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=14),
        ).grid(row=2, column=0, padx=40, pady=(0, 24), sticky="ew")

        # ── Divider ────────────────────────────────────────────────────
        ctk.CTkFrame(
            self.card,
            height=1,
            fg_color=Theme.BORDER,
        ).grid(row=3, column=0, padx=40, pady=(0, 24), sticky="ew")

        # ── Password entry ─────────────────────────────────────────────
        ctk.CTkLabel(
            self.card,
            text="Password",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        ).grid(row=4, column=0, padx=40, pady=(0, 4), sticky="ew")

        self.password_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Enter master password",
            show="*",
            height=44,
            fg_color=Theme.SURFACE_RAISED,
            border_color=Theme.BORDER,
            text_color=Theme.TEXT,
        )
        self.password_entry.grid(row=5, column=0, padx=40, pady=(0, 16), sticky="ew")
        self.password_entry.bind("<Return>", lambda _e: self.confirm_entry.focus_set())

        # ── Confirm entry ──────────────────────────────────────────────
        ctk.CTkLabel(
            self.card,
            text="Confirm Password",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        ).grid(row=6, column=0, padx=40, pady=(0, 4), sticky="ew")

        self.confirm_entry = ctk.CTkEntry(
            self.card,
            placeholder_text="Re-enter master password",
            show="*",
            height=44,
            fg_color=Theme.SURFACE_RAISED,
            border_color=Theme.BORDER,
            text_color=Theme.TEXT,
        )
        self.confirm_entry.grid(row=7, column=0, padx=40, pady=(0, 20), sticky="ew")
        self.confirm_entry.bind("<Return>", self._handle_create)

        # ── Create button ──────────────────────────────────────────────
        self.create_button = ctk.CTkButton(
            self.card,
            text="Create Password & Continue",
            height=46,
            fg_color=Theme.PRIMARY,
            hover_color=Theme.PRIMARY_HOVER,
            font=ctk.CTkFont(size=15, weight="bold"),
            command=self._handle_create,
        )
        self.create_button.grid(row=8, column=0, padx=40, pady=(0, 16), sticky="ew")

        # ── Status label ───────────────────────────────────────────────
        self.status_label = ctk.CTkLabel(
            self.card,
            text="",
            font=ctk.CTkFont(size=13),
            text_color=self.STATUS_COLORS["neutral"],
            justify="center",
            wraplength=360,
        )
        self.status_label.grid(row=9, column=0, padx=40, pady=(0, 32), sticky="ew")

        self.password_entry.focus_set()

    def set_status(self, message, status_type="neutral"):
        """Update the inline status message."""
        self.status_label.configure(
            text=message,
            text_color=self.STATUS_COLORS.get(status_type, Theme.MUTED_TEXT),
        )

    def set_controls_enabled(self, enabled):
        """Enable or disable all interactive controls."""
        state = "normal" if enabled else "disabled"
        self.password_entry.configure(state=state)
        self.confirm_entry.configure(state=state)
        self.create_button.configure(state=state)

    def _handle_create(self, _event=None):
        """Collect the two password fields and forward to the app."""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        self.setup_callback(password, confirm)


class PasswordFieldsDialog(ctk.CTkToplevel):
    """Modal password dialog that reports validation errors inline."""

    def __init__(self, master, title, fields):
        super().__init__(master)
        self.result = None
        self.entries = {}

        self.title(title)
        self.geometry("420x340")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(size=22, weight="bold")
        )
        header.grid(row=0, column=0, padx=28, pady=(24, 18), sticky="ew")

        for row, (field_key, label_text) in enumerate(fields, start=1):
            entry = ctk.CTkEntry(
                self,
                placeholder_text=label_text,
                show="*",
                height=38
            )
            entry.grid(row=row, column=0, padx=28, pady=7, sticky="ew")
            self.entries[field_key] = entry

        self.status_label = ctk.CTkLabel(
            self,
            text="",
            text_color="#ef4444",
            justify="center"
        )
        self.status_label.grid(
            row=len(fields) + 1,
            column=0,
            padx=28,
            pady=(8, 4),
            sticky="ew"
        )

        button_row = ctk.CTkFrame(self, fg_color="transparent")
        button_row.grid(
            row=len(fields) + 2,
            column=0,
            padx=28,
            pady=(10, 24),
            sticky="ew"
        )
        button_row.grid_columnconfigure((0, 1), weight=1)

        cancel_button = ctk.CTkButton(
            button_row,
            text="Cancel",
            fg_color="gray35",
            command=self._cancel
        )
        cancel_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        ok_button = ctk.CTkButton(
            button_row,
            text="Continue",
            command=self._submit
        )
        ok_button.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        self.bind("<Return>", self._submit)
        self.bind("<Escape>", self._cancel)
        first_entry = next(iter(self.entries.values()))
        first_entry.focus_set()

    def show_error(self, message):
        """Display validation feedback inside the dialog."""
        self.status_label.configure(text=message)

    def _submit(self, _event=None):
        """Collect field values and close the dialog."""
        self.result = {
            key: entry.get()
            for key, entry in self.entries.items()
        }
        self.destroy()

    def _cancel(self, _event=None):
        """Close the dialog without returning values."""
        self.result = None
        self.destroy()


class IntegrityAlertDialog(ctk.CTkToplevel):
    """Modal database integrity alert with Recovery and Exit choices."""

    def __init__(self, master):
        super().__init__(master)
        self.result = "exit"

        self.title("Database Integrity Alert")
        self.geometry("500x260")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.configure(fg_color=Theme.BACKGROUND)
        self.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            self,
            text="Database Integrity Alert",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, padx=28, pady=(28, 12), sticky="ew")

        message = ctk.CTkLabel(
            self,
            text=(
                "Folder Locker detected that locker.db does not match "
                "its saved signature."
            ),
            text_color=Theme.MUTED_TEXT,
            wraplength=420,
            justify="center"
        )
        message.grid(row=1, column=0, padx=28, pady=(0, 26), sticky="ew")

        button_row = ctk.CTkFrame(self, fg_color="transparent")
        button_row.grid(row=2, column=0, padx=28, pady=(0, 28), sticky="ew")
        button_row.grid_columnconfigure((0, 1), weight=1)

        recovery_button = ctk.CTkButton(
            button_row,
            text="Recovery",
            command=self._recover
        )
        recovery_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        exit_button = ctk.CTkButton(
            button_row,
            text="Exit",
            fg_color=Theme.DANGER,
            hover_color=Theme.DANGER_HOVER,
            command=self._exit
        )
        exit_button.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        self.protocol("WM_DELETE_WINDOW", self._exit)
        self.bind("<Escape>", self._exit)

    def _recover(self):
        """Choose recovery."""
        self.result = "recovery"
        self.destroy()

    def _exit(self, _event=None):
        """Choose exit."""
        self.result = "exit"
        self.destroy()


class ActivityLogWindow(ctk.CTkToplevel):
    """Scrollable activity log viewer."""

    def __init__(self, master):
        super().__init__(master)
        self.title("Activity Log")
        self.geometry("820x560")
        self.minsize(640, 420)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(18, 10), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header,
            text="Activity Log",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w")

        refresh_button = ctk.CTkButton(
            header,
            text="Refresh",
            width=110,
            command=self.load_log
        )
        refresh_button.grid(row=0, column=1, sticky="e")

        self.log_text = ctk.CTkTextbox(self, wrap="none")
        self.log_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.load_log()

    def load_log(self):
        """Load activity.log with newest entries first."""
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")

        if not os.path.exists(backend.LOG_FILE):
            self.log_text.insert("end", "No activity log found.")
            self.log_text.configure(state="disabled")
            return

        try:
            with open(backend.LOG_FILE, "r", encoding="utf-8") as log_file:
                lines = log_file.readlines()
        except OSError:
            self.log_text.insert(
                "end",
                "Could not read activity log. Please check file permissions."
            )
            self.log_text.configure(state="disabled")
            return

        self.log_text.insert("end", "".join(reversed(lines)))
        self.log_text.configure(state="disabled")


class SettingsWindow(ctk.CTkToplevel):
    """Application settings editor backed by config.json."""

    def __init__(self, master, settings, save_callback):
        super().__init__(master)
        self.settings = settings
        self.save_callback = save_callback
        self.variables = {}

        self.title("Settings")
        self.geometry("520x520")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.configure(fg_color=Theme.BACKGROUND)
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            self,
            text="Settings",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=26, weight="bold")
        )
        header.grid(row=0, column=0, padx=28, pady=(26, 16), sticky="w")

        form = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1
        )
        form.grid(row=1, column=0, padx=28, pady=(0, 18), sticky="ew")
        form.grid_columnconfigure(0, weight=1)

        boolean_settings = (
            ("open_maximized_on_startup", "Open maximized on startup"),
            ("remember_window_size", "Remember window size"),
            ("confirm_before_lock_folder", "Confirm before lock folder"),
            ("confirm_before_unlock_folder", "Confirm before unlock folder"),
            ("confirm_before_remove_folder", "Confirm before remove folder"),
        )

        for row, (key, label) in enumerate(boolean_settings):
            variable = BooleanVar(value=bool(settings.get(key)))
            self.variables[key] = variable
            checkbox = ctk.CTkCheckBox(
                form,
                text=label,
                variable=variable,
                text_color=Theme.TEXT
            )
            checkbox.grid(row=row, column=0, padx=20, pady=10, sticky="w")

        theme_row = ctk.CTkFrame(form, fg_color="transparent")
        theme_row.grid(
            row=len(boolean_settings),
            column=0,
            padx=20,
            pady=(14, 18),
            sticky="ew"
        )
        theme_row.grid_columnconfigure(1, weight=1)

        theme_label = ctk.CTkLabel(
            theme_row,
            text="Theme",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        theme_label.grid(row=0, column=0, padx=(0, 16), sticky="w")

        theme_variable = StringVar(value=settings.get("theme", "Dark"))
        self.variables["theme"] = theme_variable
        theme_menu = ctk.CTkOptionMenu(
            theme_row,
            values=("Dark", "Light"),
            variable=theme_variable
        )
        theme_menu.grid(row=0, column=1, sticky="ew")

        self.status_label = ctk.CTkLabel(
            self,
            text="",
            text_color=Theme.MUTED_TEXT
        )
        self.status_label.grid(row=2, column=0, padx=28, pady=(0, 10))

        button_row = ctk.CTkFrame(self, fg_color="transparent")
        button_row.grid(row=3, column=0, padx=28, pady=(0, 26), sticky="ew")
        button_row.grid_columnconfigure((0, 1), weight=1)

        cancel_button = ctk.CTkButton(
            button_row,
            text="Cancel",
            fg_color="gray35",
            command=self.destroy
        )
        cancel_button.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        save_button = ctk.CTkButton(
            button_row,
            text="Save",
            command=self._save
        )
        save_button.grid(row=0, column=1, padx=(8, 0), sticky="ew")

        self.bind("<Escape>", lambda _event: self.destroy())

    def _save(self):
        """Collect and save settings."""
        updated_settings = {}

        for key, variable in self.variables.items():
            updated_settings[key] = variable.get()

        self.save_callback(updated_settings)
        self.status_label.configure(
            text="Settings saved.",
            text_color=Theme.SUCCESS
        )
        self.after(350, self.destroy)


class DashboardFrame(ctk.CTkFrame):
    """Dashboard with folder table, statistics, and folder actions."""

    PLACEHOLDER_BUTTONS = (
        "Exit",
    )

    TABLE_COLUMNS = (
        "ID",
        "Nickname",
        "Folder Name",
        "Status",
    )

    DISPLAY_STATUSES = {
        backend.STATUS_REGISTERED: "🟢 Registered",
        backend.STATUS_HIDDEN: "🟡 Hidden",
        backend.STATUS_LOCKED: "🔴 Locked",
    }

    STATUS_COLORS = {
        "neutral": Theme.MUTED_TEXT,
        "success": Theme.SUCCESS,
        "warning": Theme.WARNING,
        "error": Theme.ERROR,
    }

    def __init__(self, master, connection):
        super().__init__(master, fg_color="transparent")
        self.connection = connection
        self.settings = self.master.settings
        self.all_folders = []
        self.stat_labels = {}
        self.folder_records = {}
        self.action_buttons = []
        self.operation_after_id = None
        self.operation_queue = None
        self.operation_running = False
        self.loading_frame = None
        self.configure(fg_color=Theme.BACKGROUND)

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        self._build_sidebar()
        self._build_content_area()
        self._build_status_bar()
        self.refresh_folders()

    def _build_sidebar(self):
        """Create the dashboard action sidebar."""
        sidebar = ctk.CTkFrame(
            self,
            width=250,
            corner_radius=0,
            fg_color=Theme.SIDEBAR
        )
        sidebar.grid(row=0, column=0, rowspan=2, sticky="ns")
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_propagate(False)

        title = ctk.CTkLabel(
            sidebar,
            text=APP_NAME,
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title.grid(row=0, column=0, padx=22, pady=(30, 4), sticky="ew")

        subtitle = ctk.CTkLabel(
            sidebar,
            text=f"Version {APP_VERSION}",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=14)
        )
        subtitle.grid(row=1, column=0, padx=22, pady=(0, 26), sticky="ew")

        actions = (
            ("Add Folder", self.add_folder),
            ("Remove Folder", self.remove_selected_folder),
            ("Refresh", self.refresh_folders),
            ("Hide Folder", self.hide_selected_folder),
            ("Unhide Folder", self.unhide_selected_folder),
            ("Lock Folder", self.lock_selected_folder),
            ("Unlock Folder", self.unlock_selected_folder),
            ("Change Password", self.change_master_password),
            ("Activity Log", self.open_activity_log),
            ("Backup Database", self.backup_database),
            ("Restore Database", self.restore_database),
            ("Export Activity Log", self.export_activity_log),
            ("Settings", self.open_settings),
            ("About", self.master.open_about_window),
        )

        for row, (label, command) in enumerate(actions, start=2):
            self._add_sidebar_button(sidebar, row, label, command)

        for offset, label in enumerate(self.PLACEHOLDER_BUTTONS, start=15):
            command = (
                self.master.close_application
                if label == "Exit"
                else self.show_later_version_message
            )
            self._add_sidebar_button(
                sidebar,
                offset,
                label,
                command
            )

    def _add_sidebar_button(self, parent, row, label, command):
        """Add one consistently styled sidebar button."""
        button = ctk.CTkButton(
            parent,
            text=f"{BUTTON_ICONS.get(label, '')}  {label}",
            height=34,
            anchor="w",
            fg_color=Theme.PRIMARY if label != "Exit" else Theme.DANGER,
            hover_color=(
                Theme.PRIMARY_HOVER
                if label != "Exit"
                else Theme.DANGER_HOVER
            ),
            font=ctk.CTkFont(size=14, weight="bold"),
            command=command
        )
        button.grid(row=row, column=0, padx=20, pady=3, sticky="ew")
        self.action_buttons.append(button)

    def _build_content_area(self):
        """Create the statistics panel and folder table."""
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.grid(
            row=0,
            column=1,
            padx=32,
            pady=(30, 18),
            sticky="nsew"
        )
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(3, weight=1)

        title = ctk.CTkLabel(
            self.content_frame,
            text="Folder Management",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=32, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w")

        stats_frame = ctk.CTkFrame(
            self.content_frame,
            corner_radius=8,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1
        )
        stats_frame.grid(row=1, column=0, pady=(18, 18), sticky="ew")

        stat_names = (
            "Total Folders",
            "Registered",
            "Hidden",
            "Locked",
        )

        for column, name in enumerate(stat_names):
            stats_frame.grid_columnconfigure(column, weight=1)
            label = ctk.CTkLabel(
                stats_frame,
                text=f"{name}: 0",
                text_color=Theme.TEXT,
                font=ctk.CTkFont(size=15, weight="bold")
            )
            label.grid(row=0, column=column, padx=18, pady=18, sticky="ew")
            self.stat_labels[name] = label

        table_frame = ctk.CTkFrame(
            self.content_frame,
            corner_radius=8,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1
        )
        search_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        search_frame.grid(row=2, column=0, pady=(0, 12), sticky="ew")
        search_frame.grid_columnconfigure(0, weight=1)

        self.search_var = StringVar(value="")
        self.search_var.trace_add("write", self._handle_search_change)
        self.search_entry = ctk.CTkEntry(
            search_frame,
            textvariable=self.search_var,
            placeholder_text="Search by ID, nickname, folder name, or status",
            height=38,
            fg_color=Theme.SURFACE_RAISED,
            border_color=Theme.BORDER,
            text_color=Theme.TEXT
        )
        self.search_entry.grid(row=0, column=0, sticky="ew")

        table_frame.grid(row=3, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        self._configure_tree_style()

        self.folder_table = ttk.Treeview(
            table_frame,
            columns=self.TABLE_COLUMNS,
            show="headings",
            selectmode="browse"
        )

        for column in self.TABLE_COLUMNS:
            self.folder_table.heading(column, text=column)
            self.folder_table.column(column, anchor="center", width=130)

        self.folder_table.column("ID", width=70)
        self.folder_table.column("Nickname", width=180)
        self.folder_table.column("Folder Name", width=220)
        self.folder_table.column("Status", width=120)

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.folder_table.yview
        )
        self.folder_table.configure(yscrollcommand=scrollbar.set)

        self.folder_table.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.folder_table.bind("<Button-3>", self._show_context_menu)

        self._build_context_menu()
        self._build_loading_frame()

    def _build_status_bar(self):
        """Create a permanent bottom status bar."""
        status_frame = ctk.CTkFrame(
            self,
            height=38,
            corner_radius=0,
            fg_color=Theme.SURFACE,
            border_color=Theme.BORDER,
            border_width=1
        )
        status_frame.grid(row=1, column=1, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)
        status_frame.grid_columnconfigure(1, weight=0)

        self.status_label = ctk.CTkLabel(
            status_frame,
            text="Ready",
            text_color=self.STATUS_COLORS["neutral"],
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        self.status_label.grid(row=0, column=0, padx=16, pady=8, sticky="ew")

        self.version_label = ctk.CTkLabel(
            status_frame,
            text=f"{APP_NAME} v{APP_VERSION}",
            text_color=Theme.MUTED_TEXT,
            anchor="e",
            font=ctk.CTkFont(size=13)
        )
        self.version_label.grid(
            row=0,
            column=1,
            padx=(0, 16),
            pady=8,
            sticky="e"
        )

    def _build_loading_frame(self):
        """Create the in-dashboard loading screen used during long work."""
        self.loading_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.loading_frame.grid_columnconfigure(0, weight=1)
        self.loading_frame.grid_rowconfigure(0, weight=1)

        loading_card = ctk.CTkFrame(self.loading_frame, corner_radius=8)
        loading_card.grid(row=0, column=0, padx=80, pady=80, sticky="nsew")
        loading_card.grid_columnconfigure(0, weight=1)

        self.loading_operation_label = ctk.CTkLabel(
            loading_card,
            text="Locking Folder...",
            font=ctk.CTkFont(size=30, weight="bold")
        )
        self.loading_operation_label.grid(
            row=0,
            column=0,
            padx=36,
            pady=(44, 12),
            sticky="ew"
        )

        self.loading_detail_label = ctk.CTkLabel(
            loading_card,
            text="Processing files...",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.loading_detail_label.grid(
            row=1,
            column=0,
            padx=36,
            pady=(0, 8),
            sticky="ew"
        )

        self.loading_folder_label = ctk.CTkLabel(
            loading_card,
            text="",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=15)
        )
        self.loading_folder_label.grid(
            row=2,
            column=0,
            padx=36,
            pady=(0, 24),
            sticky="ew"
        )

        self.loading_progress_bar = ttk.Progressbar(
            loading_card,
            orient="horizontal",
            mode="determinate",
            maximum=100
        )
        self.loading_progress_bar.grid(
            row=3,
            column=0,
            padx=54,
            pady=(0, 18),
            sticky="ew"
        )

        self.loading_counter_label = ctk.CTkLabel(
            loading_card,
            text="0 / 0 files",
            font=ctk.CTkFont(size=16)
        )
        self.loading_counter_label.grid(
            row=4,
            column=0,
            padx=36,
            pady=(0, 8),
            sticky="ew"
        )

        self.loading_percent_label = ctk.CTkLabel(
            loading_card,
            text="0%",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.loading_percent_label.grid(
            row=5,
            column=0,
            padx=36,
            pady=(0, 20),
            sticky="ew"
        )

        wait_label = ctk.CTkLabel(
            loading_card,
            text="Please wait...",
            font=ctk.CTkFont(size=15)
        )
        wait_label.grid(row=6, column=0, padx=36, pady=(0, 44), sticky="ew")

    def _configure_tree_style(self):
        """Style ttk widgets so they fit the dark CustomTkinter UI."""
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#1f2937",
            foreground="#f9fafb",
            fieldbackground="#1f2937",
            borderwidth=0,
            rowheight=30
        )
        style.configure(
            "Treeview.Heading",
            background="#111827",
            foreground="#f9fafb",
            font=("Segoe UI", 10, "bold")
        )
        style.map(
            "Treeview",
            background=[("selected", "#2563eb")],
            foreground=[("selected", "#ffffff")]
        )

    def _build_context_menu(self):
        """Create the Treeview right-click menu."""
        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Open Folder",
            command=self.open_selected_folder
        )
        self.context_menu.add_command(
            label="Hide Folder",
            command=self.hide_selected_folder
        )
        self.context_menu.add_command(
            label="Unhide Folder",
            command=self.unhide_selected_folder
        )
        self.context_menu.add_command(
            label="Lock Folder",
            command=self.lock_selected_folder
        )
        self.context_menu.add_command(
            label="Unlock Folder",
            command=self.unlock_selected_folder
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Refresh",
            command=self.refresh_folders
        )

    def add_folder(self):
        """Register a folder using a file picker dialog."""
        selected_path = filedialog.askdirectory(
            title="Select Folder to Add"
        )

        if not selected_path:
            return

        folder_path = backend.normalize_folder_path(selected_path)
        validation_message = self._validate_folder_path(folder_path)

        if validation_message is not None:
            messagebox.showerror("Add Folder", validation_message)
            return

        nickname = simpledialog.askstring(
            "Folder Nickname",
            "Enter a nickname for this folder:",
            parent=self
        )

        if nickname is None:
            return

        nickname = nickname.strip()

        if not nickname:
            messagebox.showerror("Add Folder", "Nickname cannot be empty.")
            return

        self._insert_folder_record(folder_path, nickname)

    def _validate_folder_path(self, folder_path):
        """Return an error message when the selected path is invalid."""
        if not folder_path:
            return "Folder path cannot be empty."

        if not backend.os.path.exists(folder_path):
            return "Folder does not exist. Please choose a valid folder."

        if not backend.os.path.isdir(folder_path):
            return "The selected path exists, but it is not a folder."

        if backend.folder_path_exists(self.connection, folder_path):
            return "This folder is already registered."

        folder_name = backend.os.path.basename(
            backend.os.path.normpath(folder_path)
        )

        if not folder_name:
            return "Invalid folder path. Please choose a normal folder."

        return None

    def _insert_folder_record(self, folder_path, nickname):
        """Insert a new folder record using the backend's existing schema."""
        folder_name = backend.os.path.basename(
            backend.os.path.normpath(folder_path)
        )

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                """
                INSERT INTO folders (
                    nickname,
                    folder_name,
                    folder_path,
                    status,
                    date_added
                )
                VALUES (?, ?, ?, ?, date('now', 'localtime'))
                """,
                (
                    nickname,
                    folder_name,
                    folder_path,
                    backend.STATUS_REGISTERED
                )
            )
            self.connection.commit()
            self.refresh_folders()
            self.set_status("Folder added successfully.", "success")
            messagebox.showinfo("Add Folder", "Folder added successfully.")
        except backend.sqlite3.IntegrityError:
            messagebox.showerror(
                "Add Folder",
                "This folder is already registered."
            )
        except backend.sqlite3.Error:
            messagebox.showerror(
                "Add Folder",
                friendly_error_message("Adding the folder")
            )

    def remove_selected_folder(self):
        """Remove the selected folder record from the database."""
        selected_item = self.folder_table.selection()

        if not selected_item:
            self.set_status("No folder selected", "warning")
            return

        folder_id = self.folder_table.item(selected_item[0], "values")[0]
        folder = backend.get_folder_by_id(self.connection, folder_id)

        if folder is None:
            self.set_status("Folder ID does not exist", "error")
            self.refresh_folders(update_status=False)
            return

        if self.settings.get("confirm_before_remove_folder", True):
            confirmed = messagebox.askyesno(
                "Remove Folder",
                "Are you sure you want to remove this folder?"
            )

            if not confirmed:
                return

        self._delete_folder_record(folder_id)

    def _delete_folder_record(self, folder_id):
        """Delete one folder row using the existing folders table."""
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
            self.connection.commit()
            self.refresh_folders()
            self.set_status("Folder removed successfully.", "success")
            messagebox.showinfo(
                "Remove Folder",
                "Folder removed successfully."
            )
        except backend.sqlite3.Error:
            messagebox.showerror(
                "Remove Folder",
                friendly_error_message("Removing the folder")
            )

    def refresh_folders(self, update_status=True):
        """Reload folder rows and refresh dashboard statistics."""
        folders = backend.get_registered_folders(self.connection)
        self.all_folders = folders
        self._clear_table()
        self._load_table_rows(self._get_filtered_folders())
        self._refresh_statistics(folders)

        if update_status:
            self.set_status("Ready", "neutral")

    def _handle_search_change(self, *_args):
        """Update the folder table as the search text changes."""
        if not hasattr(self, "folder_table"):
            return

        self._clear_table()
        self._load_table_rows(self._get_filtered_folders())

    def _get_filtered_folders(self):
        """Return folders matching the search box."""
        search_text = self.search_var.get().strip().lower()

        if not search_text:
            return self.all_folders

        filtered_folders = []

        for folder in self.all_folders:
            folder_id, nickname, folder_name, _path, status, _date_added = folder
            searchable_values = (
                str(folder_id),
                nickname,
                folder_name,
                status,
                self._format_status(status),
            )

            if any(search_text in str(value).lower() for value in searchable_values):
                filtered_folders.append(folder)

        return filtered_folders

    def _clear_table(self):
        """Remove all rows from the folder table."""
        for item in self.folder_table.get_children():
            self.folder_table.delete(item)

        self.folder_records = {}

    def _load_table_rows(self, folders):
        """Add folder rows to the Treeview."""
        for folder in folders:
            folder_id, nickname, folder_name, _path, status, _date_added = folder
            self.folder_records[str(folder_id)] = folder
            self.folder_table.insert(
                "",
                "end",
                values=(
                    folder_id,
                    nickname,
                    folder_name,
                    self._format_status(status)
                )
            )

    def _refresh_statistics(self, folders):
        """Update dashboard counts from the latest folder data."""
        total_count = len(folders)
        registered_count = self._count_status(
            folders,
            backend.STATUS_REGISTERED
        )
        hidden_count = self._count_status(folders, backend.STATUS_HIDDEN)
        locked_count = self._count_status(folders, backend.STATUS_LOCKED)

        stats = {
            "Total Folders": total_count,
            "Registered": registered_count,
            "Hidden": hidden_count,
            "Locked": locked_count,
        }

        for name, count in stats.items():
            self.stat_labels[name].configure(text=f"{name}: {count}")

    def _count_status(self, folders, status):
        """Count folders with the requested status."""
        return sum(1 for folder in folders if folder[4] == status)

    def _format_status(self, status):
        """Return the display-only status text for a database status."""
        return self.DISPLAY_STATUSES.get(status, status)

    def set_status(self, message, status_type="neutral"):
        """Update the dashboard status bar."""
        self.status_label.configure(
            text=message,
            text_color=self.STATUS_COLORS[status_type]
        )

    def _get_selected_folder(self):
        """Return the selected backend folder record, or None."""
        selected_item = self.folder_table.selection()

        if not selected_item:
            self.set_status("No folder selected", "warning")
            return None

        folder_id = str(self.folder_table.item(selected_item[0], "values")[0])
        folder = backend.get_folder_by_id(self.connection, folder_id)

        if folder is None:
            self.set_status("Folder ID does not exist", "error")
            self.refresh_folders(update_status=False)
            return None

        return folder

    def hide_selected_folder(self):
        """Hide the selected folder using existing backend helpers."""
        folder = self._get_selected_folder()

        if folder is None:
            return

        folder_id, nickname, _name, folder_path, status, _date_added = folder

        if not self._folder_exists_on_disk(folder_path):
            return

        if status == backend.STATUS_LOCKED:
            self.set_status("Folder is locked", "error")
            return

        if status == backend.STATUS_HIDDEN:
            self.set_status("Folder is already hidden", "warning")
            return

        if not backend.apply_hidden_attribute(folder_path, True):
            self.set_status("Could not hide folder", "error")
            return

        if not backend.update_folder_status(
            self.connection,
            folder_id,
            backend.STATUS_HIDDEN
        ):
            self.set_status("Database error while hiding folder", "error")
            return

        backend.write_log(f"HIDE FOLDER | {nickname}")
        self.refresh_folders()
        self.set_status("Folder hidden successfully", "success")

    def unhide_selected_folder(self):
        """Unhide the selected hidden folder after GUI password verification."""
        folder = self._get_selected_folder()

        if folder is None:
            return

        folder_id, nickname, _name, folder_path, status, _date_added = folder

        if status != backend.STATUS_HIDDEN:
            self.set_status("Folder is not hidden", "warning")
            return

        password_result = self._prompt_for_master_password()

        if not password_result["success"]:
            if not password_result.get("cancelled", False):
                self.set_status(
                    password_result["message"],
                    password_result["status_type"]
                )
            return

        if not self._folder_exists_on_disk(folder_path):
            return

        if not backend.apply_hidden_attribute(folder_path, False):
            self.set_status("Could not unhide folder", "error")
            return

        if not backend.update_folder_status(
            self.connection,
            folder_id,
            backend.STATUS_REGISTERED
        ):
            self.set_status("Database error while unhiding folder", "error")
            return

        backend.write_log(f"UNHIDE FOLDER | {nickname}")
        self.refresh_folders()
        self.set_status("Folder unhidden successfully", "success")

    def lock_selected_folder(self):
        """Start an asynchronous lock operation for the selected folder."""
        if self.operation_running:
            self.set_status("Another operation is already running", "warning")
            return

        folder = self._get_selected_folder()

        if folder is None:
            return

        folder_id, nickname, _name, folder_path, status, _date_added = folder

        if status == backend.STATUS_LOCKED:
            self.set_status("Folder is already locked", "warning")
            return

        if not self._folder_exists_on_disk(folder_path):
            return

        if self.settings.get("confirm_before_lock_folder", True):
            confirmed = messagebox.askyesno(
                "Lock Folder",
                f"Lock '{folder[2]}' now?"
            )

            if not confirmed:
                return

        passwords = self._ask_for_password_fields(
            "Lock Folder",
            (
                ("master_password", "Master Password"),
                ("folder_password", "Folder Encryption Password"),
            )
        )

        if passwords is None:
            return

        master_result = self._verify_protected_action_password(
            passwords["master_password"]
        )

        if not master_result["success"]:
            self.set_status(
                master_result["message"],
                master_result["status_type"]
            )
            return

        folder_password = passwords["folder_password"].strip()

        if not folder_password:
            self.set_status("Folder password cannot be empty", "warning")
            return

        self._start_threaded_operation(
            "Locking Folder...",
            self._lock_folder_worker,
            folder[2],
            folder_id,
            nickname,
            folder_path,
            folder_password
        )

    def unlock_selected_folder(self):
        """Start an asynchronous unlock operation for the selected folder."""
        if self.operation_running:
            self.set_status("Another operation is already running", "warning")
            return

        folder = self._get_selected_folder()

        if folder is None:
            return

        folder_id, nickname, _name, folder_path, status, _date_added = folder

        if status != backend.STATUS_LOCKED:
            self.set_status("Folder is not locked", "warning")
            return

        if self.settings.get("confirm_before_unlock_folder", True):
            confirmed = messagebox.askyesno(
                "Unlock Folder",
                f"Unlock '{folder[2]}' now?"
            )

            if not confirmed:
                return

        passwords = self._ask_for_password_fields(
            "Unlock Folder",
            (
                ("master_password", "Master Password"),
                ("folder_password", "Folder Password"),
            )
        )

        if passwords is None:
            return

        master_result = self._verify_protected_action_password(
            passwords["master_password"]
        )

        if not master_result["success"]:
            self.set_status(
                master_result["message"],
                master_result["status_type"]
            )
            return

        folder_password = passwords["folder_password"].strip()

        if not folder_password:
            self.set_status("Folder password cannot be empty", "warning")
            return

        if not self._folder_exists_on_disk(folder_path):
            return

        self._start_threaded_operation(
            "Unlocking Folder...",
            self._unlock_folder_worker,
            folder[2],
            folder_id,
            nickname,
            folder_path,
            folder_password
        )

    def _start_threaded_operation(self, title, worker, folder_name, *worker_args):
        """Run a long folder operation without blocking Tkinter."""
        self.operation_queue = queue.Queue()
        self.operation_running = True
        self.disable_main_controls()
        self._show_loading_screen(title, folder_name)
        self._update_loading_progress(0, 0)
        self.set_status(title, "neutral")

        operation_thread = threading.Thread(
            target=worker,
            args=(self.operation_queue, *worker_args),
            daemon=True
        )
        operation_thread.start()
        self._poll_operation_queue()

    def _poll_operation_queue(self):
        """Process worker-thread messages on the Tkinter main thread."""
        if self.operation_queue is None:
            return

        self.operation_after_id = None

        try:
            while True:
                message = self.operation_queue.get_nowait()
                message_type = message.get("type")

                if message_type == "progress":
                    self._update_loading_progress(
                        message["processed"],
                        message["total"]
                    )
                elif message_type == "done":
                    self._finish_threaded_operation(message)
                    return
        except queue.Empty:
            pass

        self.operation_after_id = self.after(100, self._poll_operation_queue)

    def _finish_threaded_operation(self, message):
        """Restore the dashboard and report final operation status."""
        if self.operation_after_id is not None:
            try:
                self.after_cancel(self.operation_after_id)
            except Exception:
                pass

            self.operation_after_id = None

        self.operation_queue = None
        self.operation_running = False
        self._hide_loading_screen()
        self.enable_main_controls()
        self.refresh_folders(update_status=False)
        self.set_status(message["message"], message["status_type"])

    def _show_loading_screen(self, operation_title, folder_name):
        """Hide normal dashboard content and show in-place loading UI."""
        self.content_frame.grid_remove()
        self.loading_operation_label.configure(text=operation_title)
        self.loading_folder_label.configure(text=folder_name)
        self.loading_frame.grid(row=0, column=1, padx=28, pady=28, sticky="nsew")

    def _hide_loading_screen(self):
        """Restore normal dashboard content after long work finishes."""
        self.loading_frame.grid_remove()
        self.content_frame.grid(
            row=0,
            column=1,
            padx=32,
            pady=(30, 18),
            sticky="nsew"
        )

    def _update_loading_progress(self, processed_files, total_files):
        """Update the in-window loading progress widgets."""
        if total_files <= 0:
            percentage = 100
        else:
            percentage = int((processed_files / total_files) * 100)

        self.loading_counter_label.configure(
            text=f"{processed_files} / {total_files} files"
        )
        self.loading_progress_bar.configure(value=percentage)
        self.loading_percent_label.configure(text=f"{percentage}%")

    def _set_actions_enabled(self, enabled):
        """Enable or disable dashboard buttons while work is running."""
        state = "normal" if enabled else "disabled"

        for button in self.action_buttons:
            button.configure(state=state)

    def disable_main_controls(self):
        """Disable all main action controls during long operations."""
        self._set_actions_enabled(False)

    def enable_main_controls(self):
        """Enable all main action controls after long operations."""
        self._set_actions_enabled(True)

    def _queue_progress(self, progress_queue, processed, total):
        """Send a progress update from a worker thread."""
        progress_queue.put(
            {
                "type": "progress",
                "processed": processed,
                "total": total,
            }
        )

    def _queue_done(self, progress_queue, status_type, message):
        """Send the final operation result from a worker thread."""
        progress_queue.put(
            {
                "type": "done",
                "status_type": status_type,
                "message": message,
            }
        )

    def _open_worker_connection(self):
        """Create a SQLite connection for a background worker thread."""
        return backend.sqlite3.connect(backend.DATABASE_FILE)

    def _lock_folder_worker(
        self,
        progress_queue,
        folder_id,
        nickname,
        folder_path,
        folder_password
    ):
        """Encrypt files in a worker thread and report progress."""
        connection = None

        try:
            connection = self._open_worker_connection()
            files = list(backend.iter_files(folder_path))
            total_files = len(files)
            processed_files = 0
            failed_files = 0
            self._queue_progress(progress_queue, processed_files, total_files)

            if not backend.save_folder_integrity_hashes(
                connection,
                folder_id,
                folder_path
            ):
                self._queue_done(
                    progress_queue,
                    "error",
                    "Could not save integrity hashes"
                )
                return

            for file_path in files:
                if backend.encrypt_file(file_path, folder_password):
                    processed_files += 1
                else:
                    failed_files += 1
                    processed_files += 1

                self._queue_progress(
                    progress_queue,
                    processed_files,
                    total_files
                )

            if failed_files > 0:
                self._queue_done(
                    progress_queue,
                    "error",
                    "Folder lock failed. Database status was not changed."
                )
                return

            backend.apply_hidden_attribute(folder_path, True)

            if not backend.update_folder_status(
                connection,
                folder_id,
                backend.STATUS_LOCKED
            ):
                self._queue_done(
                    progress_queue,
                    "error",
                    "Database error while locking folder"
                )
                return

            backend.write_log(f"LOCK FOLDER | {nickname}")
            self._queue_done(
                progress_queue,
                "success",
                "Folder locked successfully"
            )
        except Exception:
            self._queue_done(
                progress_queue,
                "error",
                friendly_error_message("Locking the folder")
            )
        finally:
            if connection is not None:
                connection.close()

    def _unlock_folder_worker(
        self,
        progress_queue,
        folder_id,
        nickname,
        folder_path,
        folder_password
    ):
        """Decrypt files in a worker thread and report progress."""
        connection = None

        try:
            connection = self._open_worker_connection()
            files = list(
                backend.iter_files(
                    folder_path,
                    skip_locked=False,
                    locked_only=True
                )
            )
            total_files = len(files)
            processed_files = 0
            failed_files = 0
            self._queue_progress(progress_queue, processed_files, total_files)

            if not backend.apply_hidden_attribute(folder_path, False):
                self._queue_done(
                    progress_queue,
                    "error",
                    "Folder could not be unhidden"
                )
                return

            for file_path in files:
                if backend.decrypt_file(file_path, folder_password):
                    processed_files += 1
                else:
                    failed_files += 1
                    processed_files += 1

                self._queue_progress(
                    progress_queue,
                    processed_files,
                    total_files
                )

            if failed_files > 0:
                backend.apply_hidden_attribute(folder_path, True)
                self._queue_done(
                    progress_queue,
                    "error",
                    "Folder unlock failed. Check the folder password."
                )
                return

            integrity_ok = backend.verify_folder_integrity(
                connection,
                folder_id,
                folder_path
            )

            if not backend.update_folder_status(
                connection,
                folder_id,
                backend.STATUS_REGISTERED
            ):
                self._queue_done(
                    progress_queue,
                    "error",
                    "Database error while unlocking folder"
                )
                return

            backend.write_log(f"UNLOCK FOLDER | {nickname}")

            if integrity_ok:
                self._queue_done(
                    progress_queue,
                    "success",
                    "Folder unlocked successfully"
                )
            else:
                self._queue_done(
                    progress_queue,
                    "warning",
                    "Folder unlocked. Integrity verification found issues."
                )
        except Exception:
            self._queue_done(
                progress_queue,
                "error",
                friendly_error_message("Unlocking the folder")
            )
        finally:
            if connection is not None:
                connection.close()

    def change_master_password(self):
        """Change the master password using a GUI dialog."""
        confirmed = messagebox.askyesno(
            "Change Password",
            "Are you sure you want to change the master password?"
        )

        if not confirmed:
            return

        passwords = self._ask_for_password_fields(
            "Change Password",
            (
                ("current_password", "Current Password"),
                ("new_password", "New Password"),
                ("confirm_password", "Confirm Password"),
            )
        )

        if passwords is None:
            return

        current_result = self._verify_protected_action_password(
            passwords["current_password"]
        )

        if not current_result["success"]:
            self.set_status(
                current_result["message"],
                current_result["status_type"]
            )
            return

        new_password = passwords["new_password"]
        confirm_password = passwords["confirm_password"]

        if not new_password:
            self.set_status("New password cannot be empty", "warning")
            return

        if new_password != confirm_password:
            self.set_status("New passwords do not match", "warning")
            return

        (
            password_hash,
            password_salt,
            password_algorithm,
            password_iterations
        ) = backend.hash_password(new_password)

        if not backend.save_password_hash(
            self.connection,
            password_hash,
            password_salt,
            password_algorithm,
            password_iterations
        ):
            self.set_status("Password could not be changed", "error")
            return

        backend.write_log("PASSWORD CHANGED")
        self.set_status("Password changed successfully", "success")

    def open_activity_log(self):
        """Open a scrollable activity log viewer."""
        ActivityLogWindow(self)

    def backup_database(self):
        """Create a timestamped database backup in Backups/."""
        if self.operation_running:
            self.set_status("Please wait for the current operation to finish.", "warning")
            return

        try:
            backend.save_database_signature(self.connection)
            backup_path = backend.backup_database_files(
                self.connection,
                prefix="locker",
                write_activity=True
            )
        except (OSError, backend.sqlite3.Error):
            backup_path = None

        if backup_path is None:
            self.set_status(
                "Database backup failed. Please check the Backups folder.",
                "error"
            )
            return

        self.set_status(
            f"Database backup created: {os.path.basename(backup_path)}",
            "success"
        )

    def restore_database(self):
        """Restore locker.db from a selected backup file."""
        if self.operation_running:
            self.set_status("Please wait for the current operation to finish.", "warning")
            return

        backup_path = filedialog.askopenfilename(
            title="Select Database Backup",
            initialdir=backend.BACKUPS_DIR,
            filetypes=(("Database files", "*.db"), ("All files", "*.*"))
        )

        if not backup_path:
            return

        password_result = self._prompt_for_master_password()

        if not password_result["success"]:
            if not password_result.get("cancelled", False):
                self.set_status(
                    password_result["message"],
                    password_result["status_type"]
                )
            return

        if not backend.backup_database_is_readable(backup_path):
            self.set_status(
                "Selected backup is not a readable Folder Locker database.",
                "error"
            )
            return

        signature_path = backend.get_matching_backup_signature_path(backup_path)

        if os.path.exists(signature_path) and not backend.verify_backup_signature(
            backup_path,
            signature_path
        ):
            self.set_status(
                "Restore stopped because the backup signature is invalid.",
                "error"
            )
            return

        confirmed = messagebox.askyesno(
            "Restore Database",
            "Restore this backup now? A safety backup of the current database will be created first."
        )

        if not confirmed:
            return

        try:
            safety_backup_path = backend.backup_database_files(
                self.connection,
                prefix="safety_locker",
                write_activity=False
            )

            if safety_backup_path is None:
                self.set_status(
                    "Restore stopped because the safety backup failed.",
                    "error"
                )
                return

            temporary_database_path = backend.prepare_restore_file(
                backup_path,
                backend.DATABASE_FILE
            )
            temporary_signature_path = None

            if os.path.exists(signature_path):
                temporary_signature_path = backend.prepare_restore_file(
                    signature_path,
                    backend.DATABASE_SIGNATURE_FILE
                )

            self.connection.close()

            backend.finish_restore_file(
                temporary_database_path,
                backend.DATABASE_FILE
            )

            if temporary_signature_path is not None:
                backend.finish_restore_file(
                    temporary_signature_path,
                    backend.DATABASE_SIGNATURE_FILE
                )
            else:
                backend.save_database_signature()

            self.connection = backend.connect_to_database()
            backend.create_tables(self.connection)
            backend.save_database_signature(self.connection)
            self.master.connection = self.connection
            backend.write_log("DATABASE RESTORED")
            self.refresh_folders(update_status=False)
            self.set_status(
                (
                    "Database restored successfully. "
                    f"Safety backup: {os.path.basename(safety_backup_path)}"
                ),
                "success"
            )
        except (OSError, backend.sqlite3.Error):
            self.connection = backend.connect_to_database()
            self.master.connection = self.connection
            self.set_status(
                "Database restore failed. The current database was left in place if replacement did not finish.",
                "error"
            )

    def export_activity_log(self):
        """Export activity.log as a TXT file to a user-selected location."""
        if not os.path.exists(backend.LOG_FILE):
            self.set_status("No activity log found to export.", "warning")
            return

        default_name = f"activity_log_{backend.get_timestamp_for_filename()}.txt"
        export_path = filedialog.asksaveasfilename(
            title="Export Activity Log",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )

        if not export_path:
            return

        try:
            shutil.copy2(backend.LOG_FILE, export_path)
            backend.write_log("ACTIVITY LOG EXPORTED")
        except OSError:
            self.set_status(
                "Activity log export failed. Please choose another location.",
                "error"
            )
            return

        self.set_status(
            f"Activity log exported: {os.path.basename(export_path)}",
            "success"
        )

    def open_settings(self):
        """Open application settings."""
        SettingsWindow(self, self.settings, self._save_settings)

    def _save_settings(self, updated_settings):
        """Save dashboard settings through the application."""
        self.master.update_settings(updated_settings)
        self.settings = self.master.settings
        self.set_status("Settings saved.", "success")

    def _ask_for_password_fields(self, title, fields):
        """Open a modal password dialog and return its entered values."""
        dialog = PasswordFieldsDialog(self, title, fields)
        self.wait_window(dialog)
        return dialog.result

    def _prompt_for_master_password(self):
        """Ask for and verify the master password with backend helpers."""
        password = simpledialog.askstring(
            "Master Password",
            "Enter master password:",
            parent=self,
            show="*"
        )

        if password is None:
            return {
                "success": False,
                "cancelled": True,
            }

        return self._verify_protected_action_password(password)

    def _verify_protected_action_password(self, password):
        """Verify a protected-action password without popup error messages."""
        failed_attempts, lockout_until = backend.get_security_state(
            self.connection
        )
        current_time = time.time()

        if current_time < lockout_until:
            remaining_seconds = int(lockout_until - current_time)
            return {
                "success": False,
                "status_type": "error",
                "message": (
                    "Too many failed attempts.\n"
                    f"Try again in {remaining_seconds} seconds."
                )
            }

        if lockout_until > 0 and failed_attempts > 0:
            failed_attempts = 0
            lockout_until = 0
            backend.update_security_state(
                self.connection,
                failed_attempts,
                lockout_until
            )

        stored_record = backend.get_stored_password_record(self.connection)

        if stored_record is None:
            return {
                "success": False,
                "status_type": "error",
                "message": "No master password is set."
            }

        password_is_valid = backend.verify_password_record(
            password,
            stored_record["password_hash"],
            stored_record["password_salt"],
            stored_record["password_algorithm"],
            stored_record["password_iterations"]
        )

        if password_is_valid:
            migrate_password_if_needed(
                self.connection,
                password,
                stored_record
            )
            backend.update_security_state(self.connection, 0, 0)
            return {
                "success": True,
                "message": "Password verified."
            }

        return self._record_protected_action_failed_password(failed_attempts)

    def _record_protected_action_failed_password(self, failed_attempts):
        """Update failed password attempts and return a status-bar message."""
        failed_attempts += 1
        remaining_attempts = backend.MAX_LOGIN_ATTEMPTS - failed_attempts

        if remaining_attempts > 0:
            backend.update_security_state(
                self.connection,
                failed_attempts,
                0
            )
            return {
                "success": False,
                "status_type": "warning",
                "message": (
                    "Invalid password.\n"
                    f"Attempts remaining: {remaining_attempts}"
                )
            }

        lockout_until = time.time() + backend.LOCKOUT_SECONDS
        backend.update_security_state(
            self.connection,
            failed_attempts,
            lockout_until
        )

        return {
            "success": False,
            "status_type": "error",
            "message": (
                "Too many failed attempts.\n"
                f"Try again in {backend.LOCKOUT_SECONDS} seconds."
            )
        }

    def _folder_exists_on_disk(self, folder_path):
        """Show a dashboard error when the saved folder path is missing."""
        if not os.path.exists(folder_path):
            self.set_status("Folder no longer exists on disk.", "error")
            return False

        if not os.path.isdir(folder_path):
            self.set_status(
                "The saved path is no longer a folder.",
                "error"
            )
            return False

        return True

    def open_selected_folder(self):
        """Open the selected folder in Windows File Explorer."""
        folder = self._get_selected_folder()

        if folder is None:
            return

        folder_path = folder[3]

        if not self._folder_exists_on_disk(folder_path):
            return

        try:
            os.startfile(folder_path)
            self.set_status("Folder opened", "success")
        except OSError:
            self.set_status(
                "Could not open folder. Please check the saved path.",
                "error"
            )

    def _show_context_menu(self, event):
        """Show the context menu for the row under the mouse."""
        if self.operation_running:
            self.set_status(
                "Please wait for the current operation to finish.",
                "warning"
            )
            return

        row_id = self.folder_table.identify_row(event.y)

        if row_id:
            self.folder_table.selection_set(row_id)
            try:
                self.context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.context_menu.grab_release()

    def show_later_version_message(self):
        """Show the placeholder popup for future dashboard features."""
        messagebox.showinfo(
            "Folder Locker",
            "Feature will be connected in a later version"
        )


class FolderLockerGUI(ctk.CTk):
    """Main CustomTkinter application for Folder Locker."""

    def __init__(self):
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                APP_USER_MODEL_ID
            )
        except Exception:
            pass

        super().__init__()

        from pathlib import Path

        if getattr(sys, "frozen", False):
            base_path = Path(sys._MEIPASS)
        else:
            base_path = Path(__file__).parent

        icon_path = base_path / "Assets" / "icon.ico"

        try:
            self.iconbitmap(str(icon_path))
        except Exception as exc:
            try:
                with open(STARTUP_DIAGNOSTIC_LOG, "a", encoding="utf-8") as log:
                    log.write(f"Icon load failed: {exc} (path={icon_path})\n")
            except OSError:
                pass

        self.connection = None
        self.master_password = None
        self.backend_ready = False
        self.countdown_after_id = None
        self.config_data = load_app_config()
        self.settings = self.config_data["settings"]
        Theme.apply_mode(self.settings.get("theme", "Dark"))

        self.title(f"Folder Locker v{APP_VERSION}")
        self.geometry(self._get_startup_geometry())
        self.minsize(900, 600)
        self.protocol("WM_DELETE_WINDOW", self.close_application)
        self._build_menu_bar()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._prepare_backend()
        if not self.backend_ready:
            return

        if self.settings.get("open_maximized_on_startup", False):
            self.after(50, self._maximize_window)

        self.show_login_screen()

    def _get_startup_geometry(self):
        """Return the configured startup geometry."""
        if self.settings.get("remember_window_size", True):
            return self.settings.get("window_geometry", "1100x700")

        return DEFAULT_SETTINGS["window_geometry"]

    def _maximize_window(self):
        """Maximize the window after Tk has initialized."""
        try:
            self.state("zoomed")
        except TclError:
            self.geometry(self._get_startup_geometry())

    def update_settings(self, updated_settings):
        """Persist updated settings and apply immediate app-level changes."""
        self.settings.update(updated_settings)
        self.config_data["settings"] = self.settings
        self.config_data["version"] = APP_VERSION
        save_app_config(self.config_data)
        Theme.apply_mode(self.settings.get("theme", "Dark"))

    def _build_menu_bar(self):
        """Create the top menu bar with Help -> About."""
        menu_bar = Menu(self)
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.open_about_window)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu_bar)

    def open_about_window(self):
        """Open a non-modal About window using the app's current theme."""
        about_window = ctk.CTkToplevel(self)
        about_window.title("About Folder Locker")
        about_window.geometry("460x380")
        about_window.resizable(False, False)
        about_window.configure(fg_color=Theme.BACKGROUND)
        about_window.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            about_window,
            text=f"Folder Locker v{APP_VERSION}",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=30, weight="bold")
        )
        title.grid(row=0, column=0, padx=24, pady=(30, 8), sticky="ew")

        author = ctk.CTkLabel(
            about_window,
            text=f"Author: {APP_AUTHOR}",
            text_color=Theme.TEXT,
            font=ctk.CTkFont(size=16)
        )
        author.grid(row=1, column=0, padx=24, pady=(0, 8), sticky="ew")

        description = ctk.CTkLabel(
            about_window,
            text="Secure Folder Protection Utility",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=15)
        )
        description.grid(row=2, column=0, padx=24, pady=(0, 8), sticky="ew")

        copyright_label = ctk.CTkLabel(
            about_window,
            text="\u00a9 2026",
            text_color=Theme.MUTED_TEXT,
            font=ctk.CTkFont(size=14)
        )
        copyright_label.grid(row=3, column=0, padx=24, pady=(0, 16), sticky="ew")

        ctk.CTkFrame(
            about_window,
            height=1,
            fg_color=Theme.BORDER,
        ).grid(row=4, column=0, padx=24, pady=(0, 16), sticky="ew")

        features = ctk.CTkLabel(
            about_window,
            text=(
                "Features:\n"
                "\u2022 Folder Hiding\n"
                "\u2022 Folder Locking\n"
                "\u2022 Encryption\n"
                "\u2022 Integrity Verification\n"
                "\u2022 Database Protection\n"
                "\u2022 Activity Logging"
            ),
            text_color=Theme.TEXT,
            justify="left",
            anchor="w",
            font=ctk.CTkFont(size=14)
        )
        features.grid(row=5, column=0, padx=36, pady=(0, 20), sticky="ew")

        close_button = ctk.CTkButton(
            about_window,
            text="Close",
            width=120,
            fg_color=Theme.PRIMARY,
            hover_color=Theme.PRIMARY_HOVER,
            command=about_window.destroy
        )
        close_button.grid(row=6, column=0, padx=24, pady=(0, 24), sticky="e")

    def _write_startup_diagnostic(self, message):
        """Append startup integrity diagnostics outside locker.db."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        try:
            with open(
                STARTUP_DIAGNOSTIC_LOG,
                "a",
                encoding="utf-8"
            ) as diagnostic_file:
                diagnostic_file.write(f"{timestamp} | {message}\n")
        except OSError:
            pass

    def _database_file_state(self):
        """Return a lightweight physical file state for startup diagnostics."""
        if not os.path.exists(backend.DATABASE_FILE):
            return "missing"

        try:
            file_stat = os.stat(backend.DATABASE_FILE)
            sha256 = backend.hashlib.sha256()

            with open(backend.DATABASE_FILE, "rb") as database_file:
                while True:
                    chunk = database_file.read(1024 * 1024)

                    if not chunk:
                        break

                    sha256.update(chunk)

            return (
                f"size={file_stat.st_size};"
                f"mtime_ns={file_stat.st_mtime_ns};"
                f"sha256={sha256.hexdigest()}"
            )
        except OSError as error:
            return f"unreadable:{type(error).__name__}"

    def _run_startup_step(self, step_name, callback):
        """Run one startup step and log whether it changed locker.db."""
        before_state = self._database_file_state()
        self._write_startup_diagnostic(
            f"before {step_name}: {before_state}"
        )
        result = callback()
        after_state = self._database_file_state()
        self._write_startup_diagnostic(
            f"after {step_name}: {after_state}"
        )

        if before_state != after_state:
            self._write_startup_diagnostic(
                f"locker.db changed during startup step: {step_name}"
            )

        return result

    def _prepare_backend(self):
        """Open the database and run the same startup checks as the backend."""
        self._write_startup_diagnostic(
            f"startup begin | app_version={APP_VERSION}"
        )
        database_existed = backend.startup_file_has_content("locker.db")
        signature_existed = backend.startup_file_exists(
            "locker.db.signature"
        )

        self._run_startup_step(
            "ensure_project_files",
            backend.ensure_project_files
        )

        try:
            self.connection = self._run_startup_step(
                "connect_to_database",
                backend.connect_to_database
            )
        except RuntimeError as db_error:
            self._write_startup_diagnostic(f"connect_to_database failed: {db_error}")
            messagebox.showerror(
                "Startup Error",
                f"Folder Locker could not open its database.\n\n{db_error}\n\n"
                "Please check that the application data directory is accessible "
                "and try again."
            )
            return

        if database_existed and signature_existed:
            self._write_startup_diagnostic(
                "verify_database_signature started"
            )
            signature_is_valid = self._run_startup_step(
                "verify_database_signature",
                lambda: backend.verify_database_signature(self.connection)
            )

            if not signature_is_valid:
                self._write_startup_diagnostic(
                    "verify_database_signature failed"
                )

                if not self._handle_database_integrity_alert():
                    self.close_application(save_signature=False)
                    return
            else:
                self._write_startup_diagnostic(
                    "verify_database_signature passed"
                )

        self._write_startup_diagnostic("create_tables started")
        try:
            self._run_startup_step(
                "create_tables",
                lambda: backend.create_tables(self.connection)
            )
        except RuntimeError as db_error:
            self._write_startup_diagnostic(f"create_tables failed: {db_error}")
            messagebox.showerror(
                "Startup Error",
                f"Folder Locker could not initialise its database.\n\n{db_error}\n\n"
                "The database file may be corrupted. "
                "Try restoring from a backup."
            )
            return
        self._write_startup_diagnostic("create_tables finished")
        self._run_startup_step(
            "ensure_database_signature_file",
            lambda: backend.ensure_database_signature_file(self.connection)
        )

        self._write_startup_diagnostic("startup complete")
        self.backend_ready = True

    def _handle_database_integrity_alert(self):
        """Show GUI recovery options after signature verification fails."""
        dialog = IntegrityAlertDialog(self)
        self.wait_window(dialog)

        if dialog.result != "recovery":
            return False

        password_result = self._prompt_for_recovery_password()

        if password_result is None:
            return self._handle_database_integrity_alert()

        if not password_result["success"]:
            messagebox.showerror(
                "Database Integrity Alert",
                password_result["message"]
            )
            return self._handle_database_integrity_alert()

        if not backend.save_database_signature(self.connection):
            messagebox.showerror(
                "Database Integrity Alert",
                "Recovery failed. The database signature could not be saved."
            )
            return False

        self._write_startup_diagnostic(
            "database signature rebuilt through GUI recovery"
        )
        messagebox.showinfo(
            "Database Integrity Alert",
            "Recovery Successful"
        )
        return True

    def _prompt_for_recovery_password(self):
        """Ask for the master password and verify it for recovery."""
        password = simpledialog.askstring(
            "Database Recovery",
            "Enter master password:",
            parent=self,
            show="*"
        )

        if password is None:
            return None

        return self._verify_recovery_password(password)

    def _verify_recovery_password(self, password):
        """Verify the master password during startup recovery."""
        failed_attempts, lockout_until = backend.get_security_state(
            self.connection
        )
        current_time = time.time()

        if current_time < lockout_until:
            remaining_seconds = int(lockout_until - current_time)
            return {
                "success": False,
                "message": (
                    "Too many failed attempts.\n"
                    f"Try again in {remaining_seconds} seconds."
                )
            }

        if lockout_until > 0 and failed_attempts > 0:
            failed_attempts = 0
            lockout_until = 0
            backend.update_security_state(
                self.connection,
                failed_attempts,
                lockout_until
            )

        stored_record = backend.get_stored_password_record(self.connection)

        if stored_record is None:
            return {
                "success": False,
                "message": "No master password is set."
            }

        password_is_valid = backend.verify_password_record(
            password,
            stored_record["password_hash"],
            stored_record["password_salt"],
            stored_record["password_algorithm"],
            stored_record["password_iterations"]
        )

        if password_is_valid:
            migrate_password_if_needed(self.connection, password, stored_record)
            backend.update_security_state(self.connection, 0, 0)
            return {"success": True}

        failed_attempts += 1
        remaining_attempts = backend.MAX_LOGIN_ATTEMPTS - failed_attempts

        if remaining_attempts > 0:
            backend.update_security_state(self.connection, failed_attempts, 0)
            return {
                "success": False,
                "message": (
                    "Invalid password.\n"
                    f"Attempts remaining: {remaining_attempts}"
                )
            }

        lockout_until = time.time() + backend.LOCKOUT_SECONDS
        backend.update_security_state(
            self.connection,
            failed_attempts,
            lockout_until
        )

        return {
            "success": False,
            "message": (
                "Too many failed attempts.\n"
                f"Try again in {backend.LOCKOUT_SECONDS} seconds."
            )
        }

    def _password_exists(self):
        """Return True when a master password record is already stored."""
        return backend.get_stored_password_record(self.connection) is not None

    def show_setup_screen(self):
        """Display the first-run setup frame when no master password exists."""
        self.setup_frame = FirstRunSetupFrame(self, self.handle_first_run_setup)
        self.setup_frame.grid(row=0, column=0, sticky="nsew")

    def show_login_screen(self):
        """Display the login frame, or the setup screen on first run."""
        if not self._password_exists():
            self.show_setup_screen()
            return

        self.login_frame = LoginFrame(self, self.handle_login)
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.login_frame.focus_password_entry()
        self._show_existing_lockout_if_needed()

    def handle_first_run_setup(self, password, confirm):
        """Validate the new password, save it, and proceed to the app."""
        if not password:
            self.setup_frame.set_status(
                "Password cannot be empty.", "error"
            )
            return

        if len(password) < 4:
            self.setup_frame.set_status(
                "Password must be at least 4 characters.", "error"
            )
            return

        if password != confirm:
            self.setup_frame.set_status(
                "Passwords do not match. Please try again.", "error"
            )
            return

        # Disable controls while saving
        self.setup_frame.set_controls_enabled(False)
        self.setup_frame.set_status("Creating password…", "neutral")

        try:
            password_hash, password_salt, password_algorithm, password_iterations = (
                backend.hash_password(password)
            )
            success = backend.save_password_hash(
                self.connection,
                password_hash,
                password_salt,
                password_algorithm,
                password_iterations,
            )

            if not success:
                self.setup_frame.set_controls_enabled(True)
                self.setup_frame.set_status(
                    "Could not save password. Please try again.", "error"
                )
                return

            # Rebuild the database signature now that the password row exists
            backend.save_database_signature(self.connection)
            backend.write_log("MASTER PASSWORD CREATED (first-run setup)")

        except Exception:
            self.setup_frame.set_controls_enabled(True)
            self.setup_frame.set_status(
                "An unexpected error occurred. Please try again.", "error"
            )
            return

        self.setup_frame.set_status(
            "Password created! Taking you to Folder Locker…", "success"
        )
        # Brief pause so the user sees the success message, then go to dashboard
        self.after(900, self._transition_from_setup)

    def show_dashboard(self):
        """Hide login and display the Phase 1 dashboard."""
        self._cancel_countdown()
        self.login_frame.grid_forget()
        self.dashboard_frame = DashboardFrame(self, self.connection)
        self.dashboard_frame.grid(row=0, column=0, sticky="nsew")

    def _transition_from_setup(self):
        """Remove the setup frame and go directly to the dashboard."""
        self.setup_frame.grid_forget()
        # The password was just created and we know it – skip re-login
        # by reading it back from the setup frame's entry widget.
        # Since the frame may already be gone, drive the normal login flow.
        self.login_frame = LoginFrame(self, self.handle_login)
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.login_frame.focus_password_entry()

    def handle_login(self, entered_password):
        """Verify the entered password using existing backend helpers."""
        if not entered_password:
            self.login_frame.set_status(
                "Please enter your password.",
                "orange"
            )
            self.login_frame.focus_password_entry()
            return

        login_result = self._verify_password(entered_password)

        if login_result["success"]:
            self.master_password = entered_password
            self.login_frame.set_status("Login successful.", "green")
            self.login_frame.set_login_enabled(False)
            self.after(500, self.show_dashboard)
            return

        self.login_frame.set_status(
            login_result["message"],
            login_result["status_type"]
        )
        self.login_frame.clear_password()

        if login_result.get("locked"):
            self._start_lockout_countdown(
                login_result["lockout_until"],
                login_result.get("show_lock_message", False)
            )

    def _verify_password(self, entered_password):
        """Verify the entered password using the backend security helpers."""
        failed_attempts, lockout_until = backend.get_security_state(
            self.connection
        )
        current_time = time.time()

        if current_time < lockout_until:
            remaining_seconds = int(lockout_until - current_time)
            return {
                "success": False,
                "locked": True,
                "lockout_until": lockout_until,
                "status_type": "red",
                "message": (
                    "Too many failed attempts.\n"
                    f"Try again in {remaining_seconds} seconds."
                )
            }

        if lockout_until > 0:
            failed_attempts = 0
            lockout_until = 0
            backend.update_security_state(
                self.connection,
                failed_attempts,
                lockout_until
            )

        stored_record = backend.get_stored_password_record(self.connection)

        if stored_record is None:
            return {
                "success": False,
                "status_type": "orange",
                "message": "No master password is set."
            }

        password_is_valid = backend.verify_password_record(
            entered_password,
            stored_record["password_hash"],
            stored_record["password_salt"],
            stored_record["password_algorithm"],
            stored_record["password_iterations"]
        )

        if password_is_valid:
            migrate_password_if_needed(
                self.connection,
                entered_password,
                stored_record
            )
            backend.update_security_state(self.connection, 0, 0)
            backend.write_log("LOGIN SUCCESS")
            return {"success": True, "message": "Login successful."}

        return self._record_failed_login(failed_attempts)

    def _record_failed_login(self, failed_attempts):
        """Update failed-attempt tracking after an incorrect password."""
        failed_attempts += 1
        remaining_attempts = backend.MAX_LOGIN_ATTEMPTS - failed_attempts

        if remaining_attempts > 0:
            backend.update_security_state(
                self.connection,
                failed_attempts,
                0
            )
            return {
                "success": False,
                "status_type": "orange",
                "message": (
                    "Incorrect password.\n"
                    f"Attempts remaining: {remaining_attempts}"
                )
            }

        lockout_until = time.time() + backend.LOCKOUT_SECONDS
        backend.update_security_state(
            self.connection,
            failed_attempts,
            lockout_until
        )
        backend.write_log("LOGIN LOCKOUT")

        return {
            "success": False,
            "locked": True,
            "lockout_until": lockout_until,
            "show_lock_message": True,
            "status_type": "red",
            "message": (
                "Too many failed attempts.\n"
                f"Locked for {backend.LOCKOUT_SECONDS} seconds."
            )
        }

    def _show_existing_lockout_if_needed(self):
        """Resume the countdown if the backend says login is locked."""
        _failed_attempts, lockout_until = backend.get_security_state(
            self.connection
        )

        if time.time() < lockout_until:
            self._start_lockout_countdown(lockout_until)

    def _start_lockout_countdown(self, lockout_until, show_lock_message=False):
        """Disable login controls and start a live lockout countdown."""
        self._cancel_countdown()
        self.login_frame.set_login_enabled(False)

        if show_lock_message:
            self.countdown_after_id = self.after(
                1000,
                self._update_lockout_countdown,
                lockout_until
            )
            return

        self._update_lockout_countdown(lockout_until)

    def _update_lockout_countdown(self, lockout_until):
        """Refresh the lockout message once per second."""
        remaining_seconds = max(0, int(lockout_until - time.time()))

        if remaining_seconds <= 0:
            self.login_frame.set_login_enabled(True)
            self.login_frame.set_status("You may try again.", "neutral")
            self.countdown_after_id = None
            return

        self.login_frame.set_status(
            (
                "Too many failed attempts.\n"
                f"Try again in {remaining_seconds} seconds."
            ),
            "red"
        )
        self.countdown_after_id = self.after(
            1000,
            self._update_lockout_countdown,
            lockout_until
        )

    def _cancel_countdown(self):
        """Cancel any pending countdown callback."""
        if self.countdown_after_id is None:
            return

        self.after_cancel(self.countdown_after_id)
        self.countdown_after_id = None

    def close_application(self, save_signature=True):
        """Close the database connection and exit the GUI."""
        if save_signature:
            confirmed = messagebox.askyesno(
                "Exit",
                "Exit Folder Locker?"
            )

            if not confirmed:
                return

        dashboard = getattr(self, "dashboard_frame", None)

        if (
            dashboard is not None
            and getattr(dashboard, "operation_running", False)
        ):
            dashboard.set_status(
                "Please wait for the current operation to finish.",
                "warning"
            )
            return

        self._cancel_countdown()

        if self.settings.get("remember_window_size", True):
            self.settings["window_geometry"] = self.geometry()
            self.config_data["settings"] = self.settings
            try:
                save_app_config(self.config_data)
            except OSError:
                pass

        if save_signature:
            try:
                backend.save_database_signature(self.connection)
            except Exception:
                pass

        if self.connection is not None:
            try:
                self.connection.close()
            except backend.sqlite3.Error:
                pass

        self.destroy()


if __name__ == "__main__":
    app = FolderLockerGUI()
    if app.backend_ready:
        app.mainloop()
