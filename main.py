import os
import hashlib
import sqlite3
import json
import sys
import subprocess
import time
import hmac
import secrets
import struct
import shutil
# NOTE: 'getpass' is imported lazily inside console-only functions so that
# importing this module as a backend library never triggers a console read.

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    Fernet = None
    InvalidToken = None
    hashes = None
    PBKDF2HMAC = None


# File and folder names used by the application. Keeping them in constants makes
# the program easier to update later without hunting through the code.
APP_VERSION = "6.8.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_app_data_dir():
    """Return the Folder Locker user-data directory under LOCALAPPDATA."""
    local_app_data = os.environ.get("LOCALAPPDATA")

    if not local_app_data:
        local_app_data = os.path.join(
            os.path.expanduser("~"),
            "AppData",
            "Local"
        )

    app_data_dir = os.path.join(local_app_data, "FolderLocker")
    os.makedirs(app_data_dir, exist_ok=True)
    return app_data_dir


APP_DATA_DIR = get_app_data_dir()
DATABASE_FILE = os.path.join(APP_DATA_DIR, "locker.db")
CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")
LOG_FILE = os.path.join(APP_DATA_DIR, "activity.log")
SECURITY_LOG_FILE = os.path.join(APP_DATA_DIR, "security.log")
STARTUP_DIAGNOSTIC_LOG = os.path.join(
    APP_DATA_DIR,
    "startup_diagnostics.log"
)
DATABASE_SIGNATURE_FILE = os.path.join(
    APP_DATA_DIR,
    "locker.db.signature"
)
SECRET_KEY_FILE = os.path.join(
    APP_DATA_DIR,
    "secret.key"
)
LOCKED_FOLDERS_DIR = os.path.join(APP_DATA_DIR, "Locked Folders")
BACKUPS_DIR = os.path.join(APP_DATA_DIR, "Backups")
EXPORTS_DIR = os.path.join(APP_DATA_DIR, "Exports")
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_SECONDS = 30
STATUS_REGISTERED = "REGISTERED"
STATUS_HIDDEN = "HIDDEN"
STATUS_LOCKED = "LOCKED"
PASSWORD_ALGORITHM_PBKDF2 = "pbkdf2_sha256"
PASSWORD_ALGORITHM_LEGACY_SHA256 = "sha256"
PASSWORD_PBKDF2_ITERATIONS = 600000
SALT_SIZE_BYTES = 16
STREAM_FILE_MAGIC = b"FLK2"
ENCRYPTION_CHUNK_SIZE = 4 * 1024 * 1024
MAX_ENCRYPTED_CHUNK_SIZE = ENCRYPTION_CHUNK_SIZE * 2
MAX_LEGACY_DECRYPT_BYTES = 100 * 1024 * 1024
LOG_CHAIN_START = "0" * 64


LEGACY_FILE_NAMES = (
    "locker.db",
    "locker.db.signature",
    "secret.key",
    "config.json",
    "activity.log",
    "startup_diagnostics.log",
    "security.log"
)
LEGACY_DIRECTORY_NAMES = (
    "Locked Folders",
    "Backups",
    "Exports"
)


def migrate_path_if_needed(old_path, new_path):
    """Move one legacy file or directory into APP_DATA_DIR when possible."""
    if os.path.abspath(old_path) == os.path.abspath(new_path):
        return None

    if not os.path.exists(old_path) or os.path.exists(new_path):
        return None

    os.makedirs(os.path.dirname(new_path), exist_ok=True)
    shutil.move(old_path, new_path)
    return os.path.basename(old_path)


def migrate_legacy_user_files():
    """Migrate user data from the old application directory."""
    migrated_names = []

    for file_name in LEGACY_FILE_NAMES:
        migrated_name = migrate_path_if_needed(
            os.path.join(BASE_DIR, file_name),
            os.path.join(APP_DATA_DIR, file_name)
        )

        if migrated_name is not None:
            migrated_names.append(migrated_name)

    for directory_name in LEGACY_DIRECTORY_NAMES:
        migrated_name = migrate_path_if_needed(
            os.path.join(BASE_DIR, directory_name),
            os.path.join(APP_DATA_DIR, directory_name)
        )

        if migrated_name is not None:
            migrated_names.append(migrated_name)

    return migrated_names


def startup_file_exists(file_name):
    """Return True when a user file exists in either current or legacy storage."""
    current_path = os.path.join(APP_DATA_DIR, file_name)
    legacy_path = os.path.join(BASE_DIR, file_name)

    return os.path.exists(current_path) or os.path.exists(legacy_path)


def startup_file_has_content(file_name):
    """Return True when a user file exists with content before migration."""
    for parent_dir in (APP_DATA_DIR, BASE_DIR):
        file_path = os.path.join(parent_dir, file_name)

        if not os.path.exists(file_path):
            continue

        try:
            if os.path.getsize(file_path) > 0:
                return True
        except OSError:
            continue

    return False


def log_startup_status(message):
    """Write a startup status message without depending on protected logging."""
    from datetime import datetime

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:
        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as log_file:
            log_file.write(f"{timestamp} | STARTUP | {message}\n")
    except OSError:
        print(f"STARTUP | {message}")


def write_default_config():
    """Create the default config.json file."""
    default_config = {
        "app_name": "Folder Locker",
        "version": APP_VERSION,
        "locked_folders_directory": "Locked Folders"
    }

    with open(
        CONFIG_FILE,
        "w",
        encoding="utf-8"
    ) as config_file:

        json.dump(default_config, config_file, indent=4)

    return default_config


def ensure_project_files():
    """Create basic project files and folders if they are missing."""
    try:
        migrated_names = migrate_legacy_user_files()

        for migrated_name in migrated_names:
            log_startup_status(
                f"Migrated {migrated_name} to app data directory."
            )

        if not os.path.exists(LOCKED_FOLDERS_DIR):
            os.makedirs(LOCKED_FOLDERS_DIR)
            log_startup_status("Created missing Locked Folders directory.")

        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "a", encoding="utf-8"):
                pass
            log_startup_status("Created missing activity.log.")
        else:
            log_startup_status("Found activity.log.")

        if not os.path.exists(STARTUP_DIAGNOSTIC_LOG):
            with open(STARTUP_DIAGNOSTIC_LOG, "a", encoding="utf-8"):
                pass
            log_startup_status("Created missing startup_diagnostics.log.")
        else:
            log_startup_status("Found startup_diagnostics.log.")

        if not os.path.exists(SECRET_KEY_FILE):
            get_or_create_secret_key()
            log_startup_status("Created missing secret.key.")
        else:
            log_startup_status("Found secret.key.")

        if not os.path.exists(DATABASE_FILE):
            sqlite3.connect(DATABASE_FILE).close()
            log_startup_status("Created missing locker.db.")
        else:
            log_startup_status("Found locker.db.")

        default_config = {
            "app_name": "Folder Locker",
            "version": APP_VERSION,
            "locked_folders_directory": "Locked Folders"
        }

        if not os.path.exists(CONFIG_FILE) or os.path.getsize(CONFIG_FILE) == 0:
            write_default_config()
            log_startup_status("Created missing config.json.")
        else:
            with open(
                CONFIG_FILE,
                "r",
                encoding="utf-8"
            ) as config_file:

                config_data = json.load(config_file)

            if not isinstance(config_data, dict):
                config_data = {}

            config_changed = False

            for key, value in default_config.items():
                if key == "locked_folders_directory":
                    if key not in config_data:
                        config_data[key] = value
                        config_changed = True
                elif config_data.get(key) != value:
                    config_data[key] = value
                    config_changed = True

            if config_changed:
                with open(
                    CONFIG_FILE,
                    "w",
                    encoding="utf-8"
                ) as config_file:

                    json.dump(config_data, config_file, indent=4)
                log_startup_status("Updated config.json with missing defaults.")
            else:
                log_startup_status("Found config.json.")

    except (OSError, json.JSONDecodeError) as error:
        log_startup_status(f"Error preparing project files: {error}")
        try:
            write_default_config()
            log_startup_status(
                "Recreated config.json after startup read error."
            )
        except OSError:
            pass


def ensure_database_signature_file(connection=None):
    """Create locker.db.signature if it is missing."""
    if os.path.exists(DATABASE_SIGNATURE_FILE):
        log_startup_status("Found locker.db.signature.")
        return True

    if save_database_signature(connection):
        log_startup_status("Created missing locker.db.signature.")
        return True

    log_startup_status("Could not create locker.db.signature.")
    return False


def ensure_cryptography_available():
    """Return False when the cryptography package is not installed."""

    if (
        Fernet is not None and
        InvalidToken is not None and
        hashes is not None and
        PBKDF2HMAC is not None
    ):
        return True

    log_startup_status(
        "Missing dependency: cryptography. "
        "Install it with: pip install cryptography"
    )
    return False


def connect_to_database():
    """Open a connection to the SQLite database.

    Raises RuntimeError on failure so callers (GUI or console) can handle
    the error appropriately instead of receiving a hard sys.exit.
    """
    try:
        return sqlite3.connect(DATABASE_FILE)
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not open database: {error}") from error


def create_tables(connection):
    """Create the required database tables if they do not already exist."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nickname TEXT NOT NULL,
                folder_name TEXT NOT NULL,
                folder_path TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'REGISTERED',
                date_added TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                sha256_hash TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                lockout_until REAL NOT NULL DEFAULT 0
            )
            """
        )
        cursor.execute(
            """
            SELECT id
            FROM security_state
            WHERE id = 1
            """
        )

        if cursor.fetchone() is None:
            cursor.execute(
                """
                INSERT INTO security_state
                (
                    id,
                    failed_attempts,
                    lockout_until
                )
                VALUES
                (
                    1,
                    0,
                    0
                )
                """
            )

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM folders
            WHERE status = 'UNLOCKED'
            """
        )
        unlocked_count = cursor.fetchone()[0]

        if unlocked_count > 0:
            cursor.execute(
                """
                UPDATE folders
                SET status = 'REGISTERED'
                WHERE status = 'UNLOCKED'
                """
            )
        connection.commit()
        add_column_if_missing(
            connection,
            "master_password",
            "password_salt",
            "TEXT"
        )
        add_column_if_missing(
            connection,
            "master_password",
            "password_algorithm",
            "TEXT DEFAULT 'sha256'"
        )
        add_column_if_missing(
            connection,
            "master_password",
            "password_iterations",
            "INTEGER DEFAULT 0"
        )
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not create database tables: {error}") from error


def add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition
):
    """Add a column only if it does not already exist."""

    cursor = connection.cursor()

    cursor.execute(
        f"PRAGMA table_info({table_name})"
    )

    existing_columns = [
        row[1]
        for row in cursor.fetchall()
    ]

    if column_name not in existing_columns:

        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name}
            {column_definition}
            """
        )

        connection.commit()
        log_startup_status(f"Schema migration: added column '{column_name}' to '{table_name}'.")


def hash_password(
    password,
    salt_hex=None,
    iterations=PASSWORD_PBKDF2_ITERATIONS
):
    """Return a PBKDF2-HMAC-SHA256 password record."""

    if salt_hex is None:
        salt = secrets.token_bytes(SALT_SIZE_BYTES)
    else:
        salt = bytes.fromhex(salt_hex)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    ).hex()

    return (
        password_hash,
        salt.hex(),
        PASSWORD_ALGORITHM_PBKDF2,
        iterations
    )


def legacy_hash_password(password):
    """Return the old SHA-256 password hash for migration checks."""

    return hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


def verify_password_record(
    password,
    stored_hash,
    salt_hex,
    algorithm,
    iterations
):
    """Verify a password against either the new or legacy hash format."""

    if (
        algorithm == PASSWORD_ALGORITHM_PBKDF2 and
        salt_hex and
        iterations
    ):
        try:
            password_iterations = int(iterations)
            password_hash, _, _, _ = hash_password(
                password,
                salt_hex,
                password_iterations
            )
        except (TypeError, ValueError):
            return False

        return hmac.compare_digest(
            password_hash,
            stored_hash
        )

    return hmac.compare_digest(
        legacy_hash_password(password),
        stored_hash
    )


def password_record_needs_migration(
    salt_hex,
    algorithm,
    iterations
):
    """Return True when a stored master password should be upgraded."""

    try:
        current_iterations = int(iterations or 0)
    except (TypeError, ValueError):
        current_iterations = 0

    return (
        algorithm != PASSWORD_ALGORITHM_PBKDF2 or
        not salt_hex or
        current_iterations < PASSWORD_PBKDF2_ITERATIONS
    )


def calculate_file_sha256(file_path):
    """Return SHA256 hash of a file."""

    if not os.path.exists(file_path):
        return None

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def iter_files(folder_path, skip_locked=True, locked_only=False):
    """Yield files under a folder in deterministic order."""

    for current_folder, subfolders, file_names in os.walk(folder_path):
        subfolders.sort()

        for file_name in sorted(file_names):
            file_path = os.path.join(
                current_folder,
                file_name
            )
            file_is_locked = file_path.endswith(".locked")

            if locked_only and not file_is_locked:
                continue

            if skip_locked and file_is_locked:
                continue

            yield file_path


def get_hash_record_path(folder_path, file_path):
    """Return a stable relative path for a file hash record."""

    relative_path = os.path.relpath(file_path, folder_path)
    return os.path.normcase(os.path.normpath(relative_path))


def get_or_create_secret_key():
    """Load the stable app secret key or create it once.

    The database signature depends on this key.  Folder Locker never rotates it
    during normal startup or shutdown, so a valid signature remains verifiable
    across sessions unless locker.db is actually changed outside the app.
    """

    if os.path.exists(SECRET_KEY_FILE):

        with open(
            SECRET_KEY_FILE,
            "rb"
        ) as file:

            return file.read()

    secret_key = secrets.token_bytes(32)

    with open(
        SECRET_KEY_FILE,
        "wb"
    ) as file:

        file.write(secret_key)

    return secret_key


def checkpoint_database(connection):
    """Flush committed SQLite WAL content before signing the database.

    This is intentionally best-effort.  Projects using rollback journals do not
    need a checkpoint, and SQLite may report that no WAL exists.  The signature
    still protects the logical locker.db content, while transient journal/WAL
    files are excluded from the signed bytes.
    """
    if connection is None:
        return

    try:
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(FULL)")
    except sqlite3.Error:
        pass


def remove_temporary_database_files(database_path):
    """Remove temporary files SQLite may create for a snapshot database."""
    for suffix in ("", "-journal", "-wal", "-shm"):
        temporary_path = database_path + suffix

        if os.path.exists(temporary_path):
            try:
                os.remove(temporary_path)
            except OSError:
                pass


def create_database_signature_snapshot(connection=None):
    """Create a stable SQLite snapshot used only for signature hashing.

    Hashing a live SQLite file directly can produce false tamper warnings if a
    connection has recently committed or if WAL/journal housekeeping is still
    settling.  SQLite's backup API gives us a consistent committed snapshot of
    locker.db.  The snapshot excludes locker.db-wal, locker.db-shm, and journal
    files as independent inputs, so those transient files cannot cause false
    positives while locker.db remains protected.
    """
    if not os.path.exists(DATABASE_FILE):
        return None

    checkpoint_database(connection)

    snapshot_path = DATABASE_FILE + ".signature_snapshot"
    remove_temporary_database_files(snapshot_path)

    source_connection = connection
    opened_source_connection = False
    snapshot_connection = None

    try:
        if source_connection is None:
            source_connection = sqlite3.connect(DATABASE_FILE)
            opened_source_connection = True
            checkpoint_database(source_connection)

        snapshot_connection = sqlite3.connect(snapshot_path)
        source_connection.backup(snapshot_connection)
        snapshot_connection.close()
        snapshot_connection = None
        return snapshot_path
    except sqlite3.Error:
        remove_temporary_database_files(snapshot_path)
        return None
    finally:
        if snapshot_connection is not None:
            try:
                snapshot_connection.close()
            except sqlite3.Error:
                pass

        if opened_source_connection:
            try:
                source_connection.close()
            except sqlite3.Error:
                pass


def calculate_database_hmac(connection=None):
    """Create HMAC signature for a stable committed locker.db snapshot."""

    if not os.path.exists(DATABASE_FILE):
        return None

    snapshot_path = create_database_signature_snapshot(connection)

    if snapshot_path is None:
        return None

    secret_key = get_or_create_secret_key()

    hmac_object = hmac.new(
        secret_key,
        digestmod=hashlib.sha256
    )

    try:
        with open(snapshot_path, "rb") as file:

            while True:

                chunk = file.read(1024 * 1024)

                if not chunk:
                    break

                hmac_object.update(chunk)
    finally:
        remove_temporary_database_files(snapshot_path)

    return hmac_object.hexdigest()


def calculate_file_hmac(file_path):
    """Create an HMAC signature for any file using the app secret key."""

    if not os.path.exists(file_path):
        return None

    secret_key = get_or_create_secret_key()

    hmac_object = hmac.new(
        secret_key,
        digestmod=hashlib.sha256
    )

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            hmac_object.update(chunk)

    return hmac_object.hexdigest()


def save_database_signature(connection=None):
    """Save HMAC signature after all current database commits are complete."""
    signature = calculate_database_hmac(connection)

    if signature is None:
        return False

    temporary_signature_file = DATABASE_SIGNATURE_FILE + ".tmp"

    with open(
        temporary_signature_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(signature)

    os.replace(
        temporary_signature_file,
        DATABASE_SIGNATURE_FILE
    )

    return True


def verify_database_signature(connection=None):
    """Verify database HMAC against the stable committed database snapshot."""

    if not os.path.exists(DATABASE_FILE):
        return True

    if not os.path.exists(DATABASE_SIGNATURE_FILE):
        return False

    current_signature = calculate_database_hmac(connection)

    if current_signature is None:
        return False

    with open(
        DATABASE_SIGNATURE_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        saved_signature = file.read().strip()

    if not saved_signature:
        return False

    return hmac.compare_digest(
        current_signature,
        saved_signature
    )


def verify_backup_signature(database_backup_path, signature_backup_path):
    """Return True if a backup database matches its backup signature file."""

    current_signature = calculate_file_hmac(database_backup_path)

    if current_signature is None:
        return False

    try:
        with open(
            signature_backup_path,
            "r",
            encoding="utf-8"
        ) as file:

            saved_signature = file.read().strip()
    except OSError:
        return False

    if not saved_signature:
        return False

    return hmac.compare_digest(
        current_signature,
        saved_signature
    )


def get_timestamp_for_filename():
    """Return a filesystem-safe timestamp for backup and export names."""

    return time.strftime("%Y_%m_%d_%H_%M_%S")


def get_unique_file_path(folder_path, file_name):
    """Return a path that will not overwrite an existing file."""

    candidate_path = os.path.join(folder_path, file_name)

    if not os.path.exists(candidate_path):
        return candidate_path

    base_name, extension = os.path.splitext(file_name)
    counter = 1

    while True:
        candidate_name = f"{base_name}_{counter}{extension}"
        candidate_path = os.path.join(folder_path, candidate_name)

        if not os.path.exists(candidate_path):
            return candidate_path

        counter += 1


def copy_file_if_exists(source_path, destination_path):
    """Copy one file if it exists and return True when copied."""

    if not os.path.exists(source_path):
        return False

    shutil.copy2(
        source_path,
        destination_path
    )

    return True


def sanitize_log_action(action):
    """Return a single-line log action."""

    return str(action).replace("\r", " ").replace("\n", " ").strip()


def calculate_log_entry_hmac(timestamp, action, previous_hash):
    """Return the HMAC hash for one chained log entry."""

    secret_key = get_or_create_secret_key()
    message = (
        f"{previous_hash}|{timestamp}|{action}"
    ).encode("utf-8")

    return hmac.new(
        secret_key,
        message,
        hashlib.sha256
    ).hexdigest()


def parse_protected_log_line(line):
    """Parse a protected log line, or return None for legacy lines."""

    line = line.rstrip("\n")

    if " | prev=" not in line or " | hmac=" not in line:
        return None

    try:
        left, signature = line.rsplit(" | hmac=", 1)
        entry, previous_hash = left.rsplit(" | prev=", 1)
        timestamp, action = entry.split(" | ", 1)
    except ValueError:
        return None

    return timestamp, action, previous_hash, signature


def get_last_log_hash():
    """Return the last protected log entry hash."""

    if not os.path.exists(LOG_FILE):
        return LOG_CHAIN_START

    last_hash = LOG_CHAIN_START

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:
            parsed = parse_protected_log_line(line)

            if parsed is None:
                continue

            last_hash = parsed[3]

    return last_hash


def verify_activity_log_integrity():
    """Return True if every protected log entry verifies."""

    if not os.path.exists(LOG_FILE):
        return True

    expected_previous_hash = LOG_CHAIN_START
    seen_protected_entry = False

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:
            parsed = parse_protected_log_line(line)

            if parsed is None:
                if seen_protected_entry and line.strip():
                    return False

                continue

            seen_protected_entry = True
            timestamp, action, previous_hash, signature = parsed

            if previous_hash != expected_previous_hash:
                return False

            expected_signature = calculate_log_entry_hmac(
                timestamp,
                action,
                previous_hash
            )

            if not hmac.compare_digest(
                signature,
                expected_signature
            ):
                return False

            expected_previous_hash = signature

    return True


def write_log(action):
    """Write a tamper-evident activity entry to activity.log."""

    from datetime import datetime

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    clean_action = sanitize_log_action(action)
    previous_hash = get_last_log_hash()
    entry_hash = calculate_log_entry_hmac(
        timestamp,
        clean_action,
        previous_hash
    )

    log_entry = (
        f"{timestamp} | {clean_action} | "
        f"prev={previous_hash} | hmac={entry_hash}\n"
    )

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8"
    ) as file:

        file.write(log_entry)


def save_file_hash(connection, folder_id, file_path, file_hash):
    """Stage a file hash for a registered folder."""
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO file_hashes
        (folder_id, file_path, sha256_hash)
        VALUES (?, ?, ?)
        """,
        (folder_id, file_path, file_hash)
    )

def get_saved_file_hashes(connection, folder_id):
    """Return all saved file hashes for a folder."""
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT file_path, sha256_hash
        FROM file_hashes
        WHERE folder_id = ?
        """,
        (folder_id,)
    )

    return {
        file_path: sha256_hash
        for file_path, sha256_hash in cursor.fetchall()
    }


def get_security_state(connection):
    """Return saved failed login count and lockout time."""
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            failed_attempts,
            lockout_until
        FROM security_state
        WHERE id = 1
        """
    )

    row = cursor.fetchone()

    if row is None:
        return 0, 0

    return row


def update_security_state(
    connection,
    failed_attempts,
    lockout_until
):
    """Update saved failed login count and lockout time."""
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE security_state
        SET
            failed_attempts = ?,
            lockout_until = ?
        WHERE id = 1
        """,
        (
            failed_attempts,
            lockout_until
        )
    )

    connection.commit()


def clear_folder_hashes(connection, folder_id):
    """Remove old hashes for a folder before saving new ones."""
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM file_hashes
        WHERE folder_id = ?
        """,
        (folder_id,)
    )


def verify_folder_integrity(connection, folder_id, folder_path):
    """Verify all decrypted files against stored hashes."""

    print()
    print("Verifying file integrity...")

    saved_hashes = get_saved_file_hashes(connection, folder_id)
    seen_paths = set()
    total_verified = 0
    total_failed = 0
    total_missing = 0
    total_untracked = 0

    for file_path in iter_files(folder_path):
        hash_record_path = get_hash_record_path(
            folder_path,
            file_path
        )

        saved_hash = saved_hashes.get(hash_record_path)

        if saved_hash is None:
            total_untracked += 1

            print()
            print("UNTRACKED FILE:")
            print(file_path)

            continue

        seen_paths.add(hash_record_path)

        current_hash = calculate_file_sha256(
            file_path
        )

        if current_hash == saved_hash:
            total_verified += 1
        else:
            total_failed += 1

            print()
            print("INTEGRITY FAILURE:")
            print(file_path)

    for saved_path in saved_hashes:
        if saved_path in seen_paths:
            continue

        total_missing += 1

        print()
        print("MISSING FILE:")
        print(saved_path)

    print()
    print("Files verified:", total_verified)
    print("Files failed:", total_failed)
    print("Files missing:", total_missing)
    print("Files untracked:", total_untracked)

    return (
        total_failed == 0 and
        total_missing == 0 and
        total_untracked == 0
    )


def get_stored_password_hash(connection):
    """Return the saved master password hash, or None if no password exists."""

    record = get_stored_password_record(connection)

    if record is None:
        return None

    return record["password_hash"]


def password_storage_supports_pbkdf2(connection):
    """Return True when migration columns exist for PBKDF2 passwords."""

    try:
        cursor = connection.cursor()
        cursor.execute("PRAGMA table_info(master_password)")

        columns = {
            row[1]
            for row in cursor.fetchall()
        }

        return {
            "password_salt",
            "password_algorithm",
            "password_iterations"
        }.issubset(columns)

    except sqlite3.Error:
        return False


def get_stored_password_record(connection):
    """Return the saved master password record."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT
                password_hash,
                password_salt,
                password_algorithm,
                password_iterations
            FROM master_password
            WHERE id = 1
            """
        )
        row = cursor.fetchone()

        if row is None:
            return None

        (
            password_hash,
            password_salt,
            password_algorithm,
            password_iterations
        ) = row

        return {
            "password_hash": password_hash,
            "password_salt": password_salt,
            "password_algorithm": (
                password_algorithm or
                PASSWORD_ALGORITHM_LEGACY_SHA256
            ),
            "password_iterations": password_iterations or 0
        }

    except sqlite3.Error:
        try:
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT password_hash
                FROM master_password
                WHERE id = 1
                """
            )
            row = cursor.fetchone()

            if row is None:
                return None

            return {
                "password_hash": row[0],
                "password_salt": None,
                "password_algorithm": PASSWORD_ALGORITHM_LEGACY_SHA256,
                "password_iterations": 0
            }

        except sqlite3.Error as error:
            log_startup_status(f"Error reading password from database: {error}")
            return None


def save_password_hash(
    connection,
    password_hash,
    password_salt,
    password_algorithm=PASSWORD_ALGORITHM_PBKDF2,
    password_iterations=PASSWORD_PBKDF2_ITERATIONS
):
    """Insert or update the master password hash in the database."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO master_password
            (
                id,
                password_hash,
                password_salt,
                password_algorithm,
                password_iterations
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                password_hash = excluded.password_hash,
                password_salt = excluded.password_salt,
                password_algorithm = excluded.password_algorithm,
                password_iterations = excluded.password_iterations
            """,
            (
                1,
                password_hash,
                password_salt,
                password_algorithm,
                password_iterations
            )
        )
        connection.commit()
        return True
    except sqlite3.Error as error:
        log_startup_status(f"Error saving password to database: {error}")
        return False


def prompt_for_new_password():
    """Ask the user to enter and confirm a new password (console only)."""
    import getpass as _getpass
    while True:
        password = _getpass.getpass("Enter new master password: ")
        confirm_password = _getpass.getpass("Confirm new master password: ")

        if not password:
            print("Password cannot be empty. Please try again.")
            continue

        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue

        return password


def setup_master_password(connection):
    """Create the first master password for a new installation."""
    print("No master password found.")
    print("Please create a master password to protect Folder Locker.")

    password = prompt_for_new_password()
    (
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    ) = hash_password(password)

    if save_password_hash(
        connection,
        password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    ):
        print("Master password created successfully.")
        return password

    print("Could not create master password.")
    return None


def verify_password(connection, prompt_text="Enter master password: "):
    """Ask for a password and compare it with the stored password hash."""
    return prompt_for_verified_password(
        connection,
        prompt_text
    ) is not None


def prompt_for_verified_password(connection, prompt_text="Enter master password: "):
    """Return the entered master password only when it verifies (console only)."""
    import getpass as _getpass
    stored_record = get_stored_password_record(connection)

    if stored_record is None:
        print("No master password is set.")
        return None

    entered_password = _getpass.getpass(prompt_text)

    password_is_valid = verify_password_record(
        entered_password,
        stored_record["password_hash"],
        stored_record["password_salt"],
        stored_record["password_algorithm"],
        stored_record["password_iterations"]
    )

    if (
        password_is_valid and
        password_storage_supports_pbkdf2(connection) and
        password_record_needs_migration(
            stored_record["password_salt"],
            stored_record["password_algorithm"],
            stored_record["password_iterations"]
        )
    ):
        (
            password_hash,
            password_salt,
            password_algorithm,
            password_iterations
        ) = hash_password(entered_password)

        save_password_hash(
            connection,
            password_hash,
            password_salt,
            password_algorithm,
            password_iterations
        )

    if password_is_valid:
        return entered_password

    return None


def login(connection):

    failed_attempts, lockout_until = (
        get_security_state(connection)
    )

    current_time = time.time()

    if current_time < lockout_until:

        remaining_seconds = int(
            lockout_until - current_time
        )

        print()
        print(
            "Too many failed attempts."
        )

        print(
            f"Try again in "
            f"{remaining_seconds} seconds."
        )

        return False

    if lockout_until > 0:
        failed_attempts = 0
        lockout_until = 0

        update_security_state(
            connection,
            failed_attempts,
            lockout_until
        )

    while failed_attempts < MAX_LOGIN_ATTEMPTS:

        verified_password = prompt_for_verified_password(connection)

        if verified_password is not None:

            update_security_state(
                connection,
                0,
                0
            )

            write_log("LOGIN SUCCESS")

            print(
                "Login successful."
            )

            return verified_password

        failed_attempts += 1

        remaining_attempts = (
            MAX_LOGIN_ATTEMPTS - failed_attempts
        )

        if remaining_attempts > 0:

            update_security_state(
                connection,
                failed_attempts,
                0
            )

            print(
                "Incorrect password."
            )

            print(
                "Attempts remaining:",
                remaining_attempts
            )

    lockout_until = (
        time.time() +
        LOCKOUT_SECONDS
    )

    update_security_state(
        connection,
        failed_attempts,
        lockout_until
    )

    print()
    print(
        "Too many failed attempts."
    )

    print(
        f"Application locked "
        f"for {LOCKOUT_SECONDS} seconds."
    )

    write_log("LOGIN LOCKOUT")

    return False


def display_menu():
    """Show the main menu after the user logs in successfully."""
    print()
    print("=================================")
    print("FOLDER LOCKER")
    print("=============")
    print()
    print("1. Add Folder")
    print("2. View Folders")
    print("3. Hide Folder")
    print("4. Unhide Folder")
    print("5. Remove Folder")
    print("6. Change Password")
    print("7. Lock Folder")
    print("8. Unlock Folder")
    print("9. Search Folder")
    print("10. Backup Database")
    print("11. Restore Database")
    print("12. Export Activity Log")
    print("13. View Activity Log")
    print("14. View Security Log")
    print("15. Rebuild Database Signature")
    print("16. Exit")
    print()


def normalize_folder_path(folder_path):
    """Return a clean absolute path for a folder path entered by the user."""
    cleaned_path = folder_path.strip().strip('"').strip("'")
    if not cleaned_path:
        return ""

    cleaned_path = os.path.expanduser(cleaned_path)
    cleaned_path = os.path.expandvars(cleaned_path)
    return os.path.abspath(os.path.normpath(cleaned_path))


def folder_path_exists(connection, folder_path):
    """Check whether a folder path is already registered in the database."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM folders WHERE LOWER(folder_path) = LOWER(?)",
            (folder_path,)
        )
        return cursor.fetchone() is not None
    except sqlite3.Error as error:
        print("Error checking folder path:", error)
        return False


def apply_hidden_attribute(folder_path, should_hide):
    """Add or remove the Windows hidden attribute on a folder."""

    if os.name != "nt":
        if should_hide:
            print(
                "Folder hiding is only supported on Windows. "
                "The folder will not be hidden on this platform."
            )
            return False

        return True

    attribute_option = "+h" if should_hide else "-h"

    try:
        result = subprocess.run(
            ["attrib", attribute_option, folder_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("Windows could not update the folder attributes.")
            if result.stderr:
                print(result.stderr)
            return False

        return True

    except Exception as error:
        print("Could not run the Windows attrib command:")
        print(error)
        return False


def update_folder_status(connection, folder_id, status):
    """Update the saved status for a folder record."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE folders SET status = ? WHERE id = ?",
            (status, folder_id)
        )
        connection.commit()
        return True
    except sqlite3.Error as error:
        print("Error updating folder status:", error)
        return False


def add_folder(connection):
    """Ask for a folder path and nickname, then register the folder."""
    entered_path = input("Enter folder path: ").strip()

    if not entered_path:
        print("Folder path cannot be empty.")
        return

    folder_path = normalize_folder_path(entered_path)

    if not folder_path:
        print("Folder path cannot be empty.")
        return

    if not os.path.exists(folder_path):
        print("Folder does not exist. Please enter a valid folder path.")
        return

    if not os.path.isdir(folder_path):
        print("The path exists, but it is not a folder.")
        return

    if folder_path_exists(connection, folder_path):
        print("This folder is already registered.")
        return

    folder_name = os.path.basename(os.path.normpath(folder_path))
    if not folder_name:
        print("Invalid folder path. Please choose a normal folder, not a drive root.")
        return

    nickname = input("Enter a nickname for this folder: ").strip()
    if not nickname:
        print("Nickname cannot be empty.")
        return

    try:
        cursor = connection.cursor()
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
            (nickname, folder_name, folder_path, STATUS_REGISTERED)
        )
        connection.commit()
        print("Folder added successfully.")
    except sqlite3.IntegrityError:
        print("This folder is already registered.")
    except sqlite3.Error as error:
        print("Error adding folder:", error)


def get_registered_folders(connection):
    """Return all folders currently saved in the database."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, nickname, folder_name, folder_path, status, date_added
            FROM folders
            ORDER BY id
            """
        )
        return cursor.fetchall()
    except sqlite3.Error as error:
        print("Error reading registered folders:", error)
        return []


def get_hidden_folders(connection):
    """Return folders that are currently marked as hidden."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, nickname, folder_name, folder_path, status, date_added
            FROM folders
            WHERE status = ?
            ORDER BY id
            """,
            (STATUS_HIDDEN,)
        )
        return cursor.fetchall()
    except sqlite3.Error as error:
        print("Error reading hidden folders:", error)
        return []


def get_locked_folders(connection):
    """Return folders that are currently marked as locked."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, nickname, folder_name, folder_path, status, date_added
            FROM folders
            WHERE status = ?
            ORDER BY id
            """,
            (STATUS_LOCKED,)
        )
        return cursor.fetchall()
    except sqlite3.Error as error:
        print("Error reading locked folders:", error)
        return []


def display_registered_folders(
        folders,
        title="REGISTERED FOLDERS",
        empty_message="No folders registered."):
    """Display registered folders in a clear, beginner-friendly format."""
    if not folders:
        print(empty_message)
        return

    print()
    print("==================================================")
    print(title)
    print("=" * len(title))
    print()

    for folder in folders:
        folder_id, nickname, folder_name, folder_path, status, date_added = folder
        print("ID:", folder_id)
        print("Nickname:", nickname)
        print("Folder Name:", folder_name)
        print("Status:", status)
        print("Path:", folder_path)
        print("Date Added:", date_added)
        print()
        print("---")
        print()


def view_folders(connection):
    """Show every folder registered in the application."""
    folders = get_registered_folders(connection)
    display_registered_folders(folders)


def get_folder_by_id(connection, folder_id):
    """Return one folder record by ID, or None if it does not exist."""
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, nickname, folder_name, folder_path, status, date_added
            FROM folders
            WHERE id = ?
            """,
            (folder_id,)
        )
        return cursor.fetchone()
    except sqlite3.Error as error:
        print("Error finding folder:", error)
        return None


def ask_for_folder_id():
    """Ask the user for a folder ID and return it as an integer."""
    entered_id = input("Enter Folder ID: ").strip()

    if not entered_id:
        print("Folder ID cannot be empty.")
        return None

    try:
        folder_id = int(entered_id)
    except ValueError:
        print("Invalid Folder ID. Please enter a number.")
        return None

    if folder_id <= 0:
        print("Folder ID must be greater than zero.")
        return None

    return folder_id


def folder_still_exists(folder_path):
    """Confirm that the folder still exists on disk."""
    if not os.path.exists(folder_path):
        print("Folder no longer exists on disk.")
        return False

    if not os.path.isdir(folder_path):
        print("The saved path exists, but it is no longer a folder.")
        return False

    return True


def hide_folder(connection):
    """Hide a registered folder and mark it as hidden in the database."""
    folders = get_registered_folders(connection)
    display_registered_folders(folders)

    if not folders:
        return

    folder_id = ask_for_folder_id()
    if folder_id is None:
        return

    folder = get_folder_by_id(connection, folder_id)
    if folder is None:
        print("Folder ID does not exist.")
        return

    saved_folder_id, nickname, folder_name, folder_path, status, date_added = folder

    if not folder_still_exists(folder_path):
        return

    if status == STATUS_LOCKED:
        print("Folder is locked. Unlock it before using the normal hide option.")
        return

    if status == STATUS_HIDDEN:
        print("Folder is already hidden.")
        return

    if apply_hidden_attribute(folder_path, True):
        if update_folder_status(connection, saved_folder_id, STATUS_HIDDEN):
            write_log(
                f"HIDE FOLDER | {nickname}"
            )

            print("Folder hidden successfully.")


def unhide_folder(connection):
    """Unhide a hidden folder after asking for the master password again."""
    hidden_folders = get_hidden_folders(connection)
    display_registered_folders(
        hidden_folders,
        title="HIDDEN FOLDERS",
        empty_message="No hidden folders registered."
    )

    if not hidden_folders:
        return

    folder_id = ask_for_folder_id()
    if folder_id is None:
        return

    folder = get_folder_by_id(connection, folder_id)
    if folder is None:
        print("Folder ID does not exist.")
        return

    saved_folder_id, nickname, folder_name, folder_path, status, date_added = folder

    if status != STATUS_HIDDEN:
        print("This folder is not hidden.")
        return

    if not verify_password(connection, "Enter master password to unhide folder: "):
        print("Access denied.")
        return

    if not folder_still_exists(folder_path):
        return

    if apply_hidden_attribute(folder_path, False):
        if update_folder_status(connection, saved_folder_id, STATUS_REGISTERED):
            write_log(
                f"UNHIDE FOLDER | {nickname}"
            )

            print("Folder unhidden successfully.")


def remove_folder(connection):
    """Remove only the selected folder record from the database."""
    folders = get_registered_folders(connection)
    display_registered_folders(folders)

    if not folders:
        return

    folder_id = ask_for_folder_id()

    if folder_id is None:
        return

    folder = get_folder_by_id(connection, folder_id)
    if folder is None:
        print("Folder ID does not exist.")
        return

    confirmation = input("Are you sure? (y/n): ").strip().lower()
    if confirmation != "y":
        print("Folder was not removed.")
        return

    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
        connection.commit()
        print("Folder removed successfully.")
    except sqlite3.Error as error:
        print("Error removing folder:", error)


def change_password(connection, current_master_password=None):
    """Verify the current password, then save a new password hash."""
    verified_master_password = prompt_for_verified_password(
        connection,
        "Enter current master password: "
    )

    if verified_master_password is None:
        print("Current password is incorrect. Password was not changed.")
        return current_master_password

    new_password = prompt_for_new_password()

    (
        new_password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    ) = hash_password(new_password)

    if save_password_hash(
        connection,
        new_password_hash,
        password_salt,
        password_algorithm,
        password_iterations
    ):
        write_log("PASSWORD CHANGED")

        print("Password changed successfully.")

        return new_password
    else:
        print("Password could not be changed.")

    return current_master_password


def derive_key_from_password(password, salt):
    """Create a Fernet encryption key from a password and random salt."""
    import base64

    if not ensure_cryptography_available():
        raise RuntimeError("cryptography is required")

    password_bytes = password.encode("utf-8")
    key_derivation_function = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )

    return base64.urlsafe_b64encode(
        key_derivation_function.derive(password_bytes)
    )


def remove_temporary_file(file_path):
    """Remove a temporary file if it exists."""

    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except OSError:
        pass


def encrypt_file(file_path, password=None):
    """Encrypt a single file and save it with a .locked extension."""

    if not ensure_cryptography_available():
        return False

    if password is None:
        import getpass as _getpass
        password = _getpass.getpass("Enter encryption password: ")

    if not password:
        print("Password cannot be empty.")
        return False

    if not os.path.exists(file_path):
        print("File does not exist.")
        return False

    if not os.path.isfile(file_path):
        print("Path is not a file.")
        return False

    if file_path.endswith(".locked"):
        print("File is already encrypted.")
        return False

    locked_file_path = file_path + ".locked"
    if os.path.exists(locked_file_path):
        print("A locked version of this file already exists.")
        return False

    temporary_locked_file_path = locked_file_path + ".tmp"

    try:
        remove_temporary_file(temporary_locked_file_path)

        file_size = os.path.getsize(file_path)

        if file_size > MAX_LEGACY_DECRYPT_BYTES:
            print(
                "Large file detected. "
                "Streaming encryption will be used."
            )

        salt = secrets.token_bytes(SALT_SIZE_BYTES)
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)

        with open(file_path, "rb") as source_file, open(
            temporary_locked_file_path,
            "wb"
        ) as destination_file:

            destination_file.write(STREAM_FILE_MAGIC)
            destination_file.write(salt)

            while True:
                chunk = source_file.read(ENCRYPTION_CHUNK_SIZE)

                if not chunk:
                    break

                encrypted_chunk = fernet.encrypt(chunk)

                destination_file.write(
                    struct.pack(">I", len(encrypted_chunk))
                )
                destination_file.write(encrypted_chunk)

        os.replace(
            temporary_locked_file_path,
            locked_file_path
        )
        os.remove(file_path)
        print("File encrypted successfully.")
        return True
    except PermissionError:
        remove_temporary_file(temporary_locked_file_path)
        print("Permission denied while encrypting file.")
        return False
    except OSError as error:
        remove_temporary_file(temporary_locked_file_path)
        print("File system error while encrypting file:", error)
        return False
    except Exception as error:
        remove_temporary_file(temporary_locked_file_path)
        print("Encryption failed:", error)
        return False


def decrypt_file(file_path, password=None):
    """Decrypt a .locked file and restore the original file name."""

    if not ensure_cryptography_available():
        return False

    if password is None:
        import getpass as _getpass
        password = _getpass.getpass("Enter decryption password: ")

    if not password:
        print("Password cannot be empty.")
        return False

    if not os.path.exists(file_path):
        print("File does not exist.")
        return False

    if not os.path.isfile(file_path):
        print("Path is not a file.")
        return False

    if not file_path.endswith(".locked"):
        print("Encrypted file must end with .locked.")
        return False

    original_file_path = file_path[:-7]
    if os.path.exists(original_file_path):
        print("Cannot decrypt because the original file already exists.")
        return False

    temporary_original_file_path = original_file_path + ".tmp"

    if os.path.exists(temporary_original_file_path):
        print("Temporary decrypted file already exists.")
        return False

    try:
        with open(file_path, "rb") as source_file, open(
            temporary_original_file_path,
            "wb"
        ) as destination_file:

            magic = source_file.read(len(STREAM_FILE_MAGIC))

            if magic == STREAM_FILE_MAGIC:
                salt = source_file.read(SALT_SIZE_BYTES)

                if len(salt) != SALT_SIZE_BYTES:
                    print("Decryption failed. File is not valid.")
                    remove_temporary_file(temporary_original_file_path)
                    return False

                key = derive_key_from_password(password, salt)
                fernet = Fernet(key)

                while True:
                    length_data = source_file.read(4)

                    if not length_data:
                        break

                    if len(length_data) != 4:
                        print("Decryption failed. File is corrupted.")
                        remove_temporary_file(temporary_original_file_path)
                        return False

                    encrypted_chunk_size = struct.unpack(
                        ">I",
                        length_data
                    )[0]

                    if (
                        encrypted_chunk_size <= 0 or
                        encrypted_chunk_size > MAX_ENCRYPTED_CHUNK_SIZE
                    ):
                        print("Decryption failed. File is corrupted.")
                        remove_temporary_file(temporary_original_file_path)
                        return False

                    encrypted_chunk = source_file.read(
                        encrypted_chunk_size
                    )

                    if len(encrypted_chunk) != encrypted_chunk_size:
                        print("Decryption failed. File is corrupted.")
                        remove_temporary_file(temporary_original_file_path)
                        return False

                    decrypted_chunk = fernet.decrypt(encrypted_chunk)
                    destination_file.write(decrypted_chunk)

            else:
                file_size = os.path.getsize(file_path)

                if file_size > MAX_LEGACY_DECRYPT_BYTES:
                    print(
                        "This legacy locked file is too large "
                        "to decrypt safely in memory."
                    )
                    remove_temporary_file(temporary_original_file_path)
                    return False

                source_file.seek(0)
                locked_data = source_file.read()

                if len(locked_data) <= SALT_SIZE_BYTES:
                    print("Decryption failed. File is not a valid locked file.")
                    remove_temporary_file(temporary_original_file_path)
                    return False

                salt = locked_data[:SALT_SIZE_BYTES]
                encrypted_data = locked_data[SALT_SIZE_BYTES:]
                key = derive_key_from_password(password, salt)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)

                destination_file.write(decrypted_data)

        os.replace(
            temporary_original_file_path,
            original_file_path
        )
        os.remove(file_path)
        print("File decrypted successfully.")
        return True
    except InvalidToken:
        remove_temporary_file(temporary_original_file_path)
        print("Access denied. Incorrect password or corrupted encrypted file.")
        return False
    except PermissionError:
        remove_temporary_file(temporary_original_file_path)
        print("Permission denied while decrypting file.")
        return False
    except OSError as error:
        remove_temporary_file(temporary_original_file_path)
        print("File system error while decrypting file:", error)
        return False
    except Exception as error:
        remove_temporary_file(temporary_original_file_path)
        print("Decryption failed:", error)
        return False


def test_encrypt_decrypt_file():
    """Create, encrypt, decrypt, and verify one test text file."""
    test_file_path = os.path.join(APP_DATA_DIR, "test.txt")
    locked_file_path = test_file_path + ".locked"
    test_password = "Jarvis123"
    original_data = b"Hello World\nThis is a test file."

    try:
        if os.path.exists(locked_file_path):
            os.remove(locked_file_path)

        with open(test_file_path, "wb") as file:
            file.write(original_data)

        before_hash = hashlib.sha256(original_data).hexdigest()

        if not encrypt_file(test_file_path, test_password):
            return False

        if not decrypt_file(locked_file_path, test_password):
            return False

        with open(test_file_path, "rb") as file:
            final_data = file.read()

        after_hash = hashlib.sha256(final_data).hexdigest()

        if before_hash == after_hash:
            print("Test passed. File is exactly the same after decrypting.")
            return True

        print("Test failed. File changed after decrypting.")
        return False
    except OSError as error:
        print("Test failed because of a file error:", error)
        return False


def encrypt_folder(folder_path, folder_password=None):
    """Encrypt every normal file inside a folder and its subfolders."""

    if not os.path.exists(folder_path):
        print("Folder does not exist.")
        return False

    if not os.path.isdir(folder_path):
        print("Path is not a folder.")
        return False

    if folder_password is None:
        import getpass as _getpass
        folder_password = _getpass.getpass(
            "Enter encryption password for entire folder: "
        )

    if not folder_password:
        print("Password cannot be empty.")
        return False

    total_files_encrypted = 0
    total_files_failed = 0

    for file_path in iter_files(folder_path):
        print("Encrypting:", file_path)

        try:
            if encrypt_file(file_path, folder_password):
                total_files_encrypted += 1
            else:
                total_files_failed += 1
        except Exception as error:
            print("Could not encrypt this file:", error)
            total_files_failed += 1

    print("Encryption complete.")
    print("Total files encrypted:", total_files_encrypted)
    if total_files_failed > 0:
        print("Total files failed:", total_files_failed)
        return False

    return True


def decrypt_folder(folder_path, folder_password=None):
    """Decrypt every .locked file inside a folder and its subfolders."""

    if not os.path.exists(folder_path):
        print("Folder does not exist.")
        return False

    if not os.path.isdir(folder_path):
        print("Path is not a folder.")
        return False

    if folder_password is None:
        import getpass as _getpass
        folder_password = _getpass.getpass(
            "Enter decryption password for entire folder: "
        )

    if not folder_password:
        print("Password cannot be empty.")
        return False

    total_files_decrypted = 0
    total_files_failed = 0

    for file_path in iter_files(
        folder_path,
        skip_locked=False,
        locked_only=True
    ):
        print("Decrypting:", file_path)

        try:
            if decrypt_file(file_path, folder_password):
                total_files_decrypted += 1
            else:
                total_files_failed += 1
        except Exception as error:
            print("Could not decrypt this file:", error)
            total_files_failed += 1

    print("Decryption complete.")
    print("Total files decrypted:", total_files_decrypted)
    if total_files_failed > 0:
        print("Total files failed:", total_files_failed)
        return False

    return True


def save_folder_integrity_hashes(connection, folder_id, folder_path):
    """Save integrity hashes for every normal file in a folder."""

    print("Creating file integrity hashes...")

    clear_folder_hashes(connection, folder_id)

    for file_path in iter_files(folder_path):
        try:
            file_hash = calculate_file_sha256(
                file_path
            )
            hash_record_path = get_hash_record_path(
                folder_path,
                file_path
            )

            save_file_hash(
                connection,
                folder_id,
                hash_record_path,
                file_hash
            )

        except Exception as error:
            print(
                "Failed to hash:",
                file_path
            )
            print(error)
            connection.rollback()
            return False

    connection.commit()

    return True


def lock_folder(connection):
    """Encrypt a registered folder, hide it, and mark it as locked."""
    folders = get_registered_folders(connection)
    display_registered_folders(folders)

    if not folders:
        return

    folder_id = ask_for_folder_id()
    if folder_id is None:
        return

    folder = get_folder_by_id(connection, folder_id)
    if folder is None:
        print("Folder ID does not exist.")
        return

    saved_folder_id, nickname, folder_name, folder_path, status, date_added = folder

    if status == STATUS_LOCKED:
        print("Folder is already locked.")
        return

    if not folder_still_exists(folder_path):
        return

    import getpass as _getpass
    folder_password = _getpass.getpass("Enter folder encryption password: ")
    if not folder_password:
        print("Password cannot be empty.")
        return

    if not save_folder_integrity_hashes(
        connection,
        saved_folder_id,
        folder_path
    ):
        return

    if not encrypt_folder(folder_path, folder_password):
        print("Folder lock failed. Database status was not changed.")
        return

    if not apply_hidden_attribute(folder_path, True):
        print("Folder was encrypted, but it could not be hidden.")
        print("Saving status as LOCKED so it can still be unlocked later.")

    if update_folder_status(connection, saved_folder_id, STATUS_LOCKED):
        write_log(
            f"LOCK FOLDER | {nickname}"
        )

        print("Folder locked successfully.")


def unlock_folder(connection):
    """Unhide a locked folder, decrypt it, and mark it as registered."""
    locked_folders = get_locked_folders(connection)
    display_registered_folders(
        locked_folders,
        title="LOCKED FOLDERS",
        empty_message="No locked folders registered."
    )

    if not locked_folders:
        return

    folder_id = ask_for_folder_id()
    if folder_id is None:
        return

    folder = get_folder_by_id(connection, folder_id)
    if folder is None:
        print("Folder ID does not exist.")
        return

    saved_folder_id, nickname, folder_name, folder_path, status, date_added = folder

    if status != STATUS_LOCKED:
        print("This folder is not locked.")
        return

    if not verify_password(connection, "Enter master password to unlock folder: "):
        print("Access denied.")
        return

    if not folder_still_exists(folder_path):
        return

    import getpass as _getpass
    folder_password = _getpass.getpass("Enter folder encryption password: ")
    if not folder_password:
        print("Password cannot be empty.")
        return

    if not apply_hidden_attribute(folder_path, False):
        print("Folder could not be unhidden. Unlock was stopped.")
        return

    if not decrypt_folder(folder_path, folder_password):
        print("Folder unlock failed. Database status remains LOCKED.")
        apply_hidden_attribute(folder_path, True)
        return

    if not verify_folder_integrity(
        connection,
        saved_folder_id,
        folder_path
    ):
        print()
        print(
            "WARNING: One or more files "
            "failed integrity verification."
        )

    if update_folder_status(connection, saved_folder_id, STATUS_REGISTERED):
        write_log(
            f"UNLOCK FOLDER | {nickname}"
        )

        print("Folder unlocked successfully.")


def get_unique_backup_stem(prefix):
    """Return a backup filename stem that will not collide."""

    timestamp = get_timestamp_for_filename()
    stem = f"{prefix}_{timestamp}"
    counter = 1

    while os.path.exists(
        os.path.join(BACKUPS_DIR, f"{stem}.db")
    ):
        stem = f"{prefix}_{timestamp}_{counter}"
        counter += 1

    return stem


def backup_database_files(connection=None, prefix="locker", write_activity=True):
    """Create a timestamped backup of the database and related files."""

    try:
        if connection is not None:
            connection.commit()

        if not os.path.exists(DATABASE_FILE):
            print("Database file was not found.")
            return None

        os.makedirs(BACKUPS_DIR, exist_ok=True)

        backup_stem = get_unique_backup_stem(prefix)
        database_backup_path = os.path.join(
            BACKUPS_DIR,
            f"{backup_stem}.db"
        )
        signature_backup_path = os.path.join(
            BACKUPS_DIR,
            f"{backup_stem}.signature"
        )

        shutil.copy2(
            DATABASE_FILE,
            database_backup_path
        )

        signature_was_copied = copy_file_if_exists(
            DATABASE_SIGNATURE_FILE,
            signature_backup_path
        )

        security_backup_path = None

        if os.path.exists(SECURITY_LOG_FILE):
            security_backup_path = get_unique_file_path(
                BACKUPS_DIR,
                f"security_{get_timestamp_for_filename()}.log"
            )
            shutil.copy2(
                SECURITY_LOG_FILE,
                security_backup_path
            )

        print()
        print("Database backup created successfully.")
        print("Database:", database_backup_path)

        if signature_was_copied:
            print("Signature:", signature_backup_path)
        else:
            print("Signature file was not found, so it was not backed up.")

        if security_backup_path is not None:
            print("Security log:", security_backup_path)

        if write_activity:
            write_log("DATABASE BACKUP CREATED")

        return database_backup_path

    except OSError as error:
        print("Database backup failed:", error)
        return None


def backup_database(connection):
    """Create a user-requested backup of locker.db and related files."""

    backup_database_files(
        connection,
        prefix="locker",
        write_activity=True
    )


def get_database_backups():
    """Return database backup paths sorted newest first."""

    if not os.path.exists(BACKUPS_DIR):
        return []

    backup_paths = []

    for file_name in os.listdir(BACKUPS_DIR):
        file_path = os.path.join(BACKUPS_DIR, file_name)

        if not os.path.isfile(file_path):
            continue

        if not file_name.lower().endswith(".db"):
            continue

        backup_paths.append(file_path)

    backup_paths.sort(
        key=lambda path: os.path.getmtime(path),
        reverse=True
    )

    return backup_paths


def display_database_backups(backup_paths):
    """Show available database backups with matching signature status."""

    print()
    print("=" * 50)
    print("DATABASE BACKUPS")
    print("=" * 50)
    print()

    for index, backup_path in enumerate(backup_paths, start=1):
        backup_name = os.path.basename(backup_path)
        signature_path = get_matching_backup_signature_path(backup_path)
        modified_time = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(os.path.getmtime(backup_path))
        )

        if os.path.exists(signature_path):
            signature_status = "signature found"
        else:
            signature_status = "no signature"

        print(f"{index}. {backup_name}")
        print("   Modified:", modified_time)
        print("   Status:", signature_status)
        print()


def ask_for_backup_choice(backup_count):
    """Ask the user which backup to restore."""

    entered_choice = input("Enter backup number: ").strip()

    if not entered_choice:
        print("Backup number cannot be empty.")
        return None

    try:
        choice = int(entered_choice)
    except ValueError:
        print("Invalid backup number. Please enter a number.")
        return None

    if choice < 1 or choice > backup_count:
        print("Backup number is out of range.")
        return None

    return choice - 1


def get_matching_backup_signature_path(database_backup_path):
    """Return the expected signature path for a database backup."""

    backup_root, extension = os.path.splitext(database_backup_path)
    return backup_root + ".signature"


def backup_database_is_readable(database_backup_path):
    """Return True when a backup database passes SQLite integrity check."""

    backup_connection = None

    try:
        backup_connection = sqlite3.connect(database_backup_path)
        cursor = backup_connection.cursor()
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()

        return result is not None and result[0] == "ok"

    except sqlite3.Error:
        return False
    finally:
        if backup_connection is not None:
            backup_connection.close()


def prepare_restore_file(source_path, destination_path):
    """Copy one restore source to a temporary destination file."""

    temporary_path = destination_path + ".restore_tmp"

    shutil.copy2(
        source_path,
        temporary_path
    )

    return temporary_path


def finish_restore_file(temporary_path, destination_path):
    """Move a prepared restore file into place atomically."""

    os.replace(
        temporary_path,
        destination_path
    )


def restore_database(connection):
    """Restore locker.db from a selected backup after password verification."""

    backup_paths = get_database_backups()

    if not backup_paths:
        print("No database backups found.")
        return False

    display_database_backups(backup_paths)

    backup_index = ask_for_backup_choice(len(backup_paths))

    if backup_index is None:
        return False

    database_backup_path = backup_paths[backup_index]
    signature_backup_path = get_matching_backup_signature_path(
        database_backup_path
    )

    if not verify_password(
        connection,
        "Enter master password to restore database: "
    ):
        print("Access denied.")
        return False

    if not backup_database_is_readable(database_backup_path):
        print("Selected backup is not a readable SQLite database.")
        return False

    if os.path.exists(signature_backup_path):
        if not verify_backup_signature(
            database_backup_path,
            signature_backup_path
        ):
            print("Backup signature verification failed.")
            return False

    try:
        safety_backup_path = backup_database_files(
            connection,
            prefix="safety_locker",
            write_activity=False
        )

        if safety_backup_path is None:
            print("Restore stopped because the safety backup failed.")
            return False

        temporary_database_path = prepare_restore_file(
            database_backup_path,
            DATABASE_FILE
        )
        temporary_signature_path = None

        if os.path.exists(signature_backup_path):
            temporary_signature_path = prepare_restore_file(
                signature_backup_path,
                DATABASE_SIGNATURE_FILE
            )

        try:
            connection.close()
        except sqlite3.Error:
            pass

        finish_restore_file(
            temporary_database_path,
            DATABASE_FILE
        )

        if temporary_signature_path is not None:
            finish_restore_file(
                temporary_signature_path,
                DATABASE_SIGNATURE_FILE
            )
        else:
            save_database_signature()

        write_log("DATABASE RESTORED")

        print()
        print("Database restored successfully.")
        print("Safety backup:", safety_backup_path)
        print("Please restart Folder Locker before using it again.")

        return True

    except OSError as error:
        print("Database restore failed:", error)
        return False


def export_activity_log():
    """Export the current activity log to a timestamped text file."""

    if not os.path.exists(LOG_FILE):
        print("No activity log found.")
        return

    try:
        os.makedirs(EXPORTS_DIR, exist_ok=True)

        export_path = get_unique_file_path(
            EXPORTS_DIR,
            f"activity_log_{get_timestamp_for_filename()}.txt"
        )

        shutil.copy2(
            LOG_FILE,
            export_path
        )

        write_log("ACTIVITY LOG EXPORTED")

        print()
        print("Activity log exported successfully.")
        print("Export location:", export_path)

    except OSError as error:
        print("Activity log export failed:", error)


def search_folder(connection):
    """Search folders by nickname, folder name, or path."""

    search_text = input("Enter search text: ").strip()

    if not search_text:
        print("Search text cannot be empty.")
        return

    search_pattern = f"%{search_text.lower()}%"

    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT id, nickname, folder_name, folder_path, status, date_added
            FROM folders
            WHERE LOWER(nickname) LIKE ?
            OR LOWER(folder_name) LIKE ?
            OR LOWER(folder_path) LIKE ?
            ORDER BY id
            """,
            (
                search_pattern,
                search_pattern,
                search_pattern
            )
        )

        folders = cursor.fetchall()

        display_registered_folders(
            folders,
            title="SEARCH RESULTS",
            empty_message="No matching folders found."
        )

    except sqlite3.Error as error:
        print("Folder search failed:", error)


def rebuild_database_signature(connection):
    """Regenerate database signature."""

    if not verify_password(
        connection,
        "Enter master password: "
    ):
        print("Access denied.")
        return

    save_database_signature(connection)

    write_log(
        "DATABASE RECOVERY MODE USED"
    )

    print("Database signature rebuilt.")


def view_activity_log():
    """Show activity log entries without HMAC chain metadata."""

    if not os.path.exists(LOG_FILE):
        print("No activity log found.")
        return

    log_is_valid = verify_activity_log_integrity()

    print()
    print("=" * 50)
    print("ACTIVITY LOG")
    print("=" * 50)
    print()

    if not log_is_valid:
        print("WARNING: Activity log integrity could not be verified.")
        print()

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        has_content = False

        for line in file:
            has_content = True
            parsed = parse_protected_log_line(line)

            if parsed is not None:
                timestamp, action, previous_hash, signature = parsed
                print(f"{timestamp} | {action}")
                continue

            clean_line = line.rstrip("\n")

            if " | prev=" in clean_line:
                clean_line = clean_line.split(" | prev=", 1)[0]

            print(clean_line)

    if not has_content:
        print("Log is empty.")


def view_security_log():
    """Show the raw protected activity log exactly as stored."""

    if not os.path.exists(LOG_FILE):
        print("No activity log found.")
        return

    print()
    print("=" * 50)
    print("SECURITY LOG")
    print("=" * 50)
    print()

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        content = file.read()

    if not content:
        print("Log is empty.")
    else:
        print(content)


def run_menu(connection, master_password=None):
    """Keep showing the main menu until the user chooses to exit."""
    while True:
        display_menu()
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            add_folder(connection)
        elif choice == "2":
            view_folders(connection)
        elif choice == "3":
            hide_folder(connection)
        elif choice == "4":
            unhide_folder(connection)
        elif choice == "5":
            remove_folder(connection)
        elif choice == "6":
            master_password = change_password(
                connection,
                master_password
            )
        elif choice == "7":
            lock_folder(connection)
        elif choice == "8":
            unlock_folder(connection)
        elif choice == "9":
            search_folder(connection)
        elif choice == "10":
            backup_database(connection)
        elif choice == "11":
            restart_required = restore_database(connection)

            if restart_required:
                break
        elif choice == "12":
            export_activity_log()
        elif choice == "13":
            view_activity_log()
        elif choice == "14":
            view_security_log()
        elif choice == "15":
            rebuild_database_signature(connection)
        elif choice == "16":
            print("Exiting Folder Locker.")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 16.")


def main():
    """Start the Folder Locker console application."""
    database_existed_before_connect = startup_file_has_content("locker.db")
    signature_existed_before_startup = startup_file_exists(
        "locker.db.signature"
    )

    ensure_project_files()

    try:
        connection = connect_to_database()
    except RuntimeError as error:
        print(f"Fatal error: {error}")
        sys.exit(1)

    database_signature_valid = True
    master_password = None

    try:
        if database_existed_before_connect and signature_existed_before_startup:

            if not verify_database_signature(connection):
                database_signature_valid = False

                print()
                print("===================================")
                print("DATABASE TAMPERING DETECTED")
                print("===================================")
                print()

                print("locker.db signature is invalid.")
                print()
                print("1. Exit")
                print("2. Recovery Mode")
                print()

                recovery_choice = input(
                    "Enter choice: "
                ).strip()

                if recovery_choice == "1":
                    sys.exit(1)

                elif recovery_choice == "2":

                    stored_hash = get_stored_password_hash(
                        connection
                    )

                    if stored_hash is None:
                        print(
                            "No master password found."
                        )

                        sys.exit(1)

                    print()
                    print("WARNING:")
                    print("Only continue if YOU intentionally")
                    print("modified the database.")

                    if not verify_password(
                        connection,
                        "Enter master password: "
                    ):
                        print(
                            "Access denied."
                        )

                        sys.exit(1)

                    save_database_signature(connection)
                    database_signature_valid = True

                    print()
                    print(
                        "Database signature rebuilt."
                    )

                    print(
                        "Recovery successful."
                    )

                else:
                    print(
                        "Invalid option."
                    )

                    sys.exit(1)

        try:
            create_tables(connection)
        except RuntimeError as error:
            print(f"Fatal error: {error}")
            sys.exit(1)

        ensure_database_signature_file(connection)

        stored_hash = get_stored_password_hash(connection)

        if stored_hash is None:
            if not setup_master_password(connection):
                sys.exit(1)

        else:
            master_password = login(connection)

            if not master_password:
                sys.exit(1)

        run_menu(
            connection,
            master_password
        )

    finally:
        if database_signature_valid:
            try:
                save_database_signature(connection)
            except Exception:
                pass

        try:
            connection.close()
        except sqlite3.Error:
            pass

if __name__ == "__main__":
    main()
