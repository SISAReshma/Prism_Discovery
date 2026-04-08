# File: src/utils/file_utils.py
import os
import shutil
import stat
import time
from pathlib import Path
import zipfile

def ensure_dir(p: Path):
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    return p

def _on_rm_error(func, path, exc_info):
    """
    Error handler for shutil.rmtree to handle read-only files on Windows.
    func: os.remove or os.rmdir
    path: the path that caused error
    exc_info: sys.exc_info()
    """
    try:
        # Try to make the file writable and retry the operation
        os.chmod(path, stat.S_IWRITE)
    except Exception:
        pass

    try:
        func(path)
    except Exception as e:
        # As a last resort: if it's a directory, attempt to remove its contents manually
        try:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for name in files:
                        fp = os.path.join(root, name)
                        try:
                            os.chmod(fp, stat.S_IWRITE)
                            os.remove(fp)
                        except Exception:
                            pass
                    for name in dirs:
                        dp = os.path.join(root, name)
                        try:
                            os.chmod(dp, stat.S_IWRITE)
                            os.rmdir(dp)
                        except Exception:
                            pass
                # finally try removing the directory itself
                if os.path.isdir(path):
                    shutil.rmtree(path, onerror=_on_rm_error)
            else:
                # try to remove file again
                if os.path.exists(path):
                    os.remove(path)
        except Exception as ex:
            # Give up and surface the error (caller can log)
            raise ex from e

def cleanup_workspace(workspace: Path, scan_id: str, temp_base: Path) -> bool:
    """
    Clean workspace contents but keep the folder structure.
    Deletes all files and subdirectories inside workspace, but keeps the workspace folder itself.
    This allows tracking which scans have been run while saving disk space.
    
    Returns True if cleanup succeeded, False otherwise.
    """
    workspace = Path(workspace)
    if not workspace.exists():
        return True

    # Delete all contents inside the workspace folder, but keep the folder itself
    attempts = 5
    wait = 0.5
    for attempt in range(1, attempts + 1):
        try:
            # Remove all contents (files and subdirectories)
            for item in workspace.iterdir():
                if item.is_file() or item.is_symlink():
                    try:
                        os.chmod(item, stat.S_IWRITE)
                        item.unlink()
                    except Exception:
                        pass
                elif item.is_dir():
                    try:
                        shutil.rmtree(item, onerror=_on_rm_error)
                    except Exception:
                        pass
            
            # Check if workspace is now empty
            if not list(workspace.iterdir()):
                # Success - workspace folder exists but is empty
                return True
        except Exception as e:
            print(f"[WARN] cleanup attempt {attempt} failed for {workspace}: {e}")
        
        time.sleep(wait)
        wait *= 2  # exponential backoff

    # Final check: try Windows cmd for stubborn files
    try:
        if os.name == "nt" and workspace.exists():
            # Delete contents but keep folder using Windows commands
            for item in workspace.iterdir():
                if item.is_file():
                    os.system(f'del /F /Q "{str(item)}"')
                elif item.is_dir():
                    os.system(f'rmdir /S /Q "{str(item)}"')
    except Exception:
        pass

    # Check final state
    try:
        remaining = list(workspace.iterdir())
        if remaining:
            print(f"⚠️ cleanup incomplete for {workspace}: {len(remaining)} items remain")
            return False
        else:
            print(f"[OK] Cleaned workspace {workspace} (folder kept, contents deleted)")
            return True
    except Exception:
        return False

def extract_zip(zip_path: Path, dest: Path):
    dest = Path(dest)
    ensure_dir(dest)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(dest)
