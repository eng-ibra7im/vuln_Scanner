import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT_DIR / "model"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="vuln_scanner_smoke_") as temp_dir:
        temp_path = Path(temp_dir)
        venv_path = temp_path / ".venv"

        print(f"[smoke] creating venv at {venv_path}")
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)

        python_exe = (
            venv_path / "Scripts" / "python.exe"
            if sys.platform == "win32"
            else venv_path / "bin" / "python"
        )

        print("[smoke] upgrading pip")
        subprocess.run(
            [str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
        )

        print("[smoke] installing API requirements")
        subprocess.run(
            [
                str(python_exe),
                "-m",
                "pip",
                "install",
                "-r",
                str(MODEL_DIR / "requirements_api.txt"),
            ],
            check=True,
        )

        print("[smoke] verifying imports")
        smoke_script = (
            "import sys; "
            f"sys.path.insert(0, r'{MODEL_DIR}'); "
            "import web_server; "
            "print('ok', web_server.app.name)"
        )
        subprocess.run([str(python_exe), "-c", smoke_script], check=True)

    print("[smoke] completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
