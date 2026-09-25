import os
import subprocess


def run_user_command(value: str) -> None:
    subprocess.run(value, shell=True, check=False)


def unsafe_token() -> str:
    return os.getenv("TOKEN", "demo")
