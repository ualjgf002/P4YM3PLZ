@echo off
REM Script para construir ram.exe usando PyInstaller (CMD)
cd /d %~dp0
python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
pyinstaller --onefile --console ram.py
echo Resultado: dist\ram.exe (si todo es correcto)
pause