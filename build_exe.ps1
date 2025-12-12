# Script PowerShell para construir ram.exe con PyInstaller
# Ejecutar desde la carpeta del proyecto

# 1) Activar entorno virtual (si existe)
if (Test-Path .venv) {
    Write-Host "Activando .venv..."
    .\.venv\Scripts\Activate.ps1
}

Write-Host "Instalando dependencias (si no están instaladas)..."
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Construyendo ejecutable con PyInstaller (onefile, consola)..."
pyinstaller --onefile --console ram.py

Write-Host "Resultado: dist\ram.exe (si todo es correcto)"