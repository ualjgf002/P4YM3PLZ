BUILD — Crear .exe del script `ram.py`

Requisitos:
- Windows con Python instalado (3.8+ recomendado).
- PowerShell (Windows) o CMD.

Pasos (PowerShell):

1) Crear un entorno virtual (recomendado):

```powershell
cd "C:\Users\ual\P4YM3PLZ\P4YM3PLZ"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2) Actualizar pip e instalar dependencias (incluye PyInstaller):

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3) Generar el ejecutable con PyInstaller:

- Ejecución en consola (output en `dist\ram.exe`):

```powershell
pyinstaller --onefile --console ram.py
```

- Si prefieres que no abra consola (aplicación sin ventana), usa `--windowed` (no recomendable si el script interactúa por consola):

```powershell
pyinstaller --onefile --windowed ram.py
```

4) Resultado:
- Ejecutable único: `dist\ram.exe`
- Archivos temporales creados por PyInstaller: `build\`, `dist\`, `ram.spec`.

Nota: PyInstaller incluirá todo el código en el ejecutable — si el script contiene credenciales (por ejemplo `contraseña_app`), estas quedarán embebidas en el exe. Antes de compilar, considera retirar credenciales del código y usar variables de entorno.

Problemas comunes:
- Python no disponible/`python` no reconocido: añade Python al PATH o usa la ruta completa a tu python.exe.
- Antivirus detecta el exe: algunos AVs marcan ejecutables nuevos; firma el binario o añade excepción.
- Librerías nativas: PyInstaller suele manejar `cryptography`, pero en entornos raros puede necesitar ajustes.

Recomendación de seguridad (muy importante):
- Usar variables de entorno para `P4Y_GMAIL_USER` y `P4Y_GMAIL_APP_PASS` antes de crear el exe.
- Si quieres, puedo aplicar ese cambio al código para que el exe no contenga credenciales en claro.
