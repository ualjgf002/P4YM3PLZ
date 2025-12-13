# P4YM3 - Sistema de Cifrado Automático de Archivos

## Descripción
P4YM3 es un sistema de cifrado automático que:
- Utiliza AES-256-CTR por archivo para cifrado simétrico
- Envuelve la clave AES con RSA-OAEP (RSA-3072)
- Firma los datos con RSA-PSS-SHA256 para verificar autenticidad
- Incluye utilidades para cifrado masivo y un menú interactivo para descifrar/verificar

## Flujo de Ejecución del EXE

Cuando ejecutas `P4YM3PLZ_ram.exe`:

### Paso 1: Generación de Claves (primera ejecución)
- El exe genera 3 pares RSA-3072 si no existen:
  - `rsa_main_private.pem` / `rsa_main_public.pem` - par principal para envolver claves AES
  - `rsa_two_private.pem` / `rsa_two_public.pem` - par alterno (se usa para cifrar aleatoriamente algunos archivos)
  - `rsa_special_private.pem` / `rsa_special_public.pem` - par para firma digital
- Los archivos de clave pública (`*_public.pem`) están incluidos/enlazados para uso por la aplicación y **sí** se empaquetan en el exe.
- Las claves privadas pueden generarse localmente, pero han sido excluidas del control de versiones (`.gitignore`) y el programa intenta limpiar la clave de firma del disco después del cifrado automático; por seguridad, trate las privadas como secretos y muévalas fuera del repo.

### Paso 2: Cifrado Automático
- Escanea automáticamente:
  - `C:\Users\<usuario>\Documents`
  - `C:\Users\<usuario>\Desktop`
- Cifra todos los archivos encontrados (máx 500 MB por archivo)
- Archivos cifrados se guardan con extensión `.p4ym3`.
- Cuando un archivo fue cifrado usando la clave alternativa `rsa_two`, el nombre de salida incluye el `KEYID` (p. ej. `documento_two.p4ym3`). Esto facilita identificar con qué par RSA fue envuelta la clave.
- Por defecto, el archivo original se elimina tras cifrar (si la opción está activada en la ejecución automática).
- Las firmas digitales (RSA-PSS) se incluyen en cada archivo cifrado cuando están habilitadas.

### Paso 3: Limpieza de Claves Locales
- El programa puede eliminar localmente la clave privada de firma (`rsa_special_private.pem`) tras completar el proceso automático.
- **Importante**: las claves privadas NO se deben versionar. En este repositorio las privadas fueron removidas del historial y están listadas en `.gitignore`.

### Paso 4: Menú Interactivo
Después del cifrado, se abre un menú con opciones:

```
[1] Descifrar archivo (.p4ym3)
[2] Verificar firma digital
[3] Salir
```

#### Opción 1: Descifrar
- Solicita la ruta del archivo `.p4ym3`.
- Antes de pedir la clave privada, el programa muestra el `KEYID` leído del encabezado (si existe). Use la clave privada correspondiente (`rsa_main_private.pem` o `rsa_two_private.pem`).
- Si la clave privada no corresponde con la clave envuelta en el archivo, el programa informará «Decryption failed» y mostrará el `KEYID` como pista.
- Genera un archivo `*_descifrado` con los datos originales y, si se proporcionó la clave pública de firma, verifica la firma.

#### Opción 2: Verificar Firma
- Verifica la autenticidad del archivo sin descifrarlo
- Solo requiere la clave pública (`rsa_special_public.pem`)
- Indica si la firma es válida o no

## Arquitectura de Claves

### Claves en el EXE
```
dist\P4YM3PLZ_ram.exe
├── rsa_main_public.pem (INCLUIDA)
├── rsa_two_public.pem (INCLUIDA)
└── rsa_special_public.pem (INCLUIDA)
```

### Claves en el Repositorio / Local
```
c:\Users\ual\P4YM3PLZ\P4YM3PLZ\
├── rsa_main_public.pem
├── rsa_two_public.pem
├── rsa_special_public.pem
├── rsa_main_private.pem (puede generarse localmente)
└── rsa_two_private.pem (puede generarse localmente)
```

**IMPORTANTE**: Las claves privadas NO deben subirse a un repositorio público. En este repositorio se han eliminado del historial y `.gitignore` incluye patrones para evitar subir `*_private.pem`.

## Formato de Archivo Cifrado (.p4ym3)

```
P4Y1
<MODO>                          (ej: CTR)
<KEYBITS>                       (ej: 256)
PKALG=RSA_OAEP_SHA256
<WRAPPED_KEY_BASE64>
KEYID=<identificador opcional: main|two>
SIGALG=RSA_PSS_SHA256
<SIGNATURE_BASE64>
<16-BYTE-IV><AES_CIPHERTEXT>
```

## Seguridad

### ✅ Lo que hace bien
- AES-256-CTR para cifrado simétrico (seguro para archivos grandes)
- RSA-3072 OAEP para envolver claves AES (imposible descifrar sin clave privada)
- RSA-PSS para firmas digitales (verifica autenticidad sin descifrar)
- Claves privadas NO en el exe (solo en repositorio, visible pero asegurado por contraseña de repo)
- Sobrescritura multi-pasada (3x) antes de eliminar (dificulta recuperación)

### ⚠️ Limitaciones
- Las claves en el repositorio git deben estar protegidas por contraseña/SSH
- Si alguien accede al repo, puede descifrar archivos anteriores
- Para máxima seguridad, extraer claves privadas a un medio offline después de primera ejecución

## Comandos Útiles

### Construir el EXE desde cero
```powershell
cd c:\Users\ual\P4YM3PLZ\P4YM3PLZ
.\.portable_python\python.exe -m PyInstaller P4YM3PLZ_ejecutable.spec
```

### Regenerar claves
```powershell
del rsa_main_private.pem
del rsa_main_public.pem
del rsa_special_private.pem
del rsa_special_public.pem
# Ejecutar exe nuevamente para regenerar
```

### Descifrar manualmente con Python
```python
from Programa.ejecutable import descifrar_archivo_automatico
descifrar_archivo_automatico(
  'archivo.p4ym3',
  'ruta/a/rsa_main_private.pem',  # o rsa_two_private.pem si KEYID=two
  'ruta/a/rsa_special_public.pem'  # opcional para verificar firma
)
```

## Requisitos

- Python 3.11+ (incluido en exe portable)
- Windows (probado en Windows 10)
- 500 MB libres (para trabajar durante cifrado)

## Próximos Pasos (Opcional)

1. Guardar claves privadas en USB o nube (para descifrado en otro equipo)
2. Automatizar ejecución con Task Scheduler:
   ```
   Programa: C:\Users\<usuario>\P4YM3PLZ\P4YM3PLZ\dist\P4YM3PLZ_ram.exe
   Hora: Diaria a las 02:00
   ```
3. Considerar dos-factor: Requiere password adicional para descifrar

## Soporte

En caso de problemas:
- Ejecutar el exe con cmd abierta para ver mensajes de error
- Revisar `README.md` en raíz del repositorio
- Verificar que todas las claves `.pem` existan en el repositorio
