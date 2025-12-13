# P4YM3 - Sistema de Cifrado Automático de Archivos

## Descripción
P4YM3 es un sistema de cifrado automático que:
- Genera claves RSA-3072 de forma segura
- Cifra automáticamente archivos de Documents y Desktop con AES-256-CTR
- Firma digitalmente los archivos con RSA-PSS-SHA256
- Elimina las claves privadas del disco local después de usar
- Proporciona un menú interactivo para descifrar y verificar firmas

## Flujo de Ejecución del EXE

Cuando ejecutas `P4YM3PLZ_ram.exe`:

### Paso 1: Generación de Claves (primera ejecución)
- El exe genera 3 pares RSA-3072 si no existen:
  - `rsa_main_private.pem` / `rsa_main_public.pem` - para cifrado
  - `rsa_two_private.pem` / `rsa_two_public.pem` - par alterno (se usa para cifrar aleatoriamente 1 archivo)
  - `rsa_special_private.pem` / `rsa_special_public.pem` - para firma digital
- Las claves se guardan en el **repositorio** (visible en git)
- El exe contiene las claves **públicas** (`rsa_main_public.pem`, `rsa_two_public.pem`, `rsa_special_public.pem`)

### Paso 2: Cifrado Automático
- Escanea automáticamente:
  - `C:\Users\<usuario>\Documents`
  - `C:\Users\<usuario>\Desktop`
- Cifra todos los archivos encontrados (máx 500 MB por archivo)
- Archivos cifrados se guardan con extensión `.p4ym3`
- Los archivos **originales se eliminan** de forma segura (sobrescritura 3x + ceros)
- Las firmas digitales se incluyen en cada archivo cifrado

### Paso 3: Limpieza de Claves Locales
- Elimina de forma segura `rsa_special_private.pem` del disco local
- `rsa_main_private.pem` se mantiene en el repositorio (para descifrado offline)

### Paso 4: Menú Interactivo
Después del cifrado, se abre un menú con opciones:

```
[1] Descifrar archivo (.p4ym3)
[2] Verificar firma digital
[3] Salir
```

#### Opción 1: Descifrar
- Solicita la ruta del archivo `.p4ym3`
- Solicita la ruta de la clave privada (`rsa_main_private.pem`)
- Genera un archivo `*_descifrado` con los datos originales
- Verifica automáticamente la firma si existe

#### Opción 2: Verificar Firma
- Verifica la autenticidad del archivo sin descifrarlo
- Solo requiere la clave pública (`rsa_special_public.pem`)
- Indica si la firma es válida o no

## Arquitectura de Claves

### Claves en el EXE
```
dist\P4YM3PLZ_ram.exe
├── rsa_main_public.pem (para cifrado - INCLUIDA)
├── rsa_two_public.pem (par alterno - INCLUIDA)
└── rsa_special_public.pem (para firmas - INCLUIDA)
```

### Claves en el Repositorio
```
c:\Users\ual\P4YM3PLZ\P4YM3PLZ\
├── rsa_main_private.pem (descifrado de archivos)
├── rsa_main_public.pem (cifrado de archivos)
├── rsa_special_private.pem (firma de archivos)
└── rsa_special_public.pem (verificación de firmas)
```

**IMPORTANTE**: Las claves privadas NUNCA se incluyen en el exe, pero están en el repositorio para descifrado offline.

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
    'rsa_main_private.pem',
    'rsa_special_public.pem'
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
