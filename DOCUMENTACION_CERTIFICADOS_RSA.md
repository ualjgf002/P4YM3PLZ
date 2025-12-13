 # Documentación Extensiva: Sistema de Certificados Digitales y Autenticación RSA

## Tabla de Contenidos

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Objetivos Cubiertos](#objetivos-cubiertos)
3. [Introducción](#introducción)
4. [Descripción de Algoritmos y Protocolos](#descripción-de-algoritmos-y-protocolos)
5. [Funcionalidad y Soluciones](#funcionalidad-y-soluciones)
6. [Diagramas de Flujo](#diagramas-de-flujo)
7. [Manual de Usuario](#manual-de-usuario)
8. [Código Criptográfico Relevante](#código-criptográfico-relevante)
9. [Bibliografía y Librerías](#bibliografía-y-librerías)

---

## Resumen Ejecutivo

Esta aplicación implementa un **sistema educativo de autenticación digital basado en Infraestructura de Clave Pública (PKI) y certificados digitales**. Simula dos escenarios reales:

1. **Conexión Legítima**: Un cliente descarga una aplicación desde un servidor legítimo verificando el certificado digital (firmado por una Autoridad de Certificación).
2. **Conexión Maliciosa**: El mismo cliente intenta conectarse a un servidor falso (banco falso), recibe un certificado inválido, y aunque se le advierte, acepta la conexión y descarga un binario ("malware simulado").

**Tecnologías clave**:
- **RSA-2048**: Criptografía asimétrica para generar claves y firmas digitales.
- **RSA-PSS**: Esquema de firma digital probabilístico.
- **SHA-256**: Función hash para garantizar integridad.
- **Certificados digitales**: Estructura que contiene identidad, clave pública e firma de CA.
- **Sockets TCP**: Comunicación cliente-servidor en red local.

---

## Objetivos Cubiertos

### Objetivo 1: Simular Conexión Autenticada a Sitio Web Legítimo
✅ **COMPLETADO**

**Requisitos**:
- El servidor envía un certificado que contiene su clave pública, emitido por una Autoridad de Certificación (CA).
- El certificado incluye identidad del propietario, clave pública, y firma del CA.
- El cliente puede verificar el certificado usando la clave pública de la CA.

**Implementación**:
- [`server_good_rsa.py`](server_good_rsa.py): Genera un certificado válido firmado por la CA.
- [`client_rsa.py`](client_rsa.py): Verifica el certificado, establece confianza y descarga aplicación legítima.
- [`ca_rsa.py`](ca_rsa.py): Actúa como Autoridad de Certificación, firmas y verifica.

### Objetivo 2: Simular Conexión a Banco Falso (Advertencia de Riesgo)
✅ **COMPLETADO**

**Requisitos**:
- El servidor falso envía un certificado que no puede ser autenticado.
- Se proporciona advertencia al usuario sobre conexión peligrosa.
- El usuario puede optar por ignorar la advertencia.
- Simulación de descarga de malware si el usuario continúa.

**Implementación**:
- [`server_fake_rsa.py`](server_fake_rsa.py): Envia certificado inválido (CA falsa).
- [`client_rsa.py`](client_rsa.py): Detecta certificado inválido, muestra advertencia.
- Simulación de descarga sin ejecución de código peligroso real.

### Objetivo 3: Demostración Automatizada
✅ **COMPLETADO**

- [`run_demo.py`](run_demo.py): Orquesta ambos escenarios automáticamente con logging.

---

## Introducción

### Contexto: ¿Por Qué Certificados Digitales?

En la era digital, cuando tu navegador descarga una aplicación o accedes a un banco en línea, necesitas asegurar que:
1. El servidor es realmente quien dice ser (autenticación).
2. Los datos no han sido alterados en tránsito (integridad).
3. Nadie puede falsificar este certificado sin la clave privada de la CA.

**Infraestructura de Clave Pública (PKI)** resuelve esto mediante:
- **Claves asimétricas**: Una clave privada (secreta) y una pública (conocida).
- **Certificados digitales**: Documentos firmados que vinculan identidad + clave pública.
- **Autoridades de Certificación (CAs)**: Entidades de confianza que emiten certificados.

### Flujo Básico

```
Usuario (Cliente) 
    ↓ (solicita aplicación)
Servidor Legítimo 
    ↓ (envía certificado + datos)
Cliente verifica certificado usando CA pública
    ↓ (certificado válido)
Descarga segura ✓
```

vs.

```
Usuario (Cliente) 
    ↓ (solicita aplicación falsa)
Servidor Falso 
    ↓ (envía certificado falso)
Cliente intenta verificar 
    ↓ (verificación falla)
⚠️ ADVERTENCIA DE RIESGO
Usuario elige ignorar ⚠️ 
    ↓
Descarga insegura (malware potencial) ✗
```

---

## Descripción de Algoritmos y Protocolos

### 1. RSA (Rivest-Shamir-Adleman)

**¿Qué es RSA?**

RSA es un algoritmo criptográfico asimétrico que permite:
- **Encriptación**: Alguien con la clave pública puede encriptar; solo quien tiene la privada puede desencriptar.
- **Firmado digital**: Quien tiene la privada firma; quien tiene la pública verifica.

**Parámetros utilizados**:
- **Tamaño de clave**: 2048 bits (seguridad de ~112 bits).
- **Exponente público**: 65537 (estándar de facto).

**Generación de claves RSA** (en [`ca_rsa.py`](ca_rsa.py)):
```python
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
```

### 2. RSA-PSS (Probabilistic Signature Scheme)

**¿Qué es RSA-PSS?**

Es un esquema de firma digital **probabilístico** basado en RSA que mejora la seguridad sobre PKCS#1 v1.5:
- Cada firma es **única** incluso para el mismo mensaje (gracias al salt aleatorio).
- **Resistente** a ataques de falsificación de firma.
- Estándar PKCS #1 v2.1.

**Parámetros utilizados**:
- **Función hash**: SHA-256.
- **Longitud de salt**: `PSS.MAX_LENGTH` (máxima para seguridad).
- **MGF1**: Mask Generation Function 1 (derivación).

**Firmado en [`ca_rsa.py`](ca_rsa.py)**:
```python
signature = ca_private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)
```

### 3. SHA-256 (Secure Hash Algorithm)

**¿Qué es SHA-256?**

Función criptográfica hash que:
- Toma entrada de tamaño arbitrario y produce salida de **256 bits** (32 bytes).
- Es **determinística**: mismo entrada → mismo hash.
- **Irreversible**: imposible recuperar input desde output.
- **Avalanche effect**: pequeño cambio en input = cambio completamente diferente en output.

**Propósito**: Garantizar integridad de datos.

### 4. Certificados Digitales (X.509 Básico)

En esta aplicación, un **certificado simplificado** contiene:

```json
{
  "identity": "www.bueno.com",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "ca_name": "MiCA_RSA",
  "signature": "a1b2c3d4e5f6... (hex)"
}
```

**Componentes**:
- **identity**: Nombre del servidor (DN - Distinguished Name simplificado).
- **public_key_pem**: Clave pública en formato PEM (Privacy Enhanced Mail).
- **ca_name**: Nombre de la CA que lo emite (para verificar confianza).
- **signature**: Firma digital del contenido anterior con clave privada de CA.

**Verificación**: Cliente recibe certificado, extrae firma, y verifica que:
```
verify(identity + public_key + ca_name, signature) == TRUE
```

### 5. Protocolo de Autenticación (Cliente-Servidor)

#### Fase 1: Handshake (Intercambio de Certificado)

```
Cliente                          Servidor
  |                                |
  |-------- CONEXIÓN TCP --------->|
  |                                |
  |<--- CERTIFICADO (JSON) --------|
  |     (identity + pubkey + sig)   |
  |                                |
  |--- VERIFICAR CERTIFICADO ----->|
  |     (usando CA pública)         |
  |                                |
```

#### Fase 2: Transferencia de Datos (si confianza establecida)

```
Cliente                          Servidor
  |                                |
  |--- GET_APP (o GET_MALWARE) -->|
  |                                |
  |<---- BINARIO DE DATOS ---------|
  |     (aplicación o malware)      |
  |                                |
  |---- GUARDAR ARCHIVO ---------->|
  |---- CERRAR CONEXIÓN ---------->|
  |                                |
```

---

## Funcionalidad y Soluciones

### Solución 1: Conexión Legítima

#### Protagonista 1: Autoridad de Certificación (CA)
**Archivo**: [`ca_rsa.py`](ca_rsa.py)

**Responsabilidades**:
1. **Generar/cargar claves**: Si no existen `ca_private_key.pem` y `ca_public_key.pem`, las genera y persiste.
2. **Firmar certificados**: Dado identidad + clave pública, genera firma RSA-PSS.
3. **Verificar firmas**: Dado datos + firma, verifica usando clave pública persistida.

**Acciones clave**:
```python
# Firmar certificado de servidor
signature = ca_private_key.sign(
    identity.encode() + public_key_pem + ca_name.encode(),
    padding.PSS(...),
    hashes.SHA256(),
)

# Verificar certificado (lado cliente)
ca_public_key.verify(
    signature,
    data,
    padding.PSS(...),
    hashes.SHA256(),
)  # Lanza excepción si inválido
```

#### Protagonista 2: Servidor Legítimo
**Archivo**: [`server_good_rsa.py`](server_good_rsa.py)

**Responsabilidades**:
1. Generar par de claves RSA-2048 (privada para futuro descifrado, pública para certificado).
2. Solicitar a CA que firme su certificado.
3. Escuchar conexiones TCP en puerto configurable.
4. Enviar certificado al cliente.
5. Esperar solicitud de aplicación y responder con binario simulado.

**Acciones**:
```python
# Crear certificado
def create_cert(identity, public_key_pem):
    to_sign = identity.encode() + public_key_pem + CA_NAME.encode()
    signature = sign(to_sign)  # Llama a ca_rsa.sign()
    return {
        "identity": identity,
        "public_key_pem": public_key_pem.decode(),
        "ca_name": CA_NAME,
        "signature": signature.hex(),
    }

# Enviar certificado
conn.sendall((json.dumps(cert) + "\n").encode())

# Responder a petición de app
if req == "GET_APP":
    conn.sendall(b"APP_LEGITIMA_BINARIA_SIMULADA")
```

#### Protagonista 3: Cliente
**Archivo**: [`client_rsa.py`](client_rsa.py) - Función `comprobar_cert()`

**Responsabilidades**:
1. Conectar al servidor.
2. Recibir certificado en JSON.
3. Verificar identidad, CA, y firma.
4. Si válido: establecer confianza y descargar.
5. Si inválido: mostrar advertencia y permitir ignorar.

**Acciones**:
```python
def comprobar_cert(cert: dict, host_esperado: str) -> bool:
    # Verificar identidad
    if cert.get("identity") != host_esperado:
        print("[!] Identidad del certificado NO coincide...")
        return False
    
    # Verificar CA
    if cert.get("ca_name") != CA_NAME:
        print("[!] CA del certificado NO está en almacén de confianza...")
        return False
    
    # Verificar firma
    public_key_pem = cert["public_key_pem"].encode()
    firma = bytes.fromhex(cert["signature"])
    to_verify = cert["identity"].encode() + public_key_pem + cert["ca_name"].encode()
    
    if not verify(to_verify, firma):  # Llama a ca_rsa.verify()
        print("[!] Firma RSA inválida...")
        return False
    
    print("[+] Certificado válido: identidad y firma correctas.")
    return True
```

### Solución 2: Conexión a Banco Falso

#### Protagonista 4: Servidor Falso
**Archivo**: [`server_fake_rsa.py`](server_fake_rsa.py)

**Diferencias respecto a servidor legítimo**:
1. **No solicita firma de CA real**: Genera certificado con CA falsa.
2. **Firma es basura**: `"signature": "00" * 256` (256 bytes de ceros - no válida).

```python
FAKE_CERT = {
    "identity": IDENTITY_FAKE,
    "public_key_pem": "PUBLIC_KEY_FALSA_EN_PEM",
    "ca_name": "OtraCA_Que_No_Es_" + CA_NAME,  # ← CA distinta
    "signature": "00" * 256,  # ← Firma inválida
}
```

**Acciones**:
- Envía certificado falso.
- Si cliente solicita `GET_MALWARE`, responde con binario simulado.

#### Protagonista 5: Cliente (Detectando Fraude)
**Archivo**: [`client_rsa.py`](client_rsa.py) - Función `conectar()`

**Flujo cuando detecta certificado inválido**:
```python
if not comprobar_cert(cert, esperado):
    print("[!] ADVERTENCIA: certificado NO confiable / conexión peligrosa.")
    seguir = input("¿Ignorar advertencia y continuar? (s/n): ").lower()
    if seguir != "s":
        print("[*] Conexión abortada por el usuario.")
        s.close()
        return
    else:
        print("[*] El usuario ha decidido continuar A PESAR de la advertencia...")
```

**Si usuario ignora la advertencia**:
- Entra en flujo falso: solicita `GET_MALWARE`.
- Descarga "malware_demo.bin" (solo simulación, no ejecuta código peligroso).

---

## Diagramas de Flujo

### Diagrama 1: Generación de Certificado (Servidor Legítimo)

```
┌─────────────────────────────────────────────────────────────┐
│         SERVIDOR LEGÍTIMO (server_good_rsa.py)              │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐
│ Generar par RSA  │  ← rsa.generate_private_key(key_size=2048)
│  (2048 bits)     │
└────────┬─────────┘
         │
         ├─→ private_key (se guarda localmente)
         └─→ public_key (se incluye en certificado)

         │
         ▼
┌──────────────────────────────────┐
│ Crear estructura de certificado  │
│ {                                │
│   "identity": "www.bueno.com",   │
│   "public_key_pem": "...",       │
│   "ca_name": "MiCA_RSA"          │
│ }                                │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│ Solicitar firma a CA (ca_rsa.sign())     │
│ sign(identity + pubkey + ca_name)        │
│          ↓                               │
│ Usa: RSA-PSS + SHA-256 + MAX SALT        │
│          ↓                               │
│ Retorna: signature (256 bytes)           │
└────────┬─────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│ Completar certificado            │
│ {                                │
│   ... (anterior)                 │
│   "signature": "a1b2c3d4..."     │
│ }                                │
└────────┬─────────────────────────┘
         │
         ▼
┌──────────────────────────────────┐
│ Guardar en memoria & enviar      │
│ cuando cliente se conecte         │
└──────────────────────────────────┘
```

### Diagrama 2: Verificación de Certificado (Cliente)

```
┌──────────────────────────────────────────────────────────┐
│         CLIENTE (client_rsa.py)                          │
└──────────────────────────────────────────────────────────┘

┌─────────────────────────────────┐
│ Conectar a servidor (socket)    │
│ socket.connect((host, port))    │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ Recibir certificado (JSON) desde servidor               │
│ cert_text = recibir_linea(sock)                         │
│ cert = json.loads(cert_text)                            │
└────────┬────────────────────────────────────────────────┘
         │
         ▼ COMPROBAR_CERT()
    ┌────────────────────────────────────┐
    │ 1. ¿Identity es "www.bueno.com"?   │
    │    (O lo esperado)                  │
    └─┬──────────────────────────────┬────┘
      │                              │
      NO                             SÍ
      │                              │
      ▼                              ▼
   FALLO                     ┌────────────────┐
   [!] Identidad NO           │ 2. ¿CA_NAME    │
       coincide                  es MiCA_RSA?  │
                              └─┬──────────┬───┘
                                │          │
                                NO         SÍ
                                │          │
                                ▼          ▼
                             FALLO     ┌──────────────────┐
                             [!] CA    │ 3. Verificar     │
                                NO es  │ firma RSA        │
                                confiada│ ca_rsa.verify() │
                                       │                  │
                                       └─┬─────────────┬──┘
                                         │             │
                                         INVÁLIDA      VÁLIDA
                                         │             │
                                         ▼             ▼
                                      FALLO       ÉXITO
                                      [!] Firma  [+] Certificado
                                          RSA        válido
                                          inválida
         │
         ▼
    ┌───────────────────────────────┐
    │ Si CUALQUIER verificación falla:
    │ Mostrar advertencia:          │
    │ "[!] ADVERTENCIA: certificado│
    │      NO confiable"           │
    │                              │
    │ Preguntar al usuario:        │
    │ "¿Ignorar y continuar?"      │
    │                              │
    │ Opción: SÍ → Continuar       │
    │         NO → Abortar         │
    └───────────────────────────────┘
```

### Diagrama 3: Flujo Completo (Cliente-Servidor Legítimo vs. Falso)

```
ESCENARIO 1: SERVIDOR LEGÍTIMO
═══════════════════════════════════════════════════════════

Cliente                                   Servidor Bueno
  │                                             │
  │─ socket.connect(host, port) ──────────────>│
  │                                             │
  │<─ Envía CERTIFICADO VÁLIDO ────────────────│
  │   identity="www.bueno.com"                 │
  │   ca_name="MiCA_RSA"                       │
  │   signature=VÁLIDA (firmado por CA)        │
  │                                             │
  │─ VERIFICAR CERTIFICADO ──>  ca_rsa.verify()│
  │   • Identidad: ✓ COINCIDE                  │
  │   • CA: ✓ EN ALMACÉN                       │
  │   • Firma: ✓ VÁLIDA                        │
  │                                             │
  │  [+] Certificado válido                    │
  │      Confianza establecida ✓               │
  │                                             │
  │─ GET_APP ─────────────────────────────────>│
  │                                             │
  │<─ APP_LEGITIMA_BINARIA_SIMULADA ──────────│
  │                                             │
  │─ Guardar app_legitima.bin ──> ÉXITO ✓    │
  │                                             │


ESCENARIO 2: SERVIDOR FALSO
═══════════════════════════════════════════════════════════

Cliente                                   Servidor Falso
  │                                             │
  │─ socket.connect(host, port) ──────────────>│
  │                                             │
  │<─ Envía CERTIFICADO FALSO ─────────────────│
  │   identity="www.banco-falso.com"           │
  │   ca_name="OtraCA_Que_No_Es_MiCA_RSA"     │
  │   signature="00000000..." (INVÁLIDA)       │
  │                                             │
  │─ VERIFICAR CERTIFICADO ──>  ca_rsa.verify()│
  │   • Identidad: Coincide con lo esperado    │
  │   • CA: ✗ NO EN ALMACÉN (distinta CA)     │
  │   • Firma: ✗ INVÁLIDA (no verifica)       │
  │                                             │
  │  [!] ADVERTENCIA: Certificado NO confiable│
  │      ⚠️ Conexión peligrosa                  │
  │                                             │
  │  Usuario: "¿Ignorar y continuar? (s/n)"   │
  │                                             │
  │  Input: "s" (usuario ignora advertencia)   │
  │                                             │
  │─ GET_MALWARE ─────────────────────────────>│
  │                                             │
  │<─ BINARIO_CORRUPTO_DEMO ───────────────────│
  │                                             │
  │─ Guardar malware_demo.bin ────────────────>│
  │                                             │
  │─ [!] Simulación: ejecutar (NO hace nada)  │
  │    ADVERTENCIA MOSTRADA ✓                  │
  │    USUARIO ALERTADO ✓                      │
```

### Diagrama 4: Estructura de Certificado

```
CERTIFICADO DIGITAL (JSON)
═══════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────┐
│ SECCIÓN DE IDENTIDAD Y DATOS PÚBLICOS                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  identity: "www.bueno.com"                             │
│  ├─ Identifica al titular del certificado              │
│  └─ Verificado por cliente contra host esperado        │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  public_key_pem:                                        │
│  "-----BEGIN PUBLIC KEY-----                           │
│   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBI...            │
│   ... (2048 bits codificados en Base64) ...            │
│   -----END PUBLIC KEY-----"                            │
│                                                         │
│  ├─ Clave pública de RSA-2048                          │
│  ├─ Usado DESPUÉS para encriptar/desencriptar          │
│  └─ Formato estándar PEM (Privacy Enhanced Mail)       │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ca_name: "MiCA_RSA"                                   │
│  ├─ Nombre de la Autoridad de Certificación            │
│  └─ Cliente verifica que confía en esta CA             │
│                                                         │
└─────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────┐
│ SECCIÓN DE AUTENTICIDAD (FIRMA)                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  signature: "a1b2c3d4e5f6a7b8c9d0...00"              │
│  (256 bytes = 512 caracteres hexadecimales)            │
│                                                         │
│  ├─ Resultado de: RSA_PSS_sign(                        │
│  │    data = identity + public_key_pem + ca_name,     │
│  │    key = CA_PRIVATE_KEY,                           │
│  │    hash = SHA256,                                  │
│  │    salt_length = MAXIMUM                           │
│  │  )                                                  │
│  │                                                     │
│  └─ Verificado por cliente usando CA_PUBLIC_KEY       │
│                                                         │
└─────────────────────────────────────────────────────────┘

VERIFICACIÓN DEL CLIENTE
═════════════════════════════════════════════════════════

1. Extrae: identity, public_key_pem, ca_name, signature

2. Reconstruye data:
   data = identity.encode() + public_key_pem.encode() + ca_name.encode()

3. Llama a: ca_rsa.verify(data, signature)
   que internamente ejecuta:
   ca_public_key.verify(
       signature,
       data,
       padding.PSS(
           mgf=padding.MGF1(hashes.SHA256()),
           salt_length=padding.PSS.MAX_LENGTH,
       ),
       hashes.SHA256(),
   )

4. Si no lanza excepción → Certificado VÁLIDO ✓
   Si lanza excepción → Certificado INVÁLIDO ✗
```

---

## Manual de Usuario

### Instalación y Configuración

#### Requisitos Previos
- Python 3.11+ (incluido en el virtualenv del proyecto)
- Librería `cryptography` (instalada automáticamente)

#### Paso 1: Configurar el Entorno

```bash
# Navega al directorio del proyecto
cd c:\Users\ual\P4YM3PLZ\P4YM3PLZ

# Asegúrate de que el venv está creado
# Si no existe, créalo (nota: la mayoría de los proyectos ya lo tienen)
python -m venv .venv
```

#### Paso 2: Instalar Dependencias

```bash
# En PowerShell o CMD (sin necesidad de activar venv):
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe -m pip install cryptography
```

#### Paso 3: Generar Claves de CA (Automático)

```bash
# La primera vez que importes ca_rsa.py, se generan automáticamente:
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe -c "import ca_rsa"
```

**Archivos creados**:
- `ca_private_key.pem` (clave privada de CA - SECRETO)
- `ca_public_key.pem` (clave pública de CA - distribuida a clientes)

### Ejecución de la Demostración

#### Opción A: Ejecución Automatizada (Recomendado)

```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe run_demo.py
```

**Qué ocurre**:
1. Se inician servidores bueno y falso en puertos libres automáticamente.
2. Cliente se conecta al servidor bueno → Descarga legítima ✓
3. Cliente se conecta al servidor falso con advertencia aceptada → Descarga falsa ✗
4. Se muestra salida completa en consola y se guarda en `run_demo.log`.

**Salida esperada**:
```
[2025-12-13 13:58:11,030] INFO: Puertos elegidos -> bueno: 53373, falso: 53374
[2025-12-13 13:58:11,045] INFO: Arrancando servidor bueno...
[2025-12-13 13:58:11,059] INFO: Arrancando servidor falso...
[2025-12-13 13:58:12,076] INFO: == Conexión al servidor bueno ==
[2025-12-13 13:58:12,440] INFO: [CLIENT_GOOD] ----
[+] Certificado válido: identidad y firma correctas.
[+] Aplicación legítima descargada como app_legitima.bin
...
[2025-12-13 13:58:12,777] INFO: == Conexión al servidor falso (aceptando advertencia) ==
[CLIENT_FAKE] ----
[!] CA del certificado NO está en el almacén de confianza.
[!] ADVERTENCIA: certificado NO confiable / conexión peligrosa.
...
```

#### Opción B: Ejecución Manual (Debugging)

**Terminal 1 - Servidor Legítimo**:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe server_good_rsa.py 55443
```

Salida esperada:
```
[+] Servidor bueno (RSA) escuchando en puerto 55443
[*] Conexión desde ('127.0.0.1', xxxxx)
```

**Terminal 2 - Servidor Falso**:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe server_fake_rsa.py 55444
```

Salida esperada:
```
[+] Servidor falso (RSA) escuchando en puerto 55444
```

**Terminal 3 - Cliente → Servidor Legítimo**:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe -c "import client_rsa; client_rsa.conectar('127.0.0.1', 55443, 'www.bueno.com','bueno')"
```

Salida esperada:
```
[+] Certificado válido: identidad y firma correctas.
[+] Aplicación legítima descargada como app_legitima.bin
[*] (Simulación) Aquí podrías 'instalar' o ejecutar la app segura.
```

**Terminal 4 - Cliente → Servidor Falso (con auto-aceptación)**:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe -c "import builtins; builtins.input=lambda *a:'s'; import client_rsa; client_rsa.conectar('127.0.0.1', 55444, 'www.banco-falso.com','falso')"
```

Salida esperada:
```
[!] CA del certificado NO está en el almacén de confianza.
[!] ADVERTENCIA: certificado NO confiable / conexión peligrosa.
[*] El usuario ha decidido continuar A PESAR de la advertencia...
[*] Visitando sitio 'banco falso'...
[!] Archivo corrupto descargado como malware_demo.bin
[!] (Simulación) Ejecutando archivo descargado... (solo demo, no hace nada peligroso)
```

### Archivos Generados

Después de ejecutar la demo, encontrarás:

```
c:\Users\ual\P4YM3PLZ\P4YM3PLZ\
├── ca_private_key.pem       # Clave privada de CA (SECRETO)
├── ca_public_key.pem        # Clave pública de CA (se distribuye)
├── app_legitima.bin         # Aplicación descargada (servidor bueno)
├── malware_demo.bin         # "Malware" descargado (servidor falso)
└── run_demo.log             # Log de ejecución de run_demo.py
```

### Troubleshooting

**Problema 1**: "No se puede cargar Activate.ps1 porque la ejecución de scripts está deshabilitada"

**Solución**: No actives el venv; ejecuta python directamente con ruta completa:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe script.py
```

**Problema 2**: "ModuleNotFoundError: No module named 'cryptography'"

**Solución**: Instala la dependencia:
```bash
C:/Users/ual/P4YM3PLZ/P4YM3PLZ/.venv/Scripts/python.exe -m pip install cryptography
```

**Problema 3**: "OSError: [WinError 10048] Solo se permite un uso de cada dirección de socket..."

**Solución**: Los puertos 4443/4444 están ocupados. Usa `run_demo.py` que elige puertos libres automáticamente, o especifica puertos diferentes:
```bash
python server_good_rsa.py 55443
python server_fake_rsa.py 55444
```

**Problema 4**: No veo salida en consola

**Solución**: Revisa `run_demo.log`:
```bash
type run_demo.log
```

---

## Código Criptográfico Relevante

### 1. Generación de Claves CA ([ca_rsa.py](ca_rsa.py))

```python
def _generate_and_persist_ca():
    """Genera par RSA-2048 y persiste en archivos PEM."""
    # Generar claves
    priv = rsa.generate_private_key(
        public_exponent=65537,  # Exponente estándar (F4)
        key_size=2048,          # 2048 bits (≈112 bits de seguridad)
    )
    pub = priv.public_key()
    
    # Serializar a PEM (formato estándar)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    # Guardar a disco
    with open("ca_private_key.pem", "wb") as f:
        f.write(priv_pem)
    with open("ca_public_key.pem", "wb") as f:
        f.write(pub_pem)
    
    return priv, pub
```

**Notas de seguridad**:
- `NoEncryption()`: Clave privada se guarda sin contraseña (en entorno de desarrollo).
- En producción: usar `BestAvailableEncryption(password)`.
- Claves privadas NO deben versionarse en git.

### 2. Firmado de Certificado ([ca_rsa.py](ca_rsa.py))

```python
def sign(data: bytes) -> bytes:
    """Firma datos con RSA-PSS + SHA-256.
    
    Args:
        data: Datos a firmar (identity + public_key_pem + ca_name)
    
    Returns:
        Firma de 256 bytes (2048 bits RSA)
    
    Raises:
        Excepción si la clave privada no está disponible.
    """
    return ca_private_key.sign(
        data,
        # Esquema PSS: probabilístico, resistente a ataques
        padding.PSS(
            # MGF1: Mask Generation Function con SHA-256
            mgf=padding.MGF1(hashes.SHA256()),
            # Salt máximo: longitud = tamaño de hash (32 bytes)
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        # Función hash: SHA-256 (segura, 256 bits de salida)
        hashes.SHA256(),
    )
```

**¿Por qué PSS y no PKCS#1 v1.5?**
- PSS es **probabilístico**: cada firma es única (gracias al salt).
- PKCS#1 v1.5 es **determinístico**: mismos datos = misma firma.
- PSS es resistente a **ataques de adaptación de ciphertext**.

### 3. Verificación de Firma ([ca_rsa.py](ca_rsa.py))

```python
def verify(data: bytes, signature: bytes) -> bool:
    """Verifica firma RSA-PSS + SHA-256.
    
    Args:
        data: Datos originales (identity + public_key_pem + ca_name)
        signature: Firma a verificar (256 bytes)
    
    Returns:
        True si firma válida, False si inválida.
    """
    try:
        # verify() lanza excepción si la firma NO es válida
        ca_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,  # Debe coincidir con sign()
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        # Cualquier excepción = firma inválida
        return False
```

**Flujo de verificación interno** (simplificado):
1. Usa clave pública de CA.
2. Desencripta firma con clave pública.
3. Extrae hash y salt.
4. Recalcula hash de datos originales.
5. Compara: hash_original == hash_recalculado.
6. Si coinciden → ✓ Válido; si no → ✗ Inválido.

### 4. Creación de Certificado ([server_good_rsa.py](server_good_rsa.py))

```python
def create_cert(identity: str, public_key_pem: bytes) -> dict:
    """Crea certificado firmado por CA.
    
    Args:
        identity: Nombre del servidor (e.g., "www.bueno.com")
        public_key_pem: Clave pública en PEM (bytes)
    
    Returns:
        Diccionario con certificado completo.
    """
    # Reconstruir datos a firmar (mismo orden que en cliente)
    to_sign = identity.encode() + public_key_pem + CA_NAME.encode()
    
    # Solicitar firma a CA
    signature = sign(to_sign)  # Llama a ca_rsa.sign()
    
    # Retornar estructura de certificado
    return {
        "identity": identity,
        "public_key_pem": public_key_pem.decode(),  # Base64 en JSON
        "ca_name": CA_NAME,
        "signature": signature.hex(),  # Convertir bytes a hexadecimal
    }
```

**Orden importante**: identity + public_key_pem + ca_name debe ser **idéntico** en firma y verificación.

### 5. Verificación de Certificado ([client_rsa.py](client_rsa.py))

```python
def comprobar_cert(cert: dict, host_esperado: str) -> bool:
    """Verifica certificado recibido del servidor.
    
    Args:
        cert: Diccionario JSON con certificado.
        host_esperado: Host esperado (e.g., "www.bueno.com")
    
    Returns:
        True si certificado es válido y confiable, False en caso contrario.
    """
    # PASO 1: Verificar identidad
    if cert.get("identity") != host_esperado:
        print("[!] Identidad del certificado NO coincide con el host esperado.")
        return False
    
    # PASO 2: Verificar que CA es de confianza
    if cert.get("ca_name") != CA_NAME:
        print("[!] CA del certificado NO está en el almacén de confianza.")
        return False
    
    # PASO 3: Verificar firma digital
    public_key_pem = cert["public_key_pem"].encode()
    firma = bytes.fromhex(cert["signature"])  # Convertir hex a bytes
    
    # Reconstruir datos (debe coincidir con servidor)
    to_verify = cert["identity"].encode() + public_key_pem + cert["ca_name"].encode()
    
    # Llamar a verificador de CA
    if not verify(to_verify, firma):  # Llama a ca_rsa.verify()
        print("[!] Firma RSA inválida: el certificado puede ser falso o manipulado.")
        return False
    
    print("[+] Certificado válido: identidad y firma correctas.")
    return True
```

### 6. Comunicación Cliente-Servidor (Resumen)

**Servidor enviando certificado** ([server_good_rsa.py](server_good_rsa.py)):
```python
cert_text = json.dumps(cert)
conn.sendall((cert_text + "\n").encode())  # Enviar como línea JSON
```

**Cliente recibiendo y verificando** ([client_rsa.py](client_rsa.py)):
```python
def recibir_linea(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode().strip()

cert_text = recibir_linea(s)
cert = json.loads(cert_text)
if not comprobar_cert(cert, "www.bueno.com"):
    # Certificado no válido
    pass
```

---

## Bibliografía y Librerías

### Librerías Utilizadas

#### 1. **cryptography** (versión 41.0.0+)
**Propósito**: Implementación de primitivas criptográficas.

**Características utilizadas**:
- `cryptography.hazmat.primitives.asymmetric.rsa`: Generación de claves RSA.
- `cryptography.hazmat.primitives.asymmetric.padding`: Esquemas PSS.
- `cryptography.hazmat.primitives.hashes`: SHA-256.
- `cryptography.hazmat.primitives.serialization`: Conversión PEM.

**Instalación**:
```bash
pip install cryptography
```

**Documentación**: https://cryptography.io/

#### 2. **socket** (Librería Estándar Python)
**Propósito**: Comunicación TCP/IP cliente-servidor.

**Características**:
- `socket.socket()`: Crear socket TCP/IP.
- `socket.bind()`: Ligar a puerto.
- `socket.connect()`: Conectar a servidor remoto.
- `socket.recv()` / `socket.sendall()`: Enviar/recibir datos.

#### 3. **json** (Librería Estándar Python)
**Propósito**: Serialización de certificados.

**Características**:
- `json.dumps()`: Convertir dict → JSON string.
- `json.loads()`: Convertir JSON string → dict.

#### 4. **subprocess** (Librería Estándar Python)
**Propósito**: Lanzar procesos servidores desde `run_demo.py`.

#### 5. **threading** (Librería Estándar Python)
**Propósito**: Lectura no-bloqueante de stdout de servidores.

#### 6. **logging** (Librería Estándar Python)
**Propósito**: Registrar eventos en archivo y consola.

### Referencias Académicas y Estándares

#### 1. **PKCS #1: RSA Cryptography Standard**
- **RFC 3447** (https://tools.ietf.org/html/rfc3447)
- Define RSA-PSS, RSA-OAEP, y operaciones RSA.
- Obligatorio para cualquier implementación seria de RSA.

#### 2. **FIPS 180-4: Secure Hash Standard (SHS)**
- **NIST** (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- Define SHA-1, SHA-224, SHA-256, SHA-384, SHA-512.
- SHA-256 es ampliamente usado en certificados y firmas.

#### 3. **FIPS 186-4: Digital Signature Standard (DSS)**
- **NIST** (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- Define estándares de firma digital (RSA-PSS, ECDSA, DSA).

#### 4. **X.509: Public Key Infrastructure**
- **ITU-T Recommendation X.509** (https://www.itu.int/rec/T-REC-X.509/en)
- Define estructura de certificados digitales.
- Implementación simplificada en esta aplicación (no es X.509 completo).

#### 5. **TLS 1.3 (RFC 8446)**
- **IETF** (https://tools.ietf.org/html/rfc8446)
- Estándar de protocolo seguro de transporte.
- Usa certificados X.509 y RSA para autenticación.
- Referencia para handshake cliente-servidor.

### Libros Recomendados

1. **"Handbook of Applied Cryptography"** - Menezes, van Oorschot, Vanstone
   - Capítulo 11: Digital Signatures
   - Capítulo 8: Public-Key Cryptosystems
   - Disponible online: https://cacr.uwaterloo.ca/hac/

2. **"Cryptography Engineering"** - Ferguson, Schneier, Kohno
   - Capítulo 21: Keys and Key Management
   - Excelente para entender cadenas de confianza.

3. **"Understanding Public Key Infrastructure"** - Housley, Ford
   - Dedicado completamente a PKI.
   - Modelos de confianza, ciclo de vida de certificados.

### Ataques Relevantes (Para Contexto de Seguridad)

#### 1. **Man-in-the-Middle (MITM) sin certificados**
- **Riesgo**: Atacante intercepta tráfico y se hace pasar por servidor legítimo.
- **Solución**: Certificados digitales verificables.
- **Mitigación en esta app**: Cliente rechaza certificados no confiables.

#### 2. **Suplantación de Identidad (Identity Spoofing)**
- **Riesgo**: Certificado falso con identidad falsificada.
- **Solución**: Verificar campo "identity" vs. host esperado.
- **Mitigación**: `comprobar_cert()` verifica identidad.

#### 3. **Falsificación de Firma**
- **Riesgo**: Atacante modifica certificado pero mantiene firma antigua (imposible sin clave privada CA).
- **Solución**: Firma RSA-PSS es inmutable sin privada.
- **Mitigación**: Cualquier cambio en certificado invalida firma.

#### 4. **Replay Attack**
- **Riesgo**: Atacante reenvía certificado anterior.
- **Nota**: No es completamente mitigado en esta app simple (requiere timestamp/nonce).

### Recursos Online

- **Cryptography.io Tutorials**: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- **OpenSSL Documentation**: https://www.openssl.org/docs/man1.1.1/
- **IETF RFC 3447 (PKCS #1)**: https://tools.ietf.org/html/rfc3447
- **Mozilla Security Guidelines**: https://infosec.mozilla.org/guidelines/web_security/

---

## Conclusión

Esta aplicación implementa un **sistema educativo completo de PKI** demostrando:

✅ **Autenticación de servidor**: Certificados verificables.
✅ **Firma digital**: RSA-PSS garantiza integridad e inmutabilidad.
✅ **Confianza basada en CA**: Modelo jerárquico de confianza.
✅ **Advertencia de riesgo**: Cliente alerta usuario de certificados inválidos.
✅ **Demostración interactiva**: Escenarios bueno vs. falso.

**Propósito educativo**: Entender los fundamentos de criptografía asimétrica, certificados digitales, y protocolos de autenticación usados en TLS/HTTPS, VPN, y otras aplicaciones de seguridad.

---

**Documento generado**: 13 de Diciembre, 2025
**Versión**: 1.0
**Autores**: Sistema P4YM3PLZ - Módulo de Certificados RSA
