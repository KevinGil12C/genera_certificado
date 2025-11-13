# Documentación: Generador de Certificados SSL/TLS

## 📄 Descripción

Este script Python genera un certificado SSL/TLS auto-firmado junto con su clave privada correspondiente, utilizando criptografía asimétrica RSA. Es ideal para entornos de desarrollo, pruebas o aplicaciones internas.

## 🛠️ Características

- **Generación de claves RSA** 2048 bits
- **Certificado auto-firmado** válido por 365 días
- **Protección con contraseña** para la clave privada
- **Formato PEM** estándar de la industria
- **Personalización** con datos del usuario

## 📋 Requisitos

### Dependencias
```bash
pip install cryptography
```

### Versiones Compatibles
- Python 3.7+
- cryptography 3.0+

## 🚀 Uso Rápido

### Ejecución Básica
```bash
python generate_certificate.py
```

### Flujo de Ejecución
1. **Solicita información personal**:
   - Nombre completo
   - Apodo
   - Nombre favorito
   - Contraseña para la clave privada

2. **Genera los archivos**:
   - `certificado.pem` - Certificado público
   - `clave_privada.pem` - Clave privada protegida

## 📁 Archivos Generados

### certificado.pem
```pem
-----BEGIN CERTIFICATE-----
... (certificado en base64) ...
-----END CERTIFICATE-----
```

### clave_privada.pem
```pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
... (clave privada encriptada en base64) ...
-----END ENCRYPTED PRIVATE KEY-----
```

## 🔧 Configuración Técnica

### Parámetros de Generación
| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Algoritmo | RSA-2048 | Clave asimétrica |
| Exponente | 65537 | Exponente público estándar |
| Hash | SHA-256 | Algoritmo de firma |
| Validez | 365 días | Duración del certificado |
| Formato | PKCS#8 | Estándar moderno para claves |

### Estructura del Certificado
```python
CertificateBuilder(
    issuer_name=subject,           # Auto-firmado
    subject_name=subject,          # Información del usuario
    public_key=public_key,         # Clave pública RSA
    serial_number=random,          # Número serial único
    not_valid_before=now,          # Fecha de inicio
    not_valid_after=now+365d       # Fecha de expiración
)
```

## 🔒 Seguridad

### Características de Seguridad
- **Clave privada encriptada** con contraseña
- **Algoritmo PKCS#8** para mejor seguridad
- **SHA-256** para integridad de firma
- **Serial number aleatorio** para evitar colisiones

### Mejores Prácticas
1. **Contraseña fuerte** para la clave privada
2. **Almacenamiento seguro** de los archivos generados
3. **Rotación periódica** en entornos productivos
4. **Uso limitado** a desarrollo y pruebas

## 🎯 Casos de Uso

### Desarrollo Web
```bash
# Uso con servidores web locales
python generate_certificate.py
# Configurar en Apache/Nginx con los archivos generados
```

### Aplicaciones Python
```python
from cryptography.hazmat.primitives import serialization

# Cargar certificado para servidor Flask/Django
with open("certificado.pem", "rb") as cert_file:
    certificate = x509.load_pem_x509_certificate(cert_file.read())

# Cargar clave privada
with open("clave_privada.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b'your_password'
    )
```

### Docker/Contenedores
```dockerfile
COPY certificado.pem /etc/ssl/certs/
COPY clave_privada.pem /etc/ssl/private/
```

## ⚠️ Limitaciones y Consideraciones

### Certificados Auto-Firmados
- **No son de confianza pública** - Navegadores mostrarán advertencias
- **Solo para entornos controlados** - No usar en producción pública
- **Requieren instalación manual** en el almacén de confianza del cliente

### Alternativas para Producción
- **Let's Encrypt** - Certificados gratuitos y confiables
- **Certificados comerciales** - Para aplicaciones empresariales
- **AC interna** - Para redes corporativas

## 🔍 Solución de Problemas

### Errores Comunes

#### "ModuleNotFoundError: No module named 'cryptography'"
```bash
# Solución: Instalar la dependencia
pip install cryptography
```

#### "Password must be 1 or more bytes"
```bash
# Solución: Asegurar que la contraseña no esté vacía
Ingrese una contraseña para la clave privada: [contraseña válida]
```

#### Problemas de Permisos
```bash
# En sistemas Unix/Linux
chmod 600 clave_privada.pem
chmod 644 certificado.pem
```

### Verificación de Archivos
```bash
# Verificar certificado
openssl x509 -in certificado.pem -text -noout

# Verificar clave privada
openssl rsa -in clave_privada.pem -check
```

## 📚 Ejemplos de Uso Avanzado

### Integración con Flask
```python
from flask import Flask
import ssl

app = Flask(__name__)

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('certificado.pem', 'clave_privada.pem')

if __name__ == '__main__':
    app.run(ssl_context=context, port=443)
```

### Uso con requests
```python
import requests

# Para testing con certificados auto-firmados
response = requests.get(
    'https://localhost:443',
    verify='certificado.pem'  # Ruta al certificado
)
```

## 🔄 Extensión del Script

### Personalización Avanzada
```python
# Agregar más atributos al certificado
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mi Empresa"),
    x509.NameAttribute(NameOID.COMMON_NAME, nombre),
])

# Extender validez
not_valid_after=now + datetime.timedelta(days=730)  # 2 años
```

### Generación por Lotes
```python
def generate_multiple_certificates(users_data):
    for user in users_data:
        # Lógica de generación para cada usuario
        pass
```

## 📊 Comparativa de Formatos

| Formato | Ventajas | Desventajas |
|---------|----------|-------------|
| PKCS#8 | Moderno, más seguro | Menor compatibilidad con sistemas antiguos |
| TraditionalOpenSSL | Mayor compatibilidad | Menos seguro |

## 🤝 Contribuciones

Las mejoras son bienvenidas:
1. Agregar soporte para más algoritmos (ECDSA)
2. Implementar revocación de certificados
3. Agregar interfaz gráfica
4. Soporte para múltiples formatos de salida

## 📄 Licencia

Este script se proporciona bajo licencia MIT. Úselo responsablemente.

---

**⚠️ Advertencia de Seguridad**: Los certificados auto-firmados no deben usarse en entornos de producción pública. Siempre use certificados de autoridades certificadas confiables para aplicaciones en producción.
