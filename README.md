Poc for CVE 2019-20372 
# m10sec@proton.me
Description

NGINX before 1.17.7, with certain error_page configurations, allows HTTP request smuggling, as demonstrated by the ability of an attacker to read unauthorized web pages in environments where NGINX is being fronted by a load balancer.

# CVE-2019-20372 Exploiter

Este script en Python está diseñado para realizar una serie de pruebas de seguridad en un servidor web con el objetivo de detectar la vulnerabilidad **CVE-2019-20372** en servidores que ejecutan una versión vulnerable de **Nginx** (1.14.2). Además, el script verifica los encabezados HTTP, los métodos permitidos y realiza un intento de explotación.

## Funciones

1. **Obtener los encabezados HTTP**:
   - Realiza una solicitud GET al servidor y muestra los encabezados HTTP obtenidos.
   
2. **Verificar la versión de Nginx**:
   - Revisa si el servidor está utilizando **Nginx** y extrae su versión desde el encabezado `Server`.
   - Si la versión es **1.14.2**, la vulnerabilidad **CVE-2019-20372** podría estar presente.
   
3. **Comprobar los métodos HTTP permitidos**:
   - Realiza una solicitud OPTIONS para verificar los métodos HTTP permitidos por el servidor.

4. **Intentar explotar la vulnerabilidad CVE-2019-20372**:
   - Si el servidor es vulnerable, intenta cargar un archivo PHP malicioso para ejecutar código en el servidor.

## Requisitos

- Python 3.x
- Paquete `requests` (Instalar usando `pip install requests`)

## Configuración

1. Modifique la variable `TARGET_URL` en el código con la URL del servidor objetivo.

   ```python
   TARGET_URL = "https://example.com"
