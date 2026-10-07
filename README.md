# TechStore

Aplicación local de gestión de inventario para el laboratorio de Desarrollo de Soluciones en la Nube.

## Funcionalidades

- Registro con correo único y contraseña de al menos 8 caracteres, mayúscula, número y carácter especial.
- Inicio de sesión con contraseña y bloqueo de 15 minutos tras 5 intentos fallidos.
- Inicio de sesión con Google y GitHub mediante OAuth, sujeto a configurar los proveedores.
- Verificación TOTP de 6 dígitos cada 30 segundos, con máximo 3 intentos por desafío.
- JWT firmado y sesiones en cookies HttpOnly después de completar MFA.
- Perfiles Administrador, Gerente, Empleado y Auditor, con permisos comprobados en el servidor.
- Autenticador local con cuentas cifradas mediante AES-GCM y una contraseña derivada con PBKDF2.
- Diseño adaptable con iconos de Google y GitHub y fondo animado en todas las pantallas.

## Ejecutar

Requiere Python 3.10 o posterior. No necesita instalar paquetes de Python adicionales.

```sh
python server.py
```

Abre http://127.0.0.1:8765/ en el navegador. El servidor escucha únicamente en el equipo local. Al iniciar crea su base SQLite, la clave de firma y productos de ejemplo. Las cuentas se registran desde la aplicación; no hay contraseñas predeterminadas.

## Google y GitHub

Abre http://127.0.0.1:8765/configurar e introduce los ID y secretos de tus propias aplicaciones OAuth.

| Proveedor | Dirección de retorno |
| --- | --- |
| Google | `http://127.0.0.1:8765/auth/google/callback` |
| GitHub | `http://127.0.0.1:8765/auth/github/callback` |

Para Google utiliza un cliente de tipo Aplicación web. Si el consentimiento está en modo de prueba, agrega el usuario correspondiente. En GitHub configura la página principal como `http://127.0.0.1:8765`.

Las claves se guardan en `oauth-config.json`, excluido del repositorio. `oauth-config.example.json` muestra únicamente los nombres de los campos. La aplicación no vincula automáticamente cuentas de distintos proveedores que comparten el mismo correo.

## Autenticador y siguientes accesos

1. Inicia sesión y copia la clave de configuración mostrada durante el alta de MFA.
2. Abre http://127.0.0.1:8765/autenticador en el mismo navegador.
3. Introduce un nombre para la cuenta, su clave y una contraseña para proteger el autenticador.
4. Pulsa **Guardar cuenta y mostrar código**. Usa el código para completar el acceso.
5. En visitas posteriores desbloquea el autenticador, elige la cuenta y copia el nuevo código.

Cada cuenta tiene su propia clave. Las cuentas cifradas quedan en el almacenamiento de ese navegador y dirección. Borrar sus datos elimina ese almacenamiento. La contraseña del autenticador no se envía al servidor ni puede recuperarse desde él.

## Roles

Las cuentas nuevas reciben el rol Empleado. En un entorno nuevo, el propietario puede asignar el primer administrador con SQLite; las cuentas y roles de la sesión original no se publican. Un administrador autenticado puede gestionar después los roles desde la interfaz.

## Alcance

Proyecto de práctica local; no está preparado para exponerlo como servicio público. La configuración de proveedores y la consulta de evidencias son herramientas locales. Un despliegue público necesita endurecimiento adicional, HTTPS y controles administrativos para esas rutas.

Las evidencias y registros de ejecución se generan en cada entorno y no forman parte de este repositorio. La ruta `/evidencias` muestra resultados cuando existe `results.json`.

## Archivos privados excluidos

No se incluyen credenciales OAuth, claves de firma, base de datos, sesiones, contraseñas, semillas MFA ni cuentas personales. El fondo visual fue generado con IA para este proyecto.
