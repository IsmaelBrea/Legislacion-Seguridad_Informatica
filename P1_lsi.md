# PRÁCTICA 1 - Seguridad Informática

## Defensas
- Traer papel y boli.  
- Revisar siempre todo lo que aparezca en pantalla.  

---

## Redes
- **Eduroam**: no permitido el tráfico a los puertos 80 y 443.  
- **UDCDocencia**: no permitido el tráfico al puerto 22.  
- **VPN**:  
  - Se obtienen dos IPs:
    - Una IP de la red para conectarse a la máquina Debian. Esta IP puede cambiar porque la tabla de la VPN se va llenando.  
      **No usar una IP fija con los 4 octetos definidos.**  
    - Una IP propia de la máquina local.  
  - Ambas IPs son diferentes.  

**IP de los alumnos:** `10.11.48.0/23`  
- `/23` porque con `/24` no alcanzan las IPs para todos los alumnos.  
- `0` → IP de subred.  
- `1` → IP de gateway.  
- `255` → IP de broadcast.  

---

## Sistema Operativo
- Se comienza con **Debian 10**.  
- Actualizar sistema: 10 → 11 → 12.  
- Actualizar también el kernel a la versión 12.  
- Una vez actualizado, eliminar ficheros de las versiones 10 y 11.  
- **No se puede saltar directamente de Debian 10 a 12.**  
- Revisar los servicios activos para asegurar que no queda nada corriendo que no corresponda.  

---

## Usuarios
- Usuario inicial:  
  - `lsi2.3.1`  
  - IP: `10.11.48.74`  
  - Contraseña inicial: `virtualj..`  
  - Root: `lsi`  

- Usuario propio:  
  - `lsi2.3.4`  
  - IP: `10.11.48.169`  

Conexión por SSH:  
```bash
ssh lsi@10.11.48.169
```

Al conectarse por primera vez, se pide aceptar la huella digital (fingerprint).




Primeros pasos obligatorios
   Cambiar la contraseña del usuario lsi.
   
   Cambiar la contraseña del usuario root.

