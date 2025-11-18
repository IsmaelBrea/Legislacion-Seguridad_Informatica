# PRÁCTICA 3 - Seguridad Informática

DEFENSA: Día 9 de diciembre, las máquinas de apagan el 5 de diciembre a las 10.

**Objetivo**: El objetivo de esta práctica es comprender la importancia de los algoritmos criptográficos, el uso de autoridades de certificación y su aplicación-funcionamiento en la forma de protocolos seguros. También se abordará el proceso de análisis de vulnerabilidades en el contexto de los procesos de auditoría de seguridad. Se deberán aplicar los conceptos adquiridos en la resolución de los siguientes apartados.
<br>


Eliminar servicios y aplicaciones anteriores: metasploit, arpon, grafana etc. Dejar solo alguno inseguro para securizar nosotros.

<br>

## **Apartado 1: SSH**
Tomando como base de trabajo el SSH pruebe sus diversas utilidades:

- **Abra un shell remoto sobre SSH y analice el proceso que se realiza. Configure su fichero `ssh_known_hosts` para dar soporte a la clave pública del servidor.**
- **Haga una copia remota de un fichero utilizando un algoritmo de cifrado determinado. Analice el proceso que se realiza.**
- **Configure su cliente y servidor para permitir conexiones basadas en un esquema de autenticación de usuario de clave pública.**
- **Mediante túneles SSH securice algún servicio no seguro.**
- **“Exporte” un directorio y “móntelo” de forma remota sobre un túnel SSH.**
- **Para plantear de forma teórica:** Securice su servidor considerando que únicamente dará servicio SSH para sesiones de usuario desde determinadas IPs.**

 <img width="757" height="304" alt="funcionamiento-ssh-pressroom-de-hostalia-hosting" src="https://github.com/user-attachments/assets/a246da89-ff0f-4ee1-9e6c-8c0820f469c9" />


Fingerprinting al conectarse a SSH. Nuestro portátil almacena la clave publica del servidor de la máquina a la que nos conectamos. Lo mismo sucede a la inversa con la máquina conectada.
1-Crear claves: ssh_keygen
2-Fichero ~/.ssh / id_rsa -> id_rsa_pub
3-Pasar el pub a ssh_know_hosts -> ssh-copy-id (mejor que no). Copiarlo uno tras otro con cat.


Servicio tunelizado:
ssh -L
ssh -R


Redirigir el tráfico por el túnel. Hay que poder leer el contenido. Usar w3m por ejemplo

---

## **Apartado 2: Servidor Apache2**
**Tomando como base de trabajo el servidor Apache2:**

- **Configure una Autoridad Certificadora en su equipo.**
- **Cree su propio certificado para ser firmado por la Autoridad Certificadora y fírmelo.**
- **Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL.**
  - **Nota: si la clave privada está cifrada en el arranque, su máquina le pedirá la frase de paso, pudiendo dejarla inaccesible desde su sesión SSH.**


Buscar entidad certificadora Debian 11/12
---

## **Apartado 3: openVPN**
**Configure una VPN entre dos equipos virtuales del laboratorio que garantice la confidencialidad de sus comunicaciones.**


Clave precompartida
---

## **Apartado 4: Autenticación en NTP**
En la Práctica 1 se configuró una infraestructura con servidores y clientes NTP.
Modifique la configuración para autenticar los equipos involucrados.

---

## **Apartado 5: Cifrado en servidores y clientes de log**
En la Práctica 1 se instalaron servidores y clientes de log.
Configure un esquema que permita cifrar las comunicaciones.

---

## **Apartado 6: Firewall Stateful**
**Cada máquina virtual será servidor y cliente de diversos servicios (NTP, syslog, ssh, web, etc.).Configure un **firewall stateful** adecuado a la situación actual de su máquina.**


Hacer un script -> son líneas que actúan como comandos. Si falla el script perdemos la conectividad de la máquina. Para probar hacer un reinicio reprogramado.
\bin\bash Programo reinicio dentro de 5 minutos


Poner toda la protección necesaria. Bloquear tráfico a todos los puertos y de todas las IPs no requeridas.

---

## **Apartado 7: Auditoría con Lynis**
**Ejecute la utilidad de auditoría de seguridad **Lynis** en su sistema e identifique:**

- **Las acciones de securización detectadas.**
- **Los consejos de mejora que se deberían aplicar.**

---

## **Apartado 8: Informe de análisis de vulnerabilidades**
**En la Práctica 2 se obtuvo un perfil de los principales sistemas de su red (puertos accesibles, fingerprinting, paquetería de red, etc.). Seleccione un subconjunto de máquinas del laboratorio y de la propia red y elabore un **informe de análisis de vulnerabilidades**.**

**Puede apoyarse en:**

- **Nessus Essentials**.
- **Greenbone Vulnerability Management (GVM)** como alternativa.

Referencias sugeridas:

- *Writing a Penetration Testing Report* (SANS Institute).
- Plantilla de vulnerabilityassessment.co.uk.


Hacer sobre nuestra propia máquina
