# PRÁCTICA 3 - Seguridad Informática

DEFENSA: Día 9 de diciembre, las máquinas de apagan el 5 de diciembre a las 10.

**Objetivo**: El objetivo de esta práctica es comprender la importancia de los algoritmos criptográficos, el uso de autoridades de certificación y su aplicación-funcionamiento en la forma de protocolos seguros. También se abordará el proceso de análisis de vulnerabilidades en el contexto de los procesos de auditoría de seguridad. Se deberán aplicar los conceptos adquiridos en la resolución de los siguientes apartados.

No se hacen los apartados 4, 5 y 7. El 8 lo haremos sobre nuestra máquina local (no la de debian).
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

> Fingerprinting al conectarse a SSH. Nuestro portátil almacena la clave publica del servidor de la máquina a la que nos conectamos. Lo mismo sucede a la inversa con la máquina conectada.
 1-Crear claves: ssh_keygen  ||  2-Fichero ~/.ssh / id_rsa -> id_rsa_pub || 3-Pasar el pub a ssh_know_hosts -> ssh-copy-id (mejor que no). Copiarlo uno tras otro con cat.


> Servicio tunelizado: ssh -L |  ssh -R
> Redirigir el tráfico por el túnel. Hay que poder leer el contenido. Usar w3m por ejemplo

<br>

### **Abra un shell remoto sobre SSH y analice el proceso que se realiza. Configure su fichero `ssh_known_hosts` para dar soporte a la clave pública del servidor.**

La primera vez que hicimos ssh en nuestra máquina, SSH me mostró la huella digital del servidor para verificar si era un servidor de confianza. Tras escribir yes, la clave pública del servidor quedó registrada automáticamente en el fichero: **~/.ssh/known_hosts**.

Si comprobamos este fichero podemos ver varias entradas correspondientes a las claves de los servidores a los que me había conectado, por ejemplo:
```
root@ismael:/home/lsi# cat ~/.ssh/known_hosts
|1|yZgB3bVWjT5r6vwNYuDDV+Z3Wys=|ns6TEsI6/teQh0aXyblieyDJ5SY= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHxap0jrffRhOxCpw2jMHa8GOXGBYdWlgAI6t/1k8PU2QY9LwAxFsanaqqJDxBCLPz+2mbL9iL+3LDAkM25fCHA=
|1|IU47K8eJb1EadlZ4tnDRB8zfgkw=|GBNEPef5n16tlW9OcDsQUjvhjFA= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBbzgxstUBFoN/nL6o/bvbUpY+V3mhCswj814PQ4KUw
|1|gaeQ15WhRm59JQhpcNydi7Kt6pA=|eAIbv2XynXh40XYsEAaGLHTMOhI= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKCWYjYaCSeq83uXokTbDJjRsrRcSxJyLdIJXvj49dE
|1|OkgA08Y6ISB6qugj6PPlaY3jU0M=|OCfo5pPBtJ3t1cutQ/IF03gjN9U= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoDTj/m8jgZwlw4Hve9sJik9UlyH0FWX9aQonh8HQe0nJYbxyvZRhzxJFGYHMy2WvrShmoLNNI1mJ9HpPx8MwpkfQ0dG+bwuH2z+MLDtvJZ0kj2kmDg7LLq0zaMQc5VmhhnIjJhwXgidueTspjulepRnkNzETrabvBLoteJcbDfFF78Qu/GR55GUdmYtDx3pqIKs+eeSxEGSIKhUOJJ8FHMZ346Q+f55q+rE2MxE5eIb8f4n+Br56DleHnApKnyBznPYh3P/sZfrX5PbezYMasjleVnUtBIB9yVjG5jHLGMfTRvwicjLKPma8ereryU49GgvQReAcIom5/8swe4W2/
|1|m+WpvDqtwqShqHbcJohbKPp4M1Y=|o0HfS6UPDxsrfZ87+UxPEOlFxkU= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHk2d8XZfabnw9drZRPK8Id1SxebO9+zglUeKnROEOA6i5D3VIqAUKGYSXXj6VRmmP5zYCnw8RiKoJtRna+yrHM=
|1|q6zUCwcNbtC117SaS/YidcHdTYU=|C1wAKc3QKxQi45Y63bnOvLDAMlo= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEj1jYLvZ0f9YhiWNnrwWdiFMSe0H8J8tbnvhtn5/A5z
|1|dsY+RjIilovVK+qSWVqTCgof1N8=|CU+5d88EtGubMrucYdi5j8qWTRY= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEj1jYLvZ0f9YhiWNnrwWdiFMSe0H8J8tbnvhtn5/A5z
```

Estas líneas representan:

- La IP del servidor (en tu caso está hashed para privacidad)

- El tipo de clave del servidor (ecdsa, rsa, ed25519…)

- La clave pública de ese servidor



Para ver información de la conexión ssh:
```bash
ssh -v lsi@10.11.48.202
```

Se puede ver información más detallada usando el triple verbose: -vvv:
```bash
ssh lsi@10.11.48.202 -vvv
```

Para el intercambio de clave se suele usar Diffie-Hellman y AES y para la autenticación, RSA o ECDSA.

En mi casi puedo ver el siguiente fingerprinting:
```bash
Server host key: ssh-ed25519 SHA256:OhY0UAaohSTRmdVmiu0wj8i8Nr9mAMW0C0ffMf+nT7g
```

En esta información podemos ver el fingerprinting actual. Podemos comprobar que se guardó ese fingerprinting en nuestra máquina con:
```
root@ismael:/home/lsi# ssh-keyscan 10.11.48.202 | ssh-keygen -lf -
# 10.11.48.202:22 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
# 10.11.48.202:22 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
# 10.11.48.202:22 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
# 10.11.48.202:22 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
# 10.11.48.202:22 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
2048 SHA256:7HISk3CQ5KbIPPEiJ9sQ5MfyVnkU6IQT1bzpXiCpAUo 10.11.48.202 (RSA)
256 SHA256:7EACNFggkXw/2AMjotj6tYnlT1bW3vmLB+nG09BqSdo 10.11.48.202 (ECDSA)
256 SHA256:OhY0UAaohSTRmdVmiu0wj8i8Nr9mAMW0C0ffMf+nT7g 10.11.48.202 (ED25519)
```


**Añadir la clave pública del servidor en ssh_known_hosts**:

Para ello:

1-Creamos el archivo nuevo de ssh_known_hosts en etc:
```bash
touch /etc/ssh/ssh_known_hosts
```

Esto crea un fichero vacío donde el administrador puede guardar claves de servidores confiables para todos los usuarios. Es como una lista “oficial” de hosts confiables para SSH. A diferencia de ~/.ssh/known_hosts que es por usuario, este fichero afecta a todos los usuarios del sistema.


2-Añadir la clave pública del servidor a ese fichero global:
```bash
ssh-keyscan 10.11.48.175 >> /etc/ssh/ssh_known_hosts
```

ssh-keyscan obtiene la clave pública del servidor sin necesidad de conectarse interactivo. Con >> la añadimos al fichero global /etc/ssh/ssh_known_hosts. Esto permite que cualquier usuario pueda conectarse a ese servidor sin que SSH pregunte por su huella digital.


3-Limpiar el fichero known_hosts del usuario:
```
echo "" > /home/lsi/.ssh/known_hosts
```
Borra el contenido del fichero personal ~/.ssh/known_hosts. Esto se hace para simular la primera conexión, donde SSH aún no conoce la clave del servidor.

Comprobar que está vacío desde el user lsi, no desde root:
```bash
lsi@ismael:~$ cat /home/lsi/.ssh/known_hosts

lsi@ismael:~$
```

Para probar:

- Conectarse al ssh de forma normal y ahora SSH no encuentra la clave en el fichero personal, pero sí la encuentra en /etc/ssh/ssh_known_hosts.
Por eso no te pide confirmar el fingerprint, aunque sea la primera conexión desde este usuario.
```bash
lsi@ismael:~$ ssh lsi@10.11.48.175
lsi@10.11.48.175's password:
```

<br>

### **Haga una copia remota de un fichero utilizando un algoritmo de cifrado determinado. Analice el proceso que se realiza.**

>Cipher es un algortimo de cifrado simétrico y asimétricos que se utilizan para establecer una conexión segura entre hosts.

- Para ver los algoritmos de cifrado disponibles en la máquina -> ssh -Q cipher:
```bash
root@ismael:/home/lsi# ssh -Q cipher
3des-cbc
aes128-cbc
aes192-cbc
aes256-cbc
aes128-ctr
aes192-ctr
aes256-ctr
aes128-gcm@openssh.com
aes256-gcm@openssh.com
chacha20-poly1305@openssh.com
```


- Para ver la lista de los algoritmos que se aplican por defecto, haciendo ssh -vv lsi@x.x.x.x veremos estas dos lineas indicando los algoritmos por defecto:
```bash
  debug2:ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
  debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com

  ---------
  ciphers ctos -> algoritmos cifrados que o cliente (ctos) está disposto a utilizar durante a negociación da conexión SSH
  ciphers stoc -> algoritmos cifrados que o servidor (stoc) acepta durante a negociación.
```

Ahora vamos a crear un documento y subirlo al servidor remoto (la máquina del compañero):

1-Crear documento:
```bash
touch documento.txt
```

Podemos escribir algo con:
```bash
nano documento.txt
```

2-Enviar al servidor con un tipo de cifrado de los vistos antes:
```bash
scp -c aes256-ctr documento.txt lsi@10.11.48.175:/home/lsi/
```


3-Verificar la copia en el servidor remoto. Acceder a la máquina y ver que se encuentra el archivo documento.txt

<br>

**Qué sucede durante la copia**

Cuando ejecutamos el comando:

1-Establecimiento de la conexión SSH:

- Se realiza la autenticación del servidor mediante el fingerprint que vimos antes.

- Se negocia un algoritmo de cifrado, MAC y compresión (en este caso AES-256-CTR).


2-Cifrado de datos:

- Todo el tráfico de la sesión (el contenido del archivo) se cifra usando AES-256-CTR.

- Esto protege la información mientras viaja por la red, impidiendo que alguien pueda leerlo aunque capture los paquetes.


3-Transmisión de datos:

- El archivo se envía bloque a bloque cifrado.

- La integridad se verifica mediante MAC (Message Authentication Code) para asegurarse de que no se ha corrompido durante el envío.

4- Recepción y almacenamiento en destino:

- El servidor descifra los bloques recibidos.

- Se escribe el archivo en la ubicación remota /home/lsi/documento.txt.

<br>

**Analizar la seguridad**

1- Cifrado AES-256-CTR:

- AES-256 → clave de 256 bits, muy segura.

- CTR (Counter mode) → cifra cada bloque de manera independiente, eficiente para transferencia de datos.


2- Integridad de los datos:

- Se utiliza MAC para detectar cualquier modificación o corrupción de los datos durante el tránsito.


3- Autenticación del servidor:

- Gracias a la clave pública registrada en known_hosts o ssh_known_hosts, se evita conectarse a un servidor falso (ataque man-in-the-middle).


<br>

## **Configure su cliente y servidor para permitir conexiones basadas en un esquema de autenticación de usuario de clave pública.**

>Esta parte la haremos toda desde el user lsi y no root.

>Los dos tenemos qe probar a ser clientes y servidores.

>Para comprobar que lo hemos hecho bien tenemos que poder entrar en la máquina del compañero sin contraseña.



1-Descomentamos la línea PubKeyAuthentication = yes en /etc/ssh/sshd_config.

**SOLO ESTA PARTE SE HACE DESDE ROOT!!!**

2-El cliente realizará los siguientes pasos:

a. Creamos la clave para la conexión. Ponemos todo por defecto, pero nos aseguramos de que se guarde en /home/lsi/.ssh. Se nos generarán dos claves: la pública y la privada.

```bash
ssh-keygen -t rsa
```


b. Le envíamos la clave pública a nuestro compañero y se la metemos en /home/lsi/.ssh.

- Usar scp:

```bash
scp /home/lsi/.ssh/id_rsa.pub lsi@10.11.48.175:./.ssh/id_rsa.pub
```

- Usar ssh-copy-id
```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub lsi@10.11.48.175
```

3-El servidor realizará los siguientes pasos:

a. Acceder a la ruta donde se envió:
```bash
cd /home/lsi/.ssh.
```

b. Copiamos la clave en el fichero authorized_keys. Si no lo tenemos creado, al ejecutar el comando se creará automáticamente.
```bash
 cat id_rsa.pub >> authorized_keys
```

c. Opcional pero recomendable: Borramos la clave con:
```bash
rm id_rsa.pub.
```


4-Para comprobar que funciona: El cliente, desde lsi, hará ssh:
```bash
lsi@10.11.48.SERVER y podrá entrar sin meter la contraseña.
```

5. Conceptos teóricos:

- a. KEX: Key Exchange

- b. SSH_MSG_KEXINIT: Algoritmo para crear una clave de sesión
(RSA, Diffie Hellman, etc.).

- c. SSH_KEX_ALG: Algoritmo para identificarse y comprobar que
el servidor es quién dice ser.


6. ¿Cómo funciona?:

El servidor cifra su clave privada con un token, el cliente lo descifra con su clave pública. Si en el token viene la identidad correcta, el único que tiene esa clave privada para haberlo cifrado es el servidor, por tanto comprobamos que es él de verdad.

<br>



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


Hacer sobre nuestra propio ordenador, no la máquina de debian.
