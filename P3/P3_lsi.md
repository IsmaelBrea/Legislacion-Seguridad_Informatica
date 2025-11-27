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

> Esta parte la haremos toda desde el user lsi y no root.

> Los dos tenemos que probar a ser clientes y servidores.

> Para comprobar que lo hemos hecho bien tenemos que poder entrar en la máquina del compañero sin contraseña.



1-Descomentamos la línea PubKeyAuthentication = yes en /etc/ssh/sshd_config.

**SOLO ESTA PARTE SE HACE DESDE ROOT!!!**

<br>

2-El **cliente** realizará los siguientes pasos:

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

<br>

3-El **servidor** realizará los siguientes pasos:

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


4-Para comprobar que funciona: El **cliente**, desde lsi, hará ssh:
```bash
lsi@10.11.48.SERVER y podrá entrar sin meter la contraseña.
```
<br>

5. Conceptos teóricos:

- a. KEX: Key Exchange

- b. SSH_MSG_KEXINIT: Algoritmo para crear una clave de sesión
(RSA, Diffie Hellman, etc.).

- c. SSH_KEX_ALG: Algoritmo para identificarse y comprobar que
el servidor es quién dice ser.

<br>


6. ¿Cómo funciona?:

El servidor cifra su clave privada con un token, el cliente lo descifra con su clave pública. Si en el token viene la identidad correcta, el único que tiene esa clave privada para haberlo cifrado es el servidor, por tanto comprobamos que es él de verdad.

<br>

### **Mediante túneles SSH securice algún servicio no seguro.**

Un túnel SSH permite proteger un servicio que no cifra sus comunicaciones (como HTTP, MySQL o VNC) encapsulando su tráfico dentro del canal cifrado de SSH. Así, aunque el servicio sea inseguro, el tráfico entre cliente y servidor viaja cifrado y no puede ser interceptado.

En nuestro caso por ejemplo tenemos un server HTTP que no es seguro porque está sin cifrar. Podemos hacer un túnel entre mi compañero y yo para que los datos viajen cifrados. 

Comando de túnel ssh:
```bash
ssh -L <puerto_local>:<ip_destino>:<puerto_destino> usuario@IP_servidor
```

El primer puerto es un puerto libre en el cliente(≥1023). El segundo puerto es el puerto inseguro.

<br>

Ejemplo 1: Securizar un servidor HTTP (puerto 80)

Yo soy el cliente 10.11.48.202 y mi compañero tiene el servidor HTTP en 10.11.48.175.

1. Creo el túnel:
```bash
ssh -L 8080:10.11.48.175:80 lsi@10.11.48.175
```

8080 → puerto local donde escucharé.

10.11.48.175:80 → servicio HTTP inseguro de mi compañero.


En otra terminal en mi máquina:
```bash
curl http://localhost:8080
```

Esto muestra la web del Apache de mi compañero, pero viajando cifrada por SSH.

Se puede comprobar qur funciona bien con:

 - El servidor hará un ettercap
```bash
ettercap-Tq -w /home/lsi/FICHERO.pcap -i ens33 -M arp:remote
/10.11.48.IPVICTIMA// /IPROUTER(10.11.48.1)//
```
- El cliente buscará la página. Si al meter el .pcap en el Wireshark no sale ningún paquete HTTP, es que está todo bien.


El comando ssh -L 8080:localhost:80 lsi@10.11.48.175 crea un túnel SSH. Esto significa que redirige una conexión desde tu propio ordenador hacia un servicio que está en la máquina remota. Es una forma segura de acceder a un puerto que normalmente no sería accesible desde fuera.

En concreto, el parámetro -L 8080:localhost:80 indica que todo lo que abras en tu navegador en http://localhost:8080 se enviará a través del túnel y acabará realmente en el puerto 80 del servidor 10.11.48.175. De este modo puedes ver la web de ese servidor como si fuese local, pero de forma cifrada gracias a SSH.

El usuario lsi es la cuenta con la que te conectas al servidor remoto. Con esta técnica no hace falta abrir puertos en el firewall, porque la conexión sale desde tu máquina hacia el servidor y va totalmente protegida dentro del túnel SSH.


<br>

**Ejemplo con NTP**:

1-Crear el túnel SSH

En tu cliente:
```bash
ssh -L 1234:localhost:123 lsi@10.11.49.83
```

1234 → puerto local donde escucharás NTP.

localhost:123 → puerto NTP del servidor.

Todo lo que envíes a localhost:1234 se cifrará hasta el servidor.


2️-Sincronizar usando el túnel

En otra terminal del cliente:
```bash
sudo ntpdate localhost 1234
```

Esto fuerza a que tu máquina consulte la hora a través del puerto local 1234, que viaja cifrado por el túnel.

Si se actualiza la hora, significa que el túnel está funcionando.


3-Comprobación adicional (opcional, más técnica)

Puedes ver el tráfico con tcpdump para confirmar que no circula NTP en texto plano:

```bash
sudo tcpdump -i lo port 1234
```

<br>

##### Resumen
Se demuestra que un servicio inseguro (por ejemplo HTTP sin HTTPS) puede viajar de forma segura y cifrada si lo encapsulas dentro de un túnel SSH.

<br>
<br>

- **“Exporte” un directorio y “móntelo” de forma remota sobre un túnel SSH.**


Instalamos sshfs: 
```bash
apt install sshfs
```

Para acceder a un directorio de un servidor remoto de forma segura, podemos usar SSHFS, que permite montar un directorio remoto como si fuera local, utilizando el protocolo SSH para cifrar todo el tráfico. Esto evita que los datos viajen en texto plano por la red y garantiza confidencialidad e integridad.

El comando básico es:

```bash
sshfs lsi@<IPCOMPA>:/<Directorio compa> <Midirectorio>
```

usuario@IP_servidor indica la cuenta y la máquina remota a la que nos conectamos.

/ruta/remota es el directorio en el servidor que queremos montar.

/ruta/local es la carpeta de nuestro equipo donde aparecerá el directorio remoto.

Todo el tráfico entre cliente y servidor viaja cifrado por SSH, y una vez montado el directorio, podemos acceder a los archivos del servidor como si fueran locales, copiar, editar o borrar, sin necesidad de transferencias adicionales ni exposición de datos por la red.


En mi caso:
```bash
sshfs lsi@10.11.48.175:/home/lsi/apartadoe /home/lsi/apartadoe
```

- lsi@10.11.48.175 indica que nos conectamos a la cuenta lsi en el servidor de mi compañero.

- /home/lsi/apartadoe del servidor es el directorio que queremos montar.

- /home/lsi/apartadoe en mi máquina es el punto de montaje local donde podremos acceder a los archivos como si fueran propios.


Ahora para probar que funciona creamos un txt en dicha carpeta:
```bash
nano hola.txt
```

Escribimos algo. Nuestro compañero debería poder verlo y escribir también en él a la vez. Si él está en el archivo nos lo indica abajo ya: El archivo x está siendo modificado por pid y. Algo así.


<br>
<br>

### **PARA PLANTEAR DE FORMA TEÓRICA.: Securice su sevidor considerando que únicamente dará servicio ssh para sesiones de usuario desde determinadas IPs.**

---

## **Apartado 2: Servidor Apache2**
**Tomando como base de trabajo el servidor Apache2:**
- **Configure una Autoridad Certificadora en su equipo.**
- **Cree su propio certificado para ser firmado por la Autoridad Certificadora y fírmelo.**
- **Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL.**
  - **Nota: si la clave privada está cifrada en el arranque, su máquina le pedirá la frase de paso, pudiendo dejarla inaccesible desde su sesión SSH.**

> Buscar entidad certificadora Debian 11/12


### **Configure una Autoridad Certificadora en su equipo.**

Una Autoridad Certificadora (CA) es como un “notario digital” que garantiza que los certificados de los servidores son auténticos y confiables. Cuando un navegador se conecta a un servidor HTTPS, confía en el certificado porque fue firmado por una CA reconocida. Si creamos nuestra propia CA en el equipo, podremos firmar nuestros propios certificados y hacer que Apache pueda usar HTTPS de forma segura incluso en entornos de prueba.

La CA tiene dos cosas importantes:

Clave privada (ca.key): secreta, usada para firmar certificados.

Certificado público (ca.crt): compartido con clientes para que puedan confiar en los certificados que firma la CA.


Para crearlo vamos a usar Easy-rsa (Easy-RSA es una herramienta que automatiza los comandos de OpenSSL, organiza las carpetas y archivos, y hace más fácil crear y gestionar tu CA y certificados sin escribir manualmente comandos complicados de OpenSSL cada vez)

1-Instalarlo y entrar en su directorio:

```bash
apt install easy-rsa
```

2-Crear directorio para la Autoridad Certificadora y copiamos el directorio anterior en este nuevo:
```bash
mkdir ~/miCA
cp -r /usr/share/easy-rsa/ ~/miCA/
cd miCA
cd easy-rsa
```

3-Inicializar la infraestructura PKI dentro del directorio anterior:
```bash
./easyrsa init-pki
```

Salida:
```bash
lsi@ismael:~/miCA/easy-rsa$ ./easyrsa init-pki
* Notice:

  init-pki complete; you may now create a CA or requests.

  Your newly created PKI dir is:
  * /home/lsi/miCA/easy-rsa/pki

* Notice:
  IMPORTANT: Easy-RSA 'vars' file has now been moved to your PKI above.
```


Esto crea la estructura de carpetas necesarias (pki/) para almacenar claves, certificados y registros. PKI significa Public Key Infrastructure.

4-Crear archivo de aleatoriedad (.rnd)
```bash
touch pki/.rnd
```

OpenSSL necesita este archivo para generar claves de manera segura. Evita errores relacionados con la semilla aleatoria.

5-Crear la CA:
```bash
./easyrsa build-ca
```

La primera vez que creas la CA: defines la contraseña. Cada vez que uses la CA para firmar certificados: introduces la contraseña. En entornos de prueba, usar nopass evita tener que introducirla cada vez, pero reduce la seguridad.

<br>


### Archivos principales que se han generado

- pki/private/ca.key   (PRIVADA)

 - Es la clave privada de tu Autoridad Certificadora (CA).
 
 - Protege tu CA y se usa para firmar los certificados de los servidores (como Apache).
 
 - La contraseña que pusiste sirve para proteger esta clave.
 
 - ¡No la compartas nunca!


- pki/ca.crt     (PÚBLICA)

Es el certificado público de tu CA.
 
 - Puede ser distribuido a clientes o navegadores para que confíen en los certificados firmados por tu CA.
 
 - Es como decir “todo certificado firmado por esta CA es confiable”.


- pki/

 - Carpeta donde se guardan todos los certificados, claves privadas y solicitudes (requests).
 
 - Contiene subdirectorios como private/, issued/, reqs/, etc.
 

**CONCLUSIÓN:**

- Ahora tenemis nuestra propia Autoridad Certificadora, que es como un “notario digital” de confianza.

- Cualquier certificado que queramos usar en servidores (Apache, NTP, etc.) puede ser firmado por esta CA.

- Esto permite que los clientes/confían en mis servicios aunque esté en un entorno de prueba, sin necesidad de comprar certificados comerciales.


<br>


### **Cree su propio certificado para ser firmado por la Autoridad Certificadora. Bueno, y fírmelo.**

1-Crear una solicitud de certificado para Apache

Ahora que tenemios la CA lista, necesitas generar un certificado para el servidor Apache.
```bash
cd ~/miCA/easy-rsa
./easyrsa gen-req lsi nopass
```

Nos pedirá un nombre de certificado (ismaCERT en mi caso) y la salida será:
```bash
lsi@ismael:~/miCA/easy-rsa$ ./easyrsa gen-req lsi nopass
* Notice:
Using Easy-RSA configuration from: /home/lsi/miCA/easy-rsa/pki/vars

* Notice:
Using SSL: openssl OpenSSL 3.0.17 1 Jul 2025 (Library: OpenSSL 3.0.17 1 Jul 2025)

.+.........+.............+...+..+.......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+...+..+...+......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+......+.+..................+......+.....+.......+.....+.............+..+...............+...+.+...+..+.+...+...........+.+...+.....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
...........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*........+.....+.+...+..+...+...+....+...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.......+...+..+......+.+.....+.+........................+........+...+.............+.....................+..................+...+..................+.....+....+...+.....+.........+...+.+.....+.......+..+.+..............+.+...........+.+.....+..........+..+..........+...........+......+.+..+.+..............+..........+...........+.......+..+.+.................+....+...........+...+.......+............+..+.+..+................+.........+.....+......+...............+.......+..+.+.....+.+...+............+..............+......+.+..................+..+..........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Common Name (eg: your user, host, or server name) [lsi]:ismaCERT
* Notice:

Keypair and certificate request completed. Your files are:
req: /home/lsi/miCA/easy-rsa/pki/reqs/lsi.req
key: /home/lsi/miCA/easy-rsa/pki/private/lsi.key
```


Como vemos se generarán dos archivos importantes en pki/:

pki/private/lsi.key → clave privada del servidor.

pki/reqs/lsi.req → solicitud de certificado para firmar.



2-Enviar el certificado a nuestro compañero para que lo firme:

```bash
scp /home/lsi/miCA/easy-rsa/pki/reqs/lsi.req lsi@10.11.48.175:/home/lsi
```

Copiamos este archivo en la carpeta de easy-rsa con otro nombre:
```bash
cd ~/miCA/easy-rsa
cp /home/lsi/lsi.req lsi-compa.req
```


3-Firmar su certificado con nuestro CA

Ahora firmamos el certificado usando nuestro CA recién creado:

```bash
./easyrsa import-req lsi-compa.req lsi-compa
./easyrsa sign-req server lsi-compa
```

Nos pedirá la contraseña de la CA (la que pusiste al crear la CA). Confirmamos el Common Name (lsi o el que hayamos puesto).

Esto genera:

pki/issued/lsi-compa.crt → certificado firmado por tu CA.


El primer comando que usamos es ./easyrsa import-req lsi-compa.req lsi-compa. Lo que hace es tomar la solicitud de certificado que tu compañero te envió, llamada lsi-compa.req, y la importa dentro de tu infraestructura PKI de Easy-RSA. Al importar la solicitud, le damos un nombre interno (lsi-compa) que sirve como etiqueta para identificarla dentro de Easy-RSA. Esto no modifica el archivo original, simplemente lo registra y lo coloca en la carpeta pki/reqs/ para poder trabajar con él. Es como guardar un documento en un archivo con un nombre que tú eliges para poder encontrarlo y procesarlo después.

El segundo comando es ./easyrsa sign-req server lsi-compa. Este comando firma la solicitud de certificado que importaste usando la clave de tu CA. Al indicar server, le decimos a Easy-RSA que el certificado que vamos a generar es para un servidor, no para un cliente. Durante este proceso, Easy-RSA te pedirá la contraseña de tu CA, ya que necesitas autorizar la firma. Una vez completado, se genera un archivo llamado pki/issued/lsi-compa.crt, que es el certificado final firmado por tu CA. Este es el certificado que tu compañero debe recibir para poder usarlo en su servidor Apache.

En resumen, import-req sirve para traer la solicitud de tu compañero a tu CA y organizarla dentro de tu infraestructura, mientras que sign-req convierte esa solicitud en un certificado real y válido firmado por tu CA, listo para ser usado por su servidor. De esta manera, tu CA actúa como un notario que valida que el certificado realmente pertenece al propietario que lo solicitó.

Por último, le cambiamos el nombre al ceritificado firmado, para saber de quien es cada uno:
```bash
cd ~/miCA/easy-rsa/pki/issued
mv lsi-compa.crt lsiLucas.cr
```



4-Devolver el certificado firmado al compañero:

```bash
scp /home/lsi/miCA/easy-rsa/pki/issued/lsiLucas.crt lsi@10.11.48.175:/home/lsi
```

A la vez yo recibo el mío firmado por él:
```bash
lsi@ismael:~$ ls -l lsiisma.crt
-rw------- 1 lsi lsi 4647 nov 27 19:47 lsiisma.crt
```

Perfecto, ya tenemos los certificados firmados mutuamente. Ahora toca configurar Apache para que use HTTPS con esos certificados.


5-Añadir el certificado al sistema de confianza

Desde root:
```bash
# Copiar el certificado de la CA al directorio de certificados del sistema
cp /home/lsi/lsiisma.crt /etc/ssl/certs/

# Entrar al directorio y renombrar a .pem
cd /etc/ssl/certs
mv lsiisma.crt lsiisma.pem

# Actualizar la base de datos de certificados de confianza
update-ca-certificates

# Opcionalmente, también lo pones en /usr/share/ca-certificates/
cp /home/lsi/lsiisma.crt /usr/share/ca-certificates/
```

Podemos ver el archivo que está firmado haciendole un cat:
```bash
cat lsiisma.crt
```

<br>

### **Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL.**
  - **Nota: si la clave privada está cifrada en el arranque, su máquina le pedirá la frase de paso, pudiendo dejarla inaccesible desde su sesión SSH.**


1- Activamos SSL para Apache:

Desde root:
```bash
a2enmod ssl
a2ensite default-ssl
systemctl restart apache2.service.
```

2-Cambiar el fichero de configuración de Apache:

En el fichero /etc/apache2/sites-enabled/default-ssl.conf debemos cambiar esta dos líneas:
```bash
SSLCertificateFile      /home/lsi/lsiisma.crt
SSLCertificateKeyFile   /home/lsi/miCA/easy-rsa/pki/private/lsi.key
```

3-Instalar el certificado en el navegador:

```bash
nano /etc/w3m/config
```

Añadimos: /usr/share/ca-certificates/lsiisma.crt


Y le damos permisos de lectura a ca.crt para que funcione desde lsi:
```bash
chmod +r lsiisma.crt
```
Para comprobar que funciona: En ambas máquinas, desde lsi, hacemos w3m https://NOMBREDOMINIO y no nos sale ningún warning.


 4- Creamos las carpetas y archivos de contraseñas para Apache:

 Creamos la carpeta:
 ```bash
mkdir /var/www//html/p3
```

```bash
htpasswd -c /home/lsi/passp3 isma
htpasswd  /home/lsi/passp3 lucas
```
Nos pedirá una contraseña para cada usuario.


Añadimos en /etc/apache2/sites-available/default-ssl.conf lo siguiente:

```bash
<Directory "/var/www/html/p3">
    AuthName "Ficheros privados"
    AuthType Basic
    AuthUserFile /home/lsi/passp3
    Require valid-user
    SSLRequireSSL
</Directory>
```

Y ahora reiniciamos apache:
```bash
systemctl restart apache2
systemctl reload apache2
```


5-Probar:

Para comprobar que todo funciona: Buscamos en ambas máquinas w3m https://NOMBRESERVIDOR/NOMBRECARPETA y nos pedirá autenticarnos.

```bash
w3m https://10.11.48.202/p3
```

La salida será:

1-Conexión HTTPS

Como estás usando un certificado firmado por tu CA propia, es normal que w3m primero te avise de que el certificado no es de una CA pública reconocida:

```bash
unable to get local issuer certificate: accept? (y/n)
Bad cert ident from 10.11.48.202: dNSName=ismaCERT : accept? (y/n)
Accept unsecure SSL session: Bad cert ...
```


2-Autenticación HTTP básica

Después de aceptar el certificado, como configuraste AuthType Basic, el navegador te pedirá usuario y contraseña:

<img width="351" height="43" alt="imagen" src="https://github.com/user-attachments/assets/681a8e8d-2e47-4550-a78f-1206470f7896" />
<img width="423" height="31" alt="imagen" src="https://github.com/user-attachments/assets/e3d90504-c20f-4630-9f83-dc46c31b2aee" />
<img width="581" height="189" alt="imagen" src="https://github.com/user-attachments/assets/a374b7ad-fab1-4854-8e52-bacba3705ac7" />


Authorization required
User: isma
Password: ********


3-Acceso al contenido

Una vez autenticado, w3m te mostrará el contenido del directorio protegido.





 ---

## **Apartado 3: openVPN**
**Configure una VPN entre dos equipos virtuales del laboratorio que garantice la confidencialidad de sus comunicaciones.**


Clave precompartida
---

## **Apartado 4: Autenticación en NTP**
**En la Práctica 1 se configuró una infraestructura con servidores y clientes NTP. Modifique la configuración para autenticar los equipos involucrados.**

#### NO SE HACE

---

## **Apartado 5: Cifrado en servidores y clientes de log**
**En la Práctica 1 se instalaron servidores y clientes de log. Configure un esquema que permita cifrar las comunicaciones.**

#### NO SE HACE

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

#### NO SE HACE
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
