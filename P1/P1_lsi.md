# PRÁCTICA 1 - Seguridad Informática

## Defensas en clase
- Traer papel y boli.  
- Revisar siempre todo lo que aparezca en pantalla.  

---

## Redes para la realización de las prácticas
- **Eduroam**: no permitido el tráfico a los puertos 80 y 443.  
- **UDCDocencia**: no permitido el tráfico al puerto 22.  
- **VPN**(recomendada):  
  - Se obtienen dos IPs:
    - Una IP de la red para conectarse a la máquina Debian. Esta IP puede cambiar porque la tabla de la VPN se va llenando.  
      **No usar una IP fija con los 4 octetos definidos.**  
    - Una IP propia de la máquina local.  
  - Ambas IPs son diferentes.  

**IP de los alumnos:** `10.11.48.0/23`  
- `/23` porque con `/24` no alcanzan las IPs para todos los alumnos, ya que solo habría 256 direcciones posibles con /24. Con /23 hay 512 direcciones IPs disponibles, suficientes para todos.
- `0` → IP de subred.  
- `1` → IP de gateway.  
- `255` → IP de broadcast.  

---

## Sistema Operativo
- Se comienza con **Debian 10**.  
- Actualizar sistema: 10 → 11 → 12.  
- Actualizar también el kernel a la versión correspondiente. 
- Una vez actualizado, eliminar ficheros de las versiones 10 y 11.  
- **No se puede saltar directamente de Debian 10 a 12.**  
- Revisar los servicios activos para asegurar que no queda nada corriendo que no corresponda.  

---

## Usuarios
- Usuario inicial:  
  - `lsi`  
  - IP: `10.11.48.74`  
  - Contraseña inicial usuario lsi: `virtual;..`  
  - Root: `root@debian`
  - - Contraseña inicial root: `virtual;..`  

- Usuario propio:  
  - `lsi2.3.4`  
  - IP: `10.11.48.169`  

---

## Primeros pasos obligatorios

### 1.Conexión por SSH:  
```bash
ssh lsi@10.11.48.169
```

Al conectarse por primera vez, se pide aceptar la huella digital (fingerprint), que es un mensaje del siguiente estilo:
```bash
The authenticity of host '192.168.1.10 (192.168.1.10)' can't be established.
ECDSA key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```
Ese mensaje habla del fingerprint (huella digital) del servidor al que te conectas.
Te lo explico fácil:

1-Cada servidor SSH tiene un par de claves (pública y privada).

    La clave privada la guarda el servidor y nunca se comparte.
    
    La clave pública se usa para identificar al servidor.

2-El fingerprint es una huella digital de esa clave pública.

    Es como el DNI de la máquina.
    
    Sirve para comprobar que realmente te estás conectando al servidor correcto y no a un impostor.

3-Primera vez que te conectas a un servidor:

    Tu cliente SSH aún no conoce esa clave.
    
    Te avisa y te muestra la huella (fingerprint).
    
    Tú decides si confiar o no. Si aceptas (yes), se guarda en el archivo ~/.ssh/known_hosts.

4-Próximas veces:

    SSH comparará la huella guardada con la que le presenta el servidor.
    
    Si coincide: todo bien.
    
    Si no coincide:  Peligro → puede significar que alguien intenta suplantar el servidor (ataque Man-in-the-Middle) o que el servidor fue reinstalado y cambió su clave.
    

POR TANTO, el fingerprint es el DNI de la máquina.

La primera vez lo guardas.

Después sirve para comprobar que siempre entras a la misma máquina y no a un impostor.    


Para comprobar esto, podemos acceder a otra powershell y poner lo siguiente:
```bash
type C:\Users\User\.ssh\known_hosts
```

Podemos observar que nos da algo asi:
```bash
10.11.48.169 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKQfI1ZugU31gRpgEwcUi6oAokkz8EELqtseoFLN0DsV
10.11.48.169 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG51QMMMvwsB+NAdwvHfhR1jQ+UrzZ6MBXlOr6ENTfWcFTJldY69HnGKsyz1xNlF6/YAwxwq4otq321jSaakjcE=
```
Eso significa que tu cliente ha aceptado dos tipos de claves del servidor:

  -Una clave ED25519
  
  -Una clave ECDSA

Esto es normal: el servidor Debian puede estar configurado con varios algoritmos de clave, y tu cliente guarda todos los que acepta.

Para comprobar que son de verdad de mi máquina debemos volver a la powershell de mi máquina y hacer lo siguiente:

```bash
root@debian:~# ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
256 SHA256:Vergq/A8tdRdcdGu6VqvAo1LBIGEr1QN4FEudeG/R9g root@debian (ED25519)
root@debian:~# ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub
256 SHA256:fBaTUZzR9oa1B2VWLwurmhlCaeRhpr5uloGtThsikF8 root@debian (ECDSA)
root@debian:~# ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub
2048 SHA256:tPl0ZxJ3YTNBasMm4T13t74nrsR9nRXgHxE2+IGG69Y root@debian (RSA)
```


Ahora podemos comprobar estas mismas claves en nuestro windows:
```bash
ssh-keygen -lf C:\Users\User\.ssh\known_hosts
```

**Huellas en el servidor Debian:**

ED25519 → SHA256:Vergq/A8tdRdcdGu6VqvAo1LBIGEr1QN4FEudeG/R9g

ECDSA → SHA256:fBaTUZzR9oa1B2VWLwurmhlCaeRhpr5uloGtThsikF8

**Huellas en tu Windows (known_hosts):**

10.11.48.169 (ED25519) → SHA256:Vergq/A8tdRdcdGu6VqvAo1LBIGEr1QN4FEudeG/R9g ✅

10.11.48.169 (ECDSA) → SHA256:fBaTUZzR9oa1B2VWLwurmhlCaeRhpr5uloGtThsikF8 ✅


---
### 2-Cambiar las contraseñas de los usuarios
  -Cambiar la contraseña del usuario lsi.
  ```bash
  passwd
  ```
  -Cambiar la contraseña del usuario root.
  ```bash
su
passwd
```

**su: access to super user**

**passwd: change password**

### Diferencia entre `$` y `#`

- `$` → estás usando un usuario normal (ej. lsi).  
- `#` → estás usando el usuario root (administrador).  


### DIFERENCIAS ENTRE SU Y SU-

- **`su`**  
  Cambia de usuario (por defecto a root) pero **mantiene tu entorno actual**, incluyendo directorio y variables.

- **`su -`**  
  Cambia de usuario **y carga el entorno completo** del nuevo usuario, incluyendo su PATH, variables y directorio inicial (`/root` si es root).
  
---
### 3-Activar sudo
Activar sudo en Debian 10

Instala sudo (como root):
```bash
su -              # Entrar como root
apt update         # Actualizar lista de paquetes
apt install sudo   # Instalar sudo
```
Añadir nuestro usuario lsi al grupo sudo
```bash 
usermod -aG sudo lsi    # Permite a 'lsi' usar sudo
```

-aG:
  - G → indica “agregar al usuario a estos grupos”.

  - a → significa “añadir al grupo sin quitarlo de los demás grupos que ya tiene”.

Prueba sudo:
```bash
sudo whoami   
```

Debería mostrar root

### Diferencia entre `su` y `sudo`

- **`su -`**  
  Te loguea como root hasta que cierres sesión. Necesitas la **contraseña de root**.

- **`sudo`**  
  Ejecuta **un solo comando como root** usando tu contraseña de usuario normal.  
  No cambia tu usuario permanentemente, solo eleva privilegios para ese comando.  


---
### 4-Comprobar el número máximo de comandos permitidos en el historial (history) y ampliarlo
**El comando history es independiente para cada usuario, incluyendo root.**

El historial del root en mi máquina empieza a partir del comando 148

Cada usuario puede tener configuraciones distintas en ~/.bashrc o /etc/profile que afecten HISTSIZE y HISTFILESIZE:
- HISTSIZE -> número máximo de comandos que se guardan en la sesión actual.
- HISTFILESIZE -> número máximo de comandos que se guardan en el archivo de historial (\~/.bash_history).


Por tanto, lo primero que debemos hacer es comprobar cuandos comandos tenemos permitidos en ambos usuarios:
```bash
lsi@debian:~$ echo $HISTSIZE
1000
lsi@debian:~$ echo $HISTFILESIZE
2000
lsi@debian:~$ su -
Contraseña:
root@debian:~# echo $HISTSIZE
500
root@debian:~# echo $HISTFILESIZE
500
```

**echo**: muestra texto o variables en la terminal. Imprime texto o el contenido de ciertas variables ($variable) en la pantalla. 

Para aumentar ambos historiales tenemos que hacer lo siguiente:
```bash
echo "export HISTSIZE=1000000" >> /root/.bashrc
echo "export HISTFILESIZE=1000000" >> /root/.bashrc
source /root/.bashrc
```
**source /root/.bashrc:** es un comando que le dice a tu shell actual que ejecute todas las instrucciones del archivo /root/.bashrc.

En otras palabras:

  - Normalmente, .bashrc se ejecuta cuando inicias sesión o abres una nueva terminal.
  
  - Con source, no necesitas cerrar ni abrir otra sesión, se aplican los cambios inmediatamente en la terminal actual.


---
# Puntos a resolver de la práctica 1

Familiarizarse con el **funcionamiento básico y la configuración de la máquina de laboratorio**, utilizando **comandos y ficheros de configuración en Linux**.  

La práctica finaliza con la **configuración básica de servicios de red**, realizada en grupos de dos alumnos.

---
### **Apartado A): Configure su máquina virtual de laboratorio con los datos proporcionados por el profesor. Analice los ficheros básicos de configuración (interfaces, hosts, resolv.conf, nsswitch.conf, sources.list,etc).**

Los pasos básicos explicados por el profesor ya los hemos realizado:
  - Conexión por SSH, entender y comprobar el correcto funcionamiento del fingerprint
  - Cambiar las contraseñas de los usuarios (lsi y root)
  - Instalar sudo
  - Ampliar el historial de comandos permitidos en ambos usuarios (lsi y root)
  - 

### **ANÁLISIS DE LOS FICHEROS BÁSICOS DE CONFIGURACIÓN (/etc - archivos de configuración del sistema)**

📂 /etc = Configuraciones del sistema y programas

Aquí casi todo son archivos de texto que puedes abrir y leer.
Son archivos de texto que contienen parámetros que definen cómo se comporta el sistema.

En Debian (y en Linux en general) casi todo se configura a través de archivos en /etc/. Es un directorio de configuración que contiene archivos y subcarpetas que configuran el sistema y los servicios.
#### 🔑 Configuración de usuarios y contraseñas:
- `/etc/passwd` → lista de usuarios del sistema, su ID, grupo, carpeta y shell, pero no contiene contraseñas reales. Ejemplo:
```bash
root:x:0:0:root:/root:/bin/bash     #nombre usuario, contraseña guardada en /etc/shadow, UID, GID, info del user, diretcorio del user, shell por defecto al iniciar sesión
```  
- `/etc/shadow` → USAR SUDO. Contraseñas cifradas de los usuarios. Ejemplo:
```bash
root:$6$FSEZLE5xfP.Xo3/M$Vd.VBf1s6M5fJWzeg8bHQxPHk75T3LBZjKGvyE4gRj0fNKVhnWHCfx2yO93NRPoAQsHMkFHS/AiJulnl3O/XC0:20345:0:99999:7:::
```
- `/etc/group` → grupos de usuarios y sus miembros.  Ejemplo:
```bash
sudo:x:27:lsi     #nombre grupo, contraseñas guardadas en /etc/shadow, GID, lista de miembros
```

#### 🌐 Configuración de red:
- `/etc/hosts` → tabla local de nombres (para resolver direcciones sin DNS).  
- `/etc/hostname` → el nombre del equipo -> debian (mi máquina) 
- `/etc/network/interfaces` (en Debian/Ubuntu viejos) → configuración de interfaces de red.  

#### ⚙️ Configuración de arranque y servicios:
- `/etc/fstab` → qué particiones montar al arrancar.  
- `/etc/systemd/` → scripts y configuraciones de servicios en sistemas modernos.  
- `/etc/init.d/` → scripts de inicio (sistemas más antiguos).  

#### 📦 Configuración de programas:
Cada aplicación suele tener su propia carpeta:  
- `/etc/ssh/sshd_config` → configuración del servidor SSH.  
- `/etc/apache2/` → configuración del servidor web Apache.  
- `/etc/mysql/` → configuración de MySQL.  

#### 📑 Otros ficheros útiles:
- `/etc/resolv.conf` → servidores DNS.  
- `/etc/sudoers` → quién puede usar `sudo`.  
- `/etc/crontab` → tareas programadas.  


### Ejemplos probados en la práctica:

**etc/network/interfaces**

```bash
lsi@debian:~$ cat /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
#source /etc/network/interfaces.d/*
# The loopback network interface
auto lo ens33
iface lo inet loopback
iface ens33 inet dhcp
```

Todo lo que lleve "#" son comentarios, no se ejeuctan.
Este archivo de configuracion le indica a mi máquina como usar sus cables y WIFI. No guarda la IP real ni lo que el ordenador está haciendo ahora, solo dice que hacer cuando arranca.

Lo que muestra mi salida es lo siguiente:

```bash
auto lo ens33
```

- Significa que estas dos interfaces (lo y ens33) se activan automáticamente al arrancar el sistema.

- “auto” = se enciende sola.

- lo = loopback, conexión interna de la máquina (no sale a Internet). La usa la máquina para hablar consigo misma.

- ens33 = cable de red o interfaz de red real.

```bash
iface lo inet loopback
```
- iface lo = esta configurando la interfaz lo
- inet = usamos el protocolo de red Ipv4
- loopback: tipo de conexión interna (la máquina habla consigo misma, no sale a Internet)

```bash
iface ens33 inet dhcp
```
- iface ens33 = esta configurando la interfaz de red real
- inet = usamos el protocolo de red Ipv4
- dhcp (dynamic host control protocol) = la IP se asigna automáticamente por el router.



En resumen:
1. lo → interna, siempre encendida, no sale a Internet.

2. ens33 → real, siempre encendida, obtiene IP automática para conectarse a la red.
---


**etc/hosts**

Es como una agenda de nombres de red para tu propio ordenador.
```bash
lsi@debian:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       debian

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Este archivo es una lista de nombres de computadoras y a qué dirección IP corresponden.
“Este nombre corresponde a esta dirección IP”.
Obtiene una relación entre un nombre de máquina y una dirección IP: en cada línea de /etc/hosts se especifica una dirección IP y los nombres de máquina que le corresponden, de forma que un usuario no tenga que recordar direcciones sino nombres de hosts. Habitualmente se suelen incluir las direcciones, nombres y alias de todos los equipos conectados a la red local, de forma que para comunicación dentro de la red no se tenga que recurrir a DNS a la hora de resolver un nombre de máquina.

```bash
127.0.0.1   localhost     #Cuando el sistema vea el nombre localhost, en realidad se conecta a 127.0.0.1 (tu propio PC).
127.0.1.1   debian        #También “yo mismo”, pero usando el nombre de la máquina (debian).
```

¿Y por qué no sale tu IP 10.11.48.169?

Porque 127.x.x.x no es tu IP real de la red, es una dirección especial solo para uso interno del ordenador.

La 10.11.48.169 sí es tu IP real en la red (la que usan otros equipos para conectarse a tu máquina).


**Resumen fácil:**

127.0.0.1 y 127.0.1.1 = tu PC hablando consigo mismo.

10.11.48.169 = tu PC hablando con otros en la red.


Las últimas líneas que aparecen con comentario hacen referencia a IPv6:
```bash
::1     localhost ip6-localhost ip6-loopback
```
- ::1 = dirección IPv6 que apunta a tu propio PC (igual que 127.0.0.1 en IPv4).

- Nombres que se le pueden dar: localhost, ip6-localhost, ip6-loopback.

- Sirve para que tu máquina se pueda hablar a sí misma usando IPv6.


```bash
ff02::1 ip6-allnodes
```
- Dirección especial que significa “todos los dispositivos de la red local”.

- Se usa en redes IPv6 para enviar mensajes a todos los equipos a la vez.

```bash
ff02::2 ip6-allrouters
```
- Dirección especial que significa “todos los routers de la red”.

- Se usa en redes IPv6 para enviar mensajes a todos los routers a la vez.


**Resumen fácil:**

- ::1 → tu PC hablando consigo mismo (IPv6).

- ff02::1 → enviar mensaje a todos los PCs de tu red.. Es como si enviaras un mensaje al aire y todos los PCs de tu red pudieran leerlo.

- ff02::2 → enviar mensaje a todos los routers de tu red. Sirve para enviar mensajes a los routers sin tener que escribir su IP exacta.
---


 
**/etc/resolv.conf**:

Ponemos los servidores de nombres (DNS) que utilizará el equipo. El orden es importante, pues las consultas se envían al servidor de la primera línea nameserver, y si este fallara, se pasa al segundo y luego al tercero; por lo tanto, en primer lugar deberíamos poner siempre el servidor DNS más rápido.

```bash
lsi@debian:~$ cat /etc/resolv.conf
domain udc.pri
search udc.pri
nameserver 10.8.8.8
nameserver 10.8.8.9
```

Este archivo le dice a tu Debian cómo traducir nombres de páginas o máquinas a direcciones IP.

  - domain udc.pri → tu dominio local, básicamente “tu zona de red”

  - search udc.pri → si escribes un nombre corto de host, el sistema lo busca dentro de este dominio

  - nameserver 10.8.8.8 → primera dirección de servidor DNS que se usará para buscar nombres

  - nameserver 10.8.8.9 → segunda dirección de servidor DNS (respaldo)

En palabras fáciles: si escribes servidor1, tu Debian intenta buscarlo como servidor1.udc.pri usando primero el DNS 10.8.8.8 y si falla, prueba con 10.8.8.9.

Ejemplo:
```bash
ping servidor1
```
Qué pasa detrás de escena:

  1. Tu ordenador ve servidor1 y como no tiene IP directa, añade automáticamente el dominio de búsqueda: servidor1.udc.pri

  2. Luego pregunta al DNS 10.8.8.8: “¿Cuál es la IP de servidor1.udc.pri?”

  3. Si 10.8.8.8 no contesta, prueba 10.8.8.9

  4. El DNS responde algo como 10.8.8.50


Tu ordenador ahora hace ping 10.8.8.50 y puedes comunicarte con el servidor.

---


**/etc/nsswitch.conf**:

El archivo /etc/nsswitch.conf le dice a tu Debian dónde mirar primero y dónde después para encontrar cosas como usuarios, contraseñas o direcciones de otros ordenadores.

```bash
passwd:         files systemd        # Usuarios: primero archivos locales (/etc/passwd), luego systemd
group:          files systemd        # Grupos: primero archivos locales (/etc/group), luego systemd
shadow:         files                # Contraseñas cifradas: solo archivos locales (/etc/shadow)
gshadow:        files                # Contraseñas de grupos: solo archivos locales (/etc/gshadow)

hosts:          files mdns4_minimal [NOTFOUND=return] dns myhostname
                                    # Nombres de ordenadores: primero /etc/hosts, luego red local (mdns),
                                    # si no está [NOTFOUND=return], luego DNS y finalmente el nombre de la máquina
networks:       files                # Redes: busca en archivos locales (/etc/networks)

protocols:      db files             # Protocolos de red: primero base de datos, luego archivo (/etc/protocols)
services:       db files             # Servicios de red: primero base de datos, luego archivo (/etc/services)
ethers:         db files             # Direcciones MAC: primero base de datos, luego archivo (/etc/ethers)
rpc:            db files             # Servicios RPC: primero base de datos, luego archivo (/etc/rpc)

netgroup:       nis                  # Grupos de red: usa NIS (servicio de red)

```

Ahora, línea por línea:

- passwd: files systemd → para encontrar usuarios, primero mira los archivos locales (/etc/passwd) y después systemd

- group: files systemd → para encontrar grupos de usuarios, igual

- shadow: files → para las contraseñas cifradas, solo mira los archivos locales (/etc/shadow)

- hosts: files mdns4_minimal [NOTFOUND=return] dns myhostname

Para encontrar otros ordenadores por su nombre:
    
    - Mira tu archivo /etc/hosts (como tu agenda local)
    
    - Busca en la red local (mdns)
    
    - Si no hay, pregunta al DNS (como la guía telefónica de Internet)
    
    - Si es tu propia máquina, usa su nombre (myhostname)

Todo lo demás (networks, protocols, services…) → funciona igual: primero archivos locales, después servidores o bases de datos externas si hace falta


**Resumen fácil:**

- nsswitch.conf = el orden que sigue tu Debian para buscar información.

- Primero mira archivos locales.

- Si no lo encuentra, pregunta a servicios de red o bases de datos.

Así siempre sabe dónde buscar y en qué orden.


### systemd = jefe del Linux que arranca y controla todos los servicios y tareas.
Sin él, tu Debian no sabría qué programas ejecutar al iniciar.

---



**/etc/apt/sources.list**:

Cada línea es el sitio donde se accede para descargar los paquetes necesarios.

```bash
lsi@debian:~$ cat /etc/apt/sources.list
#

# deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

#deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

deb http://deb.debian.org/debian/ buster main
deb-src http://deb.debian.org/debian/ buster main

deb http://security.debian.org/debian-security buster/updates main contrib
deb-src http://security.debian.org/debian-security buster/updates main contrib

# buster-updates, previously known as 'volatile'
deb http://deb.debian.org/debian/ buster-updates main contrib
deb-src http://deb.debian.org/debian/ buster-updates main contrib
```

El archivo /etc/apt/sources.list le dice a Debian de dónde puede descargar programas y actualizaciones. Cada línea indica un “repositorio”, que es un servidor con paquetes de software.

Las líneas que empiezan con # son comentarios, es decir, notas que el sistema ignora. Por ejemplo, las que hablan del DVD de instalación no se usan.

Las líneas que empiezan con deb indican paquetes listos para instalar (programas ya compilados).

Las líneas que empiezan con deb-src indican el código fuente de esos programas, que sirve si quieres compilar tú mismo el software.

Además, cada línea termina con main, contrib, etc.:

  - main → paquetes oficiales de Debian. Funcionan solos, no necesitan nada externo. Programas básicos como vim o bash.
  
  - contrib → paquetes extra que dependen de software libre adicional. Paquetes que son libres, pero necesitan algo fuera de Debian para funcionar. Es decir, el programa es libre, pero para usarlo necesitas software que no está en main.


#### **Con este archivo nos aseguramos de que partimos con una máquina Debian versión 10 (Buster)**

---

### **Apartado B) ¿Qué distro y versión tiene la máquina inicialmente entregada?. Actualice su
máquina a la última versión estable disponible.**

Distro = versión completa de Linux lista para usar. En nuestro caso Debian, y ya sabemos ques la versión 10.

Kernel = es el núcleo del Sistema Operativo. Actúa como puente entre hardware y software. Todavía no sabemos su versión.


### Versión del distro
Según el source.list ya sabemos que estamos en un Debian 10. Esto se puede comprobar de varias maneras:

1-lsb_relesase -a (Linux Standard Base release)
Muestra información sobre nuestra distrubución de Linux.
```bash
lsi@debian:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster
```

-a → significa all, es decir, “muestra toda la información disponible”.


2-cat /etc/*-release -> también nos da información sobre la versión.
```bash
lsi@debian:~$ cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 10 (buster)"
NAME="Debian GNU/Linux"
VERSION_ID="10"
VERSION="10 (buster)"
VERSION_CODENAME=buster
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```


3-/etc/debian_version
```bash
lsi@debian:~$ cat /etc/debian_version
10.4
```

### Versión del kernel

Varias formas de obtener la versión del kernel:

1. uname (Unix Name):
2. 
```bash
man uname
````

Parámetros:
-r	Muestra la versión del kernel
-a	Muestra toda la información disponible (kernel, hostname, arquitectura, fecha de compilación…)
-s	Muestra el nombre del sistema operativo
-m	Muestra la arquitectura de la máquina (amd64, i386…)

```bash
lsi@debian:~$ uname -r
4.19.0-9-amd64
```

```bash
lsi@debian:~$ uname -a
Linux debian 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64 GNU/Linux
```

### Actualizar a Debian 11 (Buster -> BullSeye)

1. Ninguna actualización con update o upgrade va funcionar en Debian 10 ya que no está soportado oficialmente y los repositorios han sido movidos a archive.debian.org. apt intenta buscar archivos que ya no existen.

Por tanto, vamos a cambiar el contenido del archivo sources.list para poder actualizar los últimos paquetes de la versión 10.

```bash
sudo nano /etc/apt/sources.list

#

# deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

#deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

deb http://archive.debian.org/debian/ buster main
deb-src http://archive.debian.org/debian/ buster main

deb http://archive.debian.org/debian-security buster/updates main contrib
deb-src http://archive.debian.org/debian-security buster/updates main contrib

# buster-updates, previously known as 'volatile'
deb http://archive.debian.org/debian/ buster-updates main contrib
deb-src http://archive.debian.org/debian/ buster-updates main contrib
```
Guarda y cierra (Ctrl+O, Enter, Ctrl+X).

- main → Contiene software completamente libre, soportado oficialmente por Debian.

- contrib → Software libre, pero depende de paquetes que están en non-free. Por ejemplo, un programa libre que necesita un driver privativo para funcionar.

- non-free → Software propietario o con restricciones. Debian no puede garantizar soporte completo, pero a veces es necesario para que ciertos dispositivos o drivers funcionen (por ejemplo, controladores Wi-Fi, tarjetas gráficas, firmware).


2. Desactivar la comprobación de fechas expiradas

Los repositorios antiguos pueden dar error de “Release file expired”. Para solucionarlo, actualiza con:
```bash
sudo apt update -o Acquire::Check-Valid-Until=false
```


3. Ver qué se puede actualizar

Ya apt detectó paquetes actualizables. Confirma la lista:
```bash
apt list --upgradable
```

No actualiza nada. SOLO INFORMA


4. Actualizar todos los paquetes de Debian 10:

```bash
sudo apt upgrade -y
```

En upgrade nos pide actualizar el GRUB en el dev/sda (gestor de arranque que usa Debian (y casi todas las distros Linux)).

Tendré que marcar [*] con un espacion en dev/sda y darle a Aceptar moviendose con en Tabulador.


```bash
lsi@debian:~$ cat /etc/debian_version
10.13
```

Después de esto, haremos:

```bash
sudo apt full-upgrade -y
sudo apt autoremove -y
sudo apt autoclean
```

- update → actualiza la lista de paquetes

- upgrade → actualiza todos los paquetes que tengan nuevas versiones sin tocar dependencias que puedan romper algo

- full-upgrade → actualiza incluso paquetes que cambian dependencias 

- autoremove → elimina paquetes que ya no hacen falta ((viejos, huérfanos, dependencias obsoletas)

- autoclean → borra los paquetes .deb descargados que ya no sirven, liberando espacio.

- -y significa “sí automáticamente”, para no tener que confirmarlas una por una.


Ya tenemos el Debian 10 LIMPIO Y ACTUALIZADO.


Vamos a pasar ahora al 11:








