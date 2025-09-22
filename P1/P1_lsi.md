# PRÁCTICA 1 - Seguridad Informática

## Defensas en clase
- Traer papel y boli.  
- Revisar siempre todo lo que aparezca en pantalla.  
 - El viernes anterior a la semana de defensas se apagan las máquinas.  Antes de cerrar todo para la defensa hacer un poweroff de la máquina.
<br>

## Repaso COMANDOS BÁSICOS útiles para las prácticas
```bash
#Accesos
last               #Sesiones de usuarios accedidas a la máquina

# Navegación
pwd                 # Carpeta actual
ls                  # Listar
ls -l               # Listar con detalles
ls -a               # Incluir ocultos
cd /ruta            # Cambiar carpeta
cd ~                # Ir al home
cd ..               # Subir un nivel

# Archivos y directorios
touch archivo.txt   # Crear archivo vacío
mkdir carpeta       # Crear carpeta
mkdir -p a/b/c      # Crear subcarpetas
cp origen destino   # Copiar archivo
cp -r dir1 dir2     # Copiar directorio
mv origen destino   # Mover/renombrar
rm archivo.txt      # Borrar archivo
rm -r carpeta       # Borrar carpeta

# Ver contenido
cat archivo.txt     # Mostrar contenido
less archivo.txt    # Leer con paginador
head archivo.txt    # Primeras 10 líneas
tail archivo.txt    # Últimas 10 líneas
tail -f archivo.log # Ver en tiempo real

# Búsqueda
find . -name "archivo.txt"  # Buscar archivo
grep "texto" archivo.txt    # Buscar texto
grep -r "texto" /ruta       # Buscar en varios archivos

# Redirección y tuberías (pipes)
> sobreescribe el archivo
>> añade al final del archivo

| tubería. Envía la salida de un comando como entrada de otro comando, conectando procesos en serie.

# Permisos
ls -l               # Ver permisos
chmod 755 archivo   # Cambiar permisos
chown usr:grp arch  # Cambiar propietario

# Procesos
ps aux              # Listar procesos
top                 # Procesos en tiempo real
kill PID            # Terminar proceso

# Paquetes (Debian/Ubuntu)
sudo apt update           # Actualizar lista
sudo apt upgrade          # Actualizar paquetes
sudo apt install paquete  # Instalar
sudo apt remove paquete   # Eliminar

# Red
ping 8.8.8.8         # Probar conexión
ip a                 # Ver IP
curl ifconfig.me     # Ver IP pública

# Usuarios
whoami               # Usuario actual
id                   # UID y grupos
adduser usuario      # Crear usuario
passwd usuario       # Cambiar contraseña

# Sistema
uname -r             # Versión kernel
lsb_release -a       # Versión distro
df -h                # Espacio en disco
du -sh carpeta       # Tamaño carpeta
free -h              # Memoria RAM
systemctl            # Gestiona servicios, targets y el estado del sistema con systemd.
uptime               # Tiempo encendido
reboot               # Reiniciar
shutdown now         # Apagar
```

---
<br>

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

- Usuario compañero_
  -  `lsi2.3.4`  
  - IP: `10.11.48.175`  


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
 

```bash
lsi@ismael:~$ last
lsi      pts/0        10.30.12.189     Wed Sep 17 20:30   still logged in
lsi      pts/0        10.20.37.81      Tue Sep 16 18:04 - 18:05  (00:00)
```

Aquí podemos ver que en dos sesiones distintas a pesar de entrar con nuestra IP que es 10.11.48.169, al conectarnos tenemos distintas IP con las que salimos al exterior. Esto es por que tenemos asignado DHCP, el cuál tendremos que cambiar más adelante  por una ruta estática con nuestra IP de la máquina.

**IP de los alumnos:** `10.11.48.0/23`  
- `/23` porque con `/24` no alcanzan las IPs para todos los alumnos, ya que solo habría 256 direcciones posibles con /24. Con /23 hay 512 direcciones IPs disponibles, suficientes para todos.
- `0` → IP de subred.  
- `1` → IP de gateway.  
- `255` → IP de broadcast.  

---
<br>

## Sistema Operativo
- Se comienza con **Debian 10**.  
- Actualizar sistema: 10 → 11 → 12.  
- Actualizar también el kernel a la versión correspondiente. 
- Una vez actualizado, eliminar ficheros de las versiones 10 y 11.  
- **No se puede saltar directamente de Debian 10 a 12.**  
- Revisar los servicios activos para asegurar que no queda nada corriendo que no corresponda.  

---
<br>


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
### 2-Cambiar las contraseñas de los usuarios y el hostname de la máquina
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


-Cambiar el hostname de la máquina:
```bash
su
nano /etc/hostname

```
Actualizar el nombre, guardar y salir.
Reiniciar la máquina

```bash
su
reboot
```


### DIFERENCIAS ENTRE SU Y SU-

- **`su`**  
  Cambia de usuario (por defecto a root) pero **mantiene tu entorno actual**, incluyendo directorio y variables.

- **`su -`**  
  Cambia de usuario **y carga el entorno completo** del nuevo usuario, incluyendo su PATH, variables y directorio inicial (`/root` si es root).
  
---
### 3-Activar sudo   (NO ES RECOMENDABLE. AYUDA A COMETER ERRORES)
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


<br>
<br>

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

**Para encontrar los ficheros que nos piden podemos usar:**
```bash
find [ruta] -name "patrón"
```
<br>

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
<br>

**Añadir nuestra IP estática en ens33 y quitar el DHCP*

Hacemos esto para que mi máquina siempre tenga la misma IP. Evitamos que DHCP nos dé otra IP diferente cada vez que reiniciamos. Necesario si vamos a usar /etc/hosts para nombres, porque los alias dependen de IP fija.

```bash
su -
nano /etc/network/interfaces
```

Cambiamos el contenido por:
```bash
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).
#source /etc/network/interfaces.d/*
# The loopback network interface
auto lo
iface lo inet loopback

# Primera interfaz
auto ens33
iface ens33 inet static
    address 10.11.48.169
    netmask 255.255.254.0
    gateway 10.11.48.1

```
Y reiniciamos el servicio:
```bash
su -
systemctl restart networking
```

Si hay cualquier fallo en el restart de las interfaes podemos usar esto para ver dodne está el fallo:
```bash
systemctl status networking.service
```

Tener la configuración con IP estática en ens33  permite que la máquina siempre tenga las mismas direcciones IP, a diferencia de la configuración anterior con DHCP, donde la IP podía cambiar cada vez que se reiniciaba. Esto es útil para:

- Conectarse por SSH usando IP o alias en /etc/hosts sin preocuparse de que cambie la dirección.

- Mantener varias interfaces de red con subredes distintas, por ejemplo una para laboratorio y otra para acceso general.

- Garantizar estabilidad en la red y coordinación con compañeros o servicios que dependen de IP fija.

<br>

Para comprobar que todo funciona bien:
```bash
root@ismael:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 00:50:56:97:9a:7f brd ff:ff:ff:ff:ff:ff
    altname enp2s1
    inet 10.11.48.169/23 brd 10.11.49.255 scope global ens33
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe97:9a7f/64 scope link
       valid_lft forever preferred_lft forever
3: ens34: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 00:50:56:97:fa:74 brd ff:ff:ff:ff:ff:ff
    altname enp2s2
```

 Ahí podemos ver que la interfaz ens33 está correctamente configurada con mi Ip estática y que está activa. 
 
 ens34 aparece aunque no la hayas configurado:

- ip a muestra todas las interfaces físicas o virtuales detectadas por el sistema, no solo las que se hayan configurado en /etc/network/interfaces.

- En mi caso, ens34 es otra tarjeta de red física o virtual de la máquina (por ejemplo, otra NIC de la máquina virtual o puerto adicional).

- Aunque esté ahí, no tiene IP asignada, y como la dejé comentada en /etc/network/interfaces, no se levanta con IP


Otra comprobación:
```bash
root@ismael:~# ping 10.11.48.1
PING 10.11.48.1 (10.11.48.1) 56(84) bytes of data.
64 bytes from 10.11.48.1: icmp_seq=1 ttl=64 time=0.337 ms
64 bytes from 10.11.48.1: icmp_seq=2 ttl=64 time=0.351 ms
64 bytes from 10.11.48.1: icmp_seq=3 ttl=64 time=0.434 ms
64 bytes from 10.11.48.1: icmp_seq=4 ttl=64 time=0.375 ms
^C
--- 10.11.48.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3039ms
rtt min/avg/max/mdev = 0.337/0.374/0.434/0.037 ms
```

#### CONCLUSIÓN:
- Tu IP estática 10.11.48.169 funciona correctamente.

- La máquina puede comunicarse con el gateway.

- La interfaz ens33 está activa y lista para usar SSH o otras conexiones de red.
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


**Añadir en hosts nuestra IP y la del compañero**
```bash
su -
nano /etc/hosts
```


Añadir:
```bash
10.11.48.169  ismael
10.11.48.175  lucas
```


- 10.11.48.169  ismael:
   - Esto hace que tu máquina se pueda referir a sí misma como ismael.

   - Opcional, no estrictamente necesario si ya estás dentro de tu máquina.
 
- 10.11.48.175  lucas
  - Esto permite que desde tu máquina puedas hacer ssh lsi@pc-compañero en vez de escribir la IP.
  - Utilidades:
     - SSH más fácil: ssh lsi@pc-compañero

     - Ping más legible: ping lucas

     - Copias de archivos más fáciles: scp archivo.txt lsi@lucas:/home/lsi/

     - Evitas memorizar IPs: si cambian las IPs, solo actualizas /etc/hosts.
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

### **Apartado B) ¿Qué distro y versión tiene la máquina inicialmente entregada?. Actualice su máquina a la última versión estable disponible.**

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

### Herramienta para ver ambas con un comando: hostnamectl (preinstalada) y neofetch
```bash
root@ismael:~# hostnamectl
 Static hostname: ismael
       Icon name: computer-vm
         Chassis: vm 🖴
      Machine ID: db1c24869f59488fb51181a0eb0bcae8
         Boot ID: 415ae81d808841ed9fa9fce59ecde482
  Virtualization: vmware
Operating System: Debian GNU/Linux 12 (bookworm)
          Kernel: Linux 6.1.0-39-amd64
    Architecture: x86-64
 Hardware Vendor: VMware, Inc.
  Hardware Model: VMware Virtual Platform
Firmware Version: 6.00
```

```bash
sudo
apt install neofetch
```

```bash
neofetch
```

![Neofetch](../images/neofetch.png)

### Actualizar a Debian 11 (Buster -> BullSeye)

1. Ninguna actualización con update o upgrade va funcionar en Debian 10 ya que no está soportado oficialmente y los repositorios han sido movidos a archive.debian.org. apt intenta buscar archivos que ya no existen.

Por tanto, vamos a cambiar el contenido del archivo sources.list para poder actualizar los últimos paquetes de la versión 10.

```bash
sudo nano /etc/apt/sources.list

#

# deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

#deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

deb http://archive.debian.org/debian buster main contrib non-free
deb-src http://archive.debian.org/debian buster main contrib non-free

deb http://archive.debian.org/debian-security buster/updates main contrib non-free
deb-src http://archive.debian.org/debian-security buster/updates main contrib non-free

# buster-updates, previously known as 'volatile'
deb http://archive.debian.org/debian buster-updates main contrib non-free
deb-src http://archive.debian.org/debian buster-updates main contrib non-free
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

Cambiamos el archivo de source.list de forma que quede tal que así:

```bash
lsi@debian:~$ sudo nano /etc/apt/sources.list
lsi@debian:~$ cat /etc/apt/sources.list
#

# deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

#deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

deb http://deb.debian.org/debian bullseye main contrib non-free
deb-src http://deb.debian.org/debian bullseye main contrib non-free

deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb-src http://security.debian.org/debian-security bullseye-security main contrib non-free

# buster-updates, previously known as 'volatile'
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb-src http://deb.debian.org/debian bullseye-updates main contrib non-free
```


Ahora hacemos al igual que antes los siguientes pasos:
```bash
sudo apt update
sudo apt upgrade -y
sudo apt full-upgrade -y
sudo apt autoremove -y
sudo apt autoclean
```



## Problemas con las actualizaciones: se queda parada la instación por que se cierra el ssh

Si mientras estaba haciendo los comandos "sudo apt upgrade -y" o "sudo apt full-upgrade -y" se paró la actualización, debemos arreglar los paquetes.


**Cosas que hice**:

1. Matar procesos:
```bash
sudo kill -9 5900 5899
sudo kill -9 20607
```
- -9: Señal SIGKILL - la más fuerte, no se puede ignorar

- 5900 5899 20607: Números de identificación de los procesos (PID)


2. Eliminar archivos de bloqueo:
```bash
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/dpkg/lock  
sudo rm /var/cache/apt/archives/lock
```

3. Comprobar paquetes pendientes de instalación
```bash
sudo dpkg --configure -a
```
Este comando intenta configurar todos los paquetes que estén descargados pero no completamente configurados. No muestra una lista explícita, pero si hay errores, los verás en la salida.


4. Comprobar paquetes rotos o dependencias
```bash
sudo apt install -f
```
-f → significa fix broken

Por tanto este comando detecta paquetes con dependencias incompletas o conflictos e intenta repararlos automáticamente.


Ya por último hacemos una limpieza del sistema. 

Es recoendable usar --dry-run antes de hacer un autoremove para ver todos los paquetes que van a ser eliminados.
```bash
sudo apt autoremove --dry-run
```

Limpiar los paquetes viejos
```bash
apt autoremove -y
apt autoclean
```


### Actualizar a Debian 12 (BullSeye -> Bookworm)

Cambiar el sources.list:
```bash
#

# deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

#deb cdrom:[Debian GNU/Linux 10.4.0 _Buster_ - Official amd64 DVD Binary-1 20200509-10:26]/ buster contrib main

deb https://deb.debian.org/debian bookworm main non-free-firmware
deb-src https://deb.debian.org/debian bookworm main non-free-firmware

deb https://security.debian.org/debian-security bookworm-security main non-free-firmware
deb-src https://security.debian.org/debian-security bookworm-security main non-free-firmware

# buster-updates, previously known as 'volatile'
deb https://deb.debian.org/debian bookworm-updates main non-free-firmware
deb-src https://deb.debian.org/debian bookworm-updates main non-free-firmware
```


```bash
sudo apt update           # Actualiza la lista de paquetes
sudo apt upgrade -y       # Actualiza paquetes sin eliminar nada. NO ES OBLIGATORIO. Podemos usar full-upgrade directamente
sudo apt full-upgrade -y  # Actualiza todo, incluso si requiere eliminar o reemplazar paquetes
sudo apt autoremove -y    # Limpia paquetes antiguos que ya no se usan
apt autoclean
```

Vamos a reiniciar la máquina para comprobar que está actualizado y sin problemas.
```bash
su
reboot
```


Ya tenemos todo instalado y limpio, pero no se me ha instalado la última versión del kernel del debian 12. Por tanto vamos a intentar actualizarla más:

```bash
sudo apt update
sudo apt install linux-image-amd64 linux-headers-amd64   #instala el kernel predeterminado de Debian 12 (paquete linux-image-amd64) y los headers del kernel (linux-headers-amd64) necesarios para compilar módulos o drivers si los necesitaras
sudo reboot
```


Ya por último vamos a borrar todo sobre los kernels 10 y 11 y dejar solo el 12:
```bash
lsi@ismael:~$ dpkg --list | grep linux-image
dpkg --list | grep linux-headers
rc  linux-image-4.19.0-27-amd64             4.19.316-1                          amd64        Linux 4.19 for 64-bit PCs (signed)
rc  linux-image-4.19.0-9-amd64              4.19.118-2+deb10u1                  amd64        Linux 4.19 for 64-bit PCs (signed)
ii  linux-image-5.10.0-35-amd64             5.10.237-1                          amd64        Linux 5.10 for 64-bit PCs (signed)
ii  linux-image-6.1.0-39-amd64              6.1.148-1                           amd64        Linux 6.1 for 64-bit PCs (signed)
ii  linux-image-amd64                       6.1.148-1                           amd64        Linux for 64-bit PCs (meta-package)
ii  linux-headers-6.1.0-39-amd64            6.1.148-1                           amd64        Header files for Linux 6.1.0-39-amd64
ii  linux-headers-6.1.0-39-common           6.1.148-1                           all          Common header files for Linux 6.1.0-39
ii  linux-headers-amd64                     6.1.148-1                           amd64        Header files for Linux amd6
```

Borrar kernels antiguos:
```bash
sudo apt purge -y linux-image-4.19.*-amd64 linux-image-5.10.*-amd64
sudo apt purge -y linux-headers-4.19.*-amd64 linux-headers-5.10.*-amd64
```

Limpiar paquetes huérfanos:
```bash
sudo apt autoremove --purge -y
sudo apt autoclean
```

### RESUMEN DE TODOS LOS COMANDOS UTILIZADOS PARA ACTUALIZAR DEBIAN:
```bash
# Repositorios
sudo nano /etc/apt/sources.list   # Editar repositorios a nueva versión

# Listas y actualizaciones
sudo apt update -o Acquire::Check-Valid-Until=false  # Actualizar lista ignorando fechas expiradas
apt list --upgradable                               # Ver paquetes actualizables
sudo apt upgrade -y                                 # Actualizar paquetes sin romper dependencias
sudo apt full-upgrade -y                            # Actualizar todo, incluso cambios de dependencias
sudo apt autoremove -y                              # Limpiar paquetes que ya no se usan
sudo apt autoclean                                  # Limpiar .deb descargados

# Problemas con bloqueos
sudo kill -9 PID                                    # Matar procesos colgados (apt/dpkg)
sudo rm /var/lib/dpkg/lock-frontend                 # Quitar lock de dpkg
sudo rm /var/lib/dpkg/lock
sudo rm /var/cache/apt/archives/lock

# Reparar paquetes
sudo dpkg --configure -a                             # Configurar paquetes pendientes
sudo apt install -f                                  # Arreglar dependencias rotas

# Kernel
sudo apt install linux-image-amd64 linux-headers-amd64  # Instalar kernel y headers de Debian 12
sudo reboot                                            # Reiniciar para aplicar cambios

# Información útil
uname -r          # Versión actual del kernel
lsb_release -a    # Información de la distro
neofetch          # Info completa de sistema y kernel (opcional)
```


dpkg hace la “operación cruda” sobre paquetes, apt hace lo mismo pero además busca dependencias y repositorios automáticamente.



---
### **Apartado C) Identifique la secuencia completa de arranque de una máquina basada en la distribución de referencia (desde la pulsación del botón de arranque hasta la pantalla de login). ¿Qué target por defecto tiene su máquina?. ¿Cómo podría cambiar el target de arranque?. ¿Qué targets tiene su sistema y en qué estado se encuentran?. ¿Y los services?. Obtenga la relación de servicios de su sistema y su estado. ¿Qué otro tipo de unidades existen?. Configure el sudo de su máquina.**

Lo primero de todo (ya lo hemos hecho, pero por si no está hecho aún), vamos a configurar sudo:
```bash
su -
apt install sudo
usermod -aG sudo lsi
```



Breve resumen de la secuencia de arranque:
La secuencia completa sería algo así:

  1. Encender máquina → BIOS/UEFI hace comprobaciones.
  
  2. MBR/GRUB → carga el kernel.
  
  3. Kernel arranca → aquí es cuando puedes ver mensajes con dmesg.
  
  4. Systemd toma el control → aquí es cuando puedes ver todo con journalctl -b.
  
  5. Se levantan servicios (red, login, etc.) → también registrado en journalctl -b.

  6. Llegas a la pantalla de login.


#### Cómo verlo en Linux

- dmesg → mensajes del kernel desde el arranque.

- journalctl -b → todo lo que hizo systemd durante este arranque.

- systemd-analyze → cuánto tardó cada parte del arranque.  

- systemctl list-dependencies default.target Lista todas →  las units (servicios y targets) que dependen del target por defecto, es decir, todo lo que se inicia automáticamente cuando arranca tu máquina.


TODO ESTO HACERLO DENTRO DEL USUARIO ROOT!!

<br>

**mesg (display message o diagnostic message)**:

Muestra los mensajes que el kernel va escribiendo desde que se arranca la máquina.

Ejemplos de mensajes que muestra:

      Memoria detectada
            
      CPU detectada
            
      Discos y particiones
            
      Tarjetas de red
            
      Errores de hardware o drivers

```bash
dmesg
```

Otra forma de verlo paso por paso en vez de ver toda la salida de golpe:
```bash
dmesg | less
```
 - | → Esto le pasa la salida del comando dmesg al siguiente comando que es less
 - less → es un visor de texto en Linux. Permite ver archivos o salidas de comandos de forma paginada, sin que todo salga de golpe en la pantalla. A diferencia de cat,que muestra todo y se va al final, less te deja moverte arriba y abajo para leer con calma.

Para salir de less, presiona q.

<br>


** journalctl -b**
Herramienta para leer los logs de systemd (que es el sistema de inicio moderno de Debian, Ubuntu, Fedora, etc.)

La opción -b significa "desde el arranque actual".

Te muestra todo lo que hizo systemd (y los servicios que maneja) desde que encendiste la máquina hasta ahora.

```bash
journalctl -b
```

<br>


**systemd-analyze**   -> Tiempo de botado de kernel (**APARTADO D**)

Mide cuánto tarda cada parte del arranque de tu sistema. Te da un resumen de kernel + userspace (espacio de usuario).

- Kernel time → tiempo que tardó el kernel en inicializar hardware y preparar el sistema de archivos raíz (/).

- Userspace time → tiempo que tardó systemd en iniciar todos los servicios hasta que el sistema está listo (login gráfico o multiusuario).


```bash
root@ismael:/home/lsi# systemd-analyze
Startup finished in 16.086s (kernel) + 1min 45.089s (userspace) = 2min 1.176s
graphical.target reached after 1min 45.050s in userspace.
```

16.086s (kernel) → el kernel tardó 16 segundos en inicializar el hardware y montar el sistema de archivos.

1min 45.089s (userspace) → systemd y todos los servicios tardaron 1 minuto 45 segundos en iniciarse.

2min 1.176s → tiempo total desde que encendiste la máquina hasta que el sistema está listo.

graphical.target reached after 1min 45.050s → la interfaz gráfica (login) estuvo lista justo después de los 1:45 min de userspace.

En resumen: el kernel arranca rápido, lo que más tarda son los servicios del sistema y la interfaz gráfica.


```bash
systemd-analyze blame
```
Este comando muestra los servicios que se iniciaron durante el arranque, ordenados por el tiempo que tardó cada uno en arrancar.

Sirve para identificar qué servicios ralentizan el inicio de tu sistema.

<br>

**systemctl list-dependencies default.target**
Lista todas las units (servicios y targets) que dependen del target por defecto, es decir, todo lo que se inicia automáticamente cuando arranca tu máquina.
```bash
root@ismael:/home/lsi# systemctl list-dependencies default.target
default.target
○ ├─anacron.service
● ├─avahi-daemon.service
● ├─console-setup.service
● ├─cron.service
● ├─cups-browsed.service
● ├─cups.path
● ├─cups.service
● ├─dbus.service
○ ├─e2scrub_reap.service
● ├─ModemManager.service
● ├─networking.service
● ├─NetworkManager.service
● ├─open-vm-tools.service
● ├─plymouth-quit-wait.service
● ├─plymouth-quit.service
● ├─pulseaudio-enable-autospawn.service
● ├─rsyslog.service
● ├─run-vmblock\x2dfuse.mount
○ ├─ssa.service
● ├─ssh.service
● ├─systemd-ask-password-wall.path
● ├─systemd-logind.service
○ ├─systemd-update-utmp-runlevel.service
● ├─systemd-user-sessions.service
○ ├─tpm2-abrmd.service
○ ├─unattended-upgrades.service
● ├─wpa_supplicant.service
● ├─basic.target
● │ ├─-.mount
● │ ├─low-memory-monitor.service
○ │ ├─tmp.mount
● │ ├─paths.target
● │ ├─slices.target
● │ │ ├─-.slice
● │ │ └─system.slice
● │ ├─sockets.target
● │ │ ├─avahi-daemon.socket
● │ │ ├─cups.socket
● │ │ ├─dbus.socket
● │ │ ├─systemd-initctl.socket
● │ │ ├─systemd-journald-audit.socket
● │ │ ├─systemd-journald-dev-log.socket
● │ │ ├─systemd-journald.socket
● │ │ ├─systemd-udevd-control.socket
● │ │ └─systemd-udevd-kernel.socket
● │ ├─sysinit.target
● │ │ ├─apparmor.service
● │ │ ├─dev-hugepages.mount
● │ │ ├─dev-mqueue.mount
● │ │ ├─keyboard-setup.service
```

Interpretación rápida

- ○ → unit cargada pero inactiva.

- ● → unit activa (está corriendo ahora).

- ├─ y │ → representan la jerarquía o dependencias entre unidades.

<br>
<br>

###  💳 Target 

Un target es como un “objetivo de arranque” del sistema. Le dice a Linux qué servicios y programas debe iniciar cuando enciendes el ordenador. Es como elegir un “modo de arranque”: con pantalla, sin pantalla, modo recuperación

Piensa en tu ordenador como si fuera un coche. Cuando enciendes el coche, puedes arrancar de diferentes maneras:

  - Modo normal → arranca todo (motor, luces, radio…).
  
  - Modo ahorro → solo arranca lo básico (motor y luces).
  
  - Modo mantenimiento → solo algunas cosas para revisar fallos.


**Target por defecto: systemctl get-default**

Es el target que Linux usa automáticamente al encender.

Existen distintos tipos de target en los sistemas Linux. Los más básicos son:

- Escritorio e interfaz gráfica→ graphical.target

- Modo multiusuario sin GUI, incluye red y servicios básicos → multi-user.target

```bash
root@ismael:/home/lsi# systemctl get-default
graphical.target
```

Esto significa que tu ordenador arrancará con la pantalla de login y el escritorio, como un PC normal de uso diario.El problema es que tal y como estamos usando nuestra máquina (sin login y sin escritorio), esta opción no es la más recomendada porque consume recursos innecesarios como CPU y memoria.

<br>

**Cambiar el target de arranque: systemctl set-default multi-user.target**

Aquí deberíamos poder cambiar el target por el de servidor (multi-user.target), ya que el que está por defecto no nos interesa ya que solo nos vamos a conectar a la máquina por ssh y no necesitamos la interfaz gráfica.
```bash
root@ismael:/home/lsi# systemctl set-default multi-user.target
Created symlink /etc/systemd/system/default.target → /lib/systemd/system/multi-user.target.
root@ismael:/home/lsi# reboot
```

Ahora nuestra máquina irá mejor. Podemos comprobar esto analizando el tiempo de botado de la máquina:
```bash
root@ismael:/home/lsi# systemd-analyze
Startup finished in 12.532s (kernel) + 2min 14.466s (userspace) = 2min 26.998s
multi-user.target reached after 2min 14.432s in userspace.
```
Vemos que el tiempo aquí ya se redujo respecto a la primera vez que lo hicimos. Paso de 16 segundos a 12 ya.
<br>

**Todos los targets del sistema: systemctl list-units --type=target**

Muestra todos los targets cargados en tu sistema, es decir, los “modos de arranque” o conjuntos de servicios que se pueden iniciar.
  - list-units → lista las unidades (units) cargadas actualmente en el sistema.
  - --type=target  → filtra la lista solo mostrando las units que son targets.

```bash
root@ismael:/home/lsi# systemctl list-units --type=target
  UNIT                   LOAD   ACTIVE SUB    DESCRIPTION
  basic.target           loaded active active Basic System
  cryptsetup.target      loaded active active Local Encrypted Volumes
  getty.target           loaded active active Login Prompts
  graphical.target       loaded active active Graphical Interface
  integritysetup.target  loaded active active Local Integrity Protected Volumes
  local-fs-pre.target    loaded active active Preparation for Local File Systems
  local-fs.target        loaded active active Local File Systems
  multi-user.target      loaded active active Multi-User System
  network-online.target  loaded active active Network is Online
  network.target         loaded active active Network
  nss-user-lookup.target loaded active active User and Group Name Lookups
  paths.target           loaded active active Path Units
  remote-fs.target       loaded active active Remote File Systems
  slices.target          loaded active active Slice Units
  sockets.target         loaded active active Socket Units
  swap.target            loaded active active Swaps
  sysinit.target         loaded active active System Initialization
  timers.target          loaded active active Timer Units
  veritysetup.target     loaded active active Local Verity Protected Volumes

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
19 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
```

```text
TIPOS DE TARGET EN LIUX (SYSTEMD)

basic.target → Servicios básicos del sistema, arranca primero.

cryptsetup.target → Volúmenes cifrados locales.

getty.target → Consolas de login en modo texto.

graphical.target → Interfaz gráfica / escritorio (GUI).

integritysetup.target → Volúmenes con protección de integridad.

local-fs-pre.target → Preparación antes de montar sistemas de archivos locales.

local-fs.target → Montaje de sistemas de archivos locales.

multi-user.target → Modo multiusuario sin GUI, incluye red y servicios básicos.

network-online.target → Red completamente lista y funcionando.

network.target → Servicios de red básicos inicializados.

nss-user-lookup.target → Resolución de usuarios y grupos (nombre → ID).

paths.target → Unidad que gestiona “path units” (supervisión de rutas de archivos).

remote-fs.target → Montaje de sistemas de archivos remotos (NFS, etc.).

slices.target → Gestión de “slices” de recursos del sistema (cgroups).

sockets.target → Sockets de red o locales que activan servicios bajo demanda.

swap.target → Activación de espacio de intercambio (swap).

sysinit.target → Inicialización del sistema: dispositivos, reloj, etc.

timers.target → Temporizadores para iniciar servicios automáticamente.

veritysetup.target → Volúmenes con verificación de integridad (dm-verity).
```
<br>



### RESUMEN FÁCIL SOBRE EL TIEMPO DE ARRANQUE Y LOS TARGETS

- Para averiguar nuestro target por defecto -> systemctl get-default
- Para cambiar el target de arranque -> systemctl set-default xxx.target (hemos puesto
multi-user.target)
- Para ver el arranque de la máquina a partir del target que tengamos por defecto -> systemctl list-dependencies default.target
- Para averiguar los targets en memoria -> systemctl list-units –type=target
- Para averiguar los targets instalados -> systemctl list-unit-files –type=target
- Para averiguar los servicios en memoria -> systemctl list-units –type=service
- Para averiguar los servicios instalados -> systemctl list-unit-files –type=service
- Para averiguar todos los tipos de unidades -> systemctl list-units
***Para mostrar el árbol de dependencias de la máquina -> systemctl list-dependencies






















