# PRÁCTICA 2 - Seguridad Informática

DEFENSA DE LA PRÁCTICA: 11 (en principio). Semana del 10 al 14 -> Apagan las máquinas el 7 de noviembre.

**Objetivo:** El objetivo de esta práctica es aprender y experimentar con la captura y el análisis del tráfico de red mediante sniffers, comprender y probar ataques DoS/DDoS, y trabajar la llamada «trilogía»: descubrimiento de hosts, escaneo de puertos y fingerprinting de sistemas (conjunto de técnicas usadas para identificar características de un equipo o servicio en la red). Además, se pretende gestionar y analizar la información de auditoría generada durante las pruebas, empleando en el laboratorio distintas herramientas sugeridas para practicar y validar los conceptos.

 1- Sniffers y análisis de tráfico: a, b, c, d.
 
 2- Ataques Man in the Middle: e, f.
 
 3-Detección y monitorización: g, i, j.
 
 4-Reconocimiento y escaneo de red: h, n, o
 
 5-Ataques y protección de servicios: k, l, p
 
 6-Sistemas de detección y respuesta: q, r 


En esta práctica se van a realizar muchos escaneos, ataques y defensas, por lo que se van a generar muchos logs en nuestro sistema. Tendremos que ir comprobando los logs poco a poco así como el espacio para que no se nos llene el disco ni ocurran cosas raras en nuestras máquinas.

**IMPORTANTE:** Mirar una vez al día cuánto espacio tiene nuestra máquina y cuando ocupa nuestro log de la máquina. Nos podemos encontrar hasta logs de 5 GB que no valen para nada.

## Repaso COMANDOS BÁSICOS útiles para la práctica

```bash
#Accesos
last               # Sesiones de usuarios accedidas a la máquina
date               # Hora sesión actual

# Navegación
pwd                 # Carpeta actual
ls                  # Listar
ls -l               # Listar con detalles
ls -a               # Incluir ocultos

cd /ruta            # Cambiar carpeta
cd ~                # Ir al home (~ es el directorio home del usuario actual)
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
     tail -n archivo.log # Especificar las últimas N líneas
     tail -f archivo.log # Ver en tiempo real

# Búsqueda
find / -name "archivo.txt"  # Buscar archivo
grep                # Se utiliza para buscar y filtrar líneas de texto que coinciden con un patrón específico
    grep "texto" archivo.txt    # Buscar texto
    grep -r "texto" /ruta       # Buscar en varios archivos

# Redirección y tuberías (pipes)
> sobreescribe el archivo
>> añade al final del archivo

| tubería. Envía la salida de un comando como entrada de otro comando, conectando procesos en serie

# Permisos
ls -l               # Ver permisos
chmod 755 archivo   # Cambiar permisos
chown usr:grp arch  # Cambiar propietario

# Procesos
ps               # Procesos ligados a tu terminal actual
   -e            # Muestra todos los procesos del sistema 
   -a            # Procesos de todos los usuarios (excepto los sin terminal)
   -u            # Procesos con info del usuario, CPU, memoria, etc.
   -x            # Incluye procesos sin terminal (daemons, servicios)
ps aux           # Vista clásica estilo BSD, muestra todos los procesos con detalles
ps -ef           # Vista estilo Unix System V, alternativa a aux

top                 # Procesos en tiempo real
sudo systemd-cgtop  # Procesos en tiempo real de los grupos de control
watch               # Ejecuta un comando repetidamente
   -n <segundos>    # Intervalo de actualización (por defecto 2 segundos)
   -d               # Resalta los cambios en cada actualización
kill PID            # Terminar proceso

# Paquetes (Debian/Ubuntu)
sudo apt update           # Actualizar lista
sudo apt upgrade          # Actualiza los paquetes instalados a sus versiones nuevas, sin eliminar ni instalar paquetes adicionales
sudo apt full-upgrade     # Actualiza todo el sistema, incluso si para hacerlo debe instalar o eliminar paquetes
sudo apt install paquete  # Instalar
sudo apt remove paquete   # Eliminar
dpkg -l | wc -l           # Lista todos los paquetes instalados  y wc -l cuenta las líneas, es decir, el total de paquetes
        -dpkg -l → lista todos los paquetes.
        -grep '^ii' → filtra los que están instalados (ii)
        -wc -l → cuenta cuántos hay

#Limpieza
apt autoremove  # Limpia espacio quitando dependencias que ya no usa ningún paquete.
apt autoclean   # Borra archivos de instalación (.deb) viejos o inutilizables del caché de APT
apt purge nombre_paquete   # Desinstala y borra también archivos de configuración

# Red
ping 8.8.8.8         # Probar conexión
    -c:              # Especifica cuantos paquetes se van a mandar
ping6 2002:0a0b:3032::1 # Probar conexión IPv6
tracert ip           # Muestra el camino a seguir para alcanzar una IP

 **IP moderno**
ip a                         # Ver IP
ip addr show                 # Igual que ip a
ip addr add <IP>/<mask> dev <interfaz>   # Añadir dirección IP temporal
ip addr del <IP>/<mask> dev <interfaz>   # Quitar dirección IP
ip link show                 # Mostrar estado de interfaces
ip link set <interfaz> up    # Activar interfaz
ip link set <interfaz> down  # Desactivar interfaz
ip route show                # Mostrar tabla de rutas
ip route add <red> via <gateway> dev <interfaz>  # Añadir ruta
ip route del <red>           # Eliminar ruta

**ifconfig (antiguo)**
ifconfig                     # Mostrar interfaces activas
ifconfig <interfaz>          # Mostrar detalles de interfaz
ifconfig <interfaz> up       # Activar interfaz
ifconfig <interfaz> down     # Desactivar interfaz
ifconfig <interfaz> <IP> netmask <mask>  # Asignar IP temporal
ifconfig <interfaz>:<n> <IP> netmask <mask>  # Crear alias/interfaz lógica

**route (rutas)**
route -n                     # Mostrar tabla de rutas
route add default gw <gateway>        # Añadir puerta de enlace predeterminada
route del default gw <gateway>        # Eliminar puerta de enlace predeterminada
route add -net <red> gw <gateway>    # Añadir ruta específica
route del -net <red> gw <gateway>    # Eliminar ruta específica

**sockets**
1-Alternativa nueva
ss           # Muestra todos los sockets
   -t        # TCP
   -u        # UDP
   -l        # Solo sockets escuchando (listening)
   -n        # Mostrar IPs y puertos en números (no nombres)
   -p        # Mostrar PID y proceso que usa el socket
   -a        # Mostrar todos los sockets (escuchando y conectados)
   -s        # Resumen de conexiones por tipo

2-Alternativa clásica (más lento que ss, pero muy usada)
netstat
   -t        # TCP
   -u        # UDP
   -l        # Solo escuchando
   -n        # Números en lugar de nombres
   -p        # PID/Nombre del proceso
   -a        # Todas las conexiones y puertos escuchando
   -r        # Tabla de rutas
   -s        # Estadísticas de protocolos
   -i        # Interfaces de red
   -o        # Muestra información adicional relacionada con los temporizadores de las conexiones TCP

 
wget <url>                    # Descarga el contenido en un archivo con el mismo nombre que en el servidor
wget -o | -O <url>                 
		-o (o minúscula) → guarda el registro (mensajes) en un archivo.
		-O (O mayúscula) → guarda el archivo descargado con ese nombre.
wget --spider https://www.google.com  # Comprueba si la URL está disponible sin descargar nada
wget --timeout=10 https://www.google.com  # Límite de espera antes de rendirse
wget --server-response --spider <url>  # Hace la petición y muestra únicamente los headers HTTP, sin guardar nada
wget -q <url>                 # Descarga sin mostrar barras ni mensajes, solo errores.


curl <url>                   # Probar conexión HTTP/HTTPS y obtener contenido
curl -I <url>                # Solo encabezados HTTP
curl -s <url>                # Silencioso, sin mostrar progreso
curl -O <url>                # Descargar archivo
curl -L <url>                # Seguir redirecciones


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
systemctl            # Gestiona el estado de los servicios del sistema
   - list-units → “lista las unidades que están activas ahora”
   - list-unit-files → “lista todas las unidades que existen y su configuración de inicio”
          ---type = service | target | socket | mount | device | timer | path | slice | automount | swap
          --state = active | inactive | enabled | disabled | masked | static
   - status <unidad> → “muestra el estado detallado de una unidad o servicio específico”
   - start <unidad> → “inicia un servicio/unidad”
   - stop <unidad> → “detiene un servicio/unidad”
   - restart <unidad> → “reinicia un servicio/unidad”
   - enable <unidad> → “configura la unidad para que arranque automáticamente”
   - disable <unidad> → “desactiva el arranque automático de la unidad”
   - get-default → “muestra el target por defecto del sistema”
   - set-default <target> → “cambia el target por defecto del sistema (permanente)”
   - isolate <target> → “cambia al target especificado inmediatamente (temporal)”
   - daemon-reload  →  e dice a systemd que recargue todas las unidades y servicios

	# Logs
Dos formas de ver los logs:
1-De forma centralizada: journald -> journalctl
journalctl           # Muestra los registros (logs) de los servicios y del sistema
     -b → “muestra los logs desde el último arranque”
     -a → “muestra todas las líneas completas, incluso las truncadas por pantalla”
     -p err → Muestra solo los mensajes de error (y más graves) del sistema
     -p warning → muestra solo mensajes de nivel warning y más graves (error, crítico, alerta)
     -x → Explica los mensajes del log con información extra si está disponible.
     -e → Va directamente al final de los logs (útil para ver los últimos errores)
     -u <unidad> → “filtra los logs de una unidad o servicio específico”
     -f  → “muestra los logs en tiempo real (como tail -f)”
     --since "YYYY-MM-DD HH:MM:SS" → “muestra logs desde una fecha/hora específica”
     --until "YYYY-MM-DD HH:MM:SS" → “muestra logs hasta una fecha/hora específica”

2-Accediendo a las carpetas de /var/log y viendo los logs que de cada tipo:
/var/log/syslog: mensajes generales del sistema
/var/log/auth.log:  autenticación, sudo, logins
/var/log/dpkg.log → instalación de paquetes
...

uptime               # Tiempo encendido
reboot               # Reiniciar
shutdown now         # Apagar

# Flag de ayuda para ver comandos grandes de golpe
--no-pager           # No hay paginación


## PRÁCTICA 2

# Transferencia de archivos
scp archivo_origen lsi@ip:directorio_destino

ETTERCAP — CHULETA DE FLAGS (TODO EN UN SOLO BLOQUE, TEXTO PLANO)

# Modos / interfaz
-T                        modo texto (CLI). Veremos toda la info de la red. Dentro de esta nos pedirá elegir:

	h → help. Ver ayuda completa de comandos disponibles

    s → statistics. Ver estadísticas de tráfico capturado

    l → list. Listar todos los hosts descubiertos (los 230)

    c → connections. Ver la lista de conexiones 

    q → Salir del programa

-C (NO USAR)                       modo curses (menús en terminal; más estructurado que -T).
-G (NO USAR)                       modo gráfico (GTK) — NO usar en servidores sin X.

# Ayuda / info
-h, --help                muestra ayuda.
-v, --version             muestra versión.
-q                        quiet: reduce verbosidad (menos salida en pantalla).

# Interfaz / captura
-i <iface>                usar interfaz (ej: eth0, wlan0).
-p, --nopromisc           no poner la interfaz en modo promiscuo.
-w <archivo.pcap>         guardar captura en archivo pcap.
-r <archivo.pcap>         leer tráfico desde un pcap (modo offline).
--autosave                (según versión) guardar automáticamente pcap.

# MitM / métodos de ataque
-M <METHOD:ARGS>          lanzar ataque man-in-the-middle.
                          Ejemplos:
                            -M arp:remote /IP1/ /IP2/   # engaña a IP1 y IP2 para que todo su tráfico pase por tu máquina (ARP poisoning entre dos hosts).
                            -M arp:gateway /IP_victima/ # hace creer a la víctima que tú eres el gateway (redirige su tráfico al gateway a través tuyo).
                            -M syn /IP1/ /IP2/          # usa método SYN (según versión, puede usarse para ciertos ataques/mitm).

-o                        only-mitm: solo hacer poisoning (no procesar/sniffear paquetes).
-B <iface1> <iface2>      modo bridge (inline) entre dos interfaces (filtrado inline).


# Filtros / modificaciones
-F <filtro_compilado>     cargar filtro compilado (output de etterfilter).
etterfilter input.ef -o out.ef   # compilar filtro antes de usarlo.
                          filtros permiten reemplazar cadenas, inyectar respuestas, bloquear, etc.

# Plugins
-P <plugin>               cargar plugin (ej: dns_spoof, chk_poison, autoadd, remote_browser).
                          algunos plugins requieren ficheros/config previos (hosts, reglas).

# Opciones de comportamiento
-u, --unoffensive         no reenviar paquetes (modo no destructivo).
-S                        modo sniffer (según versión) / minimizar acciones intrusivas.
--local-mac <MAC>         usar MAC local especificada (cuando aplicable).
--remote-mac <MAC>        especificar MAC remota (cuando aplicable).

# Logging / output
--log <file>              (según versión) guardar logs en archivo.
--debug                   modo debug (muy verboso).
--pcap                   (sin -w) opciones relacionadas con pcap (varía por versión).

# Ejecución / automatización
-q                        quiet, útil para scripts.
-n                        (según versión) no resolver nombres DNS/hosts (más rápido).
--no-spoof-check          evitar comprobaciones de spoofing (según versión).

# Señales / parada
(en lugar de Ctrl+C) usar pkill -TERM ettercap o sudo kill <PID> para parada limpia.

```


<br>
<br>

## 1-SNIFFERS Y ANÁLISIS DE TRÁFICO

Sniffers (o analizadores de paquetes) son herramientas o programas software diseñados para capturar, monitorizar y analizar el tráfico de red que circula por un segmento de red. Su funcionamiento se basa en poner la tarjeta de red (NIC) en modo promiscuo, lo que le permite capturar todos los paquetes que pasan por la red, no solo los dirigidos específicamente a esa máquina.

### **Apartado a) Instale el ettercap y pruebe sus opciones básicas en línea de comando.**

Ettercap es una herramienta usada para hacer análisis y manipulación del tráfico de red, especialmente en redes LAN.
Se utiliza mucho en auditorías de seguridad para ver cómo viajan los datos y detectar posibles ataques o vulnerabilidades.

!!SOLO ANALIZAREMOS TRÁFICO IPv4!!

Vamos a instalar ettercap en nuestra máquina sin interfaz gráfica. Para eso:

```bash
apt install ettercap-text-only
```

Al instalarlo con text-only no dejará entrar al modo interactivo. Esto quiere decir que cada vez que queramos hacer algo con ettercap solo podemos teclear sus comandos desde la línea de comandos. El modo interactivo es como una especie de shell dentro de nuestra línea de comandos, pero eso nosotros no lo hemos activado.


Llamamos a eterrcap por la línea de comandos. Ettercap tiene los siguientes parámetros principales:

- -T: modo solo texto. Muestra el tráfico de red en tiempo real. Muestra demasiada información, cientos de líneas por segundo. Subflags para -T:

- -q: Silencioso (menos output). Muestra solo LO IMPORTANTE ya que omite paquetes técnicos como ACK,SYN etc.

- -i: especificarle la interfaz. 

- -L: para escribir en un fichero con extension .ettrcap                                                                                                 
- -w: para escribir en un fichero con extension .pcap      

- -P <pluging> -> especificar que plugin usar
                                                             
- -r: para leer un fichero con extensión .pcap

- -t: filtrar por protocolo (http, tcp...)
 
- -M <metodos:argumentos> -> hace un ataque MITM(man in the middle). Subflags para -M:                                                                                                                                                 
    - arp:remote / arp:gateway -> para hacer un arp poisoning(ARP spoofing)                                          
	- icmp:MAC/IP -> ataque de redireccionamento icmp                                                          
    - DHCP:ip_pool/netmask/dns -> para un dhcp spoofing                                                         
    - port:remote/tree -> robo de puertos     

Para hacer ataques MiM, ettercap tiene **dos targets**. Esto significa que Ettercap necesita dos equipos entre los que va a ponerse en medio para espiar o alterar el tráfico.

- Target 1 (T1) = primer equipo (por ejemplo: la víctima, un PC).
	
- Target 2 (T2) = segundo equipo (por ejemplo: el router/gateway o otro PC).


No usar ettercap con target ///  -> no hacer esto porque colapsa porque se está leyendo toda la red.


¡IMPORTANTE!: a veces cerrar un comando con Ctrl+C de ettercap puede dar problemas. Para cerrar bien:

```bash
sudo pkill -TERM ettercap
# o si prefieres por PID:
sudo pgrep -a ettercap      # ver PID
sudo kill -TERM <PID>
```


<br>

---

### **Apartado b) Capture paquetería variada de su compañero de prácticas que incluya varias sesiones HTTP. Sobre esta paquetería (puede utilizar el wireshark para los siguientes subapartados)**

- **Identifique los campos de cabecera de un paquete TCP**  
- **Filtre la captura para obtener el tráfico HTTP**  
- **Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)**  
- **Visualice la paquetería TCP de una determinada sesión.**  
- **Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.**  
- **Obtenga información del tráfico de las distintas “conversaciones” mantenidas.**  
- **Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.**

 
!! Solo usaremos HTTP porque no va cifrado !!

Instalar **wireshark** en local y ver el tráfico del compañero -> tendremos que ver el gato que nuestro compañero descarga con curl. Cuidado con los balanceadores!! Buscar fotos que sean solo en http (https no que va cifrado).

Una vez instalado wireshark tenemos que instalar en la máquina **tcpdump** para poder ver el tráfico de la máquina en wireshark.


**PASOS ATAQUE-DEFENSA**

1- El atacante hace sniffing ao trafico do compañeiro:
```bash
ettercap -T -q -i ens33 -M arp:remote //10.11.48.175/ //10.11.48.1/ (sniffing da paqueteria)
```

Mientras esfina, en otro terminal:
```bash
tcpdump -i ens33 -s 65536 -w lsicompa.pcap
```

   [-i] é para espicificar a interfaz.
   [-s] o limite de bytes dos paquetes a capturar.
   [-w] o achivo donde se gardará.


<br>

2-Mientras el atacante hace el sniffing y guarda la paqueteria (tcpdump), la víctima busca imágenes, páginas, archivos en http (https no sirve ya que la info está cifrada):

 2.1- Archivo lsicompa:
```bash
   curl http://w3af.org/                                                                            #página W3AF
   curl http://www.edu4java.com/_img/web/http.png                                                   #foto de un servidor
```


2.1-Archivo lsicompa2:
```bash
curl http://securitylab.disi.unitn.it/lib/exe/fetch.php?media=teaching:netsec:2016:g4_-_mitm.pdf
curl http://cdn2.thecatapi.com/images/MTY3ODIyMQ.jpg
curl http://owasp.org/
```
Debería poder ver más adelante el atacante:
- pdf de man in the middle
- foto de un gato
- web de owasp

<br>

3- El atacante sale de ettercap con q (si salimos con ctrl+c tiramos ca conexion do compañeiro), fai ctrl+c no terminal onde está o tcpdump e enviamos o archivo á nosa maquina local:

  1º forma -> si temos windows e nos conectamos por ssh con mobaXTerm ou Bitvise SSH con arrastrar o archivo ao noso ordenador xa está.

  2º forma -> si non temos acceso ao noso arbol de directorios da maquina de lsi ou temos Linux executamos -> scp lsi@ip rutaArchivomáquina destinoLocal

  ```bash
 scp lsi@10.11.48.202:/home/lsi/lsicompa.pcap "C:\Users\User\Desktop\INGENIERIA_INFORMATICA\4_curso\1_CUATRI\LSI\P2\"
```

```bash
 scp lsi@10.11.48.202:/home/lsi/lsicompa2.pcap "C:\Users\User\Desktop\INGENIERIA_INFORMATICA\4_curso\1_CUATRI\LSI\P2\"
```

- lsicompa- http con página web e imagen de servidor
- lsicompa2- http con páginas web, imágenes y pdfs.

<br>

4- Abrimos Wireshark:

Arriba en archivos le damos a abrir y seleccionamos el archivo .pcap y veríamos toda la paqueteria que se capturo con el ettercap.


- **Identifique los campos de cabecera de un paquete TCP**

En la lista da paquetería buscamos un paquete TCP, pinchamos en uno y abajo nos pone las siguientes lineas:

    Frame 59: 165 bytes on wire (1320 bits), 165 bytes captured (1320 bits)
    Ethernet II, Src: VMware_97:24:d0 (00:50:56:97:24:d0), Dst: VMware_97:d5:d9 (00:50:56:97:d5:d9)
    .
    .
    .
    [SEQ/ACK analysis]
    TCP payload (111 bytes)      +

**Filtre la captura para obtener el tráfico http**
<img width="1595" height="171" alt="imagen" src="https://github.com/user-attachments/assets/c8dcc23d-43ba-4ca0-a84a-d3c3a04c2029" />


- **Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)**

1-IMÁGENES

Una vez que filtramos por http, pinchamos en una petición y miramos la estructura que tiene.

Para ver la imagen, accedemos al http que indica que tiene una imagen y vamos a su estructura.

Abajo del todo nos aparece en enlace:
<img width="1563" height="678" alt="imagen" src="https://github.com/user-attachments/assets/75469ca8-0c97-4cbd-a408-6c3d7cc36bf8" />

Clic derecho en el enlace -> Copiar -> Valor -> Pegamos la URL en internet y podemos visualizar la imagen
<br>

-PDFS:

Hacemos lo mismo que con las imágenes.


<br>

- **Visualice la paquetería TCP de una determinada sesión.**

Vamos a 'Analizar' > 'Seguir' > Secuencia tcp (tcp stream)


<br>

- **Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.**  

Vamos a 'Estadísticas' > Jerarquia de protocolo

<br>

- **Obtenga información del tráfico de las distintas “conversaciones” mantenidas.**

Vamos a 'Estadísticas' > Conversaciones

<br>

- **Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.**

Vamos a 'Estadísticas' > Puntos finales

<br>
<br>
---

### **Apartado c) Obtenga la relación de las direcciones MAC de los equipos de su segmento.**


Usar nmap. Solo ipv4


<br>
<br>
---

### **Apartado d) Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.**

Cuidado con localhost, que es virtual!!!




<br>
<br>

---

### **Apartado e) Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.**


Yo ataco y en mi pantalla veo lo que mi compañero ve en directo. Sus cambios como yo estoy en el medio, yo lo muestro en pantalla. Lo tenemos que ver simultaneamente. Tengo que ver como cambia mi pantalla mientras el hace cambios.


<br>
<br>

---

### **Apartado f) Instale metasploit. Haga un ejecutable que incluya un Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una víctima u objetivo lo ejecute.**


Elimino splunk e instalo metasploit. No dejarlo activo por defecto. Arrancarlo solo cuando sea necesario.

Como atacanntes vamos a engañar a la víctima para que lea un pdf. Es la víctima la que se conecta al ssh.
Buscar los comandos en wireshark, o darle a las flechas hasta que aparezca el que queramos.

Tenemos que darle permisos al fichero que le mandamos a nuestro compañero.
Tenemos que mandar dichos permisos a través de un túnel. Si no lo hacemos, no funciona.
Hay que usar meterpreter, que usa comandos distintos. Tenemos que saber que comandos tenemos que usar.


Una vez que sabemos que funciona metasploit, tenemos que hacer el filtro de ettercap (si encuentras un tag de este estilo, cambialo por eso otro -> tendremos que hacer esto en un html). Tenemos que usar ingenieria social. Tenemos que hacer que nuestro compañero entre en algo que trampa que le mandemos.


**Ingeniería Social**:
Creamos una ventanita en la que la víctima tiene que entrar. Va abrir un html normal y luego hacemos que funcione el ettercap.

1-Primero tiene que funcionar metasploit.
2-Luego ya tenemos que usar ettercap.





<br>
<br>

---

### **Apartado g) Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).**

**Carlos dice que sea lo último que hagamos antes de acabar la práctica 2!!!!**



<br>
<br>

---

### **Apartado h) Pruebe distintas técnicas de host discovey, port scanning y OS fingerprinting sobre las máquinas del laboratorio de prácticas en IPv4. Realice alguna de las pruebas de port scanning sobre IPv6. ¿Coinciden los servicios prestados por un sistema con los de IPv4?.**


NADA de IPv6.

De las que están activas cuales son sus MAC etc

Si ponemos toda la red, petamos el sistema!!!
Poner solo una red pequeña o solo al compañero y la puerta del enlace por ejemplo. Probar también todo el 48 (más riesgo).


<br>
<br>

---

### **Apartado i) Obtenga información “en tiempo real” sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.**


<br>
<br>

---

### **Apartado j) Monitorizamos nuestra infraestructura.:**

**- Instale prometheus y node_exporter y configúrelos para recopilar todo tipo de métricas de su máquina linux.**
  
**- Posteriormente instale grafana y agregue como fuente de datos las métricas de su equipo de prometheus.**

**- Importe vía grafana el dashboard 1860.**

**- En los ataques de los apartados m y n busque posibles alteraciones en las métricas visualizadas.**



En Prometeheus deberemos ver los datos de la máquina en tiempo real no en estático. La gráfica debe crecer hacia la ziquierda ycon picos altos cuanfo se relizan ataques como DoS debido a que hay mucho tráfico.

<br>
<br>
---

### **Apartado k) **PARA PLANTEAR DE FORMA TEÓRICA.: ¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.**

Carlos no lo mira mucho, solo Nino.



<br>
<br>

---

### **Apartado l) Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?**


Ataques Apache recomendados:
-perl

-python en Github: SlowLoris

<br>

Defensas Apache recomendadas:
-ModSecurity. Carlos obliga a usar ModSecurity. 

Existen 5 paquetes de apache que protegen sin querer.

Probar varios y probar que podemos atacar y nosotros podemos defendernos.

<br>
<br>

---

### **Apartado m) Instale y configure modsecurity. Vuelva a proceder con el ataque del apartado anterior. ¿Qué acontece ahora?**


Actualizar todos los módulos de ModSecurity. Nos va mandar realizar ataques sin él primero y ver que nadie defiende. Si ahora atacamos cn ModSecurity activado la máquina si que deberñia defenderse. 

Tienes que defenderse de los 4 ataques posibles que damos!!! En la defensa no probará todos, solo alguno

<br>
<br>

### **Apartado n) Buscamos información.:  
- Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado a la Universidade da Coruña.
  
- Obtenga información sobre el direccionamiento de los servidores DNS y MX de la Universidade da Coruña.
  
- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?. En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.
  
- ¿Qué gestor de contenidos se utiliza en www.usc.es?**



<br>
<br>

---

### **Apartado o) Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.**



<br>
<br>

---

## ATAQUES Y DEFENSAS DE FUERZA BRUTA:

**Ataques de fuerza bruta:** Usar Medusa para atacar. 

**Defensas de fuerza bruta:** Usar OOSEC para defenderse. Añadir Ips baneables a hosts.deny para bloquear accesos.




### **Apartado p) Realice algún ataque de “password guessing” contra su servidor ssh y compruebe que el analizador de logs reporta las correspondientes alarmas.**

Usar Medusa para atacar. 



<br>

---

### **Apartado q) Reportar alarmas está muy bien, pero no estaría mejor un sistema activo, en lugar de uno pasivo. Configure algún sistema activo, por ejemplo OSSEC, y pruebe su funcionamiento ante un “password guessing”.**

Usar OSSEC para defender a los ataques. Baneará la Ip que estña realizando el ataque constantemente.




<br>

---

### **Apartado r) Supongamos que una máquina ha sido comprometida y disponemos de un fichero con sus mensajes de log. Procese dicho fichero con OSSEC para tratar de localizar evidencias de lo acontecido (“post mortem”). Muestre las alertas detectadas con su grado de criticidad, así como un resumen de las mismas.**


<br>


























