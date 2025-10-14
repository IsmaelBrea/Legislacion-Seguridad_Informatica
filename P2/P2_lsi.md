# PRÁCTICA 2 - Seguridad Informática

DEFENSA DE LA PRÁCTICA: 4 de noviembre.

**Objetivo:** El objetivo de esta práctica es aprender y experimentar con la captura y el análisis del tráfico de red mediante sniffers, comprender y probar ataques DoS/DDoS, y trabajar la llamada «trilogía»: descubrimiento de hosts, escaneo de puertos y fingerprinting de sistemas (conjunto de técnicas usadas para identificar características de un equipo o servicio en la red). Además, se pretende gestionar y analizar la información de auditoría generada durante las pruebas, empleando en el laboratorio distintas herramientas sugeridas para practicar y validar los conceptos.

En esta práctica se van a realizar muchos escaneos, ataques y defensas, por lo que se van a generar muchos logs en nuestro sistema. Tendremos que ir comprobando los logs poco a poco así como el espacio para que no se nos llene el disco ni ocurran cosas raras en nuestras máquinas.

**IMPORTANTE:** Mirar una vez al día cuánto espacio tiene nuestra máquina y cuando ocupa nuestro log de la máquina. Nos podemos encontrar hasta logs de 5 GB que no valen para nada.

<br>
<br>

### **Apartado a) Instale el ettercap y pruebe sus opciones básicas en línea de comando.**

Lllamos a eterrcap por CLI.

tiene 2 targets.

No usar ettercap///  -> no hacer esto porque colapsa porque se está leyendo toda la red.


solo ipv4



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

 

HTTP porque no va cifrado.

Instalar wireshark en local y ver el tráfico. En wireskark  hay que ver el gato.
wget fotodelgato.png 

Nosotros capturamos la peticion con wireshark y vemos la peticion y el gato.

Cuidado con los balanceadores!! Buscar fotos que sean solo en http!!

<br>

---

### **Apartado c) Obtenga la relación de las direcciones MAC de los equipos de su segmento.**


Usar nmap. Solo ipv4



<br>
---

### **Apartado d) Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.**

Cuidado con localhost, que es virtual!!!




<br>

---

### **Apartado e) Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.**


Yo ataco y en mi pantalla veo lo que mi compañero ve en directo. Sus cambios como yo estoy en el medio, yo lo muestro en pantalla. Lo tenemos que ver simultaneamente. Tengo que ver como cambia mi pantalla mientras el hace cambios.


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

---

### **Apartado g) Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).**

**Carlos dice que sea lo último que hagamos antes de acabar la práctica 2!!!!**



<br>

---

### **Apartado h) Pruebe distintas técnicas de host discovey, port scanning y OS fingerprinting sobre las máquinas del laboratorio de prácticas en IPv4. Realice alguna de las pruebas de port scanning sobre IPv6. ¿Coinciden los servicios prestados por un sistema con los de IPv4?.**


NADA de IPv6.

De las que están activas cuales son sus MAC etc

Si ponemos toda la red, petamos el sistema!!!
Poner solo una red pequeña o solo al compañero y la puerta del enlace por ejemplo. Probar también todo el 48 (más riesgo).


<br>

---

### **Apartado i) Obtenga información “en tiempo real” sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.**


<br>

---

### **Apartado j) Monitorizamos nuestra infraestructura.:  

- Instale prometheus y node_exporter y configúrelos para recopilar todo tipo de métricas de su máquina linux.
- 
- Posteriormente instale grafana y agregue como fuente de datos las métricas de su equipo de prometheus.
- 
- Importe vía grafana el dashboard 1860.
- 
- En los ataques de los apartados m y n busque posibles alteraciones en las métricas visualizadas.**



<br>
---

### **Apartado k) **PARA PLANTEAR DE FORMA TEÓRICA.: ¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.**

Carlos no lo mira mucho, solo Nino.



<br>

---

### **Apartado l) Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?**


Ataques Apache recomendados:
-perl

-python en Github: SlowLoris

<br>

Defensas Apache recomendadas:
-ModSecurity. Carlos no obliga a usar ModSecurity. 

Existen 5 paquetes de apache que protegen sin querer.

Probar varios y probar que podemos atacar y nosotros podemos defendernos.

<br>

---

### **Apartado m) Instale y configure modsecurity. Vuelva a proceder con el ataque del apartado anterior. ¿Qué acontece ahora?**


<br>

### **Apartado n) Buscamos información.:  
- Obtenga de forma pasiva el direccionamiento público IPv4 e IPv6 asignado a la Universidade da Coruña.
  
- Obtenga información sobre el direccionamiento de los servidores DNS y MX de la Universidade da Coruña.
  
- ¿Puede hacer una transferencia de zona sobre los servidores DNS de la UDC?. En caso negativo, obtenga todos los nombres.dominio posibles de la UDC.
  
- ¿Qué gestor de contenidos se utiliza en www.usc.es?**



<br>

---

### **Apartado o) Trate de sacar un perfil de los principales sistemas que conviven en su red de prácticas, puertos accesibles, fingerprinting, etc.**



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











