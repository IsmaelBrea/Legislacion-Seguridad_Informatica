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
- `/23` porque con `/24` no alcanzan las IPs para todos los alumnos.  
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


### Primeros pasos obligatorios

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

Diferencia entre `$` y `#`

  `$` → estás usando un usuario normal (ej. lsi).  
  \# → estás usando el usuario root (administrador).  


**DIFERENCIAS ENTRE SU Y SU-**:

- **`su`**  
  Cambia de usuario (por defecto a root) pero **mantiene tu entorno actual**, incluyendo directorio y variables.

- **`su -`**  
  Cambia de usuario **y carga el entorno completo** del nuevo usuario, incluyendo su PATH, variables y directorio inicial (`/root` si es root).

---
###3-Comprobar el número máximo de comandos permitidos en el historial (history) y ampliarlo
**El comando history es independiente para cada usuario, incluyendo root.**

Cada usuario puede tener configuraciones distintas en ~/.bashrc o /etc/profile que afecten HISTSIZE y HISTFILESIZE:
    HISTSIZE -> número máximo de comandos que se guardan en la sesión actual.
    HISTFILESIZE -> número máximo de comandos que se guardan en el archivo de historial (~/.bash_history).

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

Para aumentar ambos historiales tenemos que hacer lo siguiente:
```bash
echo "export HISTSIZE=1000000" >> /root/.bashrc
echo "export HISTFILESIZE=1000000" >> /root/.bashrc
source /root/.bashrc
```
**source /root/.bashrc:** es un comando que le dice a tu shell actual que ejecute todas las instrucciones del archivo /root/.bashrc.

En otras palabras:

  Normalmente, .bashrc se ejecuta cuando inicias sesión o abres una nueva terminal.
  
  Con source, no necesitas cerrar ni abrir otra sesión, se aplican los cambios inmediatamente en la terminal actual.


---
# Puntos a resolver de la práctica 1

Familiarizarse con el **funcionamiento básico y la configuración de la máquina de laboratorio**, utilizando **comandos y ficheros de configuración en Linux**.  

La práctica finaliza con la **configuración básica de servicios de red**, realizada en grupos de dos alumnos.












