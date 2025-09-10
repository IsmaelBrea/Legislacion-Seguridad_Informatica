# PRÁCTICA 1 

Importante defensas:
!Traer papel y boli para las defensas
!Todo lo que aparezca en pantalla hay que mirarlo


Eduroam
No permitido el tráfico a puertos 80, 443

UDCDocencia
No permitido el tráfico a puertos 22

VPN
Tenemos dos IPs con la VPN

Una Ip de una red para conectarnos a la máquina Debian. Esta IP que nos da la Ip que nos da la VPN puede ir cambiando por que se va llenando la IP Table de la VPN	
!!! No poner una ip con los 4 octetos fijos!!!


Y otra IP de nuestra propia máquina

Por eso ambas IPs son diferentes. 


IP de los alumnos: 10.11.48.0/23

23 porque 24 bits no llegan para dar Ips a los alumnos
0-> ip de subred
1-> ip de gateway
255-> ip de broadcast


Empezamos con un Debian 10. Actualizaremos el SO al 12 (10-> 11-> 12) y el kernel al 12 también.

Una vez actualizados ambos al 12, tenemos que eliminar los ficheros de los 10 y 11. Hay que limpiar todos los ficheros estos. 
! No se puede saltar de la 10 a la 12 (aunque ChatGPT diga que si)


HAY QUE MIRAR BIEN LOS SERVICIOS PARA VER QUE NO HAY NANDA CORRIENDO QUE NO CORRESPONDE.


USUARIO:
lsi2.3.1
10.11.48.74
root
lsi
Contraseña inicial: virtualj..


Usuario propio:
lsi2.3.4
10.11.48.169


 ssh lsi2.3.1@10.11.48.74
AL hacer ssh nos pregunta si queremos aceptar conectarnos esta máquina guardando algo (el fingerprint)

Primero que hay que hacer:
CAMBIAR EL PASSWORD del usuario lsi
CAMBIAR EL PASSWORD del usuario root
su 
passwd


$ -> usuario
# -> root 

No puedes saber en que máquina estás, si estás en la de tu compañero.
Importante cambiar el nombre del usuario para saber quien es.