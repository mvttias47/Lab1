from scapy.all import *

def enviar_paquetes_icmp(texto_cifrado, destino):
    for caracter in texto_cifrado:
        paquete = IP(dst=destino)/ICMP()/Raw(load=caracter)
        send(paquete)
        print(f"Enviando carácter: {caracter}")
  
texto_cifrado = "cpcmkp"  
destino = "192.168.1.1"  

#
enviar_paquetes_icmp(texto_cifrado, destino)

