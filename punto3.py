import argparse
from scapy.all import rdpcap, IP, ICMP
from termcolor import colored
import string

def descifrar_cesar(texto_cifrado):
    resultados = []
    for corrimiento in range(1, 26):
        texto_descifrado = []
        for char in texto_cifrado:
            if char.isalpha():
                offset = 65 if char.isupper() else 97
                nuevo_char = chr((ord(char) - offset - corrimiento) % 26 + offset)
                texto_descifrado.append(nuevo_char)
            else:
                texto_descifrado.append(char)
        resultado = ''.join(texto_descifrado)
        resultados.append((corrimiento, resultado))
    return resultados


def procesar_archivo_pcap(archivo_pcap):
    paquetes = rdpcap(archivo_pcap)
    mensaje_cifrado = []

    for paquete in paquetes:
        if IP in paquete and ICMP in paquete:
            if paquete[ICMP].type == 8:  
                data = paquete[ICMP].payload.load.decode('utf-8', errors='ignore').strip()
                if data:
                    mensaje_cifrado.append(data)
    
    return ''.join(mensaje_cifrado)


def evaluar_calidad(texto):
    letras_comunes = "etaoinshrdlu"  
    puntuacion = sum([1 for char in texto if char in letras_comunes])
    return puntuacion

def main():

    parser = argparse.ArgumentParser(description="Procesa un archivo .pcapng y descifra los mensajes ICMP.")
    parser.add_argument("archivo_pcap", help="/home/matias/lab1/paquetes2.pcapng")
    args = parser.parse_args()

    mensaje_cifrado_str = procesar_archivo_pcap(args.archivo_pcap)

    if mensaje_cifrado_str:
        print(f"\nMensaje cifrado capturado: {mensaje_cifrado_str}")
        
   
        posibles_descifrados = descifrar_cesar(mensaje_cifrado_str)
        
       
        mejores_resultados = sorted(posibles_descifrados, key=lambda x: evaluar_calidad(x[1]), reverse=True)
        
        
        print("\nPosibles descifrados:")
        for corrimiento, resultado in mejores_resultados:
            if resultado == mejores_resultados[0][1]:
                print(colored(f"Corrimiento {corrimiento}: {resultado}", 'green'))
            else:
                print(f"Corrimiento {corrimiento}: {resultado}")
    else:
        print("No se capturó ningún mensaje cifrado.")

if __name__ == "__main__":
    main()
