def cifrado_cesar(texto, corrimiento):
    texto_cifrado = ""

    for caracter in texto:
        if caracter.isalpha():  
            limite = 65 if caracter.isupper() else 97
            posicion = (ord(caracter) - limite + corrimiento) % 26   
            texto_cifrado += chr(posicion + limite)
        else: 
            texto_cifrado += caracter

    return texto_cifrado

texto = input("Ingrese el texto a cifrar: ")
corrimiento = int(input("Ingrese el corrimiento: "))

texto_cifrado = cifrado_cesar(texto, corrimiento)
print("Texto cifrado:", texto_cifrado)
