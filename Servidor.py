# Laboratorio 5 Seguridad Informatica
# Fabian Urra, Jose Castillo

import socket, sys, random, json
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


def es_primo(numero):
    if numero <= 1:
        return False
    if numero <= 3:
        return True
    if numero % 2 == 0 or numero % 3 == 0:
        return False
    i = 5
    while i * i <= numero:
        if numero % i == 0 or numero % (i + 2) == 0:
            return False
        i += 6
    return True

def generar_p():
    primos = []
    for numero in range(501, 1000):
        if es_primo(numero):
            primos.append(numero)
    
    if primos:
        primo_aleatorio = random.choice(primos)
        return primo_aleatorio
    else:
        return None


def generar_g(num):
    g = random.randint(200,num-100)
    return g


def escoger_a(num):
    aux = True
    escoger_a = int(input("Ingrese su numero a que mayor que cero y menor que p: "))
    while(aux):
        if escoger_a> 0 and escoger_a <num:
            print("Numero a cumple las condiciones")
            return escoger_a
        else:
            print("Intentelo nuevamente")
            escoger_a = int(input("Ingrese su numero a mayor que cero y menor que p: "))

def diffie_hellamn(g,a,p):
    A = (g**a) % p
    return A

def desencriptar_des(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data


def main():
    host = '127.0.0.1'
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    print(f"Esperando conexiones en {host}:{port}...")
    conex, addr = s.accept()
    print(f"Conexión establecida con {addr}")

    numero_p = generar_p()
    print("El numero publico p es:", numero_p)

    numero_g = generar_g(numero_p)
    print("El numero publico g es:", numero_g)

    numero_a = escoger_a(numero_p)
    print("El numero a esta registrado")

    calcular_A = diffie_hellamn(numero_g,numero_a,numero_p)
    print("El numero A es:", calcular_A)
    
    tupla = (numero_p,numero_g,calcular_A)
    mensaje = json.dumps(tupla)
    conex.send(mensaje.encode('utf-8'))

    clave_des = conex.recv(8)


    mensaje_enc = conex.recv(8)

    s.close()

    with open("mensajeentrada.txt", "wb") as file:
        file.write(mensaje_enc)

    with open("mensajeentrada.txt", "rb") as file:
        mensaje_enc = file.read()

    mensaje_desencriptado = desencriptar_des("mensajeentrada.txt", clave_des)


    mensaje_desencriptado = unpad(mensaje_desencriptado, 8)

    with open("mensajerecibido.txt", "wb") as file:
        file.write(mensaje_desencriptado)

    with open("mensajerecibido.txt", "rb") as file:
        contenido = file.read()
        numero_B = int(contenido.decode('utf-8'))

    print("Número B (mensaje recibido) como entero:", numero_B)

    calcular_k = diffie_hellamn(numero_B,numero_a,numero_p)
    print("El clave K es", calcular_k)
main()