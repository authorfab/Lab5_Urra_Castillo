# Laboratorio 5 Seguridad Informatica
# Fabian Urra, Jose Castillo

import socket, json
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

def escoger_b(num):
    aux = True
    escoger_b = int(input("Ingrese su numero b mayor que cero y menor que p: "))
    while(aux):
        if escoger_b> 0 and escoger_b <num:
            print("Numero a cumple las condiciones")
            return escoger_b
        else:
            print("Intentelo nuevamente")
            escoger_b = int(input("Ingrese su numero b mayor que cero y menor que p: "))

def diffie_hellamn(g,b,p):
    B = (g**b) % p
    return B

def main():
    host = '127.0.0.1'
    port = 12345
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    mensaje_recibido = (s.recv(1024))

    recibido_enjson = mensaje_recibido.decode('utf-8')

    publicas = json.loads(recibido_enjson)

    numero_p, numero_g, calcular_A = publicas

    print("Número p recibido:", numero_p)
    print("Número g recibido:", numero_g)
    print("Número A recibido:", calcular_A)

    numero_b = escoger_b(numero_p)
    print("El numero b esta registrado")

    calcular_B = diffie_hellamn(numero_g,numero_b,numero_p)
    print("El numero B es:", calcular_B)

    clave_des = get_random_bytes(8)

    s.send(clave_des)

    cipher = DES.new(clave_des, DES.MODE_ECB)

    calcular_B_bytes = str(calcular_B).encode('utf-8')

    calcular_B_bytes_padded = pad(calcular_B_bytes, 8)

    calcular_B_encrypted = cipher.encrypt(calcular_B_bytes_padded)

    s.send(calcular_B_encrypted)
    s.close()
    
    calcular_k = diffie_hellamn(calcular_A,numero_b,numero_p)
    print("El clave K es", calcular_k)
main()
