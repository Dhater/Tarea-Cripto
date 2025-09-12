import time
from scapy.all import rdpcap, ICMP
import os
from dotenv import load_dotenv
import requests
import json
import re

# Cargar API Key de Gemini desde .env
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# Archivo pcapng capturado
ARCHIVO_PCAP = "Paquetes.pcapng"

# Función para extraer caracteres del payload
def extraer_mensaje(pcap_file):
    packets = rdpcap(pcap_file)
    mensaje = ""
    for pkt in packets:
        if ICMP in pkt:
            payload = bytes(pkt[ICMP].payload)
            if len(payload) > 8:
                mensaje += chr(payload[8])
    return mensaje

# Función para decifrar César con un desplazamiento dado
def cesar_descifrar(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        else:
            resultado += char
    return resultado

# Función para limpiar texto: duplicados, '@' y mantener solo letras y espacios
def limpiar_texto(texto):
    if not texto:
        return ""
    limpio = texto[0]
    for c in texto[1:]:
        if c != limpio[-1]:
            limpio += c
    # Mantener solo letras y espacios
    limpio = re.sub(r'[^a-zA-Z\s]', '', limpio)
    return limpio.strip()

# Función para consultar Gemini y obtener puntaje de legibilidad para cada combinación
def puntaje_legibilidad(posible):
    msg_limpio = limpiar_texto(posible)
    prompt = (
        f"Evalúa solo la legibilidad del siguiente texto: '{msg_limpio}'. "
        "Indica en porcentaje de 0 a 100 qué tan fácil es de leer y comprender. "
        "Solo responde con un número entero entre 0 y 100."
    )

    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY
    }

    data = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    response = requests.post(GEMINI_URL, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        try:
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            match = re.search(r'\d{1,3}', text)
            if match:
                return min(max(int(match.group(0)), 0), 100)
        except (KeyError, IndexError):
            return 0
    else:
        print(f"Error consultando Gemini: {response.status_code} {response.text}")
        return 0

if __name__ == "__main__":
    mensaje_codificado = extraer_mensaje(ARCHIVO_PCAP)
    print(f"Mensaje extraído de los paquetes ICMP: {mensaje_codificado}\n")

    # Generar todas las 26 combinaciones de César
    posibles = [cesar_descifrar(mensaje_codificado, d) for d in range(26)]

    print("[*] Evaluando la legibilidad de cada combinación con Gemini...")
    puntajes = {}
    for i, desc in enumerate(posibles):
        desc_limpio = limpiar_texto(desc)
        puntaje = puntaje_legibilidad(desc)
        puntajes[i] = (desc_limpio, puntaje)
        print(f"Clave {i} → '{desc_limpio}' → Puntaje: {puntaje}")
        time.sleep(2)  # Delay para no saturar la API

    # Elegir la opción con el puntaje más alto
    mejor_iteracion, (mejor_texto, mejor_puntaje) = max(puntajes.items(), key=lambda x: x[1][1])
    print(f"\n\033[92mMensaje más legible según Gemini: '{mejor_texto}' (Clave: {mejor_iteracion}, Puntaje: {mejor_puntaje})\033[0m")
