import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Función para cifrar un mensaje
def cifrar_mensaje(texto):
    clave = get_random_bytes(16)
    cipher = AES.new(clave, AES.MODE_EAX)
    mensaje = texto.encode()
    cifrado, tag = cipher.encrypt_and_digest(mensaje)

    return cifrado, clave, cipher.nonce

# Función para descifrar un mensaje
def descifrar_mensaje(cifrado, clave, nonce):
    cipher_dec = AES.new(clave, AES.MODE_EAX, nonce=nonce)
    mensaje_descifrado = cipher_dec.decrypt(cifrado).decode()

    return mensaje_descifrado

st.title("Cifrado y Descifrado con AES-EAX")
texto = st.text_input("Introduce un texto para cifrar:")

if st.button("Cifrar y Descifrar"):
    if texto:
        cifrado, clave, nonce = cifrar_mensaje(texto)
        mensaje_descifrado = descifrar_mensaje(cifrado, clave, nonce)

        st.write("### Texto Cifrado:")
        st.code(cifrado)

        st.write("### Texto Descifrado:")
        st.code(mensaje_descifrado)
    else:
        st.error("Por favor, introduce un texto antes de cifrar.")