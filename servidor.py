import paho.mqtt.client as mqtt

#teste mandando mensagem para outro computador usando mqtt

broker = "test.mosquitto.org" # servidor MQTT público conectado nas duas maquinas
topico = "minharede/chat"   #tópico para enviar mensagens

cliente = mqtt.Client() #cria uma janela de comunicação
cliente.connect(broker, 1883, 60)

while True: #loop infinito para enviar mensagens
    msg = input("Você: ")
    cliente.publish(topico, msg)
    if msg.lower() == "sair":
        break

cliente.disconnect()

#na outra maquina, usa o cliente_sub.py para receber as mensagens,
#primeiro execute o cliente_sub.py e depois o servidor.py

#/////////////////////////////////////////////////////////////////////////////

# funcoes pra mensagem criptografada e salvar em json
import json
import hashlib
import datetime
import paho.mqtt.client as mqtt
from typing import Optional

def carregar_json(arquivo: str):
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def salvar_json(arquivo: str, dados):
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

def hash_mensagem(msg: str, salt: str) -> str:
    return hashlib.sha256((msg + salt).encode('utf-8')).hexdigest()

def enviar_mensagem(
    broker: str = "test.mosquitto.org",
    topico: str = "minharede/chat",
    arquivo: str = "mensagens.json",
    salt: Optional[str] = None
) -> None:

    if salt is None:
        salt = input("Digite um salt para hash: ").strip()

    cliente = mqtt.Client()
    cliente.connect(broker, 1883, 60)
    cliente.loop_start()

    mensagens = carregar_json(arquivo)

    try:
        while True:
            msg = input("Você: ").strip()
            if not msg:
                continue

            cliente.publish(topico, msg)

            registro = {
                "original": msg,
                "hash": hash_mensagem(msg, salt),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "topico": topico,
                "broker": broker
            }

            mensagens.append(registro)
            salvar_json(arquivo, mensagens)

            if msg.lower() == "sair":
                break

    except KeyboardInterrupt:
        pass
    finally:
        cliente.loop_stop()
        cliente.disconnect()

if __name__ == "__main__":
    enviar_mensagem()
