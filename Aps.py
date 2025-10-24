from colorama import init, Fore, Style
import pyfiglet
import os
import time
import hashlib
import json
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
import paho.mqtt.client as mqtt
import datetime
from typing import Optional

init(autoreset=True)
console = Console()

arquivoUser = "usuarios.json"  # Faz o arquivoUser receber o json usuarios
salt_digitado = input("Insira um salt para você utilizar: ").strip()

def LimparTela():  # Função para limpar a tela do prompt
    os.system('cls' if os.name == 'nt' else 'clear')

def titulo(texto): # Função para estilizar o titul
    banner = pyfiglet.figlet_format(texto, font="slant")
    console.print(Panel.fit(f"[bold blue]{banner}[/bold blue]", border_style="cyan", padding=(1, 5), title="💠 Sistema Seguro 💠", title_align="center"), justify="center")

def criptografarSenha(senha): # Criptografa a senha com SHA-256
    salt = salt_digitado
    senhaComSalt = senha + salt
    hashSenha = hashlib.sha256(senhaComSalt.encode()).hexdigest()
    return hashSenha

def verificarSenha(senhaDigitada, hashArmazenado):
    hashDigitada = criptografarSenha(senhaDigitada)
    return hashDigitada == hashArmazenado

def carregarJson(arquivo): # Carrega o json (usuários) para leitura
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def salvar_dados(arquivo, dados):  # Insere os dados no json (usuarios)
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

def loginUser():
    LimparTela()
    titulo("Login de Usuários")
    usuarios = carregarJson(arquivoUser)

    username_digitado = input(Fore.CYAN + "\nDigite seu username: " + Style.RESET_ALL).strip()
    senha = input(Fore.CYAN + "Digite sua senha: " + Style.RESET_ALL).strip()

    for userId, username in usuarios.items():
        if username['username'] == username_digitado:
            if verificarSenha(senha, username.get('passwordHash', '')):
                console.print("\n[bold green]✔ Login realizado com sucesso![/bold green]")
                time.sleep(1)
                username['id'] = userId
                tipo = username.get('tipo', 'usuario').lower()
                if tipo == 'admin':
                    MenuPrincipalADM()
                    return True
                elif tipo == 'usuario':
                    MenuPrincipalUser()
                    return True
            else:
                console.print("\n[bold red]Senha incorreta. Tente novamente.[/bold red]")
                time.sleep(2)
                return
    console.print("[bold red]Usuário não encontrado.[/bold red]")
    time.sleep(2)
    return None

def adicionarUsers():
    LimparTela()
    titulo("ADICIONAR USUÁRIOS")
    usuarios = carregarJson(arquivoUser)
    if not isinstance(usuarios, dict):
        usuarios = {}

    username = input(Fore.CYAN + "Digite o username do novo usuário: " + Style.RESET_ALL).strip()
    if any(user['username'] == username for user in usuarios.values()):
        console.print("[bold red]Username já existe. Tente novamente.[/bold red]")
        time.sleep(2)
        return

    senha = input(Fore.CYAN + "Digite a senha do novo usuário: " + Style.RESET_ALL).strip()
    tipo = input(Fore.CYAN + "Digite o tipo do usuário (admin/usuario): " + Style.RESET_ALL).strip().lower()
    senha_hash = criptografarSenha(senha)
    novo_id = str(len(usuarios) + 1)
    usuarios[novo_id] = {
        'username': username,
        'passwordHash': senha_hash,
        'tipo': tipo if tipo in ['admin', 'usuario'] else 'usuario'
    }
    with open(arquivoUser, 'w', encoding='utf-8') as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=4)
    console.print(f"[bold green]Usuário '{username}' adicionado com sucesso![/bold green]")
    time.sleep(2)

def modificarUser():
    for UserId, username in carregarJson(arquivoUser).items():
        print(f"ID: {UserId} | Usuário: {username['username']} | Tipo: {username['tipo']}")
    modUser = input("Digite o ID do usuário que deseja modificar: ").strip()
    return

def excluirUsers():
    LimparTela()
    titulo("EXCLUIR USUÁRIOS")
    usuarios = carregarJson(arquivoUser)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]")
        time.sleep(2)
        return

    table = Table(title="[bold cyan]Usuários Cadastrados[/bold cyan]", title_style="bold cyan", header_style="bold white on blue", padding=(0,2))
    table.add_column("ID", justify="center", style="bright_cyan", no_wrap=True)
    table.add_column("Username", justify="center", style="magenta")
    table.add_column("Tipo", justify="center", style="green")

    for userId, dados in usuarios.items():
        table.add_row(userId, dados.get('username', ''), dados.get('tipo', 'usuario'))
    console.print(table, justify="center")

    userIdExcluir = Prompt.ask("\n[bold yellow]Digite o ID do usuário que deseja excluir[/bold yellow] ").strip()
    if userIdExcluir not in usuarios:
        console.print("[bold red]Usuário não encontrado.[/bold red]")
        time.sleep(2)
        return

    confirm = Prompt.ask(f"Tem certeza que deseja excluir o usuário '{usuarios[userIdExcluir]['username']}'? (s/n)", default="n").lower()
    if confirm == 's':
        del usuarios[userIdExcluir]
        salvar_dados(arquivoUser, usuarios)
        console.print("[bold green]Usuário excluído com sucesso![/bold green]")
    else:
        console.print("[bold yellow]Operação cancelada.[/bold yellow]")
    time.sleep(2)

def gerenciamentoUser():
    while True:
        LimparTela()
        titulo("GERENCIAMENTO DE USUÁRIOS")
        console.print(Panel.fit("[1] - Adicionar Usuários\n[2] - Modificar Usuários\n[3] - Excluir Usuários\n[4] - Sair", title="Escolha uma opção", border_style="blue"))
        result = input("➤ ").strip()
        if result == '1':
            adicionarUsers()
        elif result == '2':
            modificarUser()
        elif result == '3':
            excluirUsers()
        elif result == '4':
            break
        else:
            console.print(Fore.RED + "Digite algo válido")
    LimparTela()

def carregar_json(arquivo):
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def salvar_json(arquivo, dados):
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

def hash_mensagem(msg, salt):
    return hashlib.sha256((msg + salt).encode('utf-8')).hexdigest()

def menuPrincipal():
    while True:
        LimparTela()
        titulo("MENU PRINCIPAL")
        console.print(Panel.fit("[1] - Logar como usuário\n[2] - Logar como administrador\n[3] - Cadastrar novo usuário\n[4] - Sair", border_style="cyan", title="Escolha uma opção"))
        result = input("➤ ").strip()
        if result == '1' or result == '2':
            if loginUser():
                LimparTela()
        elif result == '3':
            adicionarUsers()
        elif result == '4':
            break
        else:
            console.print(Fore.RED + "Digite uma opção válida!")
            time.sleep(2)
            LimparTela()

def enviar_mensagem(
    broker="test.mosquitto.org",
    topico="minharede/chat",
    arquivo="mensagens.json",
    remetente="admin",
    destinatario="usuario",
    salt=None
):
    if salt is None:
        salt = input("Digite um salt para hash: ").strip()
    cliente = mqtt.Client()
    cliente.connect(broker, 1883, 60)
    cliente.loop_start()
    mensagens = carregar_json(arquivo)
    remetente_hash = hashlib.sha256((remetente + salt).encode('utf-8')).hexdigest()
    destinatario_hash = hashlib.sha256((destinatario + salt).encode('utf-8')).hexdigest()
    try:
        while True:
            console.print("\n[bold cyan]Para sua segurança, todas as mensagens são criptografadas. Digite 'sair' para encerrar.[/bold cyan]")
            msg = input(Fore.CYAN + "Você: " + Style.RESET_ALL).strip()
            if msg.lower() == "sair":
                break
            if not msg:
                continue
            cliente.publish(topico, msg)
            registro = {
                "remetente": remetente_hash,
                "destinatario": destinatario_hash,
                "original": msg,
                "hash_msg": hash_mensagem(msg, salt),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "topico": topico,
                "broker": broker
            }
            mensagens.append(registro)
            salvar_json(arquivo, mensagens)
            console.print(f"[bold green]Mensagem enviada![/bold green]  [dim]{datetime.datetime.now().strftime('%H:%M:%S')}[/dim]")
    except KeyboardInterrupt:
        pass
    finally:
        cliente.loop_stop()
        cliente.disconnect()

def receber_mensagem(
    broker="test.mosquitto.org",
    topico="minharede/chat"
):
    def on_message(client, userdata, message):
        console.print(f"\n💬 [cyan]Mensagem recebida[/cyan] → [bold yellow]{message.payload.decode()}[/bold yellow]")
    cliente = mqtt.Client()
    cliente.on_message = on_message
    cliente.connect(broker, 1883, 60)
    cliente.subscribe(topico)
    cliente.loop_start()
    try:
        console.print(f"[bold blue]Escutando mensagens no tópico '{topico}'. Para sua segurança, todas as mensagens são criptografadas. Pressione Ctrl+C para sair.[/bold blue]")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        cliente.loop_stop()
        cliente.disconnect()

def MenuPrincipalADM():
    while True:
        LimparTela()
        titulo("MENU ADMINISTRADOR")
        console.print(Panel.fit("[1] - Gerenciamento de Usuários\n[2] - Envio de Mensagens\n[3] - Sair", border_style="green"))
        result = input("➤ ").strip()
        if result == '1':
            gerenciamentoUser()
        elif result == '2':
            enviar_mensagem()
        elif result == '3':
            break
        else:
            console.print(Fore.RED + "Digite algo válido")
    LimparTela()

def MenuPrincipalUser():
    while True:
        LimparTela()
        titulo("MENU USUÁRIO")
        console.print(Panel.fit("[1] - Mensagens Recebidas\n[2] - Sair", border_style="magenta"))
        result = input("➤ ").strip()
        if result == '1':
            receber_mensagem()
        elif result == '2':
            break
        else:
            console.print(Fore.RED + "Digite algo válido")
    LimparTela()

if __name__ == "__main__":
    menuPrincipal()
