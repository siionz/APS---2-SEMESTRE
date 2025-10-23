from colorama import init, Fore, Style
import pyfiglet
import os
import time
import hashlib
import json
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
import paho.mqtt.client as mqtt
import datetime
from typing import Optional

init()
console = Console()

arquivoUser = "usuarios.json"   # Faz o arquivoUser receber o json usuarios
salt_digitado = input("Insira um salt para você utilizar: ")

def LimparTela(): # Função para limpar a tela do prompt
    os.system('cls')

def titulo(texto): # Função para estilizar o titulo
    banner = pyfiglet.figlet_format(texto, font="slant")
    print(Fore.BLUE + banner + Style.RESET_ALL)

def criptografarSenha(senha): # Criptografa a senha com SHA-256
    salt = salt_digitado  # Salt recebe o que o usuário escrever.
    senhaComSalt = senha + salt
    hashSenha = hashlib.sha256(senhaComSalt.encode()).hexdigest()
    return hashSenha

def verificarSenha(senhaDigitada, hashArmazenado):
    """Verifica se a senha digitada confere com o hash armazenado"""
    hashDigitada = criptografarSenha(senhaDigitada)
    return hashDigitada == hashArmazenado

def carregarJson(arquivo):  # Carrega o json (usuários) para leitura
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
            return {}

def salvar_dados(arquivo, dados): # Insere os dados no json (usuarios)

    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f)


def loginUser():     # Função para fazer o login

    LimparTela()
    titulo("Login de Usuarios")
    usuarios = carregarJson(arquivoUser)

    username_digitado = input("Digite seu username: ").strip()
    senha = input("Digite sua senha: ").strip()

    for userId, username in usuarios.items():
        if username['username'] == username_digitado:
            # Verifica a senha
            if verificarSenha(senha, username.get('passwordHash', '')):
                console.print("\n[bold green]Login realizado com sucesso![/bold green]")
                time.sleep(1)

                username['id'] = userId

                # normaliza o tipo para comparar de forma segura
                tipo = username.get('tipo', 'usuario').lower()


                # Direciona para o menu correspondente
                if tipo == 'admin':
                    MenuPrincipalADM()
                    return True
                elif tipo == 'usuario':
                    MenuPrincipalUser()
                    return True
            else:
                console.print("\n[bold red]Senha incorreta. Tente novamente[/bold red]")
                time.sleep(2)
                return

    console.print("[bold red]Usuário não encontrado[/bold red]")
    time.sleep(2)
    return None


def adicionarUsers():
    LimparTela()
    titulo("ADICIONAR USUÁRIOS")

    usuarios = carregarJson(arquivoUser)

    if not isinstance(usuarios, dict):
        usuarios = {}

    username = input("Digite o username do novo usuário:").strip()
    if any(user['username'] == username for user in usuarios.values()):
        console.print("[bold red]Username já existe. Tente novamente.[/bold red]")
        time.sleep(2)
        return

    senha = input("Digite a senha do novo usuário:").strip()
    tipo = input("Digite o tipo do usuário (admin/usuario):").strip().lower()
    senha_hash = criptografarSenha(senha)

    novo_id = str(len(usuarios) + 1)

    usuarios[novo_id] = {
        'username': username,
        'passwordHash': senha_hash,
        'tipo': tipo if tipo in ['admin', 'usuario'] else 'usuario'}
    salvar_dados(arquivoUser, usuarios)
    console.print(f"[bold green]Usuário '{username}' adcionado com sucesso![/bold green]")
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

    table = Table(title="Usuários Cadastrados")
    table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("Username", style="magenta")
    table.add_column("Tipo", style="green")

    for userId, dados in usuarios.items():
        table.add_row(userId, dados.get('username', ''), dados.get('tipo', 'usuario'))
    console.print(table)

    userIdExcluir = Prompt.ask("[bold yellow]Digite o ID do usuário que deseja excluir[/bold yellow] ")

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
        titulo("GERENCIAMENTO DE USUÁRIOS")
        print("  [1] - Adicionar Usuários")
        print("  [2] - Modificar Usuários")
        print("  [3] - Excluir Usuários")
        print("  [4] - Sair")

        result = int (input("Escolha uma opção: "))

        if result == 1:
            listager = adicionarUsers()
        elif result == 2:
            listaenviar = modificarUser()
        elif result == 3:
            listaenviar = excluirUsers()
        elif result == 4:
            break
        else:
            print(Fore.RED + "Digite algo válido")
    LimparTela()

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

def menuPrincipal() :
    while True:
        titulo("MENU PRINCIPAL")
        print("  [1] - Logar como usuário")
        print("  [2] - Logar como administrador")
        print("  [3] - Cadastrar novo usuário")
        print("  [4] - Sair")

        try:
            result = int(input("Escolha uma opção: "))
        except ValueError:
            print(Fore.RED + "Digite uma opção válida!")
            time.sleep(2)
            LimparTela()
            continue

        if result == 1 or result == 2:
            if loginUser():
                LimparTela()  # Limpa a tela após sair do menu do usuário
        elif result == 3:
            adicionarUsers()
        elif result == 4:
            break
        else:
            print(Fore.RED + "Digite uma opção válida!")
            time.sleep(2)
            LimparTela()
#////////////////////////////////////////////////////////#

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

#////////////////////////////////////////////////////////#

def MenuPrincipalADM():
    while True:
        titulo("MENU PRINCIPAL")
        print("  [1] - Gerenciamento de Usuários")
        print("  [2] - Envio de Mensagens")
        print("  [3] - Sair")

        result = int (input("Escolha uma opção: "))

        if result == 1:
            listaLogin = gerenciamentoUser()
        elif result == 2:
            listaCadastro = enviar_mensagem()
        elif result == 3:
            break
        else:
            print(Fore.RED + "Digite algo válido")
    LimparTela()
def GerenciamentoUserMenuAdm():
    while True:
        titulo("GERENCIAMENTO DE USUÁRIOS")
        print("  [1] - Adicionar Usuários")
        print("  [2] - Modificar Usuários")
        print("  [3] - Excluir Usuários")
        print("  [4] - Sair")

        result = int (input("Escolha uma opção: "))

        if result == 1:
            listager = adicionarUsers()
        elif result == 2:
            listaenviar = modificarUser()
        elif result == 3:
            listaenviar = excluirUsers()
        elif result == 4:
            break
        else:
            print(Fore.RED + "Digite algo válido")
    LimparTela()

def GerenciamentoAddUserMenuAdm():
    while True:
        titulo("ADICIONAR USUÁRIOS")
        break

def MenuPrincipalUser():
    while True:
        titulo("MENU PRINCIPAL")
        print("  [1] - Envio de Mensagens")
        print("  [2] - Sair")

        result = int (input("Escolha uma opção: "))

        if result == 1:
            enviar_mensagem()
        elif result == 2:
            break
        else:
            print(Fore.RED + "Digite algo válido")
    LimparTela()


if __name__ == "__main__":
    menuPrincipal()


