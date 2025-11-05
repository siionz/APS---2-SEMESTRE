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
from rich.align import Align
import paho.mqtt.client as mqtt
import datetime
from typing import Optional
import threading

init(autoreset=True)
console = Console()

arquivoUser = "usuarios.json"  
salt_digitado = input("Insira um salt para você utilizar: ").strip()

def LimparTela():  
    os.system('cls' if os.name == 'nt' else 'clear')

# ====== APENAS VISUAL AJUSTADO ======

def titulo(texto): 
    banner = pyfiglet.figlet_format(texto, font="slant")  # Fonte ajustada para CMD
    painel = Panel(
        Align.center(f"[bold blue]{banner}[/bold blue]", vertical="middle"),
        border_style="cyan",
        padding=(0, 2),
        title="// Sistema Seguro - MARINHA //",
        title_align="center",
        width=100
    )
    console.print(Align.center(painel))
    
# ====================================

def criptografarSenha(senha): 
    salt = salt_digitado
    senhaComSalt = senha + salt
    hashSenha = hashlib.sha256(senhaComSalt.encode()).hexdigest()
    return hashSenha

def verificarSenha(senhaDigitada, hashArmazenado):
    hashDigitada = criptografarSenha(senhaDigitada)
    return hashDigitada == hashArmazenado

def carregarJson(arquivo): 
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    
def salvar_dados(arquivo, dados): 
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

def loginUser():
    LimparTela()
    titulo("Login de Usuarios")
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
                    MenuPrincipalUser(username_digitado)
                    return True
            else:
                console.print("\n[bold red]Senha incorreta. Tente novamente.[/bold red]")
                time.sleep(2)
                loginUser()
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
    minusculo = lambda: any(c.islower() for c in senha)
    maiusculo = lambda: any(c.isupper() for c in senha)
    numeros = lambda: any(c.isdigit() for c in senha)
    caracteres_especiais = lambda: any(not c.isalnum() for c in senha)
    
    while True:
        if len(senha) < 8:
            console.print("\n[bold red]A senha deve ter no mínimo 8 caracteres. Tente novamente.[/bold red]")
            time.sleep(2)
            adicionarUsers()
        elif not minusculo() or not maiusculo() or not numeros or not caracteres_especiais():
            console.print("\n[bold red]A senha deve conter letras maiúsculas, minúsculas, números e caracteres especiais. Tente novamente.[/bold red]")
            time.sleep(2)
            adicionarUsers()
            break
        else:
            break
        
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
    LimparTela()
    titulo("MODIFICAR USUÁRIOS")

    usuarios = carregarJson(arquivoUser)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]")
        time.sleep(2)
        return

    console.print("\n[bold cyan]Usuários Cadastrados:[/bold cyan]")
    for uid, dados in usuarios.items():
        console.print(f"ID: [bold yellow]{uid}[/bold yellow] | Username: [bold magenta]{dados.get('username','')}[/bold magenta] | Tipo: [bold green]{dados.get('tipo','usuario')}[/bold green]")

    uid = input(Fore.CYAN + "\nDigite o ID do usuário que deseja modificar: " + Style.RESET_ALL).strip()
    if not uid:
        return
    if uid not in usuarios:
        console.print("[bold red]Usuário não encontrado.[/bold red]")
        time.sleep(2)
        return

    user = usuarios[uid]
    atual_username = user.get('username', '')
    atual_tipo = user.get('tipo', 'usuario')

    novo_username = input(Fore.CYAN + f"Digite o novo username (atual: {atual_username}): " + Style.RESET_ALL).strip()
    nova_senha = input(Fore.CYAN + "Digite a nova senha (deixe em branco para manter a atual): " + Style.RESET_ALL).strip()
    novo_tipo = input(Fore.CYAN + f"Digite o novo tipo (admin/usuario) (atual: {atual_tipo}): " + Style.RESET_ALL).strip().lower()

    if novo_username and any(d.get('username') == novo_username for k, d in usuarios.items() if k != uid):
        console.print("[bold red]Username já existe. Tente novamente.[/bold red]")
        time.sleep(2)
        return

    if novo_tipo and novo_tipo not in ['admin', 'usuario']:
        console.print("[bold red]Tipo inválido. Deve ser 'admin' ou 'usuario'.[/bold red]")
        time.sleep(2)
        return

    if novo_username:
        user['username'] = novo_username
    if nova_senha:
        user['passwordHash'] = criptografarSenha(nova_senha)
    if novo_tipo:
        user['tipo'] = novo_tipo

    salvar_dados(arquivoUser, usuarios)
    console.print("[bold green]Usuário modificado com sucesso![/bold green]")
    time.sleep(2)

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
        result = input("> ").strip()
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
        console.print(Align.center(Panel.fit("[1] - Logar como usuário\n[2] - Logar como administrador\n[3] - Sair", border_style="cyan", title="Escolha uma opção")))
        result = input("> ").strip()
        if result == '3':
            LimparTela()
            break
        elif result == '1' or result == '2':
            if loginUser():
                LimparTela()
        else:
            console.print(Fore.RED + "Digite uma opção válida!")
            time.sleep(2)
            LimparTela()
            
#///////////////////////////// MQTT /////////////////////////////

def enviar_mensagem(
    broker="test.mosquitto.org",
    remetente="Admin",
    salt=None
):
    if salt is None:
        salt = input("Digite um salt para hash: ").strip()

    usuarios = carregarJson(arquivoUser)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]")
        time.sleep(2)
        return

    LimparTela()
    titulo("SELECIONAR DESTINATÁRIO")

    table = Table(title="[bold cyan]Usuários Cadastrados[/bold cyan]", title_style="bold cyan", header_style="bold white on blue", padding=(0, 2))
    table.add_column("ID", justify="center", style="bright_cyan")
    table.add_column("Username", justify="center", style="magenta")
    table.add_column("Tipo", justify="center", style="green")

    for userId, dados in usuarios.items():
        table.add_row(userId, dados.get('username', ''), dados.get('tipo', 'usuario'))
    console.print(table, justify="center")

    destinatario_id = Prompt.ask("\n[bold yellow]Digite o ID do destinatário[/bold yellow]").strip()
    if destinatario_id not in usuarios:
        console.print("[bold red]Usuário não encontrado![/bold red]")
        time.sleep(2)
        return

    destinatario = usuarios[destinatario_id]['username']
    topico_privado = f"minharede/chat/{destinatario.lower().strip()}"


    cliente = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    cliente.connect(broker, 1883, 60)
    cliente.loop_start()

    LimparTela()
    titulo(f"CHAT PRIVADO → {destinatario.upper()}")
    contador = 1
    nome_base = input("Digite o nome do arquivo de histórico de mensagens: ").strip()


    console.print(Panel.fit(
        "[bold cyan]Digite suas mensagens abaixo.[/bold cyan]\n[dim]Digite 'sair' para encerrar a conversa.[/dim]",
        border_style="cyan",
        title=f" Chat com {destinatario}",
        title_align="center"
    ))

    try:
        while True:
            msg = Prompt.ask(Fore.LIGHTCYAN_EX + f"{remetente}" + Fore.RESET)
            if msg.lower() == "sair":
                console.print("[bold yellow]Encerrando chat...[/bold yellow]")
                break 
            if not msg.strip():
                continue

            cliente.publish(topico_privado, f"{remetente}:{msg}")

            registro = {
                "remetente": remetente,
                "destinatario": destinatario,
                "original": msg,
                "hash_msg": hash_mensagem(msg, salt),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "topico": topico_privado,
                "broker": broker
            }
            
            nome_arquivo = f"{nome_base}_{contador}.json"
            nome_arquivo_geral = f"{nome_base}_geral.json"
            salvar_json(nome_arquivo_geral, registro)
            salvar_json(nome_arquivo, registro)
            contador += 1

            hora = datetime.datetime.now().strftime("%H:%M:%S")
            console.print(f"[{hora}] [bold green]{remetente} →[/bold green] [white]{msg}[/white]")
            
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Chat encerrado.[/bold yellow]")
    finally:
        cliente.loop_stop()
        cliente.disconnect()

def historico_mensagens(usuario):
    LimparTela()
    titulo(f"HISTÓRICO DE MENSAGENS - {usuario.upper()}")
    arquivos = [f for f in os.listdir('.') if f.startswith(f"{usuario}_") and f.endswith('.json')]

    if not arquivos:
        console.print("[bold red]Nenhum histórico de mensagens encontrado.[/bold red]")
        time.sleep(2)
        return

    for arquivo in arquivos:
        dados = carregar_json(arquivo)
        console.print(Panel.fit(
            f"[bold cyan]Remetente:[/bold cyan] {dados.get('remetente','')}\n"
            f"[bold cyan]Destinatário:[/bold cyan] {dados.get('destinatario','')}\n"
            f"[bold cyan]Mensagem Original:[/bold cyan] {dados.get('original','')}\n"
            f"[bold cyan]Hash da Mensagem:[/bold cyan] {dados.get('hash_msg','')}\n"
            f"[bold cyan]Timestamp:[/bold cyan] {dados.get('timestamp','')}\n"
            f"[bold cyan]Tópico MQTT:[/bold cyan] {dados.get('topico','')}\n"
            f"[bold cyan]Broker MQTT:[/bold cyan] {dados.get('broker','')}",
            border_style="green",
            title=f"Arquivo: {arquivo}",
            title_align="center"
        ))
        console.print("\n")
    input("Pressione Enter para voltar ao menu...")

def receber_mensagem(usuario, broker="test.mosquitto.org"):
    topico = f"minharede/chat/{usuario.lower().strip()}"

    def on_message(client, userdata, message):
        hora = datetime.datetime.now().strftime("%H:%M:%S")
        conteudo = message.payload.decode()

        if ":" in conteudo:
            remetente, texto = conteudo.split(":", 1)
        else:
            remetente, texto = "Desconhecido", conteudo

        if remetente.lower() == "admin":
            remetente_exibido = "[bold red]Admin[/bold red]"
        else:
            remetente_exibido = f"[bold cyan]{remetente}[/bold cyan]"

        console.print(f"[{hora}] {remetente_exibido} → [white]{texto}[/white]")

    cliente = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    cliente.on_message = on_message
    cliente.connect(broker, 1883, 60)
    cliente.subscribe(topico)
    cliente.loop_start()

    LimparTela()
    titulo(f" CHAT PRIVADO ({usuario.upper()})")

    console.print(Panel.fit(
        f"[bold cyan]Escutando mensagens no tópico '{topico}'.[/bold cyan]\n[dim]Pressione Ctrl+C para sair.[/dim]",
        border_style="magenta",
        title="Mensagens Criptografadas",
        title_align="center"
    ))
    
    responder = input(Fore.LIGHTMAGENTA_EX + "Deseja responder às mensagens? (s/n): " + Fore.RESET).strip().lower()
    if responder == 's':
        thread_envio = threading.Thread(target=enviar_mensagem, kwargs={"broker": broker, "remetente": usuario})
        thread_envio.start()
    else:
        console.print("[bold yellow]Você escolheu não responder às mensagens.[/bold yellow]")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Chat encerrado.[/bold yellow]")
    finally:
        cliente.loop_stop()
        cliente.disconnect()
        
 #//////////////////////////////////////////////////////////

def MenuPrincipalADM():
    while True:
        LimparTela()
        titulo("MENU ADMINISTRADOR")
        console.print(Align.center(Panel.fit("[1] - Gerenciamento de Usuários\n[2] - Envio de Mensagens\n[3] - Sair", border_style="green")))
        result = input("> ").strip()
        if result == '1':
            gerenciamentoUser()
        elif result == '2':
            enviar_mensagem()
        elif result == '3':
            break
        else:
            console.print(Fore.RED + "Digite algo válido")
    LimparTela()

def MenuPrincipalUser(usuario):
    while True:
        LimparTela()
        titulo(f"MENU DO USUÁRIO ({usuario.upper()})")
        console.print(Align.center(Panel.fit(
            "[1] - Mensagens Recebidas\n[2] - Sair",
            border_style="magenta",
            title="Selecione uma opção",
            title_align="center"
        )))
        result = input("> ").strip()
        if result == '1':
            receber_mensagem(usuario)
            
        elif result == '2':
            historico_mensagens(usuario)
            
        elif result == '3':
            console.print("[bold yellow]Saindo...[/bold yellow]")
            time.sleep(1)
            break
        else:
            console.print(Fore.RED + "Digite algo válido!")
            time.sleep(1)
    LimparTela()

if __name__ == "__main__":
    menuPrincipal()