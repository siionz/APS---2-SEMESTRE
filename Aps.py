# chat_seguro_com_fernet.py
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
import threading
from cryptography.fernet import Fernet, InvalidToken

# -------------------- Inicialização --------------------
init(autoreset=True)
console = Console()

# Arquivos / pastas
ARQUIVO_USERS = "usuarios.json"
ARQUIVO_KEYS = "keys.json"
PASTA_CHAVES = "chaves"
PASTA_HIST = "historico"

# cria pastas se não existirem
os.makedirs(PASTA_CHAVES, exist_ok=True)
os.makedirs(PASTA_HIST, exist_ok=True)

salt_digitado = input("Insira um salt para você utilizar: ").strip()

# -------------------- Utilitários --------------------
def LimparTela():
    os.system('cls' if os.name == 'nt' else 'clear')

def titulo(texto):
    banner = pyfiglet.figlet_format(texto, font="slant")
    painel = Panel(
        Align.center(f"[bold blue]{banner}[/bold blue]", vertical="middle"),
        border_style="cyan",
        padding=(0, 2),
        title="// Sistema Seguro - MARINHA //",
        title_align="center",
        width=100
    )
    console.print(Align.center(painel))

def carregarJson(arquivo):
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def salvar_dados(arquivo, dados):
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(dados, f, ensure_ascii=False, indent=4)

def carregar_json_lista(arquivo):
    """Retorna lista de registros salvos (ou lista vazia)."""
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def salvar_json_lista(arquivo, lista):
    with open(arquivo, 'w', encoding='utf-8') as f:
        json.dump(lista, f, ensure_ascii=False, indent=2)

def append_historico(username, registro):
    """Adiciona um registro (criptografado) ao histórico do usuário."""
    caminho = os.path.join(PASTA_HIST, f"{username}.json")
    lst = carregar_json_lista(caminho)
    lst.append(registro)
    salvar_json_lista(caminho, lst)

# -------------------- Senhas (SHA-256) --------------------
def criptografarSenha(senha):
    senhaComSalt = senha + salt_digitado
    return hashlib.sha256(senhaComSalt.encode()).hexdigest()

def verificarSenha(senhaDigitada, hashArmazenado):
    return criptografarSenha(senhaDigitada) == hashArmazenado

# -------------------- Chaves Fernet por usuário --------------------
def carregar_keys():
    keys = carregarJson(ARQUIVO_KEYS)
    if not isinstance(keys, dict):
        keys = {}
    return keys

def salvar_keys(keys):
    salvar_dados(ARQUIVO_KEYS, keys)

def gerar_chave_para_usuario(username):
    keys = carregar_keys()
    if username in keys and keys[username]:
        return keys[username]
    chave = Fernet.generate_key().decode()  # string
    keys[username] = chave
    salvar_keys(keys)
    # salva também em arquivo individual para facilitar cópia
    with open(os.path.join(PASTA_CHAVES, f"{username}.key"), "w", encoding="utf-8") as f:
        f.write(chave)
    return chave

def obter_fernet_por_username(username):
    keys = carregar_keys()
    chave = keys.get(username)
    if not chave:
        # tentar ler arquivo em chaves/
        caminho = os.path.join(PASTA_CHAVES, f"{username}.key")
        if os.path.exists(caminho):
            with open(caminho, "r", encoding="utf-8") as f:
                chave = f.read().strip()
            # salva no keys.json para consistência
            keys[username] = chave
            salvar_keys(keys)
        else:
            return None
    try:
        return Fernet(chave.encode())
    except Exception:
        return None

def exportar_chave(username, caminho_arquivo):
    keys = carregar_keys()
    chave = keys.get(username)
    if not chave:
        return False
    with open(caminho_arquivo, "w", encoding="utf-8") as f:
        f.write(chave)
    return True

def importar_chave_para_usuario(username, caminho_arquivo):
    if not os.path.exists(caminho_arquivo):
        return False, "Arquivo não encontrado"
    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        chave = f.read().strip()
    try:
        # valida chave
        Fernet(chave.encode())
    except Exception:
        return False, "Chave inválida"
    keys = carregar_keys()
    keys[username] = chave
    salvar_keys(keys)
    # salva arquivo em chaves/
    with open(os.path.join(PASTA_CHAVES, f"{username}.key"), "w", encoding="utf-8") as f:
        f.write(chave)
    return True, "Chave importada com sucesso"

# -------------------- Usuários / Autenticação --------------------
def loginUser():
    LimparTela()
    titulo("Login de Usuarios")
    usuarios = carregarJson(ARQUIVO_USERS)

    username_digitado = input(Fore.CYAN + "\nDigite seu username: " + Style.RESET_ALL).strip()
    senha = input(Fore.CYAN + "Digite sua senha: " + Style.RESET_ALL).strip()

    for userId, dados in usuarios.items():
        if dados['username'] == username_digitado:
            if verificarSenha(senha, dados.get('passwordHash', '')):
                console.print("\n[bold green]✔ Login realizado com sucesso![/bold green]")
                time.sleep(1)
                # garante que o usuário tenha chave
                gerar_chave_para_usuario(username_digitado)
                tipo = dados.get('tipo', 'usuario').lower()
                if tipo == 'admin':
                    MenuPrincipalADM()
                    return True
                else:
                    MenuPrincipalUser(username_digitado)
                    return True
            else:
                console.print("\n[bold red]Senha incorreta.[/bold red]")
                time.sleep(2)
                return False
    console.print("[bold red]Usuário não encontrado.[/bold red]")
    time.sleep(2)
    return False

def adicionarUsers():
    LimparTela()
    titulo("ADICIONAR USUÁRIOS")
    usuarios = carregarJson(ARQUIVO_USERS)
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

    if len(senha) < 8 or not (minusculo() and maiusculo() and numeros() and caracteres_especiais()):
        console.print("\n[bold red]A senha deve ter 8+ caracteres, maiúsculas, minúsculas, números e símbolo.[/bold red]")
        time.sleep(2)
        return

    tipo = input(Fore.CYAN + "Digite o tipo do usuário (admin/usuario): " + Style.RESET_ALL).strip().lower()
    senha_hash = criptografarSenha(senha)
    novo_id = str(len(usuarios) + 1)
    usuarios[novo_id] = {
        'username': username,
        'passwordHash': senha_hash,
        'tipo': tipo if tipo in ['admin', 'usuario'] else 'usuario'
    }
    salvar_dados(ARQUIVO_USERS, usuarios)

    # gerar e salvar chave para o usuário
    chave = gerar_chave_para_usuario(username)
    console.print(f"[bold green]Usuário '{username}' adicionado com sucesso![/bold green]")
    console.print(f"[bold cyan]Chave Fernet gerada para {username} e salva em '{PASTA_CHAVES}/{username}.key'.[/bold cyan]")
    time.sleep(2)

def modificarUser():
    LimparTela()
    titulo("MODIFICAR USUÁRIOS")
    usuarios = carregarJson(ARQUIVO_USERS)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]")
        time.sleep(2)
        return

    console.print("\n[bold cyan]Usuários Cadastrados:[/bold cyan]")
    for uid, dados in usuarios.items():
        console.print(f"ID: [bold yellow]{uid}[/bold yellow] | Username: [bold magenta]{dados.get('username','')}[/bold magenta] | Tipo: [bold green]{dados.get('tipo','usuario')}[/bold green]")

    uid = input(Fore.CYAN + "\nDigite o ID do usuário que deseja modificar: " + Style.RESET_ALL).strip()
    if not uid or uid not in usuarios:
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
        console.print("[bold red]Username já existe.[/bold red]")
        time.sleep(2)
        return

    # renomeia chave se nome mudou
    if novo_username and novo_username != atual_username:
        keys = carregar_keys()
        if atual_username in keys:
            keys[novo_username] = keys.pop(atual_username)
            salvar_keys(keys)
        # renomeia arquivo de chave se existir
        old_path = os.path.join(PASTA_CHAVES, f"{atual_username}.key")
        new_path = os.path.join(PASTA_CHAVES, f"{novo_username}.key")
        if os.path.exists(old_path):
            os.replace(old_path, new_path)
        user['username'] = novo_username

    if nova_senha:
        user['passwordHash'] = criptografarSenha(nova_senha)
    if novo_tipo and novo_tipo in ['admin', 'usuario']:
        user['tipo'] = novo_tipo

    salvar_dados(ARQUIVO_USERS, usuarios)
    console.print("[bold green]Usuário modificado com sucesso![/bold green]")
    time.sleep(2)

def excluirUsers():
    LimparTela()
    titulo("EXCLUIR USUÁRIOS")
    usuarios = carregarJson(ARQUIVO_USERS)
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
        nome = usuarios[userIdExcluir]['username']
        # remover chave
        keys = carregar_keys()
        if nome in keys:
            del keys[nome]
            salvar_keys(keys)
        key_file = os.path.join(PASTA_CHAVES, f"{nome}.key")
        if os.path.exists(key_file):
            os.remove(key_file)
        del usuarios[userIdExcluir]
        salvar_dados(ARQUIVO_USERS, usuarios)
        console.print("[bold green]Usuário excluído com sucesso![/bold green]")
    else:
        console.print("[bold yellow]Operação cancelada.[/bold yellow]")
    time.sleep(2)

def gerenciamentoUser():
    while True:
        LimparTela()
        titulo("GERENCIAMENTO DE USUÁRIOS")
        console.print(Panel.fit("[1] - Adicionar Usuários\n[2] - Modificar Usuários\n[3] - Excluir Usuários\n[4] - Exportar Chave\n[5] - Importar Chave\n[6] - Sair", title="Escolha uma opção", border_style="blue"))
        result = input("> ").strip()
        if result == '1':
            adicionarUsers()
        elif result == '2':
            modificarUser()
        elif result == '3':
            excluirUsers()
        elif result == '4':
            nome = input("Username para exportar a chave: ").strip()
            caminho = input("Caminho/arquivo para salvar (ex: alice.key): ").strip()
            if exportar_chave(nome, caminho):
                console.print(f"[bold green]Chave de {nome} salva em {caminho}[/bold green]")
            else:
                console.print("[bold red]Usuário ou chave não encontrada.[/bold red]")
            time.sleep(2)
        elif result == '5':
            nome = input("Username para importar a chave: ").strip()
            caminho = input("Caminho do arquivo de chave: ").strip()
            ok, msg = importar_chave_para_usuario(nome, caminho)
            if ok:
                console.print(f"[bold green]{msg}[/bold green]")
            else:
                console.print(f"[bold red]{msg}[/bold red]")
            time.sleep(2)
        elif result == '6':
            break
        else:
            console.print(Fore.RED + "Digite algo válido")
    LimparTela()

# -------------------- Hash de mensagem (integridade) --------------------
def hash_mensagem(msg, salt):
    return hashlib.sha256((msg + salt).encode('utf-8')).hexdigest()

# -------------------- Menu principal --------------------
def menuPrincipal():
    while True:
        LimparTela()
        titulo("MENU PRINCIPAL")
        console.print(Align.center(Panel.fit("[1] - Logar como usuário\n[2] - Logar como administrador\n[3] - Sair", border_style="cyan", title="Escolha uma opção")))
        result = input("> ").strip()
        if result == '3':
            LimparTela()
            break
        elif result in ['1', '2']:
            if loginUser():
                LimparTela()
        else:
            console.print(Fore.RED + "Digite uma opção válida!")
            time.sleep(2)
            LimparTela()

# -------------------- MQTT + Fernet aplicado --------------------
def enviar_mensagem(
    broker="test.mosquitto.org",
    remetente="Admin",
    salt=None
):
    if salt is None:
        salt = input("Digite um salt para hash: ").strip()

    usuarios = carregarJson(ARQUIVO_USERS)
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

    # escolha da chave
    console.print("\n[bold cyan]Escolha qual chave usar para criptografar a mensagem:[/bold cyan]")
    console.print("[1] Usar chave do destinatário (padrão, recomendado)")
    console.print("[2] Colar uma chave manualmente")
    escolha_chave = input("Escolha (1/2) [1]: ").strip() or "1"

    if escolha_chave == "1":
        f_dest = obter_fernet_por_username(destinatario)
        if not f_dest:
            console.print("[bold red]Destinatário não possui chave registrada. Importe ou gere a chave primeiro.[/bold red]")
            time.sleep(2)
            return
        fernet_local = f_dest
    else:
        chave_manual = input("Cole a chave Fernet (string base64): ").strip()
        try:
            fernet_local = Fernet(chave_manual.encode())
        except Exception:
            console.print("[bold red]Chave inválida.[/bold red]")
            time.sleep(2)
            return

    cliente = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    cliente.connect(broker, 1883, 60)
    cliente.loop_start()

    LimparTela()
    titulo(f"CHAT PRIVADO → {destinatario.upper()}")
    contador = 1
    nome_base = input("Digite o nome do arquivo de histórico de mensagens (prefixo): ").strip() or remetente

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

            plaintext = f"{remetente}:{msg}"
            try:
                cript_bytes = fernet_local.encrypt(plaintext.encode())
                cript_str = cript_bytes.decode()
            except Exception:
                console.print("[bold red]Erro ao criptografar a mensagem.[/bold red]")
                time.sleep(2)
                continue

            # publica a string base64 do fernet
            cliente.publish(topico_privado, cript_str)

            registro = {
                "remetente": remetente,
                "destinatario": destinatario,
                "mensagem_criptografada": cript_str,
                "hash_msg": hash_mensagem(cript_str, salt),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "topico": topico_privado,
                "broker": broker,
                "usou_chave_destinatario": (escolha_chave == "1")
            }

            # salva no histórico do remetente e do destinatário (criptografado)
            append_historico(remetente, registro)
            append_historico(destinatario, registro)

            # salva arquivo individual sequencial também (prefixo)
            nome_arquivo = os.path.join(PASTA_HIST, f"{nome_base}_{contador}.json")
            salvar_json_lista(nome_arquivo, [registro])  # salva lista com 1 item
            contador += 1

            hora = datetime.datetime.now().strftime("%H:%M:%S")
            console.print(f"[{hora}] [bold green]{remetente} →[/bold green] [white]{'<mensagem criptografada enviada>'}[/white]")
            console.print(f"[dim]Mensagem salva (criptografada) nos históricos de {remetente} e {destinatario}.[/dim]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Chat encerrado.[/bold yellow]")
    finally:
        cliente.loop_stop()
        cliente.disconnect()

def historico_mensagens(usuario):
    LimparTela()
    titulo(f"HISTÓRICO DE MENSAGENS - {usuario.upper()}")
    caminho = os.path.join(PASTA_HIST, f"{usuario}.json")
    registros = carregar_json_lista(caminho)

    if not registros:
        console.print("[bold red]Nenhum histórico de mensagens encontrado.[/bold red]")
        time.sleep(2)
        return

    for rec in registros:
        console.print(Panel.fit(
            f"[bold cyan]Remetente:[/bold cyan] {rec.get('remetente','')}\n"
            f"[bold cyan]Destinatário:[/bold cyan] {rec.get('destinatario','')}\n"
            f"[bold cyan]Mensagem Criptografada:[/bold cyan] {rec.get('mensagem_criptografada','')}\n"
            f"[bold cyan]Hash da Mensagem:[/bold cyan] {rec.get('hash_msg','')}\n"
            f"[bold cyan]Timestamp:[/bold cyan] {rec.get('timestamp','')}\n"
            f"[bold cyan]Tópico MQTT:[/bold cyan] {rec.get('topico','')}\n"
            f"[bold cyan]Broker MQTT:[/bold cyan] {rec.get('broker','')}",
            border_style="green",
            title=f"Registro",
            title_align="center"
        ))
        console.print("\n")
    input("Pressione Enter para voltar ao menu...")

def receber_mensagem(usuario, broker="test.mosquitto.org"):
    topico = f"minharede/chat/{usuario.lower().strip()}"

    # carrega fernet do usuario
    f_user = None
    try:
        f_user = obter_fernet_por_username(usuario)
    except Exception:
        f_user = None

    def on_message(client, userdata, message):
        hora = datetime.datetime.now().strftime("%H:%M:%S")
        raw = message.payload
        # garante bytes
        if isinstance(raw, str):
            payload_bytes = raw.encode()
        else:
            payload_bytes = raw

        texto = None
        if f_user:
            try:
                texto = f_user.decrypt(payload_bytes).decode()
            except (InvalidToken, Exception):
                texto = None

        if texto is None:
            # não descriptografou com a chave do usuário
            try:
                raw_str = payload_bytes.decode()
            except Exception:
                raw_str = str(payload_bytes)
            console.print(f"[{hora}] [bold yellow]Mensagem recebida - NÃO PUEDE DESCRIPT.[/bold yellow]\n[dim]Raw: {raw_str}[/dim]")
            # opcional: salvar histórico como não lida/descriptografável
            registro = {
                "remetente": "desconhecido",
                "destinatario": usuario,
                "mensagem_criptografada": raw_str,
                "hash_msg": hash_mensagem(raw_str, salt_digitado),
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "topico": topico,
                "broker": broker,
                "descriptografavel": False
            }
            append_historico(usuario, registro)
            return

        # se descriptografou, separa remetente:mensagem
        if ":" in texto:
            remetente, texto_msg = texto.split(":", 1)
        else:
            remetente, texto_msg = "Desconhecido", texto

        if remetente.lower() == "admin":
            remetente_exibido = "[bold red]Admin[/bold red]"
        else:
            remetente_exibido = f"[bold cyan]{remetente}[/bold cyan]"

        console.print(f"[{hora}] {remetente_exibido} → [white]{texto_msg}[/white]")

        # salva no histórico do destinatário (criptografado conforme recebido)
        registro = {
            "remetente": remetente,
            "destinatario": usuario,
            "mensagem_criptografada": payload_bytes.decode() if isinstance(payload_bytes, bytes) else str(payload_bytes),
            "hash_msg": hash_mensagem(payload_bytes.decode() if isinstance(payload_bytes, bytes) else str(payload_bytes), salt_digitado),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "topico": topico,
            "broker": broker,
            "descriptografavel": True
        }
        append_historico(usuario, registro)

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

# -------------------- Menus finais --------------------
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
            "[1] - Enviar mensagem\n[2] - Histórico (criptografado)\n[3] - Sair",
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
