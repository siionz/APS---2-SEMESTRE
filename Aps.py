# chat_seguro_com_fernet.py
# Chat seguro com Fernet por usuário + master key salva em disco (chaves/server_master.key).
# Histórico totalmente criptografado (cada registro é um pacote cifrado).
# Comentários essenciais apenas.

import os, json, time, hashlib, base64, threading
from cryptography.fernet import Fernet, InvalidToken
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt
from rich import box
from colorama import init, Fore, Style
import paho.mqtt.client as mqtt
import pyfiglet
import datetime

# ---- Config / init ----
init(autoreset=True)
console = Console()
BANNER = "// Sistema Seguro - MARINHA //"

ARQ_USERS = "usuarios.json"
ARQ_KEYS = "keys.json"        # mapping username -> encrypted(raw_key) (encrypted with MASTER_FERNET)
PASTA_CHAVES = "chaves"      # individual files: <username>.key (also encrypted with MASTER_FERNET)
PASTA_HIST = "historico"     # per-owner files: <owner>.json -> list of {"pacote_criptografado": "..."}
MASTER_KEY_FILE = os.path.join(PASTA_CHAVES, "server_master.key")
BROKER_DEFAULT = "broker.hivemq.com"


# garante diretórios
os.makedirs(PASTA_CHAVES, exist_ok=True)
os.makedirs(PASTA_HIST, exist_ok=True)

# salt para hashing de senhas (entrada do usuário)
salt_digitado = input("Insira um salt para uso no sistema (hash de senhas): ").strip()

# ---- Master key: carregar/criar (arquivo em chaves/server_master.key) ----
def load_or_create_master_fernet():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            raw = f.read()
            try:
                # assume raw is base64 urlsafe key
                return Fernet(raw)
            except Exception:
                # arquivo inválido -> regenerate (overwrite)
                pass
    key = Fernet.generate_key()
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(key)
    return Fernet(key)

MASTER_FERNET = load_or_create_master_fernet()

# ---- utilitários JSON e UI ----
def clear(): os.system("cls" if os.name == "nt" else "clear")
def titulo(texto):
    banner = pyfiglet.figlet_format(texto, font="slant")
    painel = Panel(Align.center(f"[bold blue]{banner}[/bold blue]"), border_style="cyan", title=BANNER, title_align="center", padding=(0,1))
    console.print(Align.center(painel))

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception:
        return {}
def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, ensure_ascii=False, indent=4)
def load_list(path):
    try:
        with open(path, "r", encoding="utf-8") as f: return json.load(f)
    except Exception:
        return []
def save_list(path, lst):
    with open(path, "w", encoding="utf-8") as f: json.dump(lst, f, ensure_ascii=False, indent=2)

# ---- gerenciamento de chaves (armazenadas cifradas com MASTER_FERNET) ----
def carregar_keys_encriptadas():
    d = load_json(ARQ_KEYS)
    return d if isinstance(d, dict) else {}

def salvar_keys_encriptadas(d):
    save_json(ARQ_KEYS, d)

def gerar_chave_para_usuario(username):
    """Gera raw_key Fernet (base64 string), cifra com master e salva em keys.json e em arquivo cifrado."""
    keys = carregar_keys_encriptadas()
    enc = keys.get(username)
    if enc:
        try:
            raw = MASTER_FERNET.decrypt(enc.encode()).decode()
            return raw
        except Exception:
            pass
    raw = Fernet.generate_key().decode()
    enc_raw = MASTER_FERNET.encrypt(raw.encode()).decode()
    keys[username] = enc_raw
    salvar_keys_encriptadas(keys)
    # grava arquivo de backup cifrado (conteúdo = enc_raw)
    with open(os.path.join(PASTA_CHAVES, f"{username}.key"), "w", encoding="utf-8") as f:
        f.write(enc_raw)
    return raw

def obter_raw_key_username(username):
    """Retorna raw base64 key (string) do usuário, ou None."""
    keys = carregar_keys_encriptadas()
    enc = keys.get(username)
    if enc:
        try:
            return MASTER_FERNET.decrypt(enc.encode()).decode()
        except Exception:
            pass
    # tenta ler arquivo chaves/<user>.key (pode conter enc_raw)
    caminho = os.path.join(PASTA_CHAVES, f"{username}.key")
    if os.path.exists(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            data = f.read().strip()
        # data pode ser enc_raw (cifrado com master) ou raw (antigo)
        try:
            # se data descriptografa -> é enc_raw
            raw = MASTER_FERNET.decrypt(data.encode()).decode()
            # salva em keys.json para consistência
            keys[username] = data
            salvar_keys_encriptadas(keys)
            return raw
        except Exception:
            # assume formato antigo (raw) -> cifrar e salvar
            try:
                Fernet(data.encode())  # valida raw
                enc_raw = MASTER_FERNET.encrypt(data.encode()).decode()
                keys[username] = enc_raw
                salvar_keys_encriptadas(keys)
                with open(caminho, "w", encoding="utf-8") as f: f.write(enc_raw)
                return data
            except Exception:
                return None
    return None

def obter_fernet_por_username(username):
    raw = obter_raw_key_username(username)
    if not raw: return None
    try: return Fernet(raw.encode())
    except Exception: return None

def exportar_chave(username, caminho_arquivo):
    raw = obter_raw_key_username(username)
    if not raw: return False
    with open(caminho_arquivo, "w", encoding="utf-8") as f: f.write(raw)
    return True

def importar_chave_para_usuario(username, caminho_arquivo):
    if not os.path.exists(caminho_arquivo): return False, "Arquivo não encontrado"
    with open(caminho_arquivo, "r", encoding="utf-8") as f: raw = f.read().strip()
    try:
        Fernet(raw.encode())
    except Exception:
        return False, "Chave inválida"
    enc = MASTER_FERNET.encrypt(raw.encode()).decode()
    keys = carregar_keys_encriptadas()
    keys[username] = enc
    salvar_keys_encriptadas(keys)
    with open(os.path.join(PASTA_CHAVES, f"{username}.key"), "w", encoding="utf-8") as f:
        f.write(enc)
    return True, "Chave importada com sucesso"

# ---- histórico: pacote completo criptografado (cada entrada cifrada com chave do owner) ----
def encrypt_registro_for_owner(registro, owner):
    f = obter_fernet_por_username(owner) or MASTER_FERNET
    return {"pacote_criptografado": f.encrypt(json.dumps(registro, ensure_ascii=False).encode()).decode()}

def append_historico(owner, registro):
    caminho = os.path.join(PASTA_HIST, f"{owner}.json")
    lst = load_list(caminho)
    lst.append(encrypt_registro_for_owner(registro, owner))
    save_list(caminho, lst)

def salvar_sequencial_criptografado(nome_arquivo, registro, owner):
    caminho = os.path.join(PASTA_HIST, nome_arquivo)
    save_list(caminho, [encrypt_registro_for_owner(registro, owner)])

def decrypt_pacote_for_user(pacote_criptografado, username):
    f_user = obter_fernet_por_username(username)
    if f_user:
        try:
            dec = f_user.decrypt(pacote_criptografado.encode()).decode()
            return json.loads(dec), "user"
        except (InvalidToken, Exception):
            pass
    try:
        dec = MASTER_FERNET.decrypt(pacote_criptografado.encode()).decode()
        return json.loads(dec), "master"
    except (InvalidToken, Exception):
        return None, None

# ---- senhas (SHA-256 com salt digitado) ----
def criptografarSenha(senha): return hashlib.sha256((senha + salt_digitado).encode()).hexdigest()
def verificarSenha(senhaDigitada, hashArmazenado): return criptografarSenha(senhaDigitada) == hashArmazenado

# ---- CRUD usuários (mantive lógica original) ----
def listar_usuarios():
    usuarios = load_json(ARQ_USERS)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]"); time.sleep(1); return {}
    table = Table(title="Usuários Cadastrados", box=box.MINIMAL)
    table.add_column("ID"); table.add_column("Username"); table.add_column("Tipo")
    for uid, dados in usuarios.items():
        table.add_row(uid, dados.get("username", ""), dados.get("tipo", "usuario"))
    console.print(table)
    return usuarios

def adicionarUsers():
    clear(); titulo("ADICIONAR USUÁRIOS")
    usuarios = load_json(ARQ_USERS) or {}
    username = input("Digite o username do novo usuário: ").strip()
    if any(user['username'] == username for user in usuarios.values()):
        console.print("[bold red]Username já existe. Tente novamente.[/bold red]"); time.sleep(2); return
    senha = input("Digite a senha do novo usuário: ").strip()
    if len(senha) < 8 or not any(c.islower() for c in senha) or not any(c.isupper() for c in senha) or not any(c.isdigit() for c in senha) or not any(not c.isalnum() for c in senha):
        console.print("\n[bold red]A senha deve ter 8+ caracteres, maiúsculas, minúsculas, números e símbolo.[/bold red]"); time.sleep(2); return
    tipo = input("Digite o tipo do usuário (admin/usuario): ").strip().lower() or "usuario"
    novo_id = str(len(usuarios) + 1)
    usuarios[novo_id] = {
        'username': username,
        'passwordHash': criptografarSenha(senha),
        'tipo': tipo if tipo in ['admin', 'usuario'] else 'usuario'
    }
    save_json(ARQ_USERS, usuarios)
    gerar_chave_para_usuario(username)
    console.print(f"[bold green]Usuário '{username}' adicionado com sucesso![/bold green]"); time.sleep(1)

def modificarUser():
    clear(); titulo("MODIFICAR USUÁRIOS")
    usuarios = load_json(ARQ_USERS)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]"); time.sleep(1); return
    for uid, dados in usuarios.items():
        console.print(f"ID: {uid} | Username: {dados.get('username','')} | Tipo: {dados.get('tipo','usuario')}")
    uid = input("\nDigite o ID do usuário que deseja modificar: ").strip()
    if not uid or uid not in usuarios:
        console.print("[bold red]Usuário não encontrado.[/bold red]"); time.sleep(1); return
    user = usuarios[uid]
    atual_username = user.get('username', '')
    novo_username = input(f"Digite o novo username (atual: {atual_username}): ").strip()
    nova_senha = input("Digite a nova senha (deixe em branco para manter a atual): ").strip()
    novo_tipo = input(f"Digite o novo tipo (admin/usuario) (atual: {user.get('tipo','usuario')}): ").strip().lower()
    if novo_username and any(d.get('username') == novo_username for k, d in usuarios.items() if k != uid):
        console.print("[bold red]Username já existe.[/bold red]"); time.sleep(1); return
    if novo_username and novo_username != atual_username:
        keys = carregar_keys_encriptadas()
        if atual_username in keys:
            keys[novo_username] = keys.pop(atual_username); salvar_keys_encriptadas(keys)
        old_path = os.path.join(PASTA_CHAVES, f"{atual_username}.key"); new_path = os.path.join(PASTA_CHAVES, f"{novo_username}.key")
        if os.path.exists(old_path): os.replace(old_path, new_path)
        user['username'] = novo_username
    if nova_senha: user['passwordHash'] = criptografarSenha(nova_senha)
    if novo_tipo and novo_tipo in ['admin', 'usuario']: user['tipo'] = novo_tipo
    save_json(ARQ_USERS, usuarios)
    console.print("[bold green]Usuário modificado com sucesso![/bold green]"); time.sleep(1)

def excluirUsers():
    clear(); titulo("EXCLUIR USUÁRIOS")
    usuarios = load_json(ARQ_USERS)
    if not usuarios:
        console.print("[bold red]Nenhum usuário cadastrado.[/bold red]"); time.sleep(1); return
    table = Table(title="[bold cyan]Usuários Cadastrados[/bold cyan]", box=box.SIMPLE)
    table.add_column("ID"); table.add_column("Username"); table.add_column("Tipo")
    for userId, dados in usuarios.items():
        table.add_row(userId, dados.get('username', ''), dados.get('tipo', 'usuario'))
    console.print(table)
    userIdExcluir = Prompt.ask("\nDigite o ID do usuário que deseja excluir").strip()
    if userIdExcluir not in usuarios:
        console.print("[bold red]Usuário não encontrado.[/bold red]"); time.sleep(1); return
    confirm = Prompt.ask(f"Tem certeza que deseja excluir o usuário '{usuarios[userIdExcluir]['username']}'? (s/n)", default="n").lower()
    if confirm == 's':
        nome = usuarios[userIdExcluir]['username']
        keys = carregar_keys_encriptadas()
        if nome in keys:
            del keys[nome]; salvar_keys_encriptadas(keys)
        key_file = os.path.join(PASTA_CHAVES, f"{nome}.key")
        if os.path.exists(key_file): os.remove(key_file)
        del usuarios[userIdExcluir]; save_json(ARQ_USERS, usuarios)
        console.print("[bold green]Usuário excluído com sucesso![/bold green]")
    else:
        console.print("[bold yellow]Operação cancelada.[/bold yellow]")
    time.sleep(1)

def gerenciamentoUser():
    while True:
        clear(); titulo("GERENCIAMENTO DE USUÁRIOS")
        console.print(Panel.fit("[1] - Adicionar Usuários\n[2] - Modificar Usuários\n[3] - Excluir Usuários\n[4] - Exportar Chave\n[5] - Importar Chave\n[6] - Sair", title="Escolha uma opção"))
        result = input("> ").strip()
        if result == '1': adicionarUsers()
        elif result == '2': modificarUser()
        elif result == '3': excluirUsers()
        elif result == '4':
            nome = input("Username para exportar a chave: ").strip(); caminho = input("Caminho/arquivo para salvar (.key): ").strip()
            if exportar_chave(nome, caminho): console.print("[bold green]Exportado com sucesso.[/bold green]")
            else: console.print("[bold red]Erro: usuário/chave não encontrada.[/bold red]"); time.sleep(1)
        elif result == '5':
            nome = input("Username para importar a chave: ").strip(); caminho = input("Caminho do arquivo .key: ").strip()
            ok, msg = importar_chave_para_usuario(nome, caminho); console.print(f"[{'green' if ok else 'red'}]{msg}[/]"); time.sleep(1)
        elif result == '6': break
        else: console.print(Fore.RED + "Digite algo válido"); time.sleep(1)
    clear()

# ---- Hash integridade ----
def hash_mensagem(msg, salt): return hashlib.sha256((msg + salt).encode('utf-8')).hexdigest()

# ---- login/auth ----
def loginUser():
    clear(); titulo("Login de Usuarios")
    usuarios = load_json(ARQ_USERS)
    username_digitado = input(Fore.CYAN + "\nDigite seu username: " + Style.RESET_ALL).strip()
    senha = input(Fore.CYAN + "Digite sua senha: " + Style.RESET_ALL).strip()
    for userId, dados in usuarios.items():
        if dados.get('username') == username_digitado:
            if verificarSenha(senha, dados.get('passwordHash', '')):
                console.print("\n[bold green]✔ Login realizado com sucesso![/bold green]"); time.sleep(0.8)
                gerar_chave_para_usuario(username_digitado)
                tipo = dados.get('tipo', 'usuario').lower()
                if tipo == 'admin': MenuPrincipalADM()
                else: MenuPrincipalUser(username_digitado)
                return True
            else:
                console.print("\n[bold red]Senha incorreta.[/bold red]"); time.sleep(1); return False
    console.print("[bold red]Usuário não encontrado.[/bold red]"); time.sleep(1); return False

# ---- envio MQTT / gravação histórica (pacote completo criptografado) ----
def enviar_mensagem(broker=BROKER_DEFAULT, remetente="Admin", salt=None):
    if salt is None: salt = input("Digite um salt para hash (ou enter): ").strip() or salt_digitado
    usuarios = load_json(ARQ_USERS)
    if not usuarios: console.print("[bold red]Nenhum usuário cadastrado.[/bold red]"); time.sleep(1); return
    clear(); titulo("SELECIONAR DESTINATÁRIO")
    table = Table(title="[bold cyan]Usuários Cadastrados[/bold cyan]", box=box.SIMPLE)
    table.add_column("ID"); table.add_column("Username"); table.add_column("Tipo")
    for userId, dados in usuarios.items(): table.add_row(userId, dados.get('username', ''), dados.get('tipo', 'usuario'))
    console.print(table)
    destinatario_id = Prompt.ask("\nDigite o ID do destinatário").strip()
    if destinatario_id not in usuarios: console.print("[bold red]Usuário não encontrado![/bold red]"); time.sleep(1); return
    destinatario = usuarios[destinatario_id]['username']; topico_privado = f"minharede/chat/{destinatario.lower().strip()}"
    console.print("\n[1] Usar chave do destinatário")
    escolha_chave = input("Escolha: ").strip() or "1"
    if escolha_chave == "1":
        f_dest = obter_fernet_por_username(destinatario)
        if not f_dest: console.print("[bold red]Destinatário não possui chave registrada.[/bold red]"); time.sleep(1); return
        fernet_local = f_dest
    else:
        chave_manual = input("Cole a chave Fernet (string base64): ").strip()
        try: fernet_local = Fernet(chave_manual.encode())
        except Exception: console.print("[bold red]Chave inválida.[/bold red]"); time.sleep(1); return

    cliente = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    try: cliente.connect(broker, 1883, 60); cliente.loop_start()
    except Exception as e: console.print(f"[bold red]Erro conectar broker: {e}[/bold red]"); return

    clear(); titulo(f"CHAT PRIVADO → {destinatario.upper()}"); contador = 1
    nome_base = input("Digite o nome do arquivo de histórico de mensagens (prefixo): ").strip() or remetente
    console.print(Panel.fit("[bold cyan]Digite suas mensagens abaixo.[/bold cyan]\n[dim]Digite 'sair' para encerrar a conversa.[/dim]"))
    try:
        while True:
            msg = Prompt.ask(Fore.LIGHTCYAN_EX + f"{remetente}" + Fore.RESET)
            if msg.lower() == "sair": console.print("[bold yellow]Encerrando chat...[/bold yellow]"); break
            if not msg.strip(): continue
            plaintext = f"{remetente}:{msg}"
            try:
                cript_str = fernet_local.encrypt(plaintext.encode()).decode()
            except Exception:
                console.print("[bold red]Erro ao criptografar a mensagem.[/bold red]"); time.sleep(1); continue
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
            append_historico(remetente, registro)
            append_historico(destinatario, registro)
            salvar_sequencial_criptografado(f"{nome_base}_{contador}.json", registro, remetente)
            contador += 1
            console.print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [bold green]{remetente} →[/bold green] [white]{'<mensagem criptografada enviada>'}[/white]")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Chat encerrado.[/bold yellow]")
    finally:
        try: cliente.loop_stop(); cliente.disconnect()
        except: pass

# ---- leitura/exibição do histórico (tenta descriptografar com key do user; se não, master) ----
def historico_mensagens(usuario):
    clear(); titulo(f"HISTÓRICO DE MENSAGENS - {usuario.upper()}")
    caminho = os.path.join(PASTA_HIST, f"{usuario}.json")
    registros = load_list(caminho)
    if not registros:
        console.print("[bold red]Nenhum histórico de mensagens encontrado.[/bold red]"); time.sleep(1); return
    for rec in registros:
        pacote_criptografado = rec.get("pacote_criptografado")
        if not pacote_criptografado:
            console.print("[bold red]Registro em formato inesperado (não criptografado).[/bold red]"); continue
        pacote, metodo = decrypt_pacote_for_user(pacote_criptografado, usuario)
        if pacote is None:
            console.print(Panel.fit(f"[bold yellow]Registro não pode ser descriptografado com sua chave nem com a master key.[/bold yellow]\n[dim]{pacote_criptografado}[/dim]", border_style="red"))
            console.print("\n"); continue
        console.print(Panel.fit(
            f"[bold cyan]Remetente:[/bold cyan] {pacote.get('remetente','')}\n"
            f"[bold cyan]Destinatário:[/bold cyan] {pacote.get('destinatario','')}\n"
            f"[bold cyan]Mensagem Criptografada:[/bold cyan] {pacote.get('mensagem_criptografada','')}\n"
            f"[bold cyan]Hash da Mensagem:[/bold cyan] {pacote.get('hash_msg','')}\n"
            f"[bold cyan]Timestamp:[/bold cyan] {pacote.get('timestamp','')}\n"
            f"[bold cyan]Tópico MQTT:[/bold cyan] {pacote.get('topico','')}\n"
            f"[bold cyan]Broker MQTT:[/bold cyan] {pacote.get('broker','')}\n"
            f"[bold cyan]Descriptografado com:[/bold cyan] {metodo}",
            border_style="green", title="Registro"))
        console.print("\n")
    input("Pressione Enter para voltar ao menu...")

# ---- (nova) listar mensagens recebidas e permitir descriptografar o conteúdo interno ----
def mensagens_para_descriptografar(usuario):
    clear()
    titulo(f"MENSAGENS RECEBIDAS - {usuario.upper()}")
    caminho = os.path.join(PASTA_HIST, f"{usuario}.json")
    registros = load_list(caminho)
    if not registros:
        console.print("[bold red]Nenhuma mensagem recebida.[/bold red]"); input("Pressione Enter para voltar..."); return

    # filtra apenas registros no formato novo (pacote_criptografado)
    mensagens_validas = [r for r in registros if isinstance(r, dict) and "pacote_criptografado" in r]
    if not mensagens_validas:
        console.print("[bold red]Nenhuma mensagem com pacote criptografado encontrada.[/bold red]"); input("Pressione Enter para voltar..."); return

    # tenta obter fernet do usuário para testar descriptografia da inner message
    f_user = obter_fernet_por_username(usuario)

    # exibe lista com indicação se a inner message parece descriptografável pela chave do usuário
    table = Table(title=f"Mensagens de {usuario}", box=box.MINIMAL)
    table.add_column("#", justify="right")
    table.add_column("Timestamp")
    table.add_column("Remetente")
    table.add_column("Inner OK?")
    for i, rec in enumerate(mensagens_validas, start=1):
        pkt = rec.get("pacote_criptografado")
        pkt_meta, metodo = decrypt_pacote_for_user(pkt, usuario)
        ts = pkt_meta.get("timestamp") if pkt_meta else "—"
        remet = pkt_meta.get("remetente") if pkt_meta else "—"
        inner = pkt_meta.get("mensagem_criptografada") if pkt_meta else None
        ok_inner = False
        if inner and f_user:
            try:
                f_user.decrypt(inner.encode())
                ok_inner = True
            except Exception:
                ok_inner = False
        table.add_row(str(i), str(ts), str(remet), "Sim" if ok_inner else "Não")
    console.print(table)

    console.print("\n[bold yellow]Digite o número da mensagem para tentar descriptografar (ou 0 para sair).[/bold yellow]")
    while True:
        escolha = input("> ").strip()
        if escolha == "0": break
        if not escolha.isdigit() or int(escolha) < 1 or int(escolha) > len(mensagens_validas):
            console.print("[bold red]Número inválido![/bold red]"); continue
        idx = int(escolha) - 1
        pacote_criptografado = mensagens_validas[idx]["pacote_criptografado"]
        pacote, metodo = decrypt_pacote_for_user(pacote_criptografado, usuario)
        if pacote is None:
            console.print("[bold red]Não foi possível descriptografar o pacote com sua chave nem com a master key.[/bold red]")
            continue

        # agora tenta descriptografar a mensagem interna (campo mensagem_criptografada)
        inner = pacote.get("mensagem_criptografada")
        texto_real = None
        f_msg_key = obter_fernet_por_username(usuario)
        if inner and f_msg_key:
            try:
                texto_real = f_msg_key.decrypt(inner.encode()).decode()
            except Exception:
                texto_real = None
        # fallback com master (somente se necessário)
        if texto_real is None and inner:
            try:
                texto_real = MASTER_FERNET.decrypt(inner.encode()).decode()
            except Exception:
                texto_real = None

        # mostra painel com resultado
        painel_text = (
            f"[cyan]Remetente:[/cyan] {pacote.get('remetente','')}\n"
            f"[cyan]Destinatário:[/cyan] {pacote.get('destinatario','')}\n"
            f"[cyan]Timestamp:[/cyan] {pacote.get('timestamp','')}\n"
            f"[cyan]Tópico:[/cyan] {pacote.get('topico','')}\n"
            f"[cyan]Broker:[/cyan] {pacote.get('broker','')}\n"
            f"[cyan]Hash:[/cyan] {pacote.get('hash_msg','')}\n"
            f"[cyan]Pacote descriptografado com:[/cyan] {metodo}\n\n"
            f"[cyan]Mensagem (criptografada):[/cyan]\n{inner if inner else '—'}\n\n"
        )
        if texto_real:
            # formata se padrão "Remetente:conteudo"
            if ":" in texto_real:
                remet_inner, msg_inner = texto_real.split(":", 1)
                painel_text += f"[bold]{remet_inner}[/bold] → {msg_inner}"
            else:
                painel_text += texto_real
        else:
            painel_text += "[yellow]Não foi possível descriptografar a mensagem interna com sua chave nem com a master.[/yellow]"

        console.print(Panel.fit(painel_text, title=f"Mensagem {escolha}", border_style="green"))
        console.print()

    # fim
    input("Pressione Enter para voltar ao menu...")

# ---- recebimento MQTT (escuta e grava) ----
def receber_mensagem(usuario, broker=BROKER_DEFAULT):
    topico = f"minharede/chat/{usuario.lower().strip()}"
    try:
        f_user = obter_fernet_por_username(usuario)
    except Exception:
        f_user = None

    def on_message(client, userdata, message):
        hora = datetime.datetime.now().strftime("%H:%M:%S")
        payload = message.payload  # normalmente bytes
        texto = None

        # tenta descriptografar o pacote externo (com a chave do usuário)
        if f_user:
            try:
                token = payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode()
                texto = f_user.decrypt(token).decode()
            except (InvalidToken, Exception) as e:
                # não descriptografou com chave do usuário
                texto = None

        if texto is None:
            try:
                raw_str = payload.decode() if isinstance(payload, (bytes, bytearray)) else str(payload)
            except Exception:
                raw_str = str(payload)
            console.print(f"[{hora}] [bold yellow]Mensagem recebida - NÃO PODE DESCRIPT.[/bold yellow]\n[dim]{raw_str}[/dim]")
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

        # agora temos 'texto' (string) no formato "Remetente:conteudo" ou apenas conteudo
        try:
            remetente, texto_msg = (texto.split(":", 1) if ":" in texto else ("Desconhecido", texto))
        except Exception:
            remetente, texto_msg = "Desconhecido", texto

        remetente_exibido = "[bold red]Admin[/bold red]" if remetente.lower() == "admin" else f"[bold cyan]{remetente}[/bold cyan]"
        console.print(f"[{hora}] {remetente_exibido} → [white]{texto_msg}[/white]")

        payload_str = payload.decode() if isinstance(payload, (bytes, bytearray)) else str(payload)
        registro = {
            "remetente": remetente,
            "destinatario": usuario,
            "mensagem_criptografada": payload_str,
            "hash_msg": hash_mensagem(payload_str, salt_digitado),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "topico": topico,
            "broker": broker,
            "descriptografavel": True
        }
        append_historico(usuario, registro)

    # cria cliente MQTT com fallback caso a versão antiga não aceite callback_api_version
    try:
        cliente = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    except Exception:
        cliente = mqtt.Client()

    cliente.on_message = on_message

    try:
        cliente.connect(broker, 1883, 60)
        cliente.subscribe(topico)
        cliente.loop_start()
    except Exception as e:
        console.print(f"[bold red]Erro conectar MQTT: {e}[/bold red]")
        return

    clear()
    titulo(f" CHAT PRIVADO ({usuario.upper()})")
    console.print(Panel.fit(f"[bold cyan]Escutando mensagens no tópico '{topico}'.[/bold cyan]\n[dim]Pressione Ctrl+C para sair.[/dim]"))

    if input(Fore.LIGHTMAGENTA_EX + "Deseja responder às mensagens? (s/n): " + Fore.RESET).strip().lower() == 's':
        threading.Thread(target=enviar_mensagem, kwargs={"broker": broker, "remetente": usuario}).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Chat encerrado.[/bold yellow]")
    finally:
        try:
            cliente.loop_stop()
            cliente.disconnect()
        except Exception:
            pass



# ---- menus ----
def MenuPrincipalADM():
    while True:
        clear(); titulo("MENU ADMINISTRADOR")
        console.print(Panel.fit(
            "[1] - Gerenciamento de Usuários\n"
            "[2] - Envio de Mensagens\n"
            "[3] - Descriptografar Mensagens\n"
            "[4] - Sair"
        ))
        result = input("> ").strip()
        if result == '1': gerenciamentoUser()
        elif result == '2': enviar_mensagem()
        elif result == '3': mensagens_para_descriptografar('admin')
        elif result == '4': break
        else:
            console.print(Fore.RED + "Digite algo válido")
            time.sleep(1)
    clear()


def MenuPrincipalUser(usuario):
    while True:
        clear(); titulo(f"MENU DO USUÁRIO ({usuario.upper()})")
        console.print(Panel.fit("[1] - Enviar mensagem\n[2] - Histórico (criptografado)\n[3] - Mensagens Recebidas (descriptografar)\n[4] - Sair"))
        result = input("> ").strip()
        if result == '1': receber_mensagem(usuario)
        elif result == '2': historico_mensagens(usuario)
        elif result == '3': mensagens_para_descriptografar(usuario)
        elif result == '4': break
        else: console.print(Fore.RED + "Digite algo válido!"); time.sleep(1)
    clear()

def menuPrincipal():
    while True:
        clear(); titulo("MENU PRINCIPAL")
        console.print(Panel.fit("[1] - Efetuar login\n[2] - Sair"))
        result = input("> ").strip()
        if result == '2': clear(); break
        elif result == '1': loginUser()
        else: console.print(Fore.RED + "Digite uma opção válida!"); time.sleep(1)

# ---- main ----
if __name__ == "__main__":
    menuPrincipal()

def teste():
    return