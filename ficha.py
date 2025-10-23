from colorama import init, Fore, Back, Style
import pyfiglet
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

init()

def LimparTela():
    os.system('cls')

def ler_atividades():
    atividades = []

    print("=== CADASTRO DE ATIVIDADES ===")
    print("Digite 'S' em qualquer campo para sair\n")

    while True:
        print(f"--- Atividade {len(atividades) + 1} ---")
        data = input("Data (dd/mm/aaaa): ").strip()
        if data.upper() == 'S':
            break
        atividade = input("Atividade: ").strip()
        if atividade.upper() == 'S':
            break
        horas = input("Total de horas: ").strip()
        if horas.upper() == 'S':
            break
        item = {
            'data': data,
            'atividade': atividade,
            'horas': horas
        }

        atividades.append(item)
        print("Atividade cadastrada com sucesso!\n")

    return atividades


LimparTela()
print(Fore.GREEN + pyfiglet.figlet_format("A.P.S"))

titulo = "FICHA DE ATIVIDADES PRÃTICAS SUPERVISIONADAS"
print(Fore.LIGHTBLUE_EX + titulo)

# Style.RESET_ALL: Reseta todos os estilos e cores ao padrÃ£o, prevenindo que eles sejam aplicados a textos que vocÃª nÃ£o deseja estilizar.
print(Style.RESET_ALL + 'Este Ã© o texto padrÃ£o')


dados_aluno = {"nome": input("Digite seu nome: "),
               "ra": input("Digite seu RA: "),
               "curso": input("Digite seu curso: "),
               "campus": input("Digite seu Campus: "),
               "semestre": input("Digite seu Semestre: "),
               "turno": input("Digite seu Turno: ")
               }

LimparTela()
console = Console()
table = Table(title="Dados do Aluno")

table.add_column("Nome", dados_aluno["nome"], justify="left", style="cyan")
table.add_column("RA", dados_aluno["ra"], justify="left", style="magenta")
table.add_column("curso", dados_aluno["curso"], justify="left", style="red")
table.add_column("campus", dados_aluno["campus"], justify="left", style="cyan")
table.add_column("semestre", dados_aluno["semestre"], justify="left", style="magenta")
table.add_column("turno", dados_aluno["turno"], justify="left", style="red")

console.print(dados_aluno)

lista_atividade = ler_atividades()

for atividade in lista_atividade:
    table.add_row(lista_atividade["data"], lista_atividade["atividade"], lista_atividade["horas"])

console = Console()
console.print(table)

