"""Calculadora da nota CVSS: as perguntas do FIRST, o vetor e a nota.

O CVSS (Common Vulnerability Scoring System, mantido pelo FIRST) mede
a gravidade de uma vulnerabilidade com perguntas sobre ela: de onde
dá para atacar, se precisa de senha, o que o atacante consegue fazer.
As respostas formam o vetor, um texto como

    CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

e a fórmula oficial transforma o vetor numa nota de 0,0 a 10,0. A
fórmula vem da biblioteca cvss, da equipe de segurança da Red Hat:
reescrevê-la aqui seria repetir, e arriscar errar, o que já existe e
é testado (a da versão 4.0 usa tabelas grandes).

Este módulo guarda as perguntas das métricas base, com as explicações
em português feitas a partir da especificação do FIRST (versões 3.1 e
4.0), monta o vetor com as respostas e confere um vetor digitado. Só
as métricas base valem: elas medem a falha em si. O contexto (o tipo
do equipamento e as dependências) entra depois, no modelo de risco
(risco.py); as métricas de ambiente do CVSS o contariam duas vezes.

Não lê do teclado: quem pergunta é o main.py, e quem mostra é o
telas.py.
"""

from collections import namedtuple

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

# Uma resposta possível: código no vetor (N), nome (Rede) e o que quer
# dizer, para quem não conhece o CVSS escolher com segurança.
Opcao = namedtuple("Opcao", "codigo nome explicacao")

# Uma pergunta: código no vetor (AV), nome, a pergunta e as opções.
Metrica = namedtuple("Metrica", "codigo nome pergunta opcoes")


def _impacto(codigo, nome, pergunta, alto, baixo, nenhum):
    """Monta uma métrica de impacto: opções Alto, Baixo e Nenhum."""
    return Metrica(codigo, nome, pergunta, (
        Opcao("H", "Alto", alto),
        Opcao("L", "Baixo", baixo),
        Opcao("N", "Nenhum", nenhum),
    ))


# Alto e Baixo têm, nas duas versões, o mesmo critério: perda total, ou
# perda parcial que já causa dano direto e grave (especificação do
# FIRST, métricas de impacto).
SIGILO_ALTO = ("Tudo, ou só uma parte que já causa dano direto e grave "
               "(ex.: a senha do administrador, a chave privada do "
               "servidor).")
SIGILO_BAIXO = ("Alguma informação restrita, sem controle sobre qual ou "
                "em quantidade limitada, e sem dano direto e grave.")
ALTERACAO_ALTA = ("Tudo, ou só alguns arquivos ou dados, mas cuja "
                  "alteração já causa dano direto e grave.")
ALTERACAO_BAIXA = ("Alguma alteração, sem controle sobre o resultado ou "
                   "em quantidade limitada, e sem dano direto e grave.")
QUEDA_TOTAL = ("Totalmente: consegue impedir o uso, ou impedir conexões "
               "novas, ou derrubar de vez repetindo o ataque (ex.: "
               "vazamento de memória).")
QUEDA_PARCIAL = ("Em parte: deixa lento ou com interrupções, mas nem "
                 "repetindo o ataque consegue derrubar de vez.")
SO_NO_VULNERAVEL = "o impacto fica no sistema que tem a falha."


# --- Perguntas comuns às duas versões ---------------------------------

VETOR_DE_ATAQUE = Metrica(
    "AV", "Vetor de ataque",
    "De onde o atacante consegue explorar a falha?", (
        Opcao("N", "Rede",
              "Pela rede, atravessando roteadores: da internet ou de outra "
              "sub-rede da rede interna. A parte vulnerável recebe dados "
              "pela rede, seja um serviço (RDP, um site) ou um programa "
              "cliente (o navegador), e a falha é chamada de \"explorável "
              "remotamente\". Só estar na rede interna, ou atrás de um "
              "firewall, não muda a resposta: continua sendo Rede."),
        Opcao("A", "Rede adjacente",
              "Só da vizinhança, porque o próprio protocolo não passa de "
              "um roteador: o mesmo segmento de rede local (ARP, descoberta "
              "de vizinhos do IPv6), o mesmo meio sem fio (Bluetooth, NFC, "
              "Wi-Fi) ou uma zona administrativa restrita (MPLS, VPN "
              "segura). Ex.: inundação de ARP que derruba a rede local."),
        Opcao("L", "Local",
              "A parte vulnerável não recebe dados pela rede: o atacante "
              "precisa ler, gravar ou executar algo na própria máquina, "
              "com uma sessão nela (no teclado ou por acesso remoto, como "
              "SSH) ou enganando quem a usa (abrir um arquivo). Ex.: "
              "programa instalado que roda com privilégio demais."),
        Opcao("P", "Físico",
              "Só tocando no equipamento: porta USB, gabinete, BIOS. Ex.: "
              "notebook que dá boot por pendrive sem pedir senha."),
    ))

PRIVILEGIOS = Metrica(
    "PR", "Privilégios exigidos",
    "O atacante precisa ter uma conta no sistema antes do ataque?", (
        Opcao("N", "Nenhum",
              "Não: ataca sem login, sem acesso a configurações ou "
              "arquivos."),
        Opcao("L", "Baixos",
              "Precisa de uma conta comum, que só mexe nos próprios "
              "arquivos e configurações."),
        Opcao("H", "Altos",
              "Precisa de uma conta de administrador, ou com controle "
              "significativo do sistema."),
    ))


# --- CVSS 4.0, a versão atual (11 perguntas) --------------------------

METRICAS_40 = (
    VETOR_DE_ATAQUE,
    Metrica(
        "AC", "Complexidade do ataque",
        "Para o ataque funcionar, o atacante precisa driblar uma proteção "
        "técnica que o sistema já tem? (Login e senha não contam aqui: "
        "entram na pergunta dos privilégios.)", (
            Opcao("L", "Baixa",
                  "Não: o ataque funciona sem esforço especial, sempre que "
                  "tentado."),
            Opcao("H", "Alta",
                  "Sim: depende de contornar proteções do sistema, como o "
                  "embaralhamento de memória (ASLR) ou a proteção contra "
                  "execução (DEP), ou de obter um segredo do alvo que "
                  "nenhum reconhecimento revela, como uma chave "
                  "criptográfica."),
        )),
    Metrica(
        "AT", "Requisitos de ataque",
        "Com o sistema já na configuração vulnerável, o ataque ainda "
        "depende de uma condição que o atacante não controla?", (
            Opcao("N", "Nenhum",
                  "Não: funciona sempre que o sistema está vulnerável. Uma "
                  "configuração fora do padrão não conta aqui: a pergunta "
                  "já parte do sistema vulnerável."),
            Opcao("P", "Presentes",
                  "Sim: precisa, por exemplo, vencer uma disputa de tempo "
                  "(condição de corrida) ou estar no caminho da "
                  "comunicação entre a vítima e o sistema."),
        )),
    PRIVILEGIOS,
    Metrica(
        "UI", "Interação do usuário",
        "Alguém além do atacante precisa fazer alguma coisa para o "
        "ataque dar certo?", (
            Opcao("N", "Nenhuma", "Não: o atacante consegue sozinho."),
            Opcao("P", "Passiva",
                  "Sim, mas sem uma decisão consciente da vítima: usar "
                  "normalmente um site legítimo em que o atacante plantou "
                  "conteúdo (a maioria dos XSS armazenados e dos CSRF) ou "
                  "abrir um programa que carrega um arquivo plantado pelo "
                  "atacante."),
            Opcao("A", "Ativa",
                  "Sim, com uma ação consciente: clicar num link enviado "
                  "pelo atacante (XSS refletido), importar um arquivo de "
                  "um jeito específico, aceitar ou ignorar um aviso de "
                  "segurança."),
        )),
    _impacto(
        "VC", "Confidencialidade no sistema vulnerável",
        "O que o atacante consegue ver ou copiar no próprio sistema que "
        "tem a falha?",
        SIGILO_ALTO, SIGILO_BAIXO, "Nada."),
    _impacto(
        "VI", "Integridade no sistema vulnerável",
        "O que o atacante consegue alterar no próprio sistema que tem a "
        "falha? Conta também deixar alguém negar ações importantes, por "
        "falta de registro (log).",
        ALTERACAO_ALTA, ALTERACAO_BAIXA, "Nada."),
    _impacto(
        "VA", "Disponibilidade no sistema vulnerável",
        "O atacante consegue derrubar ou travar o próprio sistema que "
        "tem a falha?",
        QUEDA_TOTAL, QUEDA_PARCIAL, "Não."),
    _impacto(
        "SC", "Confidencialidade nos sistemas subsequentes",
        "Por causa da falha, o atacante consegue ver dados de OUTROS "
        "sistemas? Ex.: num XSS, a falha é no site, mas os dados lidos são "
        "do navegador da vítima.",
        "Tudo, ou só uma parte que já causa dano direto e grave, nos "
        "outros sistemas.",
        "Alguma informação restrita dos outros sistemas, sem dano direto "
        "e grave.",
        "Nada: " + SO_NO_VULNERAVEL),
    _impacto(
        "SI", "Integridade nos sistemas subsequentes",
        "Por causa da falha, o atacante consegue alterar dados de OUTROS "
        "sistemas? Ex.: num XSS, mudar o que o navegador da vítima mostra "
        "ou envia.",
        "Tudo, ou só uma parte cuja alteração já causa dano direto e "
        "grave, nos outros sistemas.",
        "Alguma alteração nos outros sistemas, sem dano direto e grave.",
        "Nada: " + SO_NO_VULNERAVEL),
    _impacto(
        "SA", "Disponibilidade nos sistemas subsequentes",
        "Por causa da falha, o atacante consegue derrubar OUTROS "
        "sistemas? Ex.: a falha no roteador derruba a rede dos "
        "computadores.",
        "Totalmente: consegue impedir o uso dos outros sistemas, ou "
        "impedir conexões novas a eles.",
        "Em parte: deixa os outros sistemas lentos ou com interrupções.",
        "Não: " + SO_NO_VULNERAVEL),
)


# --- CVSS 3.1, a versão anterior (8 perguntas) ------------------------

# Com escopo Alterado, a 3.1 manda avaliar o impacto no pior caso entre
# a parte vulnerável e a parte atingida.
PIOR_CASO = (" (Com escopo Alterado, responda pelo pior caso: a parte "
             "vulnerável ou a atingida.)")

METRICAS_31 = (
    VETOR_DE_ATAQUE,
    Metrica(
        "AC", "Complexidade do ataque",
        "O ataque depende de condições que o atacante não controla?", (
            Opcao("L", "Baixa",
                  "Não: o atacante pode repetir o ataque à vontade e "
                  "esperar sucesso."),
            Opcao("H", "Alta",
                  "Sim: depende de condições fora do controle dele, como "
                  "descobrir algo do alvo, preparar o ambiente ou se pôr "
                  "no meio da comunicação."),
        )),
    PRIVILEGIOS,
    Metrica(
        "UI", "Interação do usuário",
        "Alguém além do atacante precisa fazer alguma coisa para o "
        "ataque dar certo?", (
            Opcao("N", "Nenhuma", "Não: o atacante consegue sozinho."),
            Opcao("R", "Necessária",
                  "Sim: alguém precisa agir antes, como abrir um arquivo "
                  "ou clicar num link."),
        )),
    Metrica(
        "S", "Escopo",
        "A falha deixa o atacante atingir algo protegido por OUTRA "
        "autoridade de segurança, como o servidor que hospeda uma máquina "
        "virtual ou o navegador de quem visita um site?", (
            Opcao("U", "Inalterado",
                  "Não: tudo fica sob a mesma autoridade. Ex.: falha num "
                  "leitor de PDF que dá acesso a outros arquivos do mesmo "
                  "usuário, no mesmo sistema."),
            Opcao("C", "Alterado",
                  "Sim: passa para algo sob outra autoridade. Ex.: falha "
                  "numa máquina virtual que apaga arquivos do servidor que "
                  "a hospeda; XSS, em que a falha é no site e o efeito, no "
                  "navegador da vítima."),
        )),
    _impacto(
        "C", "Confidencialidade",
        "O que o atacante consegue ver ou copiar?" + PIOR_CASO,
        SIGILO_ALTO, SIGILO_BAIXO, "Nada."),
    _impacto(
        "I", "Integridade",
        "O que o atacante consegue alterar?" + PIOR_CASO,
        ALTERACAO_ALTA, ALTERACAO_BAIXA, "Nada."),
    _impacto(
        "A", "Disponibilidade",
        "O atacante consegue derrubar ou travar o sistema?" + PIOR_CASO,
        QUEDA_TOTAL, QUEDA_PARCIAL, "Não."),
)

# Versão -> perguntas. A ordem é a da calculadora do FIRST e do vetor.
VERSOES = {"4.0": METRICAS_40, "3.1": METRICAS_31}

# Vetores aceitos ao digitar: a 3.0 tem as mesmas métricas da 3.1.
_PERGUNTAS_DO_VETOR = {"4.0": METRICAS_40, "3.1": METRICAS_31,
                       "3.0": METRICAS_31}
_CALCULO_DO_VETOR = {"4.0": CVSS4, "3.1": CVSS3, "3.0": CVSS3}

# Métricas que não são base, por grupo. Com valor X (não definida) elas
# não mudam nada e são ignoradas; com outro valor, o vetor é recusado,
# porque o programa guarda só a nota base.
_GRUPOS_3 = {"temporal": "E RL RC",
             "de ambiente": "CR IR AR MAV MAC MPR MUI MS MC MI MA"}
_GRUPOS_4 = {"de ameaça": "E",
             "de ambiente": "CR IR AR MAV MAC MAT MPR MUI MVC MVI MVA "
                            "MSC MSI MSA",
             "suplementar": "S AU R V RE U"}
_NAO_BASE = {versao: {codigo: grupo
                      for grupo, codigos in grupos.items()
                      for codigo in codigos.split()}
             for versao, grupos in (("3.0", _GRUPOS_3), ("3.1", _GRUPOS_3),
                                    ("4.0", _GRUPOS_4))}


def montar_vetor(versao, escolhas):
    """Monta o vetor (CVSS:4.0/AV:N/...) a partir das respostas.

    escolhas é {código da métrica: código da opção}, com todas as
    métricas base da versão.
    """
    partes = [f"{m.codigo}:{escolhas[m.codigo]}"
              for m in _PERGUNTAS_DO_VETOR[versao]]
    return f"CVSS:{versao}/" + "/".join(partes)


def _versao_do_vetor(vetor):
    """Devolve a versão, como "3.1", escrita no começo do vetor."""
    prefixo = vetor.partition("/")[0]
    versao = prefixo.removeprefix("CVSS:")
    if not prefixo.startswith("CVSS:") or versao not in _CALCULO_DO_VETOR:
        raise ValueError(
            "O vetor deve começar com CVSS:4.0/, CVSS:3.1/ ou CVSS:3.0/ "
            "(a calculadora do FIRST mostra o vetor pronto)")
    return versao


def _conferir_trecho(trecho, versao, perguntas, respostas):
    """Confere um trecho como AV:N e, se for base, o junta às respostas.

    perguntas é {código: Metrica} da versão; respostas, o que já foi
    lido do vetor. Métrica que não é base, com valor X, é ignorada.
    """
    codigo, separador, valor = trecho.partition(":")
    if not separador or not codigo or not valor:
        raise ValueError(f"O trecho \"{trecho}\" do vetor está fora do "
                         f"formato MÉTRICA:VALOR, como AV:N")
    grupo = _NAO_BASE[versao].get(codigo)
    if grupo is not None:
        if valor == "X":
            return
        raise ValueError(
            f"{codigo}:{valor} é uma métrica {grupo}, e o programa guarda "
            f"só a nota base (as métricas base medem a falha em si): "
            f"apague \"/{codigo}:{valor}\" do vetor")
    if codigo not in perguntas:
        raise ValueError(f"{codigo} não é uma métrica do CVSS {versao}")
    if codigo in respostas:
        raise ValueError(f"A métrica {codigo} aparece duas vezes")
    validos = [opcao.codigo for opcao in perguntas[codigo].opcoes]
    if valor not in validos:
        raise ValueError(f"{codigo}:{valor} não existe; em {codigo} "
                         f"({perguntas[codigo].nome}) os valores são "
                         f"{', '.join(validos)}")
    respostas[codigo] = valor


def analisar_vetor(texto):
    """Confere um vetor CVSS e devolve (vetor arrumado, nota base).

    Aceita as versões 3.0, 3.1 e 4.0, em qualquer ordem, com
    maiúsculas ou minúsculas e com métricas não definidas (X), que são
    ignoradas. O vetor volta só com as métricas base, na ordem oficial.
    Levanta ValueError, com o motivo em português, se o vetor não
    servir. A nota é a da fórmula oficial, com uma casa decimal.
    """
    if not isinstance(texto, str):
        raise ValueError("O vetor CVSS deve ser um texto")
    vetor = "".join(texto.split())
    if not vetor.isascii():
        raise ValueError("O vetor CVSS tem só letras sem acento, números, "
                         "dois-pontos e barras")
    vetor = vetor.upper()
    versao = _versao_do_vetor(vetor)
    perguntas = {m.codigo: m for m in _PERGUNTAS_DO_VETOR[versao]}
    respostas = {}
    # Barra sobrando (no fim ou dobrada) não atrapalha: é ignorada.
    for trecho in filter(None, vetor.partition("/")[2].split("/")):
        _conferir_trecho(trecho, versao, perguntas, respostas)
    faltam = [codigo for codigo in perguntas if codigo not in respostas]
    if faltam:
        raise ValueError(f"Faltam métricas no vetor: {', '.join(faltam)}")

    arrumado = montar_vetor(versao, respostas)
    try:
        calculo = _CALCULO_DO_VETOR[versao](arrumado)
    except CVSSError as erro:      # não deveria chegar aqui: já conferido
        raise ValueError(f"Vetor CVSS inválido ({erro})") from erro
    # round: a nota vira o float de uma casa, igual ao lido do arquivo.
    return arrumado, round(float(calculo.base_score), 1)


# Teste: confere as notas com exemplos calculados na calculadora do
# FIRST, sem ninguém digitar nada.
if __name__ == "__main__":
    EXEMPLOS = (
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
         9.3),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
         8.7),
    )
    for vetor_exemplo, esperada in EXEMPLOS:
        arrumado_ex, nota_obtida = analisar_vetor(vetor_exemplo)
        print(f"{nota_obtida:>4}  {arrumado_ex}")
        assert nota_obtida == esperada, f"{vetor_exemplo}: {nota_obtida}"
        assert arrumado_ex == vetor_exemplo

    # As respostas viram o mesmo vetor que a calculadora mostra.
    todas_primeiras = {m.codigo: m.opcoes[0].codigo for m in METRICAS_40}
    todas_primeiras.update(SC="N", SI="N", SA="N")
    montado = montar_vetor("4.0", todas_primeiras)
    assert montado == EXEMPLOS[4][0], montado
    print(f"Montado pelas respostas: {montado}")

    # Ordem trocada, minúsculas, espaços, barra sobrando e métricas X: o
    # vetor sai arrumado, só com as métricas base.
    for folgado in (" cvss:3.1/ac:l/av:n/pr:n/ui:n/s:u/c:h/i:h/a:h",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X"):
        assert analisar_vetor(folgado) == (EXEMPLOS[0][0], 9.8), folgado
    print("Vetor fora de ordem, em minúsculas e com métricas X: aceito.")

    for ruim in ("AV:N/AC:L/Au:N/C:P/I:P/A:P",               # CVSS 2
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # falta A
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U",
                 EXEMPLOS[4][0] + "/E:U",
                 "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/ſ:U/C:H/I:H/A:H",
                 "CVSS:4.0/AV:N", "CVSS:3.1", "nota alta", 9.8):
        try:
            analisar_vetor(ruim)
            raise AssertionError(f"aceitou o vetor {ruim!r}")
        except ValueError as erro:
            print(f"Recusado: {erro}")

    # Cada pergunta tem um código diferente e opções diferentes, e
    # nenhuma métrica base está também na lista das que não são base.
    for versao_teste, metricas in VERSOES.items():
        codigos = [m.codigo for m in metricas]
        assert len(codigos) == len(set(codigos)), versao_teste
        assert not set(codigos) & set(_NAO_BASE[versao_teste]), versao_teste
        for m in metricas:
            assert len({o.codigo for o in m.opcoes}) == len(m.opcoes)
    print("\nOK - calculadora CVSS exercitada.")
