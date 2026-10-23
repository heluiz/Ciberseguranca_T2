"""Explicação de uma CVE em português, montada a partir dos dados.

O nome e a descrição de uma CVE, e a ação que a CISA exige para ela,
vêm em inglês, como nas fontes oficiais. Um tradutor automático
poderia errar justamente no que importa. Por isso a explicação é
montada a partir dos dados estruturados, que têm significado fixo:

- o vetor CVSS vira duas frases, como se ataca e o impacto, com os
  nomes que a calculadora do CVSS já usa em português;
- o tipo de falha (CWE) ganha um nome em português: os 30 mais comuns
  no catálogo KEV e os da base de exemplo (os outros ficam só com o
  número, que leva ao catálogo oficial do CWE);
- a ação exigida pela CISA tem poucos textos diferentes: os que se
  repetem no catálogo, que cobrem quase todas as CVEs, foram traduzidos
  aqui; um texto fora da tabela aparece em inglês, com aviso;
- a avaliação SSVC da CISA (a falha é explorada? o ataque pode ser
  automatizado? o atacante ganha controle total?) aparece em português;
- os links do catálogo são separados em boletins e página da NVD.

O módulo não lê do teclado, não imprime e não usa a rede.
"""

import re
from urllib.parse import urlsplit

from calculadora_cvss import opcoes_do_vetor

# ----------------------------------------------------------------------
# Tipos de falha (CWE)
# ----------------------------------------------------------------------

# Nome em português de cada CWE: os 30 mais comuns no catálogo KEV (78%
# das ocorrências) e os da base de exemplo. "Categoria" marca os CWEs
# que agrupam outros, que o catálogo ainda usa em CVEs antigas.
NOMES_CWE = {
    "CWE-20": "Validação de entrada inadequada",
    "CWE-22": "Acesso a arquivos fora da pasta permitida (path traversal)",
    "CWE-59": "Resolução inadequada de link antes de acessar um arquivo",
    "CWE-77": "Injeção de comando",
    "CWE-78": "Injeção de comando do sistema operacional",
    "CWE-79": "Script injetado em página web (cross-site scripting)",
    "CWE-89": "Injeção de SQL",
    "CWE-94": "Injeção de código",
    "CWE-119": "Acesso fora dos limites de um buffer de memória",
    "CWE-120": "Cópia para buffer sem conferir o tamanho (estouro de "
               "buffer)",
    "CWE-121": "Estouro de buffer na pilha",
    "CWE-122": "Estouro de buffer no heap",
    "CWE-125": "Leitura fora dos limites da memória",
    "CWE-190": "Estouro de número inteiro",
    "CWE-200": "Informação sensível exposta a quem não tem autorização",
    "CWE-212": "Informação sensível não apagada antes de guardar ou "
               "transferir",
    "CWE-250": "Execução com privilégios desnecessários",
    "CWE-262": "Senha sem prazo de validade",
    "CWE-264": "Permissões, privilégios e controle de acesso (categoria)",
    "CWE-269": "Gestão inadequada de privilégios",
    "CWE-284": "Controle de acesso inadequado",
    "CWE-287": "Autenticação inadequada",
    "CWE-288": "Autenticação contornada por outro caminho ou canal",
    "CWE-306": "Função crítica sem autenticação",
    "CWE-311": "Dado sensível sem criptografia",
    "CWE-319": "Informação sensível transmitida sem criptografia",
    "CWE-351": "Distinção insuficiente entre tipos de dados",
    "CWE-399": "Erros de gerência de recursos (categoria)",
    "CWE-416": "Uso de memória já liberada (use after free)",
    "CWE-420": "Canal alternativo desprotegido",
    "CWE-434": "Envio de arquivo de tipo perigoso sem restrição",
    "CWE-502": "Desserialização de dados não confiáveis",
    "CWE-521": "Exigências fracas para senhas",
    "CWE-522": "Credenciais mal protegidas",
    "CWE-613": "Sessão que não expira a tempo",
    "CWE-668": "Recurso exposto a quem não deveria alcançá-lo",
    "CWE-693": "Falha de mecanismo de proteção",
    "CWE-732": "Permissão incorreta em recurso crítico",
    "CWE-778": "Registro (log) insuficiente",
    "CWE-787": "Escrita fora dos limites da memória",
    "CWE-843": "Confusão de tipos (type confusion)",
    "CWE-863": "Autorização incorreta",
    "CWE-918": "Requisição forjada pelo servidor (SSRF)",
    "CWE-1392": "Uso de credenciais padrão",
}


def cwe_com_nome(cwe):
    """"CWE-416 Uso de memória já liberada (...)", ou só o número."""
    nome = NOMES_CWE.get(cwe)
    return f"{cwe} {nome}" if nome else cwe


# ----------------------------------------------------------------------
# O vetor CVSS em frases
# ----------------------------------------------------------------------

# Como se ataca: de onde (AV), com que conta (PR) e com a ajuda de quem
# (UI). Os códigos R (3.x), P e A (4.0) da interação não se repetem
# entre as versões, então uma tabela só serve às duas.
_DE_ONDE = {"N": "pela rede",
            "A": "da rede vizinha, no mesmo segmento local ou meio sem fio",
            "L": "com acesso à própria máquina",
            "P": "com acesso físico ao equipamento"}
_COM_QUE_CONTA = {"N": "sem conta no sistema",
                  "L": "com uma conta comum",
                  "H": "com uma conta de administrador"}
_COM_AJUDA = {"N": "sem ação de outra pessoa",
              "R": "com a ajuda de alguém, que precisa abrir um arquivo ou "
                   "clicar num link",
              "P": "com alguém usando o sistema normalmente",
              "A": "com a ajuda consciente de alguém, como clicar num link"}


def _juntar(partes):
    """"a", "a e b" ou "a, b e c"."""
    if len(partes) == 1:
        return partes[0]
    return ", ".join(partes[:-1]) + " e " + partes[-1]


def _impactos(pares, codigos):
    """O impacto agrupado por nível, do mais alto para o mais baixo.

    Como em "alto na disponibilidade; nenhum na confidencialidade e na
    integridade", em vez de repetir o nível a cada parte.
    """
    nomes = {"C": "confidencialidade", "I": "integridade",
             "A": "disponibilidade"}
    trechos = []
    for nivel in ("H", "L", "N"):
        onde = [f"na {nomes[codigo[-1]]}" for codigo in codigos
                if pares[codigo].codigo == nivel]
        if onde:
            nome = next(pares[codigo].nome for codigo in codigos
                        if pares[codigo].codigo == nivel)
            trechos.append(f"{nome.lower()} {_juntar(onde)}")
    return "; ".join(trechos)


def explicar_vetor(vetor):
    """Devolve [(rótulo, frase)]: como se ataca e o impacto.

    As frases saem do vetor CVSS (versões 4.0, 3.1 e 3.0), com os nomes
    das opções da calculadora. Levanta ValueError se o vetor não
    servir.
    """
    versao, lista = opcoes_do_vetor(vetor)
    pares = {metrica.codigo: opcao for metrica, opcao in lista}
    codigo = {chave: opcao.codigo for chave, opcao in pares.items()}

    ataque = (f"{_DE_ONDE[codigo['AV']]}, {_COM_QUE_CONTA[codigo['PR']]} "
              f"e {_COM_AJUDA[codigo['UI']]}.")
    if codigo["AC"] == "H":
        ataque += (" Exige contornar proteções ou depende de condições fora "
                   "do controle do atacante (complexidade alta).")
    if codigo.get("AT") == "P":
        ataque += (" Depende ainda de uma condição que o atacante não "
                   "controla, como uma disputa de tempo.")

    if versao == "4.0":
        impacto = _impactos(pares, ("VC", "VI", "VA")) + "."
        if any(codigo[c] != "N" for c in ("SC", "SI", "SA")):
            impacto += (" Nos outros sistemas: "
                        + _impactos(pares, ("SC", "SI", "SA")) + ".")
    else:
        impacto = _impactos(pares, ("C", "I", "A")) + "."
        if codigo["S"] == "C":
            impacto += (" O ataque atinge também o que está sob outra "
                        "autoridade de segurança (escopo alterado).")
    return [("Como se ataca", ataque), ("Impacto", impacto)]


# ----------------------------------------------------------------------
# A avaliação SSVC da CISA
# ----------------------------------------------------------------------

_EXPLORACAO = {"none": "sem exploração conhecida",
               "poc": "com prova de conceito pública",
               "active": "explorada em ataques"}
_AUTOMATIZAVEL = {"yes": "ataque automatizável",
                  "no": "ataque não automatizável"}
_IMPACTO = {"partial": "controle parcial do sistema",
            "total": "controle total do sistema"}

LEGENDA_SSVC = (
    "Automatizável: o ataque pode ser feito em massa, sem intervenção "
    "humana, do reconhecimento à exploração. Controle total: o atacante "
    "passa a controlar o sistema ou a ver todas as informações dele.")


def ssvc_em_portugues(ssvc):
    """Os três pontos do SSVC em português, separados por " · "."""
    return " · ".join((_EXPLORACAO[ssvc.exploracao],
                       _AUTOMATIZAVEL[ssvc.automatizavel],
                       _IMPACTO[ssvc.impacto]))


# ----------------------------------------------------------------------
# A ação exigida pela CISA
# ----------------------------------------------------------------------

# Os 17 textos do catálogo que se repetem (98,7% das CVEs no catálogo de
# 16/10/2026) e a tradução de cada um. "Links abaixo" são os das notas
# do catálogo, mostrados logo depois da ação. As siglas BOD e ED são
# diretivas da CISA para os órgãos federais dos EUA.
_ACOES = (
    ("Apply updates per vendor instructions.",
     "Aplicar as atualizações conforme as instruções do fabricante."),
    ("Apply mitigations per vendor instructions, follow applicable BOD "
     "22-01 guidance for cloud services, or discontinue use of the "
     "product if mitigations are unavailable.",
     "Aplicar as mitigações conforme as instruções do fabricante, seguir "
     "as orientações aplicáveis da BOD 22-01 para serviços em nuvem ou "
     "deixar de usar o produto se não houver mitigação."),
    ("Apply mitigations per vendor instructions or discontinue use of the "
     "product if mitigations are unavailable.",
     "Aplicar as mitigações conforme as instruções do fabricante ou deixar "
     "de usar o produto se não houver mitigação."),
    ("Apply mitigations in accordance with vendor instructions, ensuring "
     "compliance with CISA’s BOD 26-04 Prioritizing Security Updates "
     "Based on Risk (see URL in Notes) guidance and CISA’s “Forensics "
     "Triage Requirements” (see URL in Notes). Follow applicable BOD "
     "26-04 guidance for cloud services or discontinue use of the product "
     "if mitigations are unavailable. Stakeholders are responsible for "
     "evaluating each asset's internet exposure and ensuring adherence to "
     "BOD 26-04 patching guidelines.",
     "Aplicar as mitigações conforme as instruções do fabricante, "
     "cumprindo as orientações da BOD 26-04 da CISA (priorizar as "
     "atualizações de segurança pelo risco) e os requisitos de triagem "
     "forense da CISA (links abaixo). Para serviços em nuvem, seguir as "
     "orientações aplicáveis da BOD 26-04, ou deixar de usar o produto se "
     "não houver mitigação. Cabe aos responsáveis avaliar a exposição de "
     "cada ativo à internet e seguir as orientações de correção da BOD "
     "26-04."),
    ("The impacted product is end-of-life and should be disconnected if "
     "still in use.",
     "O produto afetado está no fim da vida útil (sem suporte do "
     "fabricante) e deve ser desconectado, se ainda estiver em uso."),
    ("Apply updates per vendor instructions or discontinue use of the "
     "product if updates are unavailable.",
     "Aplicar as atualizações conforme as instruções do fabricante ou "
     "deixar de usar o produto se não houver atualização."),
    ("Apply remediations or mitigations per vendor instructions or "
     "discontinue use of the product if remediation or mitigations are "
     "unavailable.",
     "Aplicar as correções ou mitigações conforme as instruções do "
     "fabricante ou deixar de usar o produto se não houver correção nem "
     "mitigação."),
    ("The impacted product is end-of-life (EoL) and/or end-of-service "
     "(EoS). Users should discontinue utilization of the product.",
     "O produto afetado está no fim da vida útil (EoL) ou do suporte "
     "(EoS). Deixar de usar o produto."),
    ("Please adhere to CISA’s guidelines to assess exposure and mitigate "
     "risks associated with Cisco SD-WAN devices as outlined in CISA’s "
     "Emergency Directive 26-03 (URL listed below in Notes) and CISA’s "
     "Hunt & Hardening Guidance for Cisco SD-WAN Devices (URL listed "
     "below in Notes). Adhere to the applicable BOD 22-01 guidance for "
     "cloud services or discontinue use of the product if mitigations "
     "are not available.",
     "Seguir as orientações da CISA para avaliar a exposição e reduzir os "
     "riscos dos equipamentos Cisco SD-WAN, descritas na Diretiva de "
     "Emergência 26-03 e no guia de busca e endurecimento (Hunt & "
     "Hardening) desses equipamentos (links abaixo). Para serviços em "
     "nuvem, seguir as orientações aplicáveis da BOD 22-01, ou deixar de "
     "usar o produto se não houver mitigação."),
    ("The impacted product could be end-of-life (EoL) and/or "
     "end-of-service (EoS). Users should discontinue product utilization "
     "if a current mitigation is unavailable.",
     "O produto afetado pode estar no fim da vida útil (EoL) ou do suporte "
     "(EoS). Deixar de usar o produto se não houver mitigação atual."),
    ("This vulnerability affects legacy D-Link products. All associated "
     "hardware revisions have reached their end-of-life (EOL) or "
     "end-of-service (EOS) life cycle and should be retired and replaced "
     "per vendor instructions.",
     "A falha afeta produtos antigos da D-Link. Todas as revisões de "
     "hardware afetadas estão no fim da vida útil (EOL) ou do suporte "
     "(EOS) e devem ser aposentadas e substituídas conforme as instruções "
     "do fabricante."),
    ("Disconnect public-facing versions of SharePoint Server that have "
     "reached their end-of-life (EOL) or end-of-service (EOS) to include "
     "SharePoint Server 2013 and earlier versions. For supported versions, "
     "please follow the mitigations according to CISA (URL listed below in "
     "Notes) and vendor instructions (URL listed below in Notes). Adhere "
     "to the applicable BOD 22-01 guidance for cloud services or "
     "discontinue use of the product if mitigations are not available.",
     "Desconectar da internet as versões do SharePoint Server no fim da "
     "vida útil (EOL) ou do suporte (EOS), o que inclui o SharePoint "
     "Server 2013 e anteriores. Nas versões com suporte, seguir as "
     "mitigações da CISA e as instruções do fabricante (links abaixo). "
     "Para serviços em nuvem, seguir as orientações aplicáveis da BOD "
     "22-01, ou deixar de usar o produto se não houver mitigação."),
    ("The impacted products are end-of-life and should be disconnected if "
     "still in use.",
     "Os produtos afetados estão no fim da vida útil e devem ser "
     "desconectados, se ainda estiverem em uso."),
    ("The KEV due date refers to the deadline by which FCEB agencies are "
     "expected to review and begin implementing the guidance outlined in "
     "Emergency Directive (ED) 25-03 (URL listed below in Notes). Agencies "
     "must follow the mitigation steps provided by CISA (URL listed below "
     "in Notes) and vendor’s instructions (URL listed below in Notes). "
     "Adhere to the applicable BOD 22-01 guidance for cloud services or "
     "discontinue use of the product if mitigations are not available.",
     "O prazo do KEV é a data em que os órgãos civis do governo federal "
     "dos EUA devem revisar e começar a aplicar as orientações da Diretiva "
     "de Emergência (ED) 25-03 (link abaixo). Os órgãos devem seguir os "
     "passos de mitigação da CISA e as instruções do fabricante (links "
     "abaixo). Para serviços em nuvem, seguir as orientações aplicáveis da "
     "BOD 22-01, ou deixar de usar o produto se não houver mitigação."),
    ("Apply mitigations as set forth in the CISA instructions linked "
     "below. Apply mitigations per vendor instructions, follow applicable "
     "BOD 22-01 guidance for cloud services, or discontinue use of the "
     "product if mitigations are unavailable.",
     "Aplicar as mitigações descritas nas instruções da CISA (link "
     "abaixo). Aplicar as mitigações conforme as instruções do fabricante, "
     "seguir as orientações aplicáveis da BOD 22-01 para serviços em nuvem "
     "ou deixar de usar o produto se não houver mitigação."),
    ("As Ivanti CSA 4.6.x has reached End-of-Life status, users are urged "
     "to remove CSA 4.6.x from service or upgrade to the 5.0.x line, or "
     "later, of supported solution.",
     "Como o Ivanti CSA 4.6.x está no fim da vida útil, a recomendação é "
     "tirá-lo de operação ou atualizar para a linha 5.0.x, ou posterior, "
     "que tem suporte."),
    ("Verify that instances of Cisco IOS XE Web UI are in compliance with "
     "BOD 23-02 and apply mitigations per vendor instructions. For "
     "affected products (Cisco IOS XE Web UI exposed to the internet or to "
     "untrusted networks), follow vendor instructions to determine if a "
     "system may have been compromised and immediately report positive "
     "findings to CISA.",
     "Verificar se as instalações do Cisco IOS XE Web UI cumprem a BOD "
     "23-02 e aplicar as mitigações conforme as instruções do fabricante. "
     "Nos produtos afetados (Cisco IOS XE Web UI exposto à internet ou a "
     "redes não confiáveis), seguir as instruções do fabricante para "
     "verificar se o sistema pode ter sido comprometido e informar "
     "imediatamente à CISA o que for encontrado."),
)


def _chave(texto):
    """O texto em minúsculas, sem aspas, espaço extra e ponto final.

    É assim que dois textos da CISA são comparados: o catálogo às vezes
    traz o mesmo texto sem o ponto final, com uma aspa a mais ou com
    "outlines" no lugar de "outlined".
    """
    sem_aspas = re.sub("[\"'‘’“”]", "", texto)
    texto = " ".join(sem_aspas.split()).rstrip(".").casefold()
    return texto.replace(" as outlines in ", " as outlined in ")


_TRADUCOES = {_chave(original): traducao for original, traducao in _ACOES}


def acao_em_portugues(texto):
    """Devolve (ação em português, True), ou (o original, False)."""
    traducao = _TRADUCOES.get(_chave(texto))
    if traducao is None:
        return texto, False
    return traducao, True


# ----------------------------------------------------------------------
# Links
# ----------------------------------------------------------------------

def separar_links(links):
    """Devolve (boletins, nvd): a página da NVD à parte dos outros.

    Os boletins são os outros links que a CISA pôs nas notas: em geral o
    do fabricante, às vezes uma orientação da própria CISA.
    """
    boletins, nvd = [], []
    for link in links:
        if urlsplit(link).hostname == "nvd.nist.gov":
            nvd.append(link)
        else:
            boletins.append(link)
    return boletins, nvd


# ----------------------------------------------------------------------
# Teste: cada parte da explicação, sem a base de CVEs.
# ----------------------------------------------------------------------

if __name__ == "__main__":
    from collections import namedtuple

    RDP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    frases = explicar_vetor(RDP)
    for rotulo, frase in frases:
        print(f"{rotulo}: {frase}")
    assert frases == [
        ("Como se ataca",
         "pela rede, sem conta no sistema e sem ação de outra pessoa."),
        ("Impacto",
         "alto na confidencialidade, na integridade e na "
         "disponibilidade.")], frases

    # Um ataque local, com interação, complexidade alta e escopo
    # alterado; e um vetor 4.0 com impacto nos outros sistemas.
    local = explicar_vetor("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N")
    assert local[0][1].startswith("com acesso à própria máquina, com uma "
                                  "conta comum e com a ajuda de alguém")
    assert "complexidade alta" in local[0][1]
    assert local[1][1].startswith("baixo na confidencialidade; nenhum na "
                                  "integridade e na disponibilidade.")
    assert "escopo alterado" in local[1][1]
    v40 = explicar_vetor("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/"
                         "VA:H/SC:L/SI:N/SA:L")
    assert "com a ajuda consciente de alguém" in v40[0][1]
    assert "disputa de tempo" in v40[0][1]
    assert v40[1][1] == (
        "alto na integridade e na disponibilidade; nenhum na "
        "confidencialidade. Nos outros sistemas: baixo na "
        "confidencialidade e na disponibilidade; nenhum na "
        "integridade."), v40
    sem_outros = explicar_vetor("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/"
                                "VI:H/VA:H/SC:N/SI:N/SA:N")
    assert "outros sistemas" not in sem_outros[1][1]
    print("Vetor: 3.1 e 4.0, com complexidade, escopo e outros sistemas.")

    assert cwe_com_nome("CWE-416") == ("CWE-416 Uso de memória já "
                                       "liberada (use after free)")
    assert cwe_com_nome("CWE-9999") == "CWE-9999"
    print(f"CWE: {cwe_com_nome('CWE-1392')}")

    Ssvc = namedtuple("Ssvc", "exploracao automatizavel impacto")
    texto_ssvc = ssvc_em_portugues(Ssvc("active", "yes", "total"))
    assert texto_ssvc == ("explorada em ataques · ataque automatizável · "
                          "controle total do sistema"), texto_ssvc
    print(f"SSVC: {texto_ssvc}")

    # A ação: o texto exato, o mesmo sem o ponto final ou com aspas
    # diferentes, e um texto fora da tabela, que volta como veio.
    assert acao_em_portugues("Apply updates per vendor instructions.") == (
        "Aplicar as atualizações conforme as instruções do fabricante.",
        True)
    assert acao_em_portugues(" Apply updates per vendor instructions")[1]
    assert acao_em_portugues(
        '"Apply mitigations per vendor instructions, follow applicable BOD '
        '22-01 guidance for cloud services, or discontinue use of the '
        'product if mitigations are unavailable')[1]
    assert acao_em_portugues(_ACOES[8][0].replace(" as outlined in ",
                                                  " as outlines in "))[1]
    estranho = "Contact the vendor for guidance on remediating firmware."
    assert acao_em_portugues(estranho) == (estranho, False)
    assert len(_TRADUCOES) == len(_ACOES), "duas traduções com a mesma chave"
    print("Ação: traduzida pela tabela; fora dela, o original em inglês.")

    boletins, nvd = separar_links((
        "https://www.cisco.com/c/en/us/support/docs/aviso.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-20198"))
    assert boletins == ["https://www.cisco.com/c/en/us/support/docs/"
                        "aviso.html"]
    assert nvd == ["https://nvd.nist.gov/vuln/detail/CVE-2023-20198"]
    print("Links: o boletim de um lado, a NVD do outro.")

    print("\nOK - explicação em português exercitada.")
