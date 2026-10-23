"""Atualização da base de CVEs pela internet (opção 16, item 4).

É o único módulo do programa que usa a rede. Ele baixa o catálogo KEV
da CISA e, para cada CVE que ainda não tem nota, o registro oficial
dela, publicado pelo CVE Program: é de lá que vêm a nota CVSS, o vetor
e o CWE, quando o KEV não traz.

O que vem da rede é tratado como suspeito:

- só HTTPS, a partir de endereços oficiais fixos, também depois de um
  redirecionamento; o certificado do site é conferido, como o Python
  faz por padrão;
- limite de tamanho e de tempo em cada download;
- JSON pela norma (sem NaN e sem nome repetido), e cada campo conferido
  como na leitura do arquivo da base;
- se algo falhar, nada muda: a base que já existia continua.

Nada do inventário sai do computador: os pedidos levam só números de
CVEs públicas do catálogo. Este módulo não lê do teclado nem grava
arquivos: a base nova é gravada por BaseCVE.salvar().
"""

import datetime
import http.client
import re
import urllib.request
from collections import namedtuple

import validacao
from base_cve import (
    MAXIMO_DE_LINKS,
    TAMANHOS,
    BaseCVE,
    RegistroCVE,
    conferir_cwes,
    conferir_data,
    conferir_link,
    conferir_ssvc,
    conferir_texto,
    json_estrito,
)
from calculadora_cvss import analisar_vetor, so_metricas_base
from vulnerabilidades import validar_cve

# De onde a atualização baixa, na ordem. O KEV: o espelho da CISA no
# GitHub, que ela mesma indica para programas, e o site da CISA.
ENDERECOS_KEV = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json",
)
# O registro de cada CVE: o CVE List no GitHub, que o CVE Program
# atualiza a cada 7 minutos pela API oficial, e a própria API.
ENDERECOS_REGISTRO = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
    "{ano}/{grupo}/{cve}.json",
    "https://cveawg.mitre.org/api/cve/{cve}",
)
# Limites de cada download: tamanho, em bytes (o catálogo tem uns 2 MB,
# e um registro, de 10 KB a 2,3 MB, o de uma CVE com centenas de
# versões afetadas), e tempo, em segundos.
LIMITE_DO_CATALOGO = 30_000_000
LIMITE_DO_REGISTRO = 10_000_000
TEMPO_LIMITE = 30
# Notas buscadas numa atualização: o catálogo cresce umas dezenas de
# CVEs por mês, e o que passar disto fica para a próxima.
MAXIMO_DE_NOTAS = 300
# Preferência da nota: a versão 3.1, a mais usada no catálogo e no
# programa, depois a 4.0 e a 3.0; em cada versão, a do CNA antes da
# dos ADPs.
VERSOES_DA_NOTA = ("cvssV3_1", "cvssV4_0", "cvssV3_0")

# O que uma atualização fez, para a tela contar ao usuário.
Resumo = namedtuple("Resumo", "total novas sairam notas_buscadas sem_nota")


class AtualizacaoError(Exception):
    """A atualização não foi feita; a base que já existia continua."""


def atualizar(base, abrir=None, maximo_de_notas=MAXIMO_DE_NOTAS,
              ao_buscar=None):
    """Baixa o catálogo KEV de novo e devolve (base nova, Resumo).

    As CVEs que já estavam na base aproveitam a nota que tinham. Para
    as outras, a nota vem do registro oficial, até maximo_de_notas
    (None: todas), das mais recentes às mais antigas; a que não tiver
    nota fica sem, e a próxima atualização tenta de novo. abrir(url)
    abre um endereço (o padrão é abrir_url); ao_buscar(feitos, total),
    se dada, é chamada a cada registro, para a tela mostrar o
    andamento. Levanta AtualizacaoError se o catálogo não puder ser
    baixado ou vier fora do formato: aí nada muda. A base recebida não
    é alterada.
    """
    abrir = abrir or abrir_url
    catalogo = baixar_primeiro(ENDERECOS_KEV, LIMITE_DO_CATALOGO, abrir)
    try:
        versao, publicado, registros = _registros_do_catalogo(catalogo,
                                                              base)
    except ValueError as erro:
        raise AtualizacaoError(
            f"o catálogo veio fora do formato esperado ({erro})"
        ) from erro
    buscadas = _buscar_notas(registros, abrir, maximo_de_notas, ao_buscar)
    nova = BaseCVE(registros.values(), catalogo=versao,
                   publicado=publicado,
                   montado_em=datetime.date.today().isoformat(),
                   origem="atualizada")
    return nova, Resumo(
        total=len(nova),
        novas=len(nova.registros.keys() - base.registros.keys()),
        sairam=len(base.registros.keys() - nova.registros.keys()),
        notas_buscadas=buscadas,
        sem_nota=len(nova) - nova.com_nota())


def _registros_do_catalogo(catalogo, anterior):
    """Confere o catálogo e devolve (versão, data, {cve: registro}).

    As CVEs que já estavam na base anterior aproveitam a nota que
    tinham. Levanta ValueError se algo estiver fora do formato.
    """
    versao, publicado, itens = _conferir_catalogo(catalogo)
    registros = {}
    for posicao, item in enumerate(itens, 1):
        registro = _registro_do_kev(item, f"entrada {posicao}")
        if registro.cve in registros:
            raise ValueError(f"a {registro.cve} aparece duas vezes")
        velho = anterior.registros.get(registro.cve)
        if velho is not None and velho.cvss is not None:
            registro = registro._replace(
                cvss=velho.cvss, vetor=velho.vetor,
                fonte_nota=velho.fonte_nota,
                cwes=registro.cwes or velho.cwes, ssvc=velho.ssvc)
        registros[registro.cve] = registro
    return versao, publicado, registros


def _buscar_notas(registros, abrir, maximo_de_notas, ao_buscar):
    """Busca a nota das CVEs que não têm; devolve quantas ganharam.

    Os registros completados entram no próprio dicionário registros.
    """
    sem_nota = sorted((r for r in registros.values() if r.cvss is None),
                      key=lambda r: r.adicionada, reverse=True)
    if maximo_de_notas is not None:
        sem_nota = sem_nota[:maximo_de_notas]
    buscadas = 0
    for feitos, registro in enumerate(sem_nota, 1):
        completo = com_nota_do_registro_oficial(registro, abrir)
        if completo.cvss is not None:
            buscadas += 1
        registros[registro.cve] = completo
        if ao_buscar is not None:
            ao_buscar(feitos, len(sem_nota))
    return buscadas


# ----------------------------------------------------------------------
# O catálogo KEV e os registros oficiais
# ----------------------------------------------------------------------

def _conferir_catalogo(catalogo):
    """Confere o catálogo KEV e devolve (versão, data, itens)."""
    validacao.exigir_objeto(catalogo, "catálogo")
    for campo in ("catalogVersion", "dateReleased", "vulnerabilities"):
        validacao.exigir_campo(catalogo, campo, "catálogo")
    versao = validacao.exigir_texto(catalogo["catalogVersion"],
                                    "catalogVersion")
    if not versao or len(versao) > 40:
        raise ValueError("catalogVersion: vazio ou longo demais")
    # A data vem com a hora (2026-10-13T19:10:43.6568Z): fica o dia.
    publicado = conferir_data(str(catalogo["dateReleased"])[:10],
                              "dateReleased")
    itens = validacao.exigir_lista(catalogo["vulnerabilities"],
                                   "vulnerabilities")
    if not itens:
        raise ValueError("o catálogo veio sem nenhuma CVE")
    return versao, publicado, itens


def _registro_do_kev(item, campo):
    """Converte uma entrada do catálogo KEV num RegistroCVE sem nota."""
    validacao.exigir_objeto(item, campo)
    for chave in ("cveID", "vendorProject", "product", "vulnerabilityName",
                  "shortDescription", "dateAdded", "dueDate",
                  "knownRansomwareCampaignUse"):
        validacao.exigir_campo(item, chave, campo)
    cve = validar_cve(item["cveID"])
    campo = f"{campo} ({cve})"
    ransomware = validacao.exigir_texto(item["knownRansomwareCampaignUse"],
                                        f"{campo}: ransomware")
    return RegistroCVE(
        cve=cve,
        fabricante=conferir_texto(item["vendorProject"], "fabricante",
                                  campo),
        produto=conferir_texto(item["product"], "produto", campo),
        nome=conferir_texto(item["vulnerabilityName"], "nome", campo),
        descricao=conferir_texto(item["shortDescription"], "descricao",
                                 campo),
        cwes=conferir_cwes(item.get("cwes") or [], f"{campo}: cwes"),
        adicionada=conferir_data(item["dateAdded"], f"{campo}: dateAdded"),
        prazo=conferir_data(item["dueDate"], f"{campo}: dueDate"),
        ransomware=ransomware.casefold() == "known",
        cvss=None, vetor=None, fonte_nota=None,
        # A ação e as notas são opcionais aqui: um catálogo sem elas
        # ainda serve, só sem a ação e sem os links.
        acao=conferir_texto(item.get("requiredAction") or None, "acao",
                            campo, obrigatorio=False),
        links=links_das_notas(item.get("notes")))


def links_das_notas(notas):
    """Os links HTTPS das notas do catálogo, sem repetir, numa tupla.

    As notas misturam links e texto, separados por ponto e vírgula.
    Um link fora do formato (sem HTTPS, com caractere estranho) é
    deixado de fora, e ficam no máximo MAXIMO_DE_LINKS.
    """
    achados = []
    for candidato in re.findall(r"https://[^\s;,<>\"]+",
                                notas if isinstance(notas, str) else ""):
        # Pontuação colada no fim do link não faz parte dele.
        candidato = candidato.rstrip(".)]")
        try:
            link = conferir_link(candidato, "notes")
        except ValueError:
            continue
        if link not in achados:
            achados.append(link)
    return tuple(achados[:MAXIMO_DE_LINKS])


def _conteineres(registro):
    """[(fonte, contêiner)] do registro oficial: o CNA e os ADPs."""
    conteineres = validacao.exigir_objeto(registro.get("containers"),
                                          "containers")
    lista = []
    if isinstance(conteineres.get("cna"), dict):
        lista.append(("CNA", conteineres["cna"]))
    adps = conteineres.get("adp")
    for adp in adps if isinstance(adps, list) else []:
        if isinstance(adp, dict):
            dados = adp.get("providerMetadata")
            nome = dados.get("shortName") if isinstance(dados, dict) else ""
            lista.append((str(nome or "ADP")[:TAMANHOS["fonte_nota"]], adp))
    return lista


def nota_do_registro(registro):
    """Devolve (nota, vetor, fonte) do registro oficial de uma CVE.

    Procura na ordem de VERSOES_DA_NOTA. A nota é a que o vetor dá pela
    fórmula oficial, depois de o vetor perder as métricas que não são
    base. (None, None, None) se nenhum vetor servir.
    """
    conteineres = _conteineres(registro)
    for versao in VERSOES_DA_NOTA:
        for fonte, conteiner in conteineres:
            metricas = conteiner.get("metrics")
            for metrica in metricas if isinstance(metricas, list) else []:
                dados = metrica.get(versao) if isinstance(metrica,
                                                          dict) else None
                vetor = (dados.get("vectorString")
                         if isinstance(dados, dict) else None)
                if not isinstance(vetor, str):
                    continue
                try:
                    arrumado, nota = analisar_vetor(so_metricas_base(vetor))
                except ValueError:
                    continue
                return nota, arrumado, fonte
    return None, None, None


def cwes_do_registro(registro):
    """Os CWEs do registro oficial (CNA primeiro), sem repetir."""
    achados = []
    for _, conteiner in _conteineres(registro):
        tipos = conteiner.get("problemTypes")
        for tipo in tipos if isinstance(tipos, list) else []:
            descricoes = tipo.get("descriptions") if isinstance(
                tipo, dict) else None
            for item in descricoes if isinstance(descricoes, list) else []:
                if isinstance(item, dict) and "cweId" in item:
                    achados.append(item["cweId"])
    return conferir_cwes(achados, "cweId")


def ssvc_do_registro(registro):
    """A avaliação SSVC do registro oficial, ou None se não houver.

    A CISA, como ADP, põe no registro uma métrica do tipo "ssvc", com as
    opções Exploitation, Automatable e Technical Impact. Uma avaliação
    fora dos valores conhecidos é ignorada.
    """
    for _, conteiner in _conteineres(registro):
        metricas = conteiner.get("metrics")
        for metrica in metricas if isinstance(metricas, list) else []:
            outra = metrica.get("other") if isinstance(metrica, dict) else None
            if not isinstance(outra, dict) or outra.get("type") != "ssvc":
                continue
            conteudo = outra.get("content")
            opcoes = (conteudo.get("options") if isinstance(conteudo, dict)
                      else None)
            valores = {}
            for opcao in opcoes if isinstance(opcoes, list) else []:
                if isinstance(opcao, dict):
                    valores.update(opcao)
            try:
                return conferir_ssvc({
                    "exploracao": str(valores.get("Exploitation")).lower(),
                    "automatizavel": str(valores.get("Automatable")).lower(),
                    "impacto": str(valores.get("Technical Impact")).lower(),
                }, "ssvc")
            except ValueError:
                continue
    return None


def com_nota_do_registro_oficial(registro, abrir):
    """Devolve o registro com a nota (e o CWE, se faltar) do oficial.

    Junto vem a avaliação SSVC, se o registro tiver. Se o registro
    oficial não puder ser baixado, for de outra CVE ou não tiver nota,
    a CVE volta como estava, sem nota.
    """
    _, ano, numero = registro.cve.split("-")
    enderecos = [modelo.format(ano=ano, grupo=f"{numero[:-3]}xxx",
                               cve=registro.cve)
                 for modelo in ENDERECOS_REGISTRO]
    try:
        oficial = baixar_primeiro(enderecos, LIMITE_DO_REGISTRO, abrir)
        validacao.exigir_objeto(oficial, "registro")
        metadados = validacao.exigir_objeto(oficial.get("cveMetadata"),
                                            "cveMetadata")
        if metadados.get("cveId") != registro.cve:
            return registro
        nota, vetor, fonte = nota_do_registro(oficial)
        cwes = registro.cwes or cwes_do_registro(oficial)
        ssvc = ssvc_do_registro(oficial)
    except (AtualizacaoError, ValueError):
        return registro
    return registro._replace(cvss=nota, vetor=vetor, fonte_nota=fonte,
                             cwes=cwes, ssvc=ssvc)


# ----------------------------------------------------------------------
# Download
# ----------------------------------------------------------------------

def abrir_url(url):
    """Abre o endereço, com tempo limite e o nome do programa.

    O nome vai no cabeçalho User-Agent, como pedem os serviços públicos
    para identificar quem baixa.
    """
    pedido = urllib.request.Request(
        url, headers={"User-Agent": "inventario-t2 (base de CVEs)"})
    return urllib.request.urlopen(pedido, timeout=TEMPO_LIMITE)


def _baixar_json(url, limite, abrir):
    """Baixa e lê um JSON pela norma, sem passar de limite bytes."""
    if not url.startswith("https://"):
        raise ValueError("só endereços HTTPS são aceitos")
    with abrir(url) as resposta:
        # Um redirecionamento não pode levar para fora do HTTPS.
        if not resposta.geturl().startswith("https://"):
            raise ValueError("a resposta veio de um endereço sem HTTPS")
        conteudo = resposta.read(limite + 1)
    if len(conteudo) > limite:
        raise ValueError(f"a resposta passou de {limite:,} bytes".replace(
            ",", "."))
    return json_estrito(conteudo.decode("utf-8"))


def _dominio(url):
    """O domínio do endereço, para as mensagens."""
    return url.split("/")[2]


def baixar_primeiro(enderecos, limite, abrir):
    """Baixa o JSON do primeiro endereço que responder.

    Levanta AtualizacaoError, com o erro de cada endereço, se nenhum
    servir. Erro de rede, de HTTP e JSON fora da norma passam para o
    próximo endereço.
    """
    erros = []
    for url in enderecos:
        try:
            return _baixar_json(url, limite, abrir)
        except (OSError, ValueError, RecursionError,
                http.client.HTTPException) as erro:
            # URLError, HTTPError, TimeoutError e o erro de TLS são
            # OSError; JSON ruim e texto fora do UTF-8 são ValueError.
            erros.append(f"{_dominio(url)}: {erro}")
    raise AtualizacaoError("; ".join(erros))


# ----------------------------------------------------------------------
# Teste: um catálogo e registros simulados, sem internet.
# ----------------------------------------------------------------------

if __name__ == "__main__":
    import io
    import json
    import urllib.error

    RDP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    VETOR_40 = ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                "SC:N/SI:N/SA:N")

    def entrada_kev(cve, fabricante_e_produto, nome, dia, cwes=()):
        """Uma entrada no formato do catálogo KEV.

        A primeira palavra de fabricante_e_produto é o fabricante.
        """
        fabricante, _, produto = fabricante_e_produto.partition(" ")
        return {"cveID": cve, "vendorProject": fabricante,
                "product": produto, "vulnerabilityName": nome,
                "shortDescription": f"{nome}. Allows remote attackers.",
                "dateAdded": dia, "dueDate": dia, "cwes": list(cwes),
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates per vendor instructions.",
                "notes": f"https://nvd.nist.gov/vuln/detail/{cve}"}

    CATALOGO = {
        "catalogVersion": "2026.01.02", "count": 3,
        "dateReleased": "2026-01-02T10:00:00.000Z",
        "vulnerabilities": [
            entrada_kev("CVE-2019-0708", "Microsoft Remote Desktop Services",
                        "Microsoft Remote Desktop Services Remote Code "
                        "Execution Vulnerability", "2021-11-03"),
            entrada_kev("CVE-2024-21762", "Fortinet FortiOS",
                        "Fortinet FortiOS Out-of-Bound Write Vulnerability",
                        "2024-02-09", ["CWE-787"]),
            dict(entrada_kev("CVE-2023-20198", "Cisco IOS XE Web UI",
                             "Cisco IOS XE Web UI Privilege Escalation "
                             "Vulnerability", "2023-10-16", ["CWE-420"]),
                 # Notas como as do catálogo: o boletim, o link da NVD
                 # repetido, um link sem HTTPS e um com ponto no fim.
                 notes="https://www.cisco.com/c/en/us/support/docs/aviso"
                       ".html;  https://nvd.nist.gov/vuln/detail/CVE-2023"
                       "-20198 ; https://nvd.nist.gov/vuln/detail/CVE-2023"
                       "-20198 ; http://sem-https.example ; "
                       "https://www.cisa.gov/diretiva.",
                 requiredAction=None),
        ]}

    def registro_oficial(cve, metricas, cwe=None, adp=None):
        """Um registro oficial de CVE, só com o que o módulo lê."""
        cna = {"metrics": metricas}
        if cwe:
            cna["problemTypes"] = [{"descriptions": [
                {"cweId": cwe, "lang": "en", "type": "CWE"}]}]
        conteineres = {"cna": cna}
        if adp:
            conteineres["adp"] = [{"providerMetadata": {
                "shortName": "CISA-ADP"}, "metrics": adp}]
        return {"cveMetadata": {"cveId": cve}, "containers": conteineres}

    def metrica_ssvc(exploracao, automatizavel, impacto):
        """A métrica SSVC do ADP da CISA, no formato do registro."""
        return {"other": {"type": "ssvc", "content": {
            "id": "CVE", "role": "CISA Coordinator", "version": "2.0.3",
            "options": [{"Exploitation": exploracao},
                        {"Automatable": automatizavel},
                        {"Technical Impact": impacto}]}}}

    OFICIAIS = {
        # A 3.1 do ADP vence a 4.0 do CNA: a versão vem antes da fonte.
        # O ADP traz também a avaliação SSVC.
        "CVE-2019-0708": registro_oficial(
            "CVE-2019-0708", [{"cvssV4_0": {"vectorString": VETOR_40}}],
            cwe="CWE-416", adp=[{"cvssV3_1": {"vectorString": RDP}},
                                metrica_ssvc("active", "yes", "total")]),
        # Vetor com métricas temporais: elas saem, e a nota fica. A
        # avaliação SSVC com um valor desconhecido é ignorada.
        "CVE-2024-21762": registro_oficial(
            "CVE-2024-21762", [{"cvssV3_1": {
                "vectorString": RDP + "/E:H/RL:O/RC:C"}}],
            adp=[metrica_ssvc("talvez", "yes", "total")]),
        # Sem nenhuma nota: a CVE fica sem.
        "CVE-2023-20198": registro_oficial("CVE-2023-20198", []),
    }

    class RespostaFalsa(io.BytesIO):
        """Uma resposta HTTP simulada, como a de urlopen()."""

        def __init__(self, conteudo, url):
            """Guarda o conteúdo e o endereço final."""
            super().__init__(conteudo)
            self.url = url

        def geturl(self):
            """O endereço de onde a resposta veio."""
            return self.url

    pedidos = []

    def abrir_falso(url):
        """Responde com o catálogo ou com o registro, sem internet."""
        pedidos.append(url)
        if url.endswith("known_exploited_vulnerabilities.json"):
            corpo = CATALOGO
        else:
            corpo = OFICIAIS[url.rsplit("/", 1)[1].removesuffix(".json")]
        return RespostaFalsa(json.dumps(corpo).encode(), url)

    # --- atualização a partir de uma base vazia -----------------------
    andamento = []
    base, resumo = atualizar(
        BaseCVE(), abrir_falso,
        ao_buscar=lambda feitos, total: andamento.append((feitos, total)))
    assert resumo == Resumo(total=3, novas=3, sairam=0, notas_buscadas=2,
                            sem_nota=1), resumo
    assert andamento[-1] == (3, 3), andamento
    rdp = base.buscar_cve("CVE-2019-0708")
    assert (rdp.cvss, rdp.vetor, rdp.fonte_nota) == (9.8, RDP, "CISA-ADP")
    assert rdp.cwes == ("CWE-416",), rdp.cwes      # do registro oficial
    assert rdp.ransomware and rdp.produto == "Remote Desktop Services"
    forti = base.buscar_cve("CVE-2024-21762")
    assert (forti.cvss, forti.vetor, forti.cwes) == (9.8, RDP, ("CWE-787",))
    assert base.buscar_cve("CVE-2023-20198").cvss is None
    # A ação, os links das notas e a avaliação SSVC.
    assert rdp.acao == "Apply updates per vendor instructions."
    assert rdp.links == ("https://nvd.nist.gov/vuln/detail/CVE-2019-0708",)
    assert rdp.ssvc == ("active", "yes", "total"), rdp.ssvc
    assert forti.ssvc is None                     # valor desconhecido
    cisco = base.buscar_cve("CVE-2023-20198")
    assert cisco.acao is None                     # o catálogo não trouxe
    assert cisco.links == (
        "https://www.cisco.com/c/en/us/support/docs/aviso.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
        "https://www.cisa.gov/diretiva"), cisco.links
    assert base.catalogo == "2026.01.02" and base.publicado == "2026-01-02"
    assert base.origem == "atualizada"
    # O primeiro endereço de cada coisa é o do GitHub.
    assert pedidos[0] == ENDERECOS_KEV[0]
    assert any(p.endswith("/2019/0xxx/CVE-2019-0708.json") for p in pedidos)
    print(f"Atualização simulada: {resumo}")

    # Atualizar de novo: as notas que já existem não são buscadas, e a
    # avaliação SSVC delas continua a de antes.
    pedidos.clear()
    segunda, resumo = atualizar(base, abrir_falso)
    assert resumo.notas_buscadas == 0 and resumo.novas == 0, resumo
    assert len(pedidos) == 2, pedidos     # o catálogo e a CVE sem nota
    assert segunda.buscar_cve("CVE-2019-0708").ssvc == rdp.ssvc
    print("Segunda atualização: só a CVE sem nota foi buscada de novo.")

    # --- o que a atualização recusa, sem mudar a base -----------------
    ruim = dict(CATALOGO, vulnerabilities=[
        dict(CATALOGO["vulnerabilities"][0], cveID="CVE-ABCD")])

    def sem_internet(url):
        """Simula a falta de internet."""
        raise urllib.error.URLError("sem conexão")

    def grande_demais(url):
        """Uma resposta maior que o limite."""
        return RespostaFalsa(b" " * (LIMITE_DO_CATALOGO + 1), url)

    def sem_https(url):
        """Um redirecionamento para um endereço sem HTTPS."""
        return RespostaFalsa(b"{}", url.replace("https://", "http://"))

    def catalogo_ruim(url):
        """Um catálogo com uma CVE fora do formato."""
        return RespostaFalsa(json.dumps(ruim).encode(), url)

    for abrir_ruim, esperados in (
            (sem_internet, ("raw.githubusercontent.com", "www.cisa.gov")),
            (grande_demais, ("passou de",)),
            (sem_https, ("sem HTTPS",)),
            (catalogo_ruim, ("fora do formato",))):
        try:
            atualizar(base, abrir_ruim)
            raise AssertionError(f"atualizou com {abrir_ruim.__name__}")
        except AtualizacaoError as erro:
            assert all(texto in str(erro) for texto in esperados), erro
    assert len(base) == 3 and base.com_nota() == 2
    print("Recusados: sem internet, resposta grande, sem HTTPS e catálogo "
          "ruim; a base continua igual.")

    print("\nOK - atualização da base de CVEs exercitada.")
