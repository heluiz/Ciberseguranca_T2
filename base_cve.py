"""Base local de CVEs: as falhas que atacantes estão explorando.

A base vem do catálogo KEV (Known Exploited Vulnerabilities) da CISA,
a agência de cibersegurança dos Estados Unidos: as CVEs que ela
confirmou exploradas de verdade, com fabricante, produto, nome,
descrição, CWE, a data em que entraram no catálogo, a ação que a CISA
exige e os links das notas (o boletim e a NVD). O KEV não traz a nota
CVSS: ela e o vetor (e o CWE, quando o KEV não tem) vêm do registro
oficial de cada CVE, publicado pelo CVE Program, de onde vem também a
avaliação SSVC da CISA.

São dois arquivos:

- a base inicial, que vem com o programa (base_cve/kev.json) e
  funciona sem internet;
- a base atualizada, baixada quando o usuário pede (opção 16) e
  gravada junto com os dados (dados/base_cve.json), porque, no
  container, a pasta do programa é só leitura.

Na leitura, vale a mais nova das duas, pela data do catálogo; a inicial
vale também quando a atualizada não existe ou está ruim. A gravação vai
para um arquivo temporário, que depois substitui o definitivo.

A busca é por palavras: cada palavra digitada precisa estar no começo
de alguma palavra do registro, sem diferença de maiúsculas e acentos.
Palavra achada no fabricante ou no produto vale mais que no nome, que
vale mais que na descrição.

Este módulo não lê do teclado nem usa a rede: a atualização, que baixa
o catálogo novo, fica em atualizacao_cve.py.
"""

import datetime
import json
import os
import re
import unicodedata
from collections import Counter, namedtuple

import validacao
from calculadora_cvss import analisar_vetor
from vulnerabilidades import validar_cve, validar_cvss, validar_cwe

PASTA_DO_PROJETO = os.path.dirname(os.path.abspath(__file__))
# A base que vem com o programa, e a variável de ambiente que muda o
# lugar da base atualizada (o padrão é dados/base_cve.json).
ARQUIVO_INICIAL = os.path.join(PASTA_DO_PROJETO, "base_cve", "kev.json")
VARIAVEL_DO_CAMINHO = "INVENTARIO_BASE_CVE"

FONTE = ("Catálogo KEV da CISA (CC0 1.0) e registros do CVE Program "
         "(Termos de Uso do CVE): veja base_cve/AVISOS.txt")

# Uma CVE da base. cwes é uma tupla, como ("CWE-416",); adicionada e
# prazo são datas AAAA-MM-DD (o prazo é o que a CISA dá aos órgãos
# federais dos EUA para corrigir); ransomware diz se a CISA sabe de uso
# em campanha de ransomware. cvss, vetor e fonte_nota podem ser None:
# fonte_nota diz quem deu a nota, o CNA (quem publicou a CVE, em geral
# o fabricante) ou um ADP, como a CISA, que completa os registros.
# acao é a ação que a CISA exige, em inglês (ou None); links, uma tupla
# com os endereços HTTPS das notas do catálogo; ssvc, a avaliação SSVC
# do registro oficial (ou None). Os três vieram depois: um arquivo sem
# eles continua valendo, com os valores padrão.
RegistroCVE = namedtuple(
    "RegistroCVE",
    "cve fabricante produto nome descricao cwes adicionada prazo "
    "ransomware cvss vetor fonte_nota acao links ssvc",
    defaults=(None, (), None))
CAMPOS_NOVOS = frozenset({"acao", "links", "ssvc"})

# A avaliação SSVC (Stakeholder-Specific Vulnerability Categorization)
# que a CISA põe no registro oficial da CVE: se a falha é explorada
# (none, poc ou active), se o ataque pode ser automatizado (no ou yes)
# e o controle que o atacante ganha (partial ou total). Os valores são
# os do registro, em inglês; a tradução fica em explicacao_cve.py.
Ssvc = namedtuple("Ssvc", "exploracao automatizavel impacto")
VALORES_SSVC = {"exploracao": ("none", "poc", "active"),
                "automatizavel": ("no", "yes"),
                "impacto": ("partial", "total")}

# Tamanho máximo de cada texto, em caracteres: uns três vezes o maior
# do catálogo.
TAMANHOS = {"fabricante": 100, "produto": 300, "nome": 300,
            "descricao": 2000, "fonte_nota": 40, "acao": 3000,
            "link": 500}
# Links por CVE: o catálogo chega a uns cinco.
MAXIMO_DE_LINKS = 10
# Um link aceito: HTTPS, com só os caracteres que um endereço pode ter
# (RFC 3986). Espaço, aspas, sinais de menor e maior e caracteres de
# controle ficam de fora: o link só é mostrado, nunca aberto, mas um
# caractere de controle poderia mexer no terminal.
_LINK = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?"
                   r"([/?#][A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?")

# Caracteres do catálogo trocados por equivalentes simples: hífens e
# espaços especiais, que a codificação do Windows (cp1252) não tem, e o
# caractere de substituição, que marca um caractere estragado na fonte.
_TROCAS = str.maketrans({"‐": "-", "‑": "-", " ": " ",
                         " ": " ", "�": ""})

# Palavras que não ajudam a achar nada, em português e em inglês.
PALAVRAS_VAZIAS = frozenset(
    "a o as os e de da do das dos em no na nos nas um uma para por com "
    "an the of and in on for to".split())
# Na ficha técnica, palavras que aparecem em produtos de muitos
# fabricantes e trariam sugestões sem relação com o equipamento.
PALAVRAS_GENERICAS = frozenset(
    "pro server servidor standard enterprise edition home plus ultimate "
    "professional business datacenter essentials core firmware web".split())
# Peso de uma palavra achada em cada parte do registro, do maior para
# o menor (a busca para no primeiro que achar).
PESOS = (("fabricante", 3), ("produto", 3), ("nome", 2), ("resto", 1))


class BaseCVEInvalidaError(Exception):
    """O arquivo da base de CVEs está ilegível ou fora do formato."""


def caminho_padrao():
    """Devolve onde fica a base atualizada: a variável, se definida."""
    return (os.environ.get(VARIAVEL_DO_CAMINHO)
            or os.path.join(PASTA_DO_PROJETO, "dados", "base_cve.json"))


# ----------------------------------------------------------------------
# Textos e palavras
# ----------------------------------------------------------------------

def palavras(texto):
    """Quebra o texto em palavras sem acento e em minúsculas.

    "Área de Trabalho" vira ["area", "de", "trabalho"]: o acento sai
    na decomposição Unicode (NFKD), que separa a letra do acento.
    """
    decomposto = unicodedata.normalize("NFKD", texto)
    sem_acento = "".join(c for c in decomposto
                         if not unicodedata.combining(c))
    return re.findall(r"[0-9a-z]+", sem_acento.casefold())


def conferir_texto(valor, campo, onde, obrigatorio=True):
    """Confere um texto da base: tipo, caracteres e tamanho.

    campo é a chave de TAMANHOS; onde diz em que CVE, para a mensagem.
    Espaços repetidos e quebras de linha viram um espaço só, e os
    caracteres de _TROCAS são trocados. Com obrigatorio=False, None
    passa.
    """
    nome = f"{onde}: {campo}"
    if valor is None and not obrigatorio:
        return None
    if not isinstance(valor, str):
        raise ValueError(f"{nome}: deveria ser texto, veio "
                         f"{type(valor).__name__}")
    limpo = " ".join(valor.translate(_TROCAS).split())
    validacao.exigir_texto(limpo, nome)
    if not limpo:
        raise ValueError(f"{nome}: está vazio")
    if len(limpo) > TAMANHOS[campo]:
        raise ValueError(f"{nome}: passa de {TAMANHOS[campo]} caracteres")
    return limpo


def conferir_data(valor, campo):
    """Confere uma data AAAA-MM-DD e a devolve como veio."""
    if not isinstance(valor, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}", valor):
        raise ValueError(f"{campo}: deveria ser uma data AAAA-MM-DD, "
                         f"veio {valor!r}")
    try:
        datetime.date.fromisoformat(valor)
    except ValueError:
        raise ValueError(f"{campo}: a data {valor} não existe") from None
    return valor


def conferir_cwes(lista, campo):
    """Os CWEs da lista no formato oficial, sem repetir.

    Um texto que não é CWE (como "NVD-CWE-noinfo", que alguns
    registros usam para "sem informação") é deixado de fora.
    """
    validacao.exigir_lista(lista, campo)
    achados = []
    for item in lista:
        try:
            cwe = validar_cwe(item)
        except ValueError:
            continue
        if cwe not in achados:
            achados.append(cwe)
    return tuple(achados)


def conferir_link(valor, campo):
    """Confere um link: HTTPS, até TAMANHOS["link"] caracteres."""
    if (not isinstance(valor, str) or len(valor) > TAMANHOS["link"]
            or not _LINK.fullmatch(valor)):
        raise ValueError(f"{campo}: o link deveria ser um endereço HTTPS "
                         f"sem espaços, veio {valor!r}")
    return valor


def conferir_links(lista, campo):
    """Os links da lista, conferidos e sem repetir, numa tupla."""
    validacao.exigir_lista(lista, campo)
    if len(lista) > MAXIMO_DE_LINKS:
        raise ValueError(f"{campo}: mais de {MAXIMO_DE_LINKS} links")
    links = tuple(conferir_link(link, campo) for link in lista)
    if len(set(links)) != len(links):
        raise ValueError(f"{campo}: link repetido")
    return links


def conferir_ssvc(dados, campo):
    """Confere a avaliação SSVC lida e devolve o Ssvc (ou None)."""
    if dados is None:
        return None
    validacao.exigir_objeto(dados, campo)
    if set(dados) != set(VALORES_SSVC):
        raise ValueError(f"{campo}: os campos deveriam ser "
                         f"{', '.join(VALORES_SSVC)}")
    for chave, validos in VALORES_SSVC.items():
        if dados[chave] not in validos:
            raise ValueError(f"{campo}: {chave} deveria ser "
                             f"{' ou '.join(validos)}, veio {dados[chave]!r}")
    return Ssvc(**dados)


def _nota(cvss, vetor, fonte, campo):
    """Confere a nota, o vetor e quem deu a nota; devolve os três.

    Com vetor, a nota tem de ser a que ele dá, pela fórmula oficial,
    como em toda vulnerabilidade do programa.
    """
    if cvss is None:
        if vetor is not None or fonte is not None:
            raise ValueError(f"{campo}: há vetor ou fonte sem a nota")
        return None, None, None
    nota = validar_cvss(cvss)
    if vetor is not None:
        arrumado, nota_do_vetor = analisar_vetor(vetor)
        if arrumado != vetor or nota_do_vetor != nota:
            raise ValueError(f"{campo}: a nota {nota} não confere com o "
                             f"vetor {vetor}")
    return nota, vetor, conferir_texto(fonte, "fonte_nota", campo,
                                       obrigatorio=False)


def _registro_de_dict(dados, campo):
    """Confere uma CVE lida do arquivo e devolve o RegistroCVE."""
    validacao.exigir_objeto(dados, campo)
    todos = set(RegistroCVE._fields)
    if not todos - CAMPOS_NOVOS <= set(dados) <= todos:
        raise ValueError(f"{campo}: os campos deveriam ser "
                         f"{', '.join(RegistroCVE._fields)}")
    cve = validar_cve(dados["cve"])
    campo = f"{campo} ({cve})"
    if not isinstance(dados["ransomware"], bool):
        raise ValueError(f"{campo}: ransomware deveria ser true ou false")
    nota, vetor, fonte = _nota(dados["cvss"], dados["vetor"],
                               dados["fonte_nota"], campo)
    return RegistroCVE(
        cve=cve,
        fabricante=conferir_texto(dados["fabricante"], "fabricante", campo),
        produto=conferir_texto(dados["produto"], "produto", campo),
        nome=conferir_texto(dados["nome"], "nome", campo),
        descricao=conferir_texto(dados["descricao"], "descricao", campo),
        cwes=conferir_cwes(dados["cwes"], f"{campo}: cwes"),
        adicionada=conferir_data(dados["adicionada"], f"{campo}: adicionada"),
        prazo=conferir_data(dados["prazo"], f"{campo}: prazo"),
        ransomware=dados["ransomware"],
        cvss=nota, vetor=vetor, fonte_nota=fonte,
        acao=conferir_texto(dados.get("acao"), "acao", campo,
                            obrigatorio=False),
        links=conferir_links(dados.get("links", []), f"{campo}: links"),
        ssvc=conferir_ssvc(dados.get("ssvc"), f"{campo}: ssvc"))


def _recusar_constante(nome):
    """Recusa NaN e Infinity, que o json do Python aceitaria."""
    raise ValueError(f"{nome} não existe em JSON")


def json_estrito(texto):
    """Lê um JSON pela norma (RFC 8259): sem NaN e sem nome repetido."""
    return json.loads(texto,
                      object_pairs_hook=validacao.objeto_sem_nome_repetido,
                      parse_constant=_recusar_constante)


def _numero_da_cve(registro):
    """Chave de ordem pelo número: (ano, número)."""
    _, ano, numero = registro.cve.split("-")
    return int(ano), int(numero)


def nome_curto(registro):
    """O nome sem fabricante e produto no começo e sem "Vulnerability".

    "Microsoft Remote Desktop Services Remote Code Execution
    Vulnerability" vira "Remote Code Execution": nas tabelas, fabricante
    e produto já estão em colunas próprias.
    """
    nome = registro.nome
    for comeco in (f"{registro.fabricante} {registro.produto} ",
                   f"{registro.produto} ", f"{registro.fabricante} "):
        if nome.casefold().startswith(comeco.casefold()):
            nome = nome[len(comeco):]
            break
    nome = re.sub(r"\s+Vulnerabilit(y|ies)$", "", nome)
    return nome or registro.nome


# ----------------------------------------------------------------------
# A base
# ----------------------------------------------------------------------

class BaseCVE:
    """As CVEs exploradas, com busca, navegação, sugestões e arquivo."""

    def __init__(self, registros=(), catalogo="", publicado="",
                 montado_em="", origem=""):
        """Monta a base. Levanta ValueError com CVE repetida.

        catalogo é a versão do KEV, como "2026.10.13"; publicado, a
        data dele; montado_em, a data em que a base foi montada; origem,
        de onde a base foi lida ("inicial" ou "atualizada").
        """
        self.registros = {}
        for registro in registros:
            if registro.cve in self.registros:
                raise ValueError(f"A {registro.cve} aparece duas vezes")
            self.registros[registro.cve] = registro
        self.catalogo = catalogo
        self.publicado = publicado
        self.montado_em = montado_em
        self.origem = origem
        # As palavras de cada registro, calculadas uma vez só.
        self._indice = {cve: _indice_de(registro)
                        for cve, registro in self.registros.items()}

    def __len__(self):
        """Quantas CVEs a base tem."""
        return len(self.registros)

    def com_nota(self):
        """Quantas CVEs têm nota CVSS."""
        return sum(1 for r in self.registros.values() if r.cvss is not None)

    def buscar_cve(self, cve):
        """Devolve o RegistroCVE da CVE (formato oficial), ou None."""
        return self.registros.get(cve)

    def _ordem(self, registro):
        """Chave de ordem: a maior nota e, no empate, a mais recente."""
        return (-(registro.cvss or 0.0), -self._indice[registro.cve]["dia"])

    # --- busca por palavras -------------------------------------------

    def buscar(self, texto):
        """Devolve as CVEs que têm todas as palavras do texto.

        Um número de CVE, com ou sem o prefixo, acha só ela. Senão, cada
        palavra precisa estar no começo de alguma palavra do registro
        ("forti" acha FortiOS e FortiGate); palavras vazias, como "de" e
        "the", não contam. A ordem vai da maior soma de PESOS para a
        menor e, no empate, da maior nota para a menor e da mais recente
        para a mais antiga.
        """
        try:
            cve = validar_cve(texto)
        except ValueError:
            cve = None
        if cve is not None:
            achado = self.registros.get(cve)
            return [achado] if achado else []
        termos = [p for p in palavras(texto) if p not in PALAVRAS_VAZIAS]
        if not termos:
            return []
        achados = []
        for cve_do_registro, registro in self.registros.items():
            pontos = _pontos(self._indice[cve_do_registro], termos)
            if pontos:
                achados.append((pontos, registro))
        achados.sort(key=lambda par: (-par[0], *self._ordem(par[1])))
        return [registro for _, registro in achados]

    # --- navegação por fabricante e produto ---------------------------

    def fabricantes(self, filtro=""):
        """Devolve [(fabricante, quantas CVEs)], de quem tem mais.

        Com filtro, só os fabricantes em que cada palavra do filtro está
        no começo de alguma palavra do nome ("dl" acha D-Link).
        """
        termos = palavras(filtro)
        contagem = Counter(r.fabricante for r in self.registros.values())
        lista = [(nome, n) for nome, n in contagem.items()
                 if all(any(p.startswith(t) for p in palavras(nome))
                        for t in termos)]
        lista.sort(key=lambda par: (-par[1], par[0].casefold()))
        return lista

    def produtos(self, fabricante):
        """Devolve [(produto, quantas CVEs)] de um fabricante."""
        contagem = Counter(r.produto for r in self.registros.values()
                           if r.fabricante == fabricante)
        return sorted(contagem.items(),
                      key=lambda par: (-par[1], par[0].casefold()))

    def do_produto(self, fabricante, produto):
        """As CVEs de um produto, da maior nota para a menor."""
        return sorted((r for r in self.registros.values()
                       if (r.fabricante, r.produto) == (fabricante, produto)),
                      key=self._ordem)

    # --- sugestões pela ficha técnica ---------------------------------

    def sugestoes(self, ficha):
        """As CVEs cujo fabricante ou produto combinam com a ficha.

        Compara, palavra por palavra (inteira), o fabricante, o modelo e
        o sistema da ficha com o fabricante e o produto de cada CVE.
        Números, palavras de menos de 3 letras, PALAVRAS_VAZIAS e
        PALAVRAS_GENERICAS não contam. Palavra no produto vale mais que
        no fabricante: "Windows" diz mais que "Microsoft". O nome do
        fabricante repetido no produto, como em "Cisco IP Phones", conta
        uma vez só, como fabricante. Devolve [(registro, palavras que
        combinaram)], da combinação mais forte para a mais fraca.
        """
        termos = set()
        for valor in (ficha.fabricante, ficha.modelo, ficha.sistema):
            for p in palavras(valor or ""):
                if (len(p) >= 3 and not p.isdigit()
                        and p not in PALAVRAS_VAZIAS
                        and p not in PALAVRAS_GENERICAS):
                    termos.add(p)
        achados = []
        for cve, registro in self.registros.items():
            indice = self._indice[cve]
            no_fabricante = termos & indice["fabricante_set"]
            no_produto = termos & (indice["produto_set"]
                                   - indice["fabricante_set"])
            if no_fabricante or no_produto:
                pontos = 2 * len(no_fabricante) + 3 * len(no_produto)
                achados.append((pontos, registro,
                                sorted(no_fabricante | no_produto)))
        achados.sort(key=lambda item: (-item[0], *self._ordem(item[1])))
        return [(registro, combinou) for _, registro, combinou in achados]

    # --- arquivo ------------------------------------------------------

    def para_texto(self):
        """O texto do arquivo da base: os dados do catálogo e as CVEs.

        Uma CVE por linha, na ordem do número: o arquivo fica legível, e
        a diferença entre duas versões, fácil de ver no Git.
        """
        cabecalho = {"fonte": FONTE, "catalogo": self.catalogo,
                     "publicado": self.publicado,
                     "montado_em": self.montado_em,
                     "quantas": len(self.registros)}
        linhas = ["{"]
        for nome, valor in cabecalho.items():
            linhas.append(f"  {json.dumps(nome)}: "
                          f"{json.dumps(valor, ensure_ascii=False)},")
        cves = [json.dumps(dict(r._asdict(), cwes=list(r.cwes),
                                links=list(r.links),
                                ssvc=r.ssvc._asdict() if r.ssvc else None),
                           ensure_ascii=False, allow_nan=False)
                for r in sorted(self.registros.values(),
                                key=_numero_da_cve)]
        linhas.append('  "cves": [')
        linhas.append(",\n".join(f"    {cve}" for cve in cves))
        linhas.append("  ]")
        linhas.append("}")
        return "\n".join(linhas) + "\n"

    @classmethod
    def de_texto(cls, texto, origem=""):
        """Monta a base a partir do texto do arquivo (de para_texto()).

        Levanta ValueError, com o motivo, se algo estiver fora do
        formato.
        """
        dados = validacao.exigir_objeto(json_estrito(texto), "base")
        campos = {"fonte", "catalogo", "publicado", "montado_em", "quantas",
                  "cves"}
        if set(dados) != campos:
            raise ValueError(f"os campos da base deveriam ser "
                             f"{', '.join(sorted(campos))}")
        lista = validacao.exigir_lista(dados["cves"], "cves")
        registros = [_registro_de_dict(item, f"CVE {posicao}")
                     for posicao, item in enumerate(lista, 1)]
        quantas = validacao.exigir_inteiro(dados["quantas"], "quantas", 0)
        if quantas != len(registros):
            raise ValueError(f"a base diz que tem {quantas} CVEs, mas "
                             f"tem {len(registros)}")
        catalogo = validacao.exigir_texto(dados["catalogo"], "catalogo")
        if len(catalogo) > 40:
            raise ValueError("catalogo: passa de 40 caracteres")
        return cls(registros, catalogo=catalogo,
                   publicado=conferir_data(dados["publicado"], "publicado"),
                   montado_em=conferir_data(dados["montado_em"], "montado_em"),
                   origem=origem)

    def salvar(self, caminho):
        """Grava a base: num temporário, que depois troca de nome.

        A troca (os.replace) é atômica: se a gravação for interrompida,
        o arquivo antigo continua inteiro, como em armazenamento.py.
        """
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)
        temporario = caminho + ".tmp"
        with open(temporario, "w", encoding="utf-8") as arquivo:
            arquivo.write(self.para_texto())
            arquivo.flush()
            os.fsync(arquivo.fileno())
        os.replace(temporario, caminho)

    @classmethod
    def carregar(cls, caminho_atualizado=None,
                 caminho_inicial=ARQUIVO_INICIAL):
        """Lê a mais nova das duas bases: a atualizada ou a inicial.

        A atualizada vale se existir, puder ser lida e o catálogo dela
        não for mais velho que o da inicial: uma versão nova do programa
        pode trazer uma base inicial mais nova que a última atualização.
        Devolve (base, aviso); o aviso diz por que a atualizada não pôde
        ser lida ("" nos outros casos). Levanta BaseCVEInvalidaError se
        nenhuma das duas puder ser lida.
        """
        caminho_atualizado = caminho_atualizado or caminho_padrao()
        atualizada, aviso = None, ""
        if os.path.exists(caminho_atualizado):
            try:
                atualizada = cls._ler(caminho_atualizado, "atualizada")
            except BaseCVEInvalidaError as erro:
                aviso = (f"A base de CVEs atualizada não pôde ser lida "
                         f"({erro}); o programa usa a que vem com ele.")
        try:
            inicial = cls._ler(caminho_inicial, "inicial")
        except BaseCVEInvalidaError:
            if atualizada is None:
                raise
            return atualizada, ""
        if atualizada is not None and (atualizada.publicado
                                       >= inicial.publicado):
            return atualizada, ""
        return inicial, aviso

    @classmethod
    def _ler(cls, caminho, origem):
        """Lê um arquivo da base; erros viram BaseCVEInvalidaError."""
        try:
            with open(caminho, encoding="utf-8-sig") as arquivo:
                return cls.de_texto(arquivo.read(), origem)
        except OSError as erro:
            raise BaseCVEInvalidaError(
                f"não foi possível abrir {caminho} ({erro})") from erro
        except (ValueError, RecursionError) as erro:
            # UnicodeDecodeError e o erro do json são ValueError.
            raise BaseCVEInvalidaError(f"{caminho}: {erro}") from erro


def _indice_de(registro):
    """As palavras de cada parte do registro, para a busca."""
    fabricante = palavras(registro.fabricante)
    produto = palavras(registro.produto)
    resto = " ".join((registro.descricao, *registro.cwes, registro.cve))
    return {"fabricante": fabricante, "produto": produto,
            "nome": palavras(registro.nome), "resto": palavras(resto),
            "fabricante_set": set(fabricante), "produto_set": set(produto),
            "dia": datetime.date.fromisoformat(
                registro.adicionada).toordinal()}


def _pontos(indice, termos):
    """A soma dos pesos das palavras achadas; 0 se faltar alguma."""
    total = 0
    for termo in termos:
        peso = next((peso for parte, peso in PESOS
                     if any(p.startswith(termo) for p in indice[parte])), 0)
        if not peso:
            return 0
        total += peso
    return total




# ----------------------------------------------------------------------
# Teste: uma base pequena, montada aqui, e a base que vem com o
# programa. A atualização é testada em atualizacao_cve.py.
# ----------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    from ficha_tecnica import FichaTecnica

    RDP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def registro_de_teste(cve, fabricante, produto, nome, dia, nota=None):
        """Um RegistroCVE pequeno; com nota, o vetor é o do RDP."""
        return RegistroCVE(
            cve=cve, fabricante=fabricante, produto=produto, nome=nome,
            descricao=f"{nome}. Allows remote attackers.", cwes=(),
            adicionada=dia, prazo=dia, ransomware=False, cvss=nota,
            vetor=RDP if nota else None, fonte_nota="CNA" if nota else None)

    base = BaseCVE([
        registro_de_teste("CVE-2019-0708", "Microsoft",
                          "Remote Desktop Services",
                          "Microsoft Remote Desktop Services Remote Code "
                          "Execution Vulnerability", "2021-11-03",
                          9.8)._replace(
            acao="Apply updates per vendor instructions.",
            links=("https://msrc.microsoft.com/update-guide/vulnerability/"
                   "CVE-2019-0708",
                   "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"),
            ssvc=Ssvc("active", "yes", "total")),
        registro_de_teste("CVE-2024-21762", "Fortinet", "FortiOS",
                          "Fortinet FortiOS Out-of-Bound Write "
                          "Vulnerability", "2024-02-09", 9.8),
        registro_de_teste("CVE-2023-20198", "Cisco", "IOS XE Web UI",
                          "Cisco IOS XE Web UI Privilege Escalation "
                          "Vulnerability", "2023-10-16"),
    ], catalogo="2026.01.02", publicado="2026-01-02",
        montado_em="2026-01-03")
    assert len(base) == 3 and base.com_nota() == 2
    try:
        BaseCVE([base.buscar_cve("CVE-2019-0708")] * 2)
        raise AssertionError("aceitou a mesma CVE duas vezes")
    except ValueError:
        pass

    # --- busca por palavras, sem acento e pelo começo da palavra ------
    assert [r.cve for r in base.buscar("remote desktop")] == [
        "CVE-2019-0708"]
    assert [r.cve for r in base.buscar("forti")] == ["CVE-2024-21762"]
    assert [r.cve for r in base.buscar("2019-0708")] == ["CVE-2019-0708"]
    assert base.buscar("CVE-2000-0001") == []
    assert base.buscar("de the") == []           # só palavras vazias
    assert base.buscar("Remóte DÉSKTOP") == base.buscar("remote desktop")
    # "remote" acha as três (está nas descrições), mas a do produto
    # Remote Desktop Services vem antes: produto vale mais.
    assert [r.cve for r in base.buscar("remote")][0] == "CVE-2019-0708"
    assert len(base.buscar("remote")) == 3
    rdp = base.buscar_cve("CVE-2019-0708")
    assert nome_curto(rdp) == "Remote Code Execution", nome_curto(rdp)
    print("Busca: palavras, acentos, começo da palavra e número da CVE.")

    # --- navegação e sugestões ----------------------------------------
    assert base.fabricantes()[0][1] == 1 and len(base.fabricantes()) == 3
    assert base.fabricantes("forti") == [("Fortinet", 1)]
    assert base.produtos("Cisco") == [("IOS XE Web UI", 1)]
    assert base.do_produto("Cisco", "IOS XE Web UI")[0].cve == (
        "CVE-2023-20198")
    ficha = FichaTecnica({"fabricante": "Fortinet",
                          "modelo": "FortiGate 60F",
                          "sistema": "FortiOS 7.2"})
    sugeridas = base.sugestoes(ficha)
    assert [(r.cve, p) for r, p in sugeridas] == [
        ("CVE-2024-21762", ["fortinet", "fortios"])], sugeridas
    assert base.sugestoes(FichaTecnica({"sistema": "Windows 11 Pro"})) == []
    print("Navegação por fabricante e sugestões pela ficha técnica.")

    # --- arquivo: ida e volta; atualizada ruim, vale a inicial --------
    with tempfile.TemporaryDirectory() as pasta:
        atualizada = os.path.join(pasta, "dados", "base_cve.json")
        inicial = os.path.join(pasta, "inicial.json")
        base.salvar(atualizada)
        base.salvar(inicial)
        lida, aviso = BaseCVE.carregar(atualizada, inicial)
        assert lida.registros == base.registros and aviso == ""
        assert lida.origem == "atualizada"
        with open(atualizada, "a", encoding="utf-8") as arquivo:
            arquivo.write("lixo")
        lida, aviso = BaseCVE.carregar(atualizada, inicial)
        assert lida.origem == "inicial" and "não pôde ser lida" in aviso
        # Uma atualização mais velha que a base inicial também perde.
        velha = BaseCVE(base.registros.values(), catalogo="2025.12.01",
                        publicado="2025-12-01", montado_em="2025-12-02")
        velha.salvar(atualizada)
        lida, aviso = BaseCVE.carregar(atualizada, inicial)
        assert (lida.origem, lida.catalogo, aviso) == (
            "inicial", "2026.01.02", "")
        print("Arquivo: ida e volta igual; atualizada ruim ou mais velha, "
              "vale a inicial.")

    # --- campos novos: ação, links e SSVC -----------------------------
    texto_bom = base.para_texto()
    lida = BaseCVE.de_texto(texto_bom)
    assert lida.registros == base.registros
    bluekeep_teste = lida.buscar_cve("CVE-2019-0708")
    assert bluekeep_teste.ssvc == Ssvc("active", "yes", "total")
    assert len(bluekeep_teste.links) == 2
    # Um arquivo de antes, sem os três campos, continua valendo.
    antigo = json.loads(texto_bom)
    for item in antigo["cves"]:
        for chave in CAMPOS_NOVOS:
            del item[chave]
    sem_campos = BaseCVE.de_texto(json.dumps(antigo))
    rdp_antigo = sem_campos.buscar_cve("CVE-2019-0708")
    assert (rdp_antigo.acao, rdp_antigo.links, rdp_antigo.ssvc) == (
        None, (), None)
    print("Ação, links e SSVC: ida e volta iguais; arquivo sem eles, aceito.")

    # --- o que a leitura recusa ---------------------------------------
    estragos = (
        (texto_bom.replace('"cvss": 9.8', '"cvss": NaN', 1), "NaN"),
        (texto_bom.replace('"quantas": 3', '"quantas": 4'), "quantas"),
        (texto_bom.replace('"cvss": 9.8', '"cvss": 7.0', 1), "vetor"),
        (texto_bom.replace("CVE-2019-0708", "CVE-19-708"), "CVE"),
        (texto_bom.replace('"fonte"', '"fonte": 1, "fonte"'), "duas"),
        (texto_bom.replace("https://msrc", "http://msrc"), "sem HTTPS"),
        (texto_bom.replace("/CVE-2019-0708\", \"https://nvd",
                           "/CVE 2019\", \"https://nvd"), "espaço"),
        (texto_bom.replace('"active"', '"talvez"'), "SSVC"),
        (texto_bom.replace('"ssvc": {', '"ssvc": {"extra": 1, ', 1),
         "SSVC a mais"),
        (texto_bom.replace('"ransomware"', '"campo_novo": 1, "ransomware"',
                           1), "campo desconhecido"))
    for estrago, motivo in estragos:
        assert estrago != texto_bom, motivo
        try:
            BaseCVE.de_texto(estrago)
            raise AssertionError(f"aceitou base com {motivo}")
        except ValueError:
            pass
    print("Recusados: NaN, contagem errada, nota contra o vetor, CVE fora "
          "do formato, nome repetido, link sem HTTPS ou com espaço, SSVC "
          "fora dos valores e campo desconhecido.")

    # --- a base que vem com o programa --------------------------------
    real, aviso = BaseCVE.carregar(os.path.join(tempfile.gettempdir(),
                                                "nao-existe.json"))
    assert aviso == "" and real.origem == "inicial"
    assert len(real) > 1000 and real.com_nota() > 0.95 * len(real)
    bluekeep = real.buscar_cve("CVE-2019-0708")
    assert bluekeep is not None and bluekeep.cvss == 9.8, bluekeep
    assert bluekeep.cve in [r.cve for r in real.buscar("remote desktop")]
    print(f"Base inicial: catálogo {real.catalogo}, {len(real)} CVEs, "
          f"{real.com_nota()} com nota.")

    print("\nOK - base de CVEs exercitada.")
