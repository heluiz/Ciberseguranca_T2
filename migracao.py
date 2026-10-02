"""Conversão da base do Trabalho 1 para o formato do Trabalho 2.

No Trabalho 1, cada falha pertencia a um ativo e tinha só uma gravidade
(1 a 4). No Trabalho 2, a vulnerabilidade é do catálogo, tem nota CVSS e
pode afetar vários equipamentos. A conversão:

  - cada ativo vira um equipamento, com o mesmo id e o tipo certo;
  - falhas iguais (mesma descrição, origem e gravidade) viram uma só
    vulnerabilidade do catálogo, ligada a cada equipamento que a tinha,
    com a situação que tinha em cada um;
  - a gravidade vira uma nota CVSS representativa (CVSS_REPRESENTATIVO),
    que cai na mesma faixa: a severidade mostrada não muda;
  - os ids das falhas deixam de existir; os dos ativos são mantidos.

O resultado é a lista de objetos do formato novo (um por equipamento,
com as suas vulnerabilidades dentro).

O armazenamento chama converter() sozinho ao encontrar um arquivo do
Trabalho 1. Também dá para converter à mão:

    python migracao.py inventario_antigo.json inventario_novo.json
"""

import sys

from validacao import (
    exigir_campo,
    exigir_inteiro,
    exigir_objeto,
)

# Uma nota para cada gravidade do Trabalho 1 (1 baixa ... 4 crítica),
# dentro da faixa dessa gravidade no CVSS v3.x e entre as notas mais
# comuns na prática.
CVSS_REPRESENTATIVO = {1: 3.1, 2: 5.3, 3: 7.5, 4: 9.8}


def eh_formato_t1(dados):
    """Diz se o conteúdo lido é do Trabalho 1.

    O formato antigo é um objeto JSON com a chave "ativos"; o novo é
    uma lista.
    """
    return isinstance(dados, dict) and "ativos" in dados


def _chave_para_id(chave, nome):
    """Devolve o id inteiro da chave do JSON antigo ("7" -> 7)."""
    try:
        numero = int(chave)
    except (TypeError, ValueError):
        numero = 0
    if numero < 1 or str(numero) != chave:
        raise ValueError(f"{nome}: id fora do formato: {chave!r}")
    return numero


def converter(dados_t1):
    """Converte o conteúdo do Trabalho 1 para o formato do Trabalho 2.

    Devolve (lista_t2, avisos): o conteúdo novo e uma lista de frases
    sobre o que a conversão precisou decidir. Levanta ValueError se o
    conteúdo antigo estiver fora do formato. O resultado ainda passa
    pela validação completa de Inventario.de_dict.
    """
    origem = "arquivo do Trabalho 1"
    ativos = exigir_objeto(exigir_campo(dados_t1, "ativos", origem),
                           f"{origem}: campo 'ativos'")
    falhas = exigir_objeto(exigir_campo(dados_t1, "falhas", origem),
                           f"{origem}: campo 'falhas'")

    equipamentos = {}
    for chave, registro in ativos.items():
        id_ativo = _chave_para_id(chave, f"ativo {chave}")
        nome = f"ativo {id_ativo}"
        exigir_objeto(registro, nome)
        equipamentos[id_ativo] = {
            "id": id_ativo,
            "tipo": exigir_campo(registro, "categoria", nome),
            "hostname": exigir_campo(registro, "hostname", nome),
            "custodiante": exigir_campo(registro, "custodiante", nome),
            "lotacao": exigir_campo(registro, "lotacao", nome),
            "descricao": exigir_campo(registro, "descricao", nome),
            "vulnerabilidades": [],
            "dependencias": [],
        }

    catalogo = {}      # (descrição, origem, gravidade) -> objeto
    avisos = []
    for chave in sorted(falhas, key=lambda c: _chave_para_id(
            c, f"falha {c}")):
        nome = f"falha {chave}"
        registro = exigir_objeto(falhas[chave], nome)
        id_ativo = exigir_inteiro(exigir_campo(registro, "ativo_id", nome),
                                  f"{nome}: campo 'ativo_id'")
        if id_ativo not in equipamentos:
            raise ValueError(f"{nome}: aponta para o ativo {id_ativo}, "
                             f"que não existe")
        gravidade = exigir_inteiro(
            exigir_campo(registro, "gravidade", nome),
            f"{nome}: campo 'gravidade'")
        if gravidade not in CVSS_REPRESENTATIVO:
            raise ValueError(f"{nome}: gravidade {gravidade} inexistente")
        descricao = exigir_campo(registro, "descricao", nome)
        origem_falha = exigir_campo(registro, "origem", nome)
        situacao = exigir_campo(registro, "situacao", nome)

        identidade = (descricao, origem_falha, gravidade)
        if identidade not in catalogo:
            catalogo[identidade] = {
                "id": len(catalogo) + 1,
                "descricao": descricao,
                "origem": origem_falha,
                "cvss": CVSS_REPRESENTATIVO[gravidade],
            }
        id_vuln = catalogo[identidade]["id"]

        vinculos = equipamentos[id_ativo]["vulnerabilidades"]
        if any(v["id"] == id_vuln for v in vinculos):
            avisos.append(
                f"O ativo {id_ativo} tinha a falha {chave} repetida; "
                f"ficou só a primeira.")
            continue
        vinculos.append({"id": id_vuln, "situacao": situacao})

    # No formato novo cada equipamento leva as suas vulnerabilidades
    # por inteiro (descrição, origem, nota e a situação nele).
    por_id = {v["id"]: v for v in catalogo.values()}
    lista = []
    for id_ativo in sorted(equipamentos):
        objeto = equipamentos[id_ativo]
        objeto["vulnerabilidades"] = [
            dict(por_id[vinculo["id"]], situacao=vinculo["situacao"])
            for vinculo in objeto["vulnerabilidades"]]
        lista.append(objeto)
    return lista, avisos


# Uso: python migracao.py origem.json destino.json
# A leitura e a gravação são as do programa (armazenamento.py), com as
# mesmas conferências: o arquivo novo sai igual ao que o menu gravaria.
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)

    from armazenamento import ArquivoInventario, BaseInvalidaError

    origem = ArquivoInventario(sys.argv[1])
    try:
        inventario = origem.carregar()      # converte e faz o .t1.bak
    except BaseInvalidaError as erro:
        sys.exit(f"Não foi possível ler {sys.argv[1]}: {erro}")
    if origem.migracao_feita is None:
        sys.exit("O arquivo de origem não está no formato do Trabalho 1.")
    ArquivoInventario(sys.argv[2]).salvar(inventario)
    for nota in origem.migracao_feita[1]:
        print("Aviso:", nota)
    print(f"{len(inventario)} equipamento(s) gravados em {sys.argv[2]}")
