"""Árvore de dependências de um equipamento, para a opção 12.

As dependências formam um grafo dirigido: "A depende de B, com fração
f" é a entrada A[a][b] da matriz A do modelo de risco e quer dizer que A
herda a fração f do risco efetivo de B. O grafo não é uma árvore: um
equipamento pode depender de vários outros, e dois podem depender um do
outro (ciclo). Para mostrá-lo como árvore a partir de um equipamento,
em um dos dois sentidos, a montagem segue três regras:

1. Cada equipamento alcançado aparece uma vez só, sob a ligação mais
   específica: a do equipamento que tem menos dependentes, no sentido
   "quem depende dele", ou menos dependências, no sentido "do que ele
   depende". Uma estação que depende do controlador de domínio e do
   roteador de borda fica sob o controlador, de que menos equipamentos
   dependem. No empate, vale o equipamento de partida, depois a fração
   maior e, por último, o menor id.
2. As outras ligações de cada um vêm no próprio item, para nenhuma
   sumir da tela. Assim, um dependente direto do equipamento de partida
   pode aparecer mais abaixo, com a ligação direta escrita no item.
3. Os que não têm nada abaixo e têm as mesmas ligações viram um item só
   (vinte estações iguais, um item com as vinte).

Os dois equipamentos de um ciclo não ficam um sob o outro, a não ser que
não haja outro caminho até um deles. A ligação de ciclo aparece
marcada.

O módulo só monta a árvore: não lê do teclado, não imprime e não altera
o inventário. A tela fica em telas.py.
"""

from collections import namedtuple

QUEM_DEPENDE = "quem depende"
DO_QUE_DEPENDE = "do que depende"
SENTIDOS = (QUEM_DEPENDE, DO_QUE_DEPENDE)

# Uma ligação escrita no item: o outro equipamento, a fração e se os
# dois dependem um do outro.
Ligacao = namedtuple("Ligacao", "equipamento fracao ciclo")

# Um item da árvore. equipamentos: um, ou vários num grupo. fracao e
# ciclo: a ligação com o item de cima (no sentido QUEM_DEPENDE, o item
# herda a fração do de cima; no outro, o de cima herda do item). outras:
# as demais ligações, em Ligacao. filhos: os itens de baixo. fora:
# quantos vizinhos do lado de baixo aparecem em outros ramos.
Item = namedtuple("Item", "equipamentos fracao ciclo outras filhos fora")

# A árvore: o equipamento de partida, o sentido, os itens do primeiro
# nível e quantos equipamentos ela alcança, sem contar o de partida.
Arvore = namedtuple("Arvore", "raiz sentido itens total")


def montar(inventario, id_raiz, sentido):
    """Monta a árvore a partir do equipamento id_raiz, no sentido dado.

    QUEM_DEPENDE mostra os que herdam risco dele, direta ou
    indiretamente; DO_QUE_DEPENDE, aqueles de quem ele herda. Levanta
    ValueError se o sentido não existir ou o equipamento não estiver no
    inventário.
    """
    if sentido not in SENTIDOS:
        raise ValueError(f"Sentido desconhecido: {sentido!r}")
    equipamentos = {e.id: e for e in inventario}
    if id_raiz not in equipamentos:
        raise ValueError(f"Não existe equipamento com o id {id_raiz}")
    return _Montagem(equipamentos, id_raiz, sentido).arvore()


class _Montagem:
    """As contas de uma montagem, guardadas para não serem refeitas."""

    def __init__(self, equipamentos, id_raiz, sentido):
        """Lê as ligações do inventário nos dois sentidos."""
        self.equipamentos = equipamentos
        self.raiz = id_raiz
        self.sentido = sentido
        self.dependencias = {i: dict(e.dependencias)
                             for i, e in equipamentos.items()}
        self.dependentes = {i: {} for i in equipamentos}
        for i, destinos in self.dependencias.items():
            for j, fracao in destinos.items():
                self.dependentes[j][i] = fracao
        self._alcances = {}
        self.nos = self.alcance(id_raiz) | {id_raiz}
        self.pai = self._escolher_pais()

    @property
    def abaixo(self):
        """Os vizinhos do lado de baixo: os filhos possíveis."""
        if self.sentido == QUEM_DEPENDE:
            return self.dependentes
        return self.dependencias

    @property
    def acima(self):
        """Os vizinhos do lado de cima: os pais possíveis."""
        if self.sentido == QUEM_DEPENDE:
            return self.dependencias
        return self.dependentes

    def alcance(self, i):
        """Os equipamentos alcançados a partir de i, para baixo.

        A busca guarda os pendentes numa lista, sem recursão: uma cadeia
        longa de dependências não estoura a pilha do Python.
        """
        if i not in self._alcances:
            vistos, pendentes = set(), [i]
            while pendentes:
                atual = pendentes.pop()
                for vizinho in self.abaixo[atual]:
                    if vizinho != i and vizinho not in vistos:
                        vistos.add(vizinho)
                        pendentes.append(vizinho)
            self._alcances[i] = vistos
        return self._alcances[i]

    def fracao(self, filho, pai):
        """A fração da ligação entre um item e o de cima dele."""
        if self.sentido == QUEM_DEPENDE:
            return self.dependencias[filho][pai]
        return self.dependencias[pai][filho]

    def mutua(self, a, b):
        """True se a depende de b e b depende de a."""
        return b in self.dependencias[a] and a in self.dependencias[b]

    def mesmo_ciclo(self, a, b):
        """True se a e b se alcançam (um chega no outro e volta)."""
        return b in self.alcance(a) and a in self.alcance(b)

    def _chave(self, filho, pai):
        """Ordem dos candidatos a pai: o mais específico primeiro."""
        return (len(self.alcance(pai)), pai != self.raiz,
                -self.fracao(filho, pai), pai)

    def _escolher_pais(self):
        """Escolhe o item de cima de cada equipamento alcançado.

        Vale a ligação mais específica (regra 1). Fora de um ciclo, cada
        pai alcança mais equipamentos que o filho, então não há volta.
        Um equipamento do mesmo ciclo só serve de pai se for o de
        partida ou se não houver outro caminho: aí o filho fica sob um
        equipamento do ciclo já colocado.
        """
        pai, pendentes = {}, []
        for filho in sorted(self.nos - {self.raiz}):
            candidatos = [p for p in self.acima[filho] if p in self.nos
                          and (p == self.raiz
                               or not self.mesmo_ciclo(p, filho))]
            if candidatos:
                pai[filho] = min(candidatos,
                                 key=lambda p, f=filho: self._chave(f, p))
            else:
                pendentes.append(filho)
        while pendentes:
            for filho in pendentes:
                candidatos = [p for p in self.acima[filho]
                              if p in pai or p == self.raiz]
                if candidatos:
                    pai[filho] = min(
                        candidatos, key=lambda p, f=filho: self._chave(f, p))
            restantes = [f for f in pendentes if f not in pai]
            if len(restantes) == len(pendentes):
                raise RuntimeError("equipamento alcançado sem caminho "
                                   "na árvore")
            pendentes = restantes
        return pai

    def arvore(self):
        """Monta os itens de baixo para cima e devolve a Arvore."""
        filhos = {i: [] for i in self.nos}
        for filho, pai in self.pai.items():
            filhos[pai].append(filho)
        # Ordem de visita sem recursão: cada pai antes dos filhos.
        ordem, pilha = [], [self.raiz]
        while pilha:
            atual = pilha.pop()
            ordem.append(atual)
            pilha.extend(filhos[atual])
        tamanho, itens = {}, {}
        for atual in reversed(ordem):
            tamanho[atual] = 1 + sum(tamanho[f] for f in filhos[atual])
            itens[atual] = self._itens_dos_filhos(atual, filhos, tamanho,
                                                  itens)
        return Arvore(self.equipamentos[self.raiz], self.sentido,
                      itens[self.raiz], len(self.nos) - 1)

    def _outras(self, filho, pai):
        """As ligações do item além da que o liga ao de cima.

        No sentido QUEM_DEPENDE, todas as outras dependências dele (são
        poucas); no outro, os outros equipamentos da árvore que dependem
        dele (todos poderiam ser dezenas).
        """
        if self.sentido == QUEM_DEPENDE:
            pares = [(w, f) for w, f in self.dependencias[filho].items()
                     if w != pai]
        else:
            pares = [(w, f) for w, f in self.dependentes[filho].items()
                     if w != pai and w in self.nos]
        pares.sort(key=lambda par: (-par[1],
                                    self.equipamentos[par[0]].hostname))
        return tuple(Ligacao(self.equipamentos[w], f, self.mutua(filho, w))
                     for w, f in pares)

    def _fora(self, filho, filhos):
        """Quantos vizinhos de baixo do item aparecem em outros ramos.

        Não conta os que estão acima dele na mesma linha da árvore (num
        ciclo, o vizinho de baixo pode ser o de cima).
        """
        acima, atual = set(), self.pai.get(filho)
        while atual is not None:
            acima.add(atual)
            atual = self.pai.get(atual)
        return sum(1 for w in self.abaixo[filho]
                   if w not in filhos[filho] and w not in acima)

    def _itens_dos_filhos(self, pai, filhos, tamanho, itens):
        """Os itens sob o pai: ramos, folhas avulsas e grupos de folhas.

        Ramos vêm primeiro, do maior para o menor; depois, as folhas.
        Folha é quem não tem vizinho nenhum do lado de baixo.
        """
        ramos = [f for f in filhos[pai] if self.abaixo[f]]
        ramos.sort(key=lambda i: (-tamanho[i], -len(self.alcance(i)),
                                  self.equipamentos[i].hostname))
        return tuple([Item((self.equipamentos[i],), self.fracao(i, pai),
                           self.mutua(i, pai), self._outras(i, pai),
                           itens[i], self._fora(i, filhos))
                      for i in ramos]
                     + self._folhas(pai, [f for f in filhos[pai]
                                          if not self.abaixo[f]]))

    def _folhas(self, pai, folhas):
        """Os itens das folhas: as de ligações iguais viram um grupo.

        As que ficaram sozinhas vêm antes, pelo nome; os grupos, do
        maior para o menor.
        """
        grupos = {}
        for folha in folhas:
            outras = self._outras(folha, pai)
            chave = (self.fracao(folha, pai),
                     tuple((lig.equipamento.id, lig.fracao)
                           for lig in outras))
            grupos.setdefault(chave, (outras, []))[1].append(folha)
        avulsos, juntos = [], []
        for (fracao, _), (outras, membros) in grupos.items():
            equipamentos = sorted((self.equipamentos[i] for i in membros),
                                  key=lambda e: e.hostname)
            item = Item(tuple(equipamentos), fracao, False, outras, (), 0)
            (avulsos if len(membros) == 1 else juntos).append(item)
        avulsos.sort(key=lambda item: item.equipamentos[0].hostname)
        juntos.sort(key=lambda item: (-len(item.equipamentos), -item.fracao,
                                      item.equipamentos[0].hostname))
        return avulsos + juntos


def equipamentos_da_arvore(arvore):
    """Devolve todos os equipamentos dos itens, na ordem da árvore."""
    vistos, pilha = [], list(reversed(arvore.itens))
    while pilha:
        item = pilha.pop()
        vistos.extend(item.equipamentos)
        pilha.extend(reversed(item.filhos))
    return vistos


# Teste rápido: roda só com "python arvore.py", nunca no import.
if __name__ == "__main__":
    from classificacoes import TipoEquipamento
    from inventario import Inventario

    inv = Inventario()

    def novo(tipo, nome):
        """Cadastra um equipamento de teste e devolve o id."""
        return inv.cadastrar_equipamento(tipo, nome, "Teste", "Teste",
                                         "Equipamento de teste").id

    nobreak = novo(TipoEquipamento.OUTRO, "NOBREAK")
    roteador = novo(TipoEquipamento.ROTEADOR, "ROTEADOR")
    dominio = novo(TipoEquipamento.SERVIDOR, "DOMINIO")
    arquivos = novo(TipoEquipamento.SERVIDOR, "ARQUIVOS")
    estacoes = [novo(TipoEquipamento.ESTACAO_TRABALHO, f"PC-{n}")
                for n in range(1, 4)]
    impressora = novo(TipoEquipamento.IMPRESSORA_REDE, "IMPRESSORA")

    inv.registrar_dependencia(roteador, nobreak, 0.2)
    inv.registrar_dependencia(dominio, roteador, 0.15)
    inv.registrar_dependencia(dominio, nobreak, 0.1)
    inv.registrar_dependencia(arquivos, roteador, 0.15)
    inv.registrar_dependencia(dominio, arquivos, 0.1)    # ciclo
    inv.registrar_dependencia(arquivos, dominio, 0.2)    # ciclo
    for pc in estacoes:
        inv.registrar_dependencia(pc, dominio, 0.2)
        inv.registrar_dependencia(pc, roteador, 0.25)
    inv.registrar_dependencia(impressora, roteador, 0.2)

    def item_de(itens, id_equipamento):
        """O item de um equipamento entre os itens dados."""
        return next(i for i in itens
                    if i.equipamentos[0].id == id_equipamento)

    def outras_de(item):
        """As outras ligações, como (hostname, fração, ciclo)."""
        return [(lig.equipamento.hostname, lig.fracao, lig.ciclo)
                for lig in item.outras]

    # Quem depende do nobreak: os sete, cada um uma vez só. O domínio
    # depende do nobreak e do roteador, mas fica sob o roteador, de que
    # menos equipamentos dependem; a ligação direta vem escrita no item.
    arv = montar(inv, nobreak, QUEM_DEPENDE)
    nomes = [e.hostname for e in equipamentos_da_arvore(arv)]
    assert arv.total == 7 and len(nomes) == 7 == len(set(nomes)), nomes
    assert [i.equipamentos[0].hostname for i in arv.itens] == ["ROTEADOR"]
    rot = arv.itens[0]
    dom = item_de(rot.filhos, dominio)
    assert outras_de(dom) == [("ARQUIVOS", 0.1, True),
                             ("NOBREAK", 0.1, False)], outras_de(dom)
    print("Quem depende do NOBREAK: 7 equipamentos, todos sob o ROTEADOR; "
          "o DOMINIO mostra a ligação direta com o NOBREAK.")

    # As três estações iguais viram um grupo, sob o domínio.
    grupo = dom.filhos[0]
    assert [e.hostname for e in grupo.equipamentos] == ["PC-1", "PC-2",
                                                       "PC-3"]
    assert grupo.fracao == 0.2
    assert outras_de(grupo) == [("ROTEADOR", 0.25, False)]
    print("As 3 estações formam um grupo sob DOMINIO e também herdam 0,25 "
          "do ROTEADOR.")

    # O ciclo: ARQUIVOS fica sob o roteador, e não sob o domínio; a
    # ligação de volta vem marcada, e o dependente dele (o domínio)
    # aparece em outro ramo.
    arq = item_de(rot.filhos, arquivos)
    assert outras_de(arq) == [("DOMINIO", 0.2, True)] and arq.fora == 1
    arv = montar(inv, arquivos, QUEM_DEPENDE)
    assert item_de(arv.itens, dominio).ciclo
    print("ARQUIVOS e DOMINIO dependem um do outro: a ligação vem marcada.")

    # Do que uma estação depende: o roteador fica sob o domínio, e a
    # ligação direta da estação com ele vem escrita no item. ARQUIVOS só
    # tem a ligação de ciclo com o domínio e fica sob ele.
    arv = montar(inv, estacoes[0], DO_QUE_DEPENDE)
    assert arv.total == 4, arv.total
    assert [i.equipamentos[0].hostname for i in arv.itens] == ["DOMINIO"]
    abaixo_do_dominio = arv.itens[0].filhos
    assert [i.equipamentos[0].hostname
            for i in abaixo_do_dominio] == ["ROTEADOR", "ARQUIVOS"]
    assert ("PC-1", 0.25, False) in outras_de(abaixo_do_dominio[0])
    print(f"PC-1 depende de {arv.total} equipamentos, contando os "
          f"indiretos.")

    # Sem ligações, a árvore é vazia; sentido errado é recusado.
    assert montar(inv, impressora, QUEM_DEPENDE).itens == ()
    assert montar(inv, nobreak, DO_QUE_DEPENDE).total == 0
    for errado in ((nobreak, "para cima"), (999, QUEM_DEPENDE)):
        try:
            montar(inv, *errado)
            raise AssertionError(f"aceitou {errado}")
        except ValueError as erro:
            print(f"Recusado: {erro}.")

    print("\nOK - árvore montada nos dois sentidos, com grupo e ciclo.")
