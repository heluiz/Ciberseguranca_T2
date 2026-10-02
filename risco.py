"""Modelo de risco por álgebra linear (requisito 4 do Trabalho 2).

Com n equipamentos e m vulnerabilidades, o modelo monta:

  M  (n x m)  matriz de incidência: M[i][j] = 1 se o equipamento i é
              afetado pela vulnerabilidade j (e ela ainda não foi
              corrigida), senão 0.
  v  (m)      nota CVSS de cada vulnerabilidade.
  F  (n x n)  matriz diagonal com o fator de exposição de cada
              equipamento, que depende do tipo
              (Equipamento.fator_exposicao, polimórfico). Guardada só
              como o vetor da diagonal (self.fatores).
  b  (n)      risco próprio:  b = F (M v). A soma das notas das
              vulnerabilidades do equipamento, ponderada pelo fator do
              tipo. Com USAR_FATOR_DE_EXPOSICAO = False (todos os
              fatores iguais a 1), é exatamente o b = M v do enunciado.
  A  (n x n)  dependências: A[i][j] é a fração do risco do equipamento j
              que o equipamento i herda. A[i][i] = 0.

O risco efetivo x é o próprio mais o herdado dos equipamentos de que se
depende, e o que se herda já é efetivo (inclui o que o outro herdou):

      x = b + A x    <=>    (I - A) x = b

Resolve-se o sistema direto (numpy.linalg.solve), sem calcular a
inversa: é mais preciso e mais rápido. Antes, verifica-se que I - A é
invertível (ModeloRisco.diagnosticar). Se cada linha de A somar menos
que 1, I - A é estritamente diagonal dominante e, por isso, invertível;
o cadastro de dependências impõe essa regra (Equipamento.
definir_dependencia). Um arquivo editado à mão pode violá-la, então a
verificação é feita aqui também, e o usuário é informado quando o
sistema não tem solução confiável.

Sem a regra da soma, o número de condição decide se I - A é
invertível. Se for, a solução ainda é conferida: herdar risco só pode
somar, então nenhum risco efetivo pode ficar menor que o próprio
(x >= b). Se ficar (dependências em ciclo com frações altas demais), a
solução não tem sentido: o usuário é avisado e nada é mostrado.

O módulo não lê do teclado nem grava em disco.
"""

from collections import namedtuple

import numpy as np

import formatacao

# True: b = F (M v), com o fator de exposição de cada tipo (a dica do
# polimorfismo no enunciado). False: todos os fatores valem 1, e
# b = M v, a definição literal do enunciado.
USAR_FATOR_DE_EXPOSICAO = True

# Acima deste número de condição, o sistema é tratado como singular. O
# número de condição mede quanto um erro pequeno nos dados vira erro
# grande na solução; em ponto flutuante de 64 bits (cerca de 16
# dígitos), 1e12 deixa uns 4 dígitos confiáveis. Um determinante
# "quase zero" não serve para decidir: seu tamanho depende da escala
# da matriz.
LIMITE_CONDICAO = 1e12

# Só para a mensagem: abaixo disto, o determinante calculado é "zero"
# (um determinante que daria zero exato em papel quase nunca dá zero
# exato em ponto flutuante, mas algo como 2e-16).
TOLERANCIA_DETERMINANTE = 1e-12

# Folga da conferência x >= b: diferenças menores são arredondamento.
FOLGA_SOLUCAO = 1e-9

# Folga na regra "soma da linha < 1": uma soma de 0,9999999999999999
# vem de arredondamento (é o que 0,7 + 0,2 + 0,1 dá em ponto flutuante)
# e não é de verdade menor que 1.
FOLGA_DOMINANCIA = 1e-9

# Cada item do relatório: o equipamento, a soma das notas CVSS das suas
# vulnerabilidades (M v), o fator do tipo, o risco próprio b e o
# efetivo x.
RiscoEquipamento = namedtuple(
    "RiscoEquipamento", "equipamento soma_cvss fator proprio efetivo")

# O que a verificação de I - A concluiu. invertivel: I - A tem inversa;
# utilizavel: além disso, a solução tem sentido de risco (x >= b).
Diagnostico = namedtuple(
    "Diagnostico",
    "invertivel utilizavel dominante maior_soma determinante condicao "
    "motivo")


class SistemaSingularError(Exception):
    """I - A não é invertível (ou está perto demais de não ser).

    A mensagem diz ao usuário o que aconteceu e como corrigir.
    """


class ModeloRisco:
    """Monta M, v, F, b e A de um inventário e resolve (I - A) x = b.

    O modelo é uma fotografia: lê o inventário ao ser criado. Depois de
    qualquer mudança no inventário, cria-se um modelo novo.
    """

    def __init__(self, inventario):
        """Monta as matrizes a partir dos dados do inventário."""
        self.equipamentos = inventario.todos()
        self.vulnerabilidades = inventario.vulnerabilidades()
        n, m = len(self.equipamentos), len(self.vulnerabilidades)

        # Posição de cada id na matriz: a linha i é o i-ésimo
        # equipamento em ordem de id; a coluna j, a j-ésima
        # vulnerabilidade.
        linha = {e.id: i for i, e in enumerate(self.equipamentos)}
        coluna = {v.id: j for j, v in enumerate(self.vulnerabilidades)}

        self.M = np.zeros((n, m))
        for equipamento in self.equipamentos:
            for id_vuln, situacao in equipamento.vulnerabilidades.items():
                if situacao.conta_no_risco:
                    self.M[linha[equipamento.id], coluna[id_vuln]] = 1.0

        self.v = np.array([v.cvss for v in self.vulnerabilidades],
                          dtype=float)
        if USAR_FATOR_DE_EXPOSICAO:
            self.fatores = np.array([e.fator_exposicao
                                     for e in self.equipamentos],
                                    dtype=float)
        else:
            self.fatores = np.ones(n)

        self.soma_cvss = self.M @ self.v      # M v
        self.b = self.fatores * self.soma_cvss

        self.A = np.zeros((n, n))
        for equipamento in self.equipamentos:
            for destino, fracao in equipamento.dependencias.items():
                self.A[linha[equipamento.id], linha[destino]] = fracao

        self.x = None            # preenchido por resolver()
        self.residuo = None      # idem: tamanho do erro da solução
        self._diagnostico = None  # preenchido por diagnosticar()
        self._linha = linha

    # ------------------------------------------------------------------
    # Verificação de I - A
    # ------------------------------------------------------------------

    def diagnosticar(self):
        """Devolve o Diagnostico de I - A, calculado uma vez só.

        O modelo é uma fotografia do inventário, então o resultado não
        muda: guardá-lo evita refazer as contas (o número de condição
        sai de uma decomposição SVD, a parte mais cara) quando a opção
        13 verifica e depois resolve.
        """
        if self._diagnostico is None:
            self._diagnostico = self._verificar()
        return self._diagnostico

    def _verificar(self):
        """Verifica se I - A é invertível e se a solução faz sentido.

        Devolve um Diagnostico. A verificação segue esta ordem:
          1. Dominância: se a maior soma de linha de A é menor que 1,
             I - A é estritamente diagonal dominante, o que garante que
             é invertível e que nenhum risco efetivo fica menor que o
             próprio.
          2. Sem essa garantia, o número de condição (np.linalg.cond,
             limite LIMITE_CONDICAO) decide se I - A é invertível.
          3. Se for invertível, a solução é conferida: risco herdado só
             soma, então o efetivo não pode ficar menor que o próprio
             (x >= b). Se ficar, a solução não tem sentido.
        O determinante é calculado só para informar: não decide.
        """
        n = len(self.b)
        if n == 0:
            return Diagnostico(True, True, True, 0.0, 1.0, 1.0,
                               "Não há equipamentos cadastrados.")

        i_menos_a = np.eye(n) - self.A
        # A não tem valores negativos, então a soma da linha é a soma
        # dos valores absolutos que a dominância pede.
        maior = float(self.A.sum(axis=1).max())
        dominante = maior < 1.0 - FOLGA_DOMINANCIA
        determinante = float(np.linalg.det(i_menos_a))
        condicao = float(np.linalg.cond(i_menos_a))

        maior_br = formatacao.fracao_br(maior)
        if dominante:
            motivo = (f"I - A é estritamente diagonal dominante: a maior "
                      f"soma de linha de A é {maior_br}, menor que 1. "
                      f"Invertível.")
            return Diagnostico(True, True, True, maior, determinante,
                               condicao, motivo)

        condicao_br = formatacao.numero_compacto(condicao)
        limite_br = formatacao.numero_compacto(LIMITE_CONDICAO)
        invertivel = bool(np.isfinite(condicao) and condicao < LIMITE_CONDICAO)
        if not invertivel:
            motivo = (f"I - A não é invertível: a maior soma de linha de A "
                      f"é {maior_br} (precisa ser menor que 1) e o número "
                      f"de condição é {condicao_br} (limite {limite_br}).")
            if determinante == 0.0:
                motivo += " O determinante calculado é 0."
            elif abs(determinante) < TOLERANCIA_DETERMINANTE:
                tolerancia_br = formatacao.numero_compacto(
                    TOLERANCIA_DETERMINANTE)
                motivo += (f" O determinante calculado, "
                           f"{formatacao.numero_compacto(determinante)}, não "
                           f"é zero exato, mas é zero dentro da tolerância "
                           f"de {tolerancia_br}: em ponto flutuante, um "
                           f"determinante que daria zero no papel raramente "
                           f"dá zero exato.")
            motivo += (" Reduza as frações de dependência de algum "
                       "equipamento até a soma ficar abaixo de 1.")
            return Diagnostico(False, False, False, maior, determinante,
                               condicao, motivo)

        # Invertível, sem a garantia da dominância: confere a solução.
        x = np.linalg.solve(i_menos_a, self.b)
        if np.all(x >= self.b - FOLGA_SOLUCAO):
            motivo = (f"A maior soma de linha de A é {maior_br} (não é "
                      f"menor que 1), mas o número de condição "
                      f"({condicao_br}) é pequeno: I - A é invertível. A "
                      f"solução foi conferida: nenhum risco efetivo ficou "
                      f"menor que o próprio.")
            return Diagnostico(True, True, False, maior, determinante,
                               condicao, motivo)

        motivo = (f"I - A é invertível (número de condição {condicao_br}), "
                  f"mas a solução daria a algum equipamento um risco "
                  f"efetivo menor que o próprio, até negativo, o que não "
                  f"tem sentido: herdar risco só pode somar. Há "
                  f"dependências em ciclo com frações altas demais; "
                  f"reduza-as até a soma de cada linha de A ficar abaixo "
                  f"de 1.")
        return Diagnostico(True, False, False, maior, determinante,
                           condicao, motivo)

    # ------------------------------------------------------------------
    # Solução
    # ------------------------------------------------------------------

    def resolver(self):
        """Resolve (I - A) x = b e devolve o vetor x do risco efetivo.

        Levanta SistemaSingularError, com a explicação, se I - A não for
        invertível ou se a solução não fizer sentido (diagnosticar). A
        solução fica em self.x, e o tamanho do erro ||(I - A) x - b||,
        em self.residuo.
        """
        diagnostico = self.diagnosticar()
        if not diagnostico.utilizavel:
            raise SistemaSingularError(diagnostico.motivo)

        n = len(self.b)
        if n == 0:
            self.x = np.zeros(0)
            self.residuo = 0.0
            return self.x

        i_menos_a = np.eye(n) - self.A
        try:
            # solve() faz a eliminação de Gauss (fatoração LU): não
            # calcula a inversa.
            x = np.linalg.solve(i_menos_a, self.b)
        except np.linalg.LinAlgError as erro:
            raise SistemaSingularError(
                "I - A é singular: o sistema não tem solução única.") \
                from erro
        if not np.all(np.isfinite(x)):
            raise SistemaSingularError("A solução do sistema não é finita.")

        self.x = x
        self.residuo = float(np.linalg.norm(i_menos_a @ x - self.b))
        return x

    def relatorio(self):
        """Devolve uma lista de RiscoEquipamento, em ordem de id.

        Resolve o sistema se ainda não foi resolvido. Levanta
        SistemaSingularError se não for possível.
        """
        if self.x is None:
            self.resolver()
        return [
            RiscoEquipamento(equipamento, float(self.soma_cvss[i]),
                             float(self.fatores[i]), float(self.b[i]),
                             float(self.x[i]))
            for i, equipamento in enumerate(self.equipamentos)
        ]

    def risco_de(self, id_equipamento):
        """Devolve o RiscoEquipamento de um equipamento, ou None."""
        for item in self.relatorio():
            if item.equipamento.id == id_equipamento:
                return item
        return None

    def contribuicoes(self, id_equipamento):
        """Devolve de onde vem o risco herdado de um equipamento.

        Cada item é (equipamento de que depende, fração, risco efetivo
        dele, parcela herdada = fração x risco efetivo dele). A soma das
        parcelas é x - b. Resolve o sistema se necessário.
        """
        if self.x is None:
            self.resolver()
        i = self._linha[id_equipamento]
        itens = []
        for outro in self.equipamentos:
            fracao = self.A[i, self._linha[outro.id]]
            if fracao > 0:
                efetivo = float(self.x[self._linha[outro.id]])
                itens.append((outro, float(fracao), efetivo,
                              float(fracao) * efetivo))
        return itens


# ----------------------------------------------------------------------
# Teste: o cenário pequeno, resolvido à mão, e verificações do modelo.
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import random
    from fractions import Fraction

    from classificacoes import (
        OrigemVulnerabilidade,
        SituacaoTratamento,
        TipoEquipamento,
    )
    from inventario import Inventario

    ABERTA = SituacaoTratamento.ABERTA
    ORIGEM = OrigemVulnerabilidade.OUTRA

    def exato(matriz_a, b):
        """Resolve (I - A) x = b com frações exatas (método de Gauss).

        Independente do NumPy: serve para conferir o resultado dele.
        """
        n = len(b)
        linhas = [[Fraction(int(i == j)) - Fraction(matriz_a[i][j]).
                   limit_denominator(10 ** 6) for j in range(n)]
                  + [Fraction(b[i]).limit_denominator(10 ** 6)]
                  for i in range(n)]
        for c in range(n):
            pivo = next(r for r in range(c, n) if linhas[r][c] != 0)
            linhas[c], linhas[pivo] = linhas[pivo], linhas[c]
            linhas[c] = [valor / linhas[c][c] for valor in linhas[c]]
            for r in range(n):
                if r != c and linhas[r][c] != 0:
                    fator = linhas[r][c]
                    linhas[r] = [a - fator * p
                                 for a, p in zip(linhas[r], linhas[c],
                                                 strict=True)]
        return [linhas[i][n] for i in range(n)]

    # --- 1. O cenário de 3 equipamentos, resolvido à mão --------------
    #
    # E1 estação (fator 1,0): V1 (4,0)           -> M v = 4   -> b1 = 4
    # E2 servidor (1,5):      V1 (4,0) + V2 (6,0) -> M v = 10 -> b2 = 15
    # E3 banco (2,0):         V2 (6,0)           -> M v = 6   -> b3 = 12
    # E1 herda 0,5 de E2; E2 herda 0,5 de E3; E3 herda 0,25 de E2.
    #
    #   x1 = 4  + 0,5 x2
    #   x2 = 15 + 0,5 x3
    #   x3 = 12 + 0,25 x2
    #
    # Substituindo x3 em x2:
    #   x2 = 15 + 0,5 (12 + 0,25 x2) = 21 + 0,125 x2
    #   => 0,875 x2 = 21  => x2 = 24
    #   => x3 = 12 + 6 = 18  e  x1 = 4 + 12 = 16.
    inv = Inventario()
    e1 = inv.cadastrar_equipamento(TipoEquipamento.ESTACAO_TRABALHO,
                                   "E1-ESTACAO", "A", "B", "Estação")
    e2 = inv.cadastrar_equipamento(TipoEquipamento.SERVIDOR,
                                   "E2-SERVIDOR", "A", "B", "Servidor")
    e3 = inv.cadastrar_equipamento(TipoEquipamento.BANCO_DADOS,
                                   "E3-BANCO", "A", "B", "Banco")
    v1 = inv.registrar_vulnerabilidade(e1.id, "V1", ORIGEM, 4.0, ABERTA)
    inv.registrar_vulnerabilidade_existente(e2.id, v1.id, ABERTA)
    v2 = inv.registrar_vulnerabilidade(e2.id, "V2", ORIGEM, 6.0, ABERTA)
    inv.registrar_vulnerabilidade_existente(e3.id, v2.id, ABERTA)
    inv.registrar_dependencia(e1.id, e2.id, 0.5)
    inv.registrar_dependencia(e2.id, e3.id, 0.5)
    inv.registrar_dependencia(e3.id, e2.id, 0.25)

    modelo = ModeloRisco(inv)
    print("M =\n", modelo.M)
    print("v =", modelo.v)
    print("A =\n", modelo.A)
    print("b = F * (M v) =", modelo.b)
    assert np.array_equal(modelo.M, [[1, 0], [1, 1], [0, 1]])
    assert np.allclose(modelo.b, [4, 15, 12]), "risco próprio errado"

    diag = modelo.diagnosticar()
    print(f"\n{diag.motivo}")
    print(f"det(I - A) = {diag.determinante:.4f}; "
          f"cond(I - A) = {diag.condicao:.4f}")
    assert diag.invertivel and diag.utilizavel and diag.dominante
    assert abs(diag.determinante - 0.875) < 1e-12   # 1 - 0,5*0,25 - ...

    x = modelo.resolver()
    print("x =", x, f"(resíduo {modelo.residuo:.1e})")
    assert np.allclose(x, [16, 24, 18]), "o NumPy não bate com a mão"
    assert modelo.residuo < 1e-12
    for linha_do_relatorio in modelo.relatorio():
        print(f"  {linha_do_relatorio.equipamento.hostname:12} "
              f"Mv={linha_do_relatorio.soma_cvss:5.1f} "
              f"fator={linha_do_relatorio.fator:3.1f} "
              f"próprio={linha_do_relatorio.proprio:5.1f} "
              f"efetivo={linha_do_relatorio.efetivo:5.1f}")
    parcelas = modelo.contribuicoes(e1.id)
    assert [(p[0].id, p[3]) for p in parcelas] == [(e2.id, 12.0)]
    assert modelo.risco_de(99) is None

    # --- 2. Corrigir uma vulnerabilidade baixa o risco ----------------
    inv.alterar_situacao(e2.id, v2.id, SituacaoTratamento.CORRIGIDA)
    depois = ModeloRisco(inv)
    assert depois.M[1, 1] == 0 and depois.M[2, 1] == 1
    # Sobra só V1 no servidor: b2 = 1,5 x 4 = 6.
    assert np.allclose(depois.b, [4, 6, 12]), depois.b
    # x2 = 6 + 0,5 x3; x3 = 12 + 0,25 x2 -> x2 = 6 + 6 + 0,125 x2
    # -> x2 = 12 / 0,875
    assert abs(depois.resolver()[1] - 12 / 0.875) < 1e-9
    inv.alterar_situacao(e2.id, v2.id, SituacaoTratamento.ACEITA_COMO_RISCO)
    assert np.allclose(ModeloRisco(inv).b, [4, 15, 12]), \
        "aceita como risco deve continuar contando"
    print("\nCorrigida sai da matriz M; aceita como risco continua nela.")

    # --- 3. Sistema singular, de um arquivo editado à mão -------------
    # Três equipamentos que se herdam 0,5 entre si: cada linha de A soma
    # 1 e I - A tem o autovetor (1, 1, 1) com autovalor 0.
    singular = Inventario()
    ids = [singular.cadastrar_equipamento(
        TipoEquipamento.OUTRO, f"S{k}", "A", "B", "C").id
        for k in range(3)]
    for i in ids:
        for j in ids:
            if i != j:
                # direto no dicionário: o cadastro recusaria
                singular.buscar_por_id(i).dependencias[j] = 0.5
    ruim = ModeloRisco(singular)
    diag = ruim.diagnosticar()
    print(f"\nSingular: {diag.motivo}")
    assert not diag.invertivel and not diag.utilizavel
    assert not diag.dominante
    try:
        ruim.resolver()
        raise AssertionError("resolveu um sistema singular")
    except SistemaSingularError as erro:
        assert "não é invertível" in str(erro)
    # Soma de linha maior que 1 não é, sozinha, sinal de singularidade:
    # E1 herda 0,9 de E2 e 0,9 de E3 (soma 1,8), e os outros não herdam
    # nada. I - A é triangular com 1 na diagonal: det = 1, invertível.
    # Sem a garantia da dominância, decide o número de condição, e a
    # solução é conferida (x >= b).
    triang = Inventario()
    t1, t2, t3 = [triang.cadastrar_equipamento(
        TipoEquipamento.OUTRO, f"T{k}", "A", "B", "C") for k in range(3)]
    t1.dependencias[t2.id] = 0.9
    t1.dependencias[t3.id] = 0.9
    d = ModeloRisco(triang).diagnosticar()
    print(f"\nSoma 1,8 mas triangular: {d.motivo}")
    assert d.invertivel and d.utilizavel and not d.dominante

    # Invertível, mas sem sentido: E1 herda 0,9 de E2 e de E3, e os dois
    # herdam 0,9 de E1 (o ciclo repassa mais do que recebe). O sistema
    # tem solução, mas com riscos efetivos negativos:
    # x1 = 5 / (1 - 1,62).
    ciclo = Inventario()
    c1, c2, c3 = [ciclo.cadastrar_equipamento(
        TipoEquipamento.OUTRO, f"C{k}", "A", "B", "C") for k in range(3)]
    ciclo.registrar_vulnerabilidade(c1.id, "x", ORIGEM, 5.0, ABERTA)
    c1.dependencias.update({c2.id: 0.9, c3.id: 0.9})
    c2.dependencias[c1.id] = 0.9
    c3.dependencias[c1.id] = 0.9
    m_ciclo = ModeloRisco(ciclo)
    d = m_ciclo.diagnosticar()
    print(f"\nInvertível mas sem sentido: {d.motivo}")
    assert d.invertivel and not d.utilizavel
    assert np.linalg.solve(np.eye(3) - m_ciclo.A, m_ciclo.b).min() < 0
    try:
        m_ciclo.resolver()
        raise AssertionError("resolveu um sistema sem sentido de risco")
    except SistemaSingularError as erro:
        assert "menor que o próprio" in str(erro)

    # O mesmo ciclo sem vulnerabilidade nenhuma nele, mais um
    # equipamento isolado com nota 7,5: a solução (x = b) faz sentido e
    # é mostrada.
    so_isolado = Inventario()
    i1, i2, i3, i4 = [so_isolado.cadastrar_equipamento(
        TipoEquipamento.OUTRO, f"I{k}", "A", "B", "C") for k in range(4)]
    so_isolado.registrar_vulnerabilidade(i4.id, "x", ORIGEM, 7.5, ABERTA)
    i1.dependencias.update({i2.id: 0.9, i3.id: 0.9})
    i2.dependencias[i1.id] = 0.9
    i3.dependencias[i1.id] = 0.9
    m_isolado = ModeloRisco(so_isolado)
    assert m_isolado.diagnosticar().utilizavel
    assert np.allclose(m_isolado.resolver(), [0, 0, 0, 7.5])

    # Ciclo quase crítico (0,9999 nos dois sentidos): ainda dominante.
    quase = Inventario()
    q1, q2 = [quase.cadastrar_equipamento(
        TipoEquipamento.OUTRO, f"Q{k}", "A", "B", "C") for k in range(2)]
    quase.registrar_vulnerabilidade(q1.id, "x", ORIGEM, 1.0, ABERTA)
    q1.dependencias[q2.id] = 0.9999
    q2.dependencias[q1.id] = 0.9999
    m_quase = ModeloRisco(quase)
    assert m_quase.diagnosticar().utilizavel
    assert abs(m_quase.resolver()[0] - 1 / (1 - 0.9999 ** 2)) < 1e-6

    # --- 4. Casos de borda --------------------------------------------
    vazio = ModeloRisco(Inventario())
    assert (vazio.diagnosticar().utilizavel
            and len(vazio.relatorio()) == 0)
    sem_dep = Inventario()
    s1 = sem_dep.cadastrar_equipamento(TipoEquipamento.ROTEADOR, "R1", "A",
                                       "B", "C")
    assert ModeloRisco(sem_dep).relatorio()[0].efetivo == 0.0  # sem vulns
    sem_dep.registrar_vulnerabilidade(s1.id, "y", ORIGEM, 5.0, ABERTA)
    unico = ModeloRisco(sem_dep).relatorio()[0]
    assert abs(unico.proprio - 6.0) < 1e-12 and unico.efetivo == unico.proprio
    print("Casos de borda: sem equipamentos, sem vulnerabilidades, sem "
          "dependências.")

    # --- 5. Dois outros métodos concordam com o solve -----------------
    # (a) frações exatas; (b) série de Neumann:
    # x = b + A b + A^2 b + ..., que é repetir x <- b + A x até
    # estabilizar (converge se a soma das linhas de A for menor que 1).
    gerador = random.Random(2026)
    for _ in range(20):
        n = gerador.randint(2, 12)
        grande = Inventario()
        for k in range(n):
            tipo = gerador.choice(list(TipoEquipamento))
            grande.cadastrar_equipamento(tipo, f"G{k}", "A", "B", "C")
        for k in range(gerador.randint(1, 8)):
            dono = gerador.choice(grande.todos())
            vuln = grande.registrar_vulnerabilidade(
                dono.id, f"v{k}", ORIGEM,
                round(gerador.uniform(0.1, 10), 1), ABERTA)
            for outro in gerador.sample(grande.todos(), gerador.randint(0, n)):
                if outro.id != dono.id:
                    grande.registrar_vulnerabilidade_existente(
                        outro.id, vuln.id, ABERTA)
        for _ in range(3 * n):
            origem, destino = gerador.sample(grande.todos(), 2)
            folga = 1 - origem.soma_dependencias
            if folga > 0.02:
                grande.registrar_dependencia(
                    origem.id, destino.id,
                    round(gerador.uniform(0.01, folga - 0.01), 4))
        m = ModeloRisco(grande)
        assert m.diagnosticar().dominante
        x = m.resolver()
        assert np.all(x >= m.b - 1e-9), "x deveria ser pelo menos b"
        neumann = m.b.copy()
        for _ in range(5000):
            neumann = m.b + m.A @ neumann
        assert np.allclose(x, neumann, atol=1e-8), "Neumann discorda"
        if n <= 6:
            ex = exato(m.A, m.b)
            assert all(abs(float(e) - xi) < 1e-6
                       for e, xi in zip(ex, x, strict=True)), \
                "frações exatas discordam"
    print("20 inventários aleatórios: solve = série de Neumann (e = frações "
          "exatas nos de até 6 equipamentos).")

    # --- 6. solve x inversa: o erro que cada um deixa -----------------
    # Um ciclo de 30 equipamentos, cada um herdando quase tudo do
    # seguinte: I - A fica perto de singular (número de condição
    # alto). O resíduo ||(I - A) x - b|| mede o erro que sobra em cada
    # método. Os dois ficam pequenos aqui; o solve costuma errar um
    # pouco menos e faz menos contas (uma fatoração, sem montar a
    # inversa inteira).
    print("\nsolve x inversa num sistema mal condicionado:")
    sorteio = np.random.default_rng(7)
    for quase_um in (0.9, 0.9999999):
        ciclo_a = np.roll(np.eye(30), 1, axis=1) * quase_um
        k_ciclo = np.eye(30) - ciclo_a
        b_ciclo = sorteio.uniform(0, 20, 30)
        com_solve = np.linalg.solve(k_ciclo, b_ciclo)
        com_inversa = np.linalg.inv(k_ciclo) @ b_ciclo
        residuo_solve = np.linalg.norm(k_ciclo @ com_solve - b_ciclo)
        residuo_inversa = np.linalg.norm(k_ciclo @ com_inversa - b_ciclo)
        numero = formatacao.numero_compacto
        print(f"  frações {str(quase_um).replace('.', ',')}: número de "
              f"condição {numero(np.linalg.cond(k_ciclo))}; resíduo com "
              f"solve {numero(residuo_solve)}, com a inversa "
              f"{numero(residuo_inversa)}")
        assert np.allclose(com_solve, com_inversa, rtol=1e-4)

    print("\nOK - modelo de risco exercitado.")
