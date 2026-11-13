"""Critérios intercambiáveis para priorização do painel (Strategy)."""

from typing import Protocol


class RankingStrategy(Protocol):
    def rank(self, report): ...


class EffectiveRiskRanking:
    def rank(self, report):
        return sorted(
            report, key=lambda row: (-row.efetivo, row.equipamento.id)
        )


class OwnRiskRanking:
    def rank(self, report):
        return sorted(
            report, key=lambda row: (-row.proprio, row.equipamento.id)
        )
