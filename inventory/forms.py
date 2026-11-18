from decimal import Decimal

from django import forms
from django.utils import timezone
from .models import Asset, Vulnerability, Finding, Dependency


class VersionForm(forms.ModelForm):
    version = forms.IntegerField(
        widget=forms.HiddenInput, initial=1, min_value=1
    )

    def clean(self):
        """Só texto visível, a mesma regra do programa de terminal.

        Um caractere de controle (ESC, quebra de linha...) seria gravado no
        banco, mas o inventário deixaria de carregar (validacao.exigir_texto),
        e com ele o modelo de risco inteiro.
        """
        data = super().clean()
        for name, value in list(data.items()):
            if isinstance(value, str) and not value.isprintable():
                self.add_error(name, "Use apenas caracteres visíveis (sem quebra de linha nem caractere de controle).")
        return data


class AssetForm(VersionForm):
    class Meta:
        model = Asset
        fields = [
            "hostname",
            "tipo",
            "custodiante",
            "lotacao",
            "descricao",
            "fabricante",
            "modelo",
            "numero_serie",
            "patrimonio",
            "sistema",
            "versao",
            "version",
        ]
        labels = {
            "custodiante": "Responsável (prefira cargo ou setor)",
            "lotacao": "Lotação",
            "descricao": "Descrição",
            "numero_serie": "Número de série",
            "versao": "Versão",
        }


class VulnerabilityForm(VersionForm):
    class Meta:
        model = Vulnerability
        fields = [
            "descricao",
            "origem",
            "cvss",
            "cve",
            "cwe",
            "vetor",
            "version",
        ]
        labels = {"descricao": "Descrição", "vetor": "Vetor CVSS (opcional)"}


class VulnerabilityWebForm(VulnerabilityForm):
    """O cadastro da tela web, com as ajudas do cadastro do terminal.

    - CVE que está na base de CVEs exploradas preenche o que ficou em branco
      (descrição, CWE, vetor e nota), como o terminal oferece;
    - com vetor e sem nota, a nota é a que o vetor dá; com os dois, eles
      precisam concordar (a mesma regra de vulnerabilidades.conferir_vetor).

    A API continua com VulnerabilityForm: o contrato publicado exige a nota.
    """

    cvss = forms.DecimalField(
        required=False,
        max_digits=3,
        decimal_places=1,
        min_value=Decimal("0.1"),
        max_value=Decimal("10.0"),
        label="Nota CVSS",
        help_text="Pode ficar em branco com um vetor ou com uma CVE da base de CVEs exploradas.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["descricao"].required = False
        self.fields["vetor"].help_text = (
            "Cole o vetor do boletim ou monte-o em Calculadora CVSS, no menu."
        )
        self.filled_from_base = []

    def _fill_from_base(self, data):
        from vulnerabilidades import validar_cve

        from .references import cve_base

        try:
            cve = validar_cve(data.get("cve") or "")
        except ValueError:
            return
        record = cve_base()[0].buscar_cve(cve)
        if record is None:
            return
        if not data.get("descricao"):
            data["descricao"] = record.nome
            self.filled_from_base.append("descrição")
        if not data.get("cwe") and record.cwes:
            data["cwe"] = record.cwes[0]
            self.filled_from_base.append("CWE")
        if data.get("cvss") is None and not data.get("vetor"):
            if record.vetor:
                data["vetor"] = record.vetor
                self.filled_from_base.append("vetor")
            elif record.cvss is not None:
                data["cvss"] = Decimal(str(record.cvss))
                self.filled_from_base.append("nota")

    def clean(self):
        from calculadora_cvss import analisar_vetor
        from formatacao import numero_br

        data = super().clean()
        if data.get("cve") and not self.instance.pk:
            self._fill_from_base(data)
        vetor = data.get("vetor")
        if vetor and "vetor" not in self.errors:
            try:
                vetor, nota = analisar_vetor(vetor)
            except ValueError as error:
                self.add_error("vetor", str(error))
            else:
                data["vetor"] = vetor
                if not nota:
                    self.add_error(
                        "vetor",
                        "O vetor dá nota 0,0 (nenhum impacto): não há vulnerabilidade a cadastrar.",
                    )
                elif data.get("cvss") is None:
                    data["cvss"] = Decimal(str(nota))
                elif float(data["cvss"]) != nota:
                    self.add_error(
                        "cvss",
                        f"A nota {numero_br(float(data['cvss']))} não confere com o vetor CVSS, "
                        f"que dá {numero_br(nota)}. Deixe a nota em branco para usar a do vetor.",
                    )
        if data.get("cvss") is None and "cvss" not in self.errors and "vetor" not in self.errors:
            self.add_error(
                "cvss",
                "Informe a nota CVSS, um vetor ou uma CVE da base de CVEs exploradas.",
            )
        if not data.get("descricao") and "descricao" not in self.errors:
            self.add_error("descricao", "Informe a descrição.")
        return data


class FindingForm(VersionForm):
    detected_at = forms.DateTimeField(
        required=False,
        label="Data e hora da detecção",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M:%S",
            attrs={"type": "datetime-local", "step": "1"},
        ),
        help_text="Horário de Brasília. Pode informar uma detecção anterior. Apague o campo se a data for desconhecida.",
    )
    corrected_at = forms.DateTimeField(
        required=False,
        label="Data e hora da correção",
        widget=forms.DateTimeInput(
            format="%Y-%m-%dT%H:%M:%S",
            attrs={"type": "datetime-local", "step": "1"},
        ),
        help_text="Ao marcar Corrigida, fica registrada a hora atual se este campo estiver vazio. Reabrir limpa a data atual e preserva o histórico.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.instance.pk and not self.is_bound:
            self.initial["detected_at"] = timezone.localtime(
                timezone.now()
            ).replace(second=0, microsecond=0)
        if self.instance.pk:
            for name in ("asset", "vulnerability"):
                self.fields[name].disabled = True

    def clean(self):
        data = super().clean()
        if not self.instance.pk and "detected_at" not in self.data:
            data["detected_at"] = timezone.now()
        if self.instance.pk:
            for name in ("asset", "vulnerability"):
                value = self.data.get(name)
                if value is not None and str(value) != str(
                    getattr(self.instance, name + "_id")
                ):
                    raise forms.ValidationError(
                        "Para outro ativo ou vulnerabilidade, crie uma nova ocorrência."
                    )
        # Não altera a instância antes da verificação de versão no serviço.
        if data.get("situacao") != 3:
            if self.instance.pk and self.instance.situacao == 3:
                data["corrected_at"] = None
            elif data.get("corrected_at"):
                self.add_error(
                    "corrected_at",
                    "A data de correção exige a situação Corrigida.",
                )
        return data

    class Meta:
        model = Finding
        fields = [
            "asset",
            "vulnerability",
            "situacao",
            "detected_at",
            "corrected_at",
            "version",
        ]
        labels = {
            "asset": "Ativo",
            "vulnerability": "Vulnerabilidade",
            "situacao": "Tratamento",
        }


class DependencyForm(VersionForm):
    class Meta:
        model = Dependency
        fields = ["source", "target", "fracao", "version"]
        labels = {
            "source": "Ativo que herda risco",
            "target": "Ativo do qual depende",
            "fracao": "Fração (0,0001 a 0,9999)",
        }


FORMS = {
    "asset": AssetForm,
    "vulnerability": VulnerabilityForm,
    "finding": FindingForm,
    "dependency": DependencyForm,
}


# O cadastro pelas telas HTML usa as ajudas do terminal; a API, o contrato.
WEB_FORMS = {**FORMS, "vulnerability": VulnerabilityWebForm}
