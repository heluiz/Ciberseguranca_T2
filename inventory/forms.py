from django import forms
from .models import Asset, Vulnerability, Finding, Dependency


class VersionForm(forms.ModelForm):
    version = forms.IntegerField(
        widget=forms.HiddenInput, initial=1, min_value=1
    )


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


class FindingForm(VersionForm):
    class Meta:
        model = Finding
        fields = ["asset", "vulnerability", "situacao", "version"]
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
