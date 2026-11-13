from django import forms
from django.utils import timezone
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
