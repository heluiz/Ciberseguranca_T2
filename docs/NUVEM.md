# Computação em nuvem: opções de hospedagem do SENTINEL

Cards S5_16 e S5_17. Este documento é o roteiro e o relatório. As partes que
dependem de conta pessoal (criar a conta, ligar o segundo fator, o alerta de
gastos, publicar e encerrar) são feitas pelo aluno; os campos de evidência
estão marcados com **[preencher]**.

## IaaS, PaaS e SaaS

| Serviço | Modelo | Por quê |
| --- | --- | --- |
| AWS EC2, Google Compute Engine, Azure VM, Oracle Cloud VM | IaaS | Você recebe uma máquina virtual e cuida do sistema para cima |
| Render, Railway, Fly.io, Google Cloud Run, Azure App Service, Heroku | PaaS | Você entrega o código ou a imagem; o provedor cuida da máquina |
| Amazon RDS, Neon, Supabase (Postgres) | PaaS (banco gerenciado) | O banco sem administrar o servidor |
| GitHub, Gmail, Microsoft 365, Trello | SaaS | Você só usa o programa |
| GitHub Container Registry | PaaS (registro de imagens) | Guarda as imagens publicadas pelo CI |

## Quem cuida de quê

| Camada | Servidor da disciplina | IaaS (VM) | PaaS (Cloud Run + banco gerenciado) |
| --- | --- | --- | --- |
| Prédio, energia, rede física | UFU | Provedor | Provedor |
| Hipervisor e hardware | UFU | Provedor | Provedor |
| Sistema operacional, atualizações, SSH, firewall | Docente | **Aluno** | Provedor |
| Docker e runtime | Docente | **Aluno** | Provedor |
| PostgreSQL (instalação, backup, atualização) | **Aluno** (container) | **Aluno** | Provedor (backup automático) |
| TLS e certificado | — (HTTP interno) | **Aluno** (Caddy) | Provedor |
| Aplicação, dependências, imagem | **Aluno** | **Aluno** | **Aluno** |
| Contas, senhas, permissões, dados | **Aluno** | **Aluno** | **Aluno** |
| Conformidade LGPD (finalidade, acesso, retenção) | Órgão + aluno | Órgão + aluno | Órgão + aluno |

Quanto mais acima no modelo, menos camadas o aluno opera, e menos controle
tem (onde fica o dado, quando atualiza).

## Custo estimado

Estimativa para o perfil do projeto (uma instância pequena da aplicação,
PostgreSQL com menos de 1 GB, acesso de poucas pessoas). Os preços mudam:
confira na calculadora do provedor antes de decidir e registre a data.

| Opção | Componentes | Custo mensal estimado |
| --- | --- | --- |
| IaaS: AWS EC2 `t4g.small` + disco 20 GB, Compose como no servidor | 1 VM (aplicação + banco + Caddy) | ~US$ 14 sob demanda em `us-east-1` (mais em São Paulo); a camada gratuita da AWS cobre instâncias `micro` por tempo limitado |
| IaaS: Oracle Cloud "Always Free" (Ampere A1) | 1 VM ARM | US$ 0, dentro dos limites gratuitos |
| PaaS: Google Cloud Run + Neon (Postgres gerenciado) | Contêiner sob demanda + banco | US$ 0 na faixa gratuita com pouco tráfego; poucos dólares se passar |
| PaaS: Render (web service + Postgres) | 2 serviços | ~US$ 7 + ~US$ 6 nos planos pagos menores |

Calculadoras: [AWS Pricing Calculator](https://calculator.aws/),
[Google Cloud Pricing Calculator](https://cloud.google.com/products/calculator),
[Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/).
Preços conferidos em: **[preencher data]**.

## A conta, com segurança (S5_16, itens 4 e 5)

Exemplo na AWS (os outros provedores têm os mesmos passos com outros nomes):

1. Criar a conta (AWS Educate/Free Tier, ou GitHub Student Developer Pack
   para créditos). **[preencher: provedor, data]**
2. **MFA na conta principal (root)**: IAM → Security credentials → Assign MFA
   device → aplicativo autenticador. **[preencher: print sem o QR code]**
3. **Alerta de gastos**: Billing → Budgets → Create budget → Zero spend budget
   (avisa no primeiro centavo) e um de US$ 5. **[preencher: print]**
4. **Usuário com permissão mínima** em vez da conta principal: IAM Identity
   Center (ou IAM → Users) → usuário `trab02-deploy`, com só o que o projeto
   usa (por exemplo `AmazonEC2FullAccess` restrito à região, ou o papel do
   Cloud Run no Google: `roles/run.developer` + `roles/iam.serviceAccountUser`),
   com MFA. A conta principal fica guardada e não é usada no dia a dia.
   **[preencher: print das permissões]**

## Publicar (S5_17)

### A imagem no GHCR

Já automatizado: a tag `v1.0.0` publica
`ghcr.io/heluiz/trab02_2026_2_12621cbs200:1.0.0` ([CI-CD.md](CI-CD.md)).

### Máquina virtual ou serviço gerenciado

Escolha recomendada: **Cloud Run (PaaS) + Postgres gerenciado**. Motivos: o
certificado HTTPS e as atualizações do sistema ficam com o provedor (menos
camadas para errar, veja a tabela de responsabilidades); a imagem é a mesma do
servidor; escala a zero quando ninguém usa (custo perto de zero). A VM só
compensa se for preciso o `compose.web.yaml` inteiro (Caddy próprio, monitor)
ou controle total do sistema.

### Roteiro: Google Cloud Run

```bash
gcloud auth login
gcloud config set project SEU_PROJETO
gcloud config set run/region southamerica-east1     # São Paulo: dado no Brasil
# Banco: crie um Postgres gerenciado (Neon ou Cloud SQL) e anote a URL.
# Segredos (nunca em variável comum):
printf '%s' "$(python -c 'import secrets;print(secrets.token_urlsafe(50))')" | \
  gcloud secrets create sentinel-secret-key --data-file=-
printf '%s' 'SENHA_DO_BANCO' | gcloud secrets create sentinel-db-password --data-file=-
gcloud run deploy sentinel \
  --image ghcr.io/heluiz/trab02_2026_2_12621cbs200:1.0.0 \
  --port 8000 --allow-unauthenticated \
  --set-env-vars DJANGO_DEBUG=0,DJANGO_HTTPS=1,TRUST_PROXY=1,DJANGO_REQUIRE_MFA=1,POSTGRES_HOST=HOST_DO_BANCO,POSTGRES_DB=sentinel,POSTGRES_USER=sentinel_app,DJANGO_ALLOWED_HOSTS=.run.app \
  --set-secrets DJANGO_SECRET_KEY=sentinel-secret-key:latest,POSTGRES_PASSWORD=sentinel-db-password:latest
```

O Cloud Run usa direto imagens públicas do GHCR (o pacote precisa estar
público, veja [CI-CD.md](CI-CD.md)); para imagem privada, um repositório
remoto do Artifact Registry apontando para o `ghcr.io`.

As migrações e a conta inicial: um Cloud Run Job com a mesma imagem e
`python manage.py bootstrap`, com o usuário proprietário do banco.

Verificar: abrir a URL `https://sentinel-xxxx.run.app` (cadeado, certificado
do Google), `curl -I` para ver o HSTS, e os logs em **Cloud Run → sentinel →
Logs** (ou `gcloud run services logs read sentinel`). **[preencher: URL,
print do cadeado e dos logs]**

### Encerrar e conferir a cobrança

```bash
gcloud run services delete sentinel
gcloud run jobs delete sentinel-bootstrap
gcloud secrets delete sentinel-secret-key
gcloud secrets delete sentinel-db-password
# e o banco no painel do provedor
```

Depois: Billing → Reports do mês, e o orçamento sem alerta disparado.
**[preencher: print da fatura zerada]**

## Onde ficam os dados e a LGPD

O inventário tem nomes de setores, de responsáveis (custodiante) e
vulnerabilidades de sistemas de um órgão público: um vazamento ajuda quem quer
atacar esses sistemas. Pontos a decidir antes de levar para a nuvem:

- **Localização**: a LGPD permite transferência internacional (art. 33) só nas
  hipóteses da lei (país com proteção adequada, cláusulas-padrão aprovadas
  pela ANPD, etc.). Preferir a região **São Paulo** (`sa-east-1`,
  `southamerica-east1`, `brazilsouth`) evita a discussão.
- **Papéis**: o órgão é o controlador; o provedor de nuvem é operador, e o
  contrato (termos do provedor) precisa prever as obrigações do art. 39.
- **Minimização**: o custodiante pode ser o setor, não a pessoa.
- **Segurança (art. 46)**: cifra em trânsito (HTTPS) e em repouso (disco do
  provedor), segundo fator, menor privilégio, backup e registro de acesso, que
  o SENTINEL já tem ou que o provedor oferece.
- **Retenção e exclusão**: definir por quanto tempo o histórico fica e
  apagar os recursos e os backups ao encerrar.
- Dados de segurança pública podem ter regra própria do órgão, que prevalece.
