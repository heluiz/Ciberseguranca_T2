# Modelo de ameaças e verificações selecionadas

Não é auditoria independente nem certificação ASVS. Objetivo de engenharia: controles selecionados do ASVS nível 2, proporcionais ao projeto acadêmico.

| Fronteira / ameaça | Controle implementado | Evidência ou ação necessária |
|---|---|---|
| Internet → sessão, força bruta | Axes, senha Argon2, MFA administrativo em produção | Testes de bloqueio e TOTP real |
| Navegador → alteração indevida | CSRF, POST/PATCH/DELETE, grupos e lista explícita de campos | Testes negativos de Leitor e atribuição indevida |
| Inventário → HTML/JS | Escape de templates, `textContent`, CSP local | Teste XSS e verificação no navegador |
| Usuários simultâneos → integridade | Transações, trava, versões, unicidade/FKs/checks/trigger | Teste concorrente real em PostgreSQL |
| JSON → banco | Limites, validação do domínio, base vazia, importação atômica | Round-trip e risco equivalente |
| Proxy → aplicação | Rede interna, cabeçalho substituído por proxy dedicado | Exige validação no servidor real |
| App → PostgreSQL | Papel runtime sem DDL/superusuário; migração separada | Configuração Compose; validar privilégios na implantação |
| Operador → segredos | Ambiente externo, exclusão de build/Git, MFA arquivo privado | Revisão operacional e cofre |
| Falha de serviço → perda | Health, restart, rotação de logs, dump/restauração | Exercício de restauração; 24h ainda pendente |
| Colega com acesso ao banco → auditoria | Eventos sem conteúdo sensível, tela somente leitura | Não resiste ao DBA; armazenamento externo futuro |

Não há varredura de redes, execução de comandos fornecidos por usuários ou requisições a destinos arbitrários. A consulta CVE web é offline. O sistema registra relações declaradas, sem afirmar descoberta de ativos ou exploração.

LGPD: minimizar identificação pessoal, definir finalidade, base legal aplicável, retenção, responsáveis pelo acesso e exclusão. A faculdade/organização deve avaliar o uso concreto; estes controles técnicos não substituem essa análise.

Referências primárias consultadas: [Django deployment checklist](https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/), [Django transactions](https://docs.djangoproject.com/en/5.2/topics/db/transactions/), [Axes](https://django-axes.readthedocs.io/en/latest/3_usage.html), [django-otp](https://django-otp-official.readthedocs.io/en/stable/auth.html), [OWASP ASVS](https://asvs.owasp.org/), [Cosmic Python Repository](https://www.cosmicpython.com/book/chapter_02_repository.html) e [Service Layer](https://www.cosmicpython.com/book/chapter_04_service_layer.html).
