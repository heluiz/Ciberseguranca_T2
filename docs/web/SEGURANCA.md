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
| Rede interna sem certificado (servidor da disciplina) | Perfil próprio com `DJANGO_HTTPS=0` explícito; lista de hosts aceitos; cookies `HttpOnly` e `SameSite`; demais controles ativos | Tráfego sem criptografia: aceitável só em rede interna; na internet usar `compose.web.yaml` |
| App → PostgreSQL | Papel runtime sem DDL/superusuário; migração separada | Configuração Compose; validar privilégios na implantação |
| Operador → segredos | Ambiente externo, exclusão de build/Git, MFA arquivo privado | Revisão operacional e cofre |
| Falha de serviço → perda | Health, restart, rotação de logs, dump/restauração | Exercício de restauração; 24h ainda pendente |
| Colega com acesso ao banco → auditoria | Eventos sem conteúdo sensível, tela somente leitura | Não resiste ao DBA; armazenamento externo futuro |
| Script → API v1 | JWT HS256 de 15 min com algoritmo, emissor e público fixos; chave de API guardada como SHA-256; papel conferido em cada rota; sem cookie (sem CSRF) | `tests_web/test_api_v1.py` (tokens vencido, adulterado, de outro segredo, `alg: none`; matriz; IDOR); Schemathesis no CI |
| Entrada da API → banco | Tipos do JSON conferidos, campo desconhecido recusado, caracteres de controle recusados, ORM com parâmetros | `tests_web/test_sqli_e_consultas.py`; laboratório em `academic/sqli_lab.py` |
| Imagem → servidor | Base atualizada na construção (`apt-get upgrade`), pip removido, Trivy no CI | Varredura antes/depois em [HARDENING.md](../HARDENING.md) |

Não há varredura de redes, execução de comandos fornecidos por usuários ou requisições a destinos arbitrários. A consulta CVE web é offline. O sistema registra relações declaradas, sem afirmar descoberta de ativos ou exploração.

LGPD: minimizar identificação pessoal, definir finalidade, base legal aplicável, retenção, responsáveis pelo acesso e exclusão. A faculdade/organização deve avaliar o uso concreto; estes controles técnicos não substituem essa análise.

Referências primárias consultadas: [Django deployment checklist](https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/), [Django transactions](https://docs.djangoproject.com/en/5.2/topics/db/transactions/), [Axes](https://django-axes.readthedocs.io/en/latest/3_usage.html), [django-otp](https://django-otp-official.readthedocs.io/en/stable/auth.html), [OWASP ASVS](https://asvs.owasp.org/), [Cosmic Python Repository](https://www.cosmicpython.com/book/chapter_02_repository.html) e [Service Layer](https://www.cosmicpython.com/book/chapter_04_service_layer.html).

Sprint 5: a análise pelo OWASP Top 10:2025, com os achados priorizados por CVSS, está em [OWASP-TOP10.md](../OWASP-TOP10.md); o modelo STRIDE por fluxo, em [ARQUITETURA.md](../ARQUITETURA.md); senhas, permissões e cookies, em [SENHAS-E-ACESSO.md](../SENHAS-E-ACESSO.md); TLS, em [TLS.md](../TLS.md).
