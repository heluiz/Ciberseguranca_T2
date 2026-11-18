# Senhas, sessões e controle de acesso

Cards S5_08 e S5_10. Testes em `tests_web/test_senhas.py` e
`tests_web/test_api_v1.py` (matriz de permissões).

## Política de senha

Baseada no NIST SP 800-63B (Digital Identity Guidelines, seção 5.1.1):

| Regra | Como está | Onde |
| --- | --- | --- |
| Comprimento mínimo de 12 caracteres | Recusa abaixo disso | `MinimumLengthValidator` (`settings.py`) |
| Aceita frases longas, espaços e qualquer caractere | Sem limite artificial de símbolos; até 4.096 caracteres na API | `validate_password` |
| **Sem** regra de composição (maiúscula + número + símbolo) | O NIST desaconselha: leva a `Senha@123` | (proposital) |
| **Sem** troca periódica obrigatória | Troca só quando houver suspeita de vazamento | (proposital) |
| Recusa senha comum ou vazada | Lista de 20 mil senhas comuns do Django | `CommonPasswordValidator` |
| Recusa senha só de números | | `NumericPasswordValidator` |
| Recusa senha parecida com o usuário ou o e-mail | | `UserAttributeSimilarityValidator` |
| Limita tentativas | 5 erros → 15 minutos de bloqueio por IP e por usuário + IP | django-axes |
| Segundo fator para administrador | TOTP (aplicativo autenticador), exigido também no token da API | django-otp |
| Senha nunca em log, resposta ou auditoria | Conferido por teste | `test_passwords_never_reach_logs_or_responses`, `test_hash_nunca_aparece_em_resposta` |

O teste `test_politica_aceita_frase_longa_sem_regra_de_composicao` garante que
`cavalo correto bateria grampo` é aceita, e `test_politica_recusa` que
`curta1`, `123456789012345`, `password1234` e uma senha igual ao nome da conta
são recusadas.

## Armazenamento: Argon2id

`PASSWORD_HASHERS` começa pelo `Argon2PasswordHasher` (argon2-cffi): Argon2id,
vencedor da Password Hashing Competition, lento e caro em memória de propósito.
O PBKDF2 fica em segundo só para ler hashes antigos.

```text
argon2$argon2id$v=19$m=102400,t=2,p=8$<sal aleatório>$<hash>
```

O hash guarda o algoritmo, os parâmetros e o sal: a mesma senha dá hashes
diferentes, e o sistema sabe conferir cada um.

### Sal e custo (laboratório)

```bash
python -m academic.senhas_lab
```

Saída registrada (notebook do desenvolvimento, Python 3.13):

| | SHA-256 puro | Argon2id (parâmetros do Django) |
| --- | --- | --- |
| Mesma senha duas vezes | mesmo hash | hashes diferentes (sal) |
| Tempo por hash | 0,36 µs | 115 ms |
| Tentativas por segundo, 1 núcleo | ~2,8 milhões | ~9 |

Argon2id é ~320 mil vezes mais lento por tentativa, e cada uma ocupa 100 MiB
de memória, o que tira a vantagem das GPUs. Para quem entra com a senha certa,
115 ms não se nota; para quem testa um dicionário de 10 milhões de senhas
roubadas, é a diferença entre 4 segundos e 13 dias por conta.

### Recálculo do hash

O Django confere `must_update()` a cada entrada certa:

- conta com hash PBKDF2 (antigo) passa a Argon2id no próximo login
  (`test_hash_antigo_e_recalculado_no_proximo_login`);
- se o projeto aumentar o custo do Argon2 (`time_cost`), o hash de cada conta é
  refeito com os parâmetros novos no próximo login
  (`test_parametros_novos_recalculam_o_hash`).

Ninguém precisa trocar a senha para o armazenamento melhorar.

## Papéis e matriz de permissões

Três grupos, criados por `python manage.py setup_roles`:

| Ação | Leitor | Analista | Administrador |
| --- | :---: | :---: | :---: |
| Ver inventário, vulnerabilidades, tratamentos, dependências, risco, mapa, relatórios | ✓ | ✓ | ✓ |
| Cadastrar, alterar e excluir ativos, vulnerabilidades, tratamentos, dependências | | ✓ | ✓ |
| Importar o JSON | | | ✓ (conta de superusuário) |
| Exportar o JSON | ✓ | ✓ | ✓ |
| Ver a auditoria (tela e `/api/v1/audit-events`) | | | ✓ |
| Criar contas, grupos e chaves de API | | | ✓ (`manage.py`) |
| Sem grupo (conta criada e não incluída) | tela "Acesso restrito", API 403 | | |

A permissão é conferida **no backend**, em cada view e em cada rota da API
(`authorize(user, "change_asset")`), nunca só escondendo o botão. A rota
administrativa da API exige, além da permissão, o papel `Administrador` no
token (`test_admin_route_needs_role_in_token_even_with_permission`). Toda
recusa vira um evento `denied` na auditoria.

Testes: `test_permission_matrix` percorre a matriz (Leitor, Analista,
Administrador e sem grupo, leitura, escrita e auditoria) e confere 200/201 ou
403 com o evento de auditoria.

### IDOR (trocar o número na URL)

Os registros do inventário são do órgão, não de uma pessoa: não há "registro
do outro usuário". O que se testa é que trocar o id na URL não dá mais do que o
perfil permite: o Leitor que manda `PATCH` ou `DELETE` para
`/api/v1/assets/<id de um ativo criado por um Analista>` recebe 403 e nada muda
(`test_reader_cannot_change_other_records_by_id`). Id inexistente dá 404, sem
dizer se existiu.

## Cookies e sessão

| Atributo | Valor | Para quê |
| --- | --- | --- |
| `HttpOnly` | sim | JavaScript (inclusive um XSS) não lê o cookie de sessão |
| `SameSite` | `Lax` | O navegador não manda o cookie em POST vindo de outro site |
| `Secure` | sim com HTTPS (`DJANGO_HTTPS=1`) | O cookie só viaja cifrado |
| Validade | 1 hora, renovada a cada pedido (`SESSION_SAVE_EVERY_REQUEST`) | Sessão esquecida aberta expira |
| Sessão nova no login | sim (Django troca a chave) | Impede fixação de sessão |
| CSRF | token por formulário + cookie `csrftoken` (`Secure` com HTTPS) | Segunda barreira contra CSRF |
| `X-Frame-Options` | `DENY` | Impede clickjacking |

Teste: `test_cookie_de_sessao_httponly_samesite_e_validade` entra pelo
formulário e confere os atributos do `Set-Cookie`.

No servidor da disciplina o acesso é por HTTP (rede interna, sem certificado):
o `Secure` fica desligado lá de propósito, senão o navegador não devolveria o
cookie. No perfil com HTTPS (`compose.web.yaml`) ele liga sozinho, junto com o
HSTS.

### Como o SameSite reduz o CSRF

No CSRF, um site malicioso faz o navegador da vítima mandar um formulário para
o SENTINEL; o navegador anexaria o cookie de sessão e o pedido sairia
"autenticado". Com `SameSite=Lax`, o navegador só manda o cookie em navegação
de nível superior com método seguro (clicar num link, GET); num POST, PUT ou
DELETE iniciado por outro site, o cookie não vai, e o pedido chega sem sessão.
Continua havendo o token CSRF em cada formulário, porque o `SameSite` depende
do navegador e não cobre subdomínios do mesmo site.

A API v1 não usa cookie: autentica pelo cabeçalho `Authorization` ou
`X-API-Key`, que o navegador nunca anexa sozinho. Por isso ela dispensa o
token CSRF (e recusa o cookie de sessão: `test_wrong_method_unknown_resource_and_no_csrf_needed`).
