# Inicialização local no Windows — correção de 11/11/2026

O pacote anterior continha o código e um copiador; abrir a URL não instalava nem iniciava a aplicação. A execução local também tinha um defeito: usava Gunicorn sem o proxy de arquivos estáticos, então CSS e JavaScript retornavam 404. A orientação de apenas executar `up -d app` era insuficiente para a primeira configuração.

## Abrir pela primeira vez

1. Instale e abra [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/), configurado para containers Linux. Conclua eventuais etapas de WSL/reinício solicitadas pelo próprio Docker.
2. Extraia **todo** o ZIP atualizado. Execute `INSTALAR-OU-ATUALIZAR.cmd` na pasta `SENTINEL-PACOTE`.
3. O copiador cria `C:\Projetos\SENTINEL`. Se encontrar uma instalação anterior reconhecida, guarda os arquivos de código substituídos em uma pasta de backup vizinha; preserva `.env`, dados e metadados Git existentes. As alterações de código aparecerão como mudanças locais no Git anterior.
4. O iniciador confere Docker/Compose, cria segredos apenas em uma instalação nova, constrói as imagens, aguarda o PostgreSQL, executa migrações e prepara os grupos.
5. Sem administrador ativo, pede que você crie seu usuário e senha. Os caracteres da senha não aparecem durante a digitação. O mínimo é 12 caracteres.
6. Se o inventário estiver vazio, pergunta se deseja importar dados fictícios. É possível iniciar sem eles.
7. Após conferir login, saúde e CSS/JS, abre o navegador em `http://127.0.0.1:8000/`.

Nas próximas vezes, abra o Docker Desktop e execute `C:\Projetos\SENTINEL\ABRIR-SENTINEL.cmd`. O script não cria outra conta quando já existe administrador ativo e não reimporta os exemplos em um inventário preenchido.

**Use Edge/Chrome do mesmo computador Windows em que o Docker está rodando.** `127.0.0.1` aponta para a máquina onde o navegador está executando; no celular ou em um navegador remoto não aponta para o seu Windows. O serviço local está ligado somente ao endereço de loopback. Não está publicado na internet.

Se houver erro, execute `VERIFICAR-SENTINEL.cmd` na pasta do projeto e envie a mensagem ou captura da janela. Ele verifica a presença da configuração sem mostrar os valores de senha, os containers e a resposta HTTP. Não envie `.env` ou credenciais.

## Proteção de uma instalação existente

- O iniciador não substitui um `.env` já existente nem apaga volumes Docker.
- Se existir volume de dados sem `.env`, a execução para e solicita recuperar a configuração original; gerar outra senha não recuperaria esse banco.
- Falhas no build, migração ou HTTP interrompem o processo. O navegador só é aberto após as verificações.
- Um conflito na porta 8000 não provoca encerramento de processos de terceiros.
- Os CMD usam uma política de execução apenas para o processo do PowerShell iniciado; não mudam permanentemente a política do Windows.

## Mudança técnica

`compose.web.local.yaml` passa a usar `manage.py runserver --noreload` com DEBUG local, hosts locais e confiança em proxy desativada. A porta publicada continua `127.0.0.1:8000`. É uma configuração de desenvolvimento; produção continua com Gunicorn, HTTPS e proxy de estáticos.

Também foram corrigidos R01 e R02 da revisão de sprints: dashboard/exportação completa exigem as quatro permissões de leitura, e GET das coleções REST aceita `limit` (1–100) e `offset` (0–2147483647), retornando `count` e `next_offset`. Exemplos: `/api/dependency/?limit=100&offset=0` e `?limit=100&offset=100`. A ordenação é por ID; não é um snapshot imutável entre requisições concorrentes.

## Verificação e limites

- HTTP com PostgreSQL real: configuração anterior retornou 200 em saúde/login e 404 nos três arquivos CSS/JS conferidos; configuração corrigida retornou 200 em todos os cinco endereços.
- 115 testes originais e 69 testes web/didáticos passaram; estes incluem 12 novos casos de permissões e paginação. Cobertura agregada de `inventory` + `academic`: 85%.
- PowerShell: sintaxe conferida e cenários de orquestração com Docker/HTTP simulados executados no Linux. Isso não equivale a testar Docker Desktop ou Windows PowerShell 5.1 no computador do usuário.
- Docker não está instalado no ambiente conectado desta conversa. O build e a execução real do Compose no Windows permanecem pendentes, assim como as demais pendências acadêmicas da revisão.
- Não houve push, publicação ou implantação remota. O banco do computador do usuário não foi acessado.
