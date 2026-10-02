# Inventário de equipamentos e vulnerabilidades - imagem do Trabalho 2.
#
# Construir:  docker build -t inventario:1.0 .
# Executar:   veja o README (docker run -dit ... ou docker compose up -d)

# Imagem oficial do Python 3.14 (em manutenção completa até 2027) sobre
# Debian 13 "trixie", na variante "slim": o Python e quase mais nada. A
# variante do Debian vai fixada no nome, como a página da imagem
# recomenda, para uma versão nova do Debian não mudar a base sem aviso.
FROM python:3.14-slim-trixie

# PYTHONUNBUFFERED: o menu aparece na hora e o "docker logs" mostra tudo.
# PYTHONDONTWRITEBYTECODE: sem arquivos .pyc na imagem.
# INVENTARIO_EM_CONTAINER: o programa avisa como sair sem derrubar o
#   container e trata Ctrl+C e "docker stop" (main.py, preparar_container).
# INVENTARIO_DADOS: onde fica o JSON, dentro do volume.
# TERM: o comando "clear" do programa precisa de um tipo de terminal.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    INVENTARIO_EM_CONTAINER=1 \
    INVENTARIO_DADOS=/app/dados/inventario.json \
    TERM=xterm

# Usuário comum, com UID e GID fixos: o programa não precisa ser root
# dentro do container (menor privilégio). O número alto (10001) fica
# longe dos usuários de verdade do servidor, que começam em 1000: um
# processo que escapasse do container não teria a identidade de
# ninguém. --no-log-init vem do exemplo da documentação do Docker; com
# UID alto, evita criar um arquivo de log enorme.
RUN groupadd --gid 10001 inventario \
    && useradd --uid 10001 --gid 10001 --no-log-init \
       --shell /usr/sbin/nologin inventario

WORKDIR /app

# As dependências vêm antes do código: enquanto o requirements.txt não
# muda, o Docker reaproveita esta camada e o build não baixa tudo de novo.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# A pasta dos dados é criada e entregue ao usuário ANTES de virar
# volume: um volume novo herda o dono da pasta da imagem. Sem isto, o
# usuário comum não conseguiria gravar o JSON.
RUN mkdir -p /app/dados && chown inventario:inventario /app/dados
VOLUME /app/dados
USER inventario

# Saudável = o arquivo de dados (se existir) está legível e válido.
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD ["python", "-c", "from armazenamento import ArquivoInventario as A; A().carregar()"]

# O processo principal é o menu: o container vive enquanto ele esperar
# o teclado. Por isso precisa de "-it" (veja o README).
CMD ["python", "main.py"]
