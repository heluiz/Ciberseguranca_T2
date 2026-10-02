# Inventário de equipamentos e vulnerabilidades - imagem do Trabalho 2.
#
# Construir:  docker build -t inventario:1.0 .
# Executar:   veja o README (docker run -dit ... ou docker compose up -d)

# Python 3.12 em Debian "slim": traz o Python e quase mais nada.
FROM python:3.12-slim

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

# Usuário comum: o programa não precisa ser root dentro do container.
RUN useradd --create-home --shell /usr/sbin/nologin inventario

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
