# HTTPS e TLS: laboratório com proxy reverso

Card S5_11. Três perfis, três situações:

| Perfil | TLS | Por quê |
| --- | --- | --- |
| Servidor da disciplina (`compose.servidor.yaml`, porta 2200) | Não (HTTP) | Rede interna da UFU, uma porta só, sem nome nem certificado; achado registrado em [OWASP-TOP10.md](OWASP-TOP10.md) |
| **Laboratório** (`compose.servidor.yaml` + `compose.tls.yaml`) | Sim, certificado de uma CA local (Caddy `tls internal`) | Este documento: proxy reverso com TLS no seu computador |
| Internet (`compose.web.yaml`) | Sim, certificado público automático (Let's Encrypt pelo Caddy) | Exige um domínio apontando para a máquina |

## 1. O certificado de um site no navegador

No Chrome ou Edge: cadeado (ou ícone de configurações) ao lado do endereço →
**A conexão é segura** → **O certificado é válido**. Anote:

- **Emitido para** (o nome no campo *Subject Alternative Name*);
- **Emitido por** (a autoridade intermediária) e a cadeia até a **raiz**, que
  vem instalada no sistema;
- **Validade** (de/até).

Exemplo em `https://www.ufu.br`: **[preencher: emissor, validade e cadeia,
com print]**.

## 2. Subir o laboratório

```powershell
cd C:\Projetos\SENTINEL
docker compose -f compose.servidor.yaml -f compose.tls.yaml up -d --build
docker compose -f compose.servidor.yaml -f compose.tls.yaml exec app python manage.py createsuperuser
```

No Windows, usa o `.env` criado pelo `ABRIR-SENTINEL.cmd` (rode-o uma vez
antes); no Linux, o criado por `sh ops/servidor/subir.sh` (que já traz a conta
inicial, e o segundo comando fica dispensado). O `compose.tls.yaml`:

- acrescenta o serviço `proxy` (Caddy, `trab02_2026_2_12621cbs200_proxy`),
  só em `127.0.0.1:8080` (HTTP) e `127.0.0.1:8443` (HTTPS);
- tira a porta própria da aplicação (`ports: !reset []`): só se chega a ela
  pelo proxy;
- liga `DJANGO_HTTPS=1` e `TRUST_PROXY=1` na aplicação: cookies `Secure`, HSTS
  e redirecionamento, confiando no `X-Forwarded-Proto` que o proxy põe.

O `ops/Caddyfile.lab`:

```text
http://localhost:8080, http://127.0.0.1:8080 {
	redir https://{host}:8443{uri} permanent
}
https://localhost:8443, https://127.0.0.1:8443 {
	tls internal
	reverse_proxy app:8000 {
		header_up X-Forwarded-Proto https
	}
}
```

`tls internal` faz o Caddy criar uma autoridade certificadora própria e emitir
com ela o certificado de `localhost` (validade curta, renovado sozinho). Para
o navegador, é como um certificado autoassinado.

Abrir `https://localhost:8443`. O navegador alerta (item 6); para o
laboratório, **Avançado** → **Continuar**.

### Certificado autoassinado com openssl (alternativa)

Se quiser gerar o certificado à mão em vez da CA do Caddy:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout lab.key -out lab.crt -days 30 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
openssl x509 -in lab.crt -noout -subject -issuer -dates -ext subjectAltName
```

e no Caddyfile trocar `tls internal` por `tls /certs/lab.crt /certs/lab.key`
(montando a pasta no container). O `.key` não vai para o Git.

## 3. Redirecionamento e HSTS

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "http://localhost:8080/entrar/?x=1"
curl -sk -D - -o /dev/null https://localhost:8443/entrar/ | grep -iE "^HTTP|strict-transport|set-cookie"
```

Resultado registrado (17/11/2026):

```text
301 https://localhost:8443/entrar/?x=1
HTTP/2 200
set-cookie: csrftoken=...; Max-Age=31449600; Path=/; SameSite=Lax; Secure
strict-transport-security: max-age=31536000; includeSubDomains; preload
```

O HSTS diz ao navegador para, durante um ano, nunca mais tentar HTTP neste
nome, mesmo que alguém digite `http://` ou um atacante na rede tente rebaixar
a conexão. O cookie de sessão, depois da entrada, sai com `Secure` e
`HttpOnly`; o login pelo proxy funciona com a verificação de CSRF (a origem é
`https://localhost:8443`).

## 4. Verificar com `openssl s_client`

```bash
echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null \
  | grep -E "Protocol|Cipher is|issuer=|Verify return"
echo | openssl s_client -connect localhost:8443 -servername localhost 2>/dev/null \
  | openssl x509 -noout -issuer -dates -ext subjectAltName
```

Resultado registrado:

```text
issuer=CN = Caddy Local Authority - ECC Intermediate
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Verify return code: 20 (unable to get local issuer certificate)
notBefore=Nov 17 23:42:36 2026 GMT
notAfter=Nov 18 11:42:36 2026 GMT
X509v3 Subject Alternative Name: critical
    DNS:localhost
```

**TLS 1.3** negociado, com AES-128-GCM. O código 20 é o mesmo motivo do alerta
do navegador: a raiz não é conhecida. Confiando na raiz do laboratório, a
verificação passa:

```bash
docker compose -f compose.servidor.yaml -f compose.tls.yaml exec -T proxy \
  cat /data/caddy/pki/authorities/local/root.crt > caddy-root.crt
echo | openssl s_client -connect localhost:8443 -servername localhost -CAfile caddy-root.crt 2>/dev/null | grep "Verify return"
# Verify return code: 0 (ok)
echo | openssl s_client -connect localhost:8443 -tls1_2 -CAfile caddy-root.crt 2>/dev/null | grep -E "Protocol  :|Cipher    :"
# Protocol  : TLSv1.2
# Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
```

Sem `-tls1_2`, o Caddy escolhe TLS 1.3; com ele, aceita TLS 1.2, só com
cifras de sigilo direto (ECDHE) e AEAD (GCM). TLS 1.0 e 1.1 não são aceitos.

## 5. Desligar

```powershell
docker compose -f compose.servidor.yaml -f compose.tls.yaml stop proxy
docker compose -f compose.servidor.yaml up -d app
```

O segundo comando devolve a porta própria da aplicação (sem o
`compose.tls.yaml`, ela volta a usar HTTP e a porta 2200).

## 6. Por que o navegador alerta

O navegador só confia num certificado se conseguir montar a cadeia até uma
**raiz** que ele já tem (as do sistema ou as do próprio navegador, mantidas
por programas de auditoria). Um certificado autoassinado, ou emitido pela CA
local do Caddy, assina a si mesmo ou a uma raiz que só existe nesta máquina:
o navegador não tem como saber se quem responde é o servidor certo ou alguém
no meio do caminho com outro certificado autoassinado. A cifra é a mesma; o
que falta é a **autenticação** do servidor. Por isso o alerta não deve ser
ignorado fora do laboratório: na internet, o `compose.web.yaml` pede um
certificado público para o domínio.
