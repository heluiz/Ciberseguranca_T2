"""Registro de disponibilidade da aplicação web.

Consulta /health/ a cada intervalo e anota o resultado.

Uso: python ops/monitor.py http://app:8000/health/ [segundos]

Cada linha traz data e hora (UTC), situação e tempo de resposta. A
saída vai para o log do container (docker compose logs monitor), que
tem rotação.
"""

import sys
import time
import urllib.request
from datetime import datetime, timezone


def check(url):
    """Devolve (ok, detalhe) de uma consulta ao endereço de saúde."""
    start = time.monotonic()
    try:
        request = urllib.request.Request(url, headers={"Host": "localhost"})
        with urllib.request.urlopen(request, timeout=10) as response:
            ok = response.status == 200
            detail = f"HTTP {response.status}"
    except Exception as error:  # qualquer falha conta como indisponível
        ok, detail = False, type(error).__name__
    elapsed = (time.monotonic() - start) * 1000
    return ok, f"{detail} {elapsed:.0f}ms"


def main():
    """Repete a verificação até o processo ser encerrado."""
    url = sys.argv[1]
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    total = failures = 0
    while True:
        ok, detail = check(url)
        total += 1
        failures += not ok
        moment = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        status = "DISPONIVEL" if ok else "INDISPONIVEL"
        print(
            f"{moment} {status} {detail} "
            f"verificacoes={total} falhas={failures}",
            flush=True,
        )
        time.sleep(interval)


if __name__ == "__main__":
    main()
