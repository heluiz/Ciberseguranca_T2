"""Laboratório de hash de senhas: sal, custo e por que não SHA-256.

Card S5_08. Mostra, sem tocar em nenhuma conta de verdade:

* a mesma senha gera hashes diferentes com Argon2id (o sal é aleatório
  e vai guardado dentro do próprio hash);
* SHA-256 puro é determinístico e rápido: ótimo para conferir arquivos,
  péssimo para senhas, porque quem rouba a base testa bilhões por
  segundo;
* Argon2id é lento de propósito e gasta memória, o que encarece o
  ataque por força bruta em GPU.

    python -m academic.senhas_lab

A aplicação usa o Argon2PasswordHasher do Django (settings.py), que é o
argon2-cffi por baixo, com os parâmetros recomendados pelo Django.
"""

import hashlib
import time

from argon2 import PasswordHasher

SENHA = "correcthorsebatterystaple"


def medir(funcao, vezes):
    """Devolve o tempo médio, em segundos, de uma chamada de funcao()."""
    inicio = time.perf_counter()
    for _ in range(vezes):
        funcao()
    return (time.perf_counter() - inicio) / vezes


def sha256(senha):
    """SHA-256 puro, sem sal: o que NÃO se usa para guardar senha."""
    return hashlib.sha256(senha.encode()).hexdigest()


def argon2id(senha, hasher=None):
    """Argon2id com sal aleatório (argon2-cffi)."""
    return (hasher or PasswordHasher()).hash(senha)


def tentativas_por_segundo(segundos_por_hash):
    """Quantas senhas um atacante testa por segundo neste computador."""
    return 1 / segundos_por_hash


if __name__ == "__main__":
    hasher = PasswordHasher()
    print("Mesma senha, SHA-256 duas vezes (iguais):")
    print(" ", sha256(SENHA))
    print(" ", sha256(SENHA))
    print("Mesma senha, Argon2id duas vezes (diferentes: sal aleatório):")
    primeiro, segundo = argon2id(SENHA, hasher), argon2id(SENHA, hasher)
    print(" ", primeiro)
    print(" ", segundo)
    print("  as duas conferem:", hasher.verify(primeiro, SENHA),
          hasher.verify(segundo, SENHA))

    t_sha = medir(lambda: sha256(SENHA), 100_000)
    t_argon = medir(lambda: argon2id(SENHA, hasher), 10)
    print(f"\nSHA-256:  {t_sha * 1e6:10.2f} µs por hash "
          f"-> {tentativas_por_segundo(t_sha):,.0f} tentativas/s")
    print(f"Argon2id: {t_argon * 1e3:10.2f} ms por hash "
          f"-> {tentativas_por_segundo(t_argon):,.0f} tentativas/s")
    print(f"Argon2id é {t_argon / t_sha:,.0f} vezes mais lento por senha.")
