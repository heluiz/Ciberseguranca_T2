# Fluxo de ramificação, versões e CHANGELOG

Card S5_13.

## O fluxo escolhido: Git Flow simplificado

| Ramo | Para quê | Quem escreve |
| --- | --- | --- |
| `main` | O que foi entregue; cada versão é uma tag `vX.Y.Z` | Só por pull request, com a verificação verde |
| `develop` | Integração do que vai para a próxima versão | Por pull request dos ramos de funcionalidade |
| `feature/<nome>` | Uma funcionalidade | Sai de `develop`, volta para `develop` |
| `fix/<nome>`, `docs/<nome>` | Correção ou documentação comum | Idem |
| `hotfix/<nome>` | Correção urgente do que já foi entregue | Sai de `main`, volta para `main` **e** `develop` |

Por que este e não o GitHub Flow puro (só `main` + ramos curtos): o trabalho
tem entregas com data (as sprints) e uma versão "oficial" que o docente avalia
e que roda no servidor. Com `develop`, a `main` fica sempre igual ao que foi
entregue e implantado, e o trabalho da sprint seguinte não a mexe até estar
pronto. Por que não o Git Flow completo (com `release/*`): uma pessoa só no
projeto; a tag na `main` faz o papel do ramo de release.

Até a Sprint 4 o repositório usou ramos de funcionalidade direto para a
`main` (pull requests #1 a #15, nomes `feature/`, `fix/`, `docs/`, `ci/`).

## Criar o `develop` e proteger a `main`

```powershell
cd C:\Projetos\SENTINEL
git switch main
git pull
git switch -c develop
git push -u origin develop
```

No GitHub: **Settings** → **Branches** → **Add branch ruleset** (ou **Add
rule**):

- Branch name pattern: `main`
- **Require a pull request before merging** (marque **Dismiss stale
  approvals** se tiver revisor)
- **Require status checks to pass**: marque `web`, `container` e
  `estilo-e-testes` (aparecem depois da primeira execução)
- **Block force pushes** e **Restrict deletions**

Repita para `develop` (pull request e verificação, sem exigir revisão). Em
**Settings → General**, deixe **Default branch** = `develop` se quiser que os
pull requests novos apontem para ele.

## Uma funcionalidade por pull request

```powershell
git switch develop
git pull
git switch -c feature/NOME
# ... trabalho, commits pequenos ...
git push -u origin feature/NOME
```

Abra o endereço que o `git push` mostra → **Create pull request** com base
`develop` → espere a verificação ficar verde → **Merge pull request**.

## Publicar a versão entregue (v1.0.0)

```powershell
git switch develop
git pull
# Pull request develop -> main no GitHub, verificação verde, merge. Depois:
git switch main
git pull
git tag -a v1.0.0 -m "Trabalho 02 entregue"
git push origin v1.0.0
```

A tag dispara o job `publicar` (imagens no GHCR). Release: **Releases** →
**Draft a new release** → **Choose a tag** `v1.0.0` → título `v1.0.0` → cole a
seção `[1.0.0]` do `CHANGELOG.md` → **Publish release**.

## Correção urgente (hotfix) e v1.0.1

Simulação: um erro achado depois da entrega.

```powershell
git switch main
git pull
git switch -c hotfix/NOME
# ... correção + teste que reproduz o erro ...
# CHANGELOG.md: nova seção "## [1.0.1] - AAAA-MM-DD" com "### Corrigido"
git commit -am "Corrige ..."
git push -u origin hotfix/NOME
# Pull request hotfix/NOME -> main, merge. Depois:
git switch main
git pull
git tag -a v1.0.1 -m "Correção: ..."
git push origin v1.0.1
# Leva a correção para o develop também:
git switch develop
git pull
git merge main
git push
```

## CHANGELOG

`CHANGELOG.md`, no formato Keep a Changelog: cada versão com data e as seções
**Adicionado**, **Alterado**, **Corrigido**, **Removido** e **Segurança**. O
que ainda não foi publicado fica em **[Não publicado]**; ao criar a tag, a seção
vira `[X.Y.Z] - data`. A versão segue o Versionamento Semântico: CORREÇÃO para
conserto sem mudar a interface, MENOR para funcionalidade nova compatível,
MAIOR quando quebra quem usa (por exemplo, mudar o formato da API v1, que
viraria `/api/v2`).
