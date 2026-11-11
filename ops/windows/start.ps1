param([switch]$DiagnosticOnly)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$composeFiles = @('compose', '-f', 'compose.web.yaml', '-f', 'compose.web.local.yaml')
$step = 'verificar os arquivos'

function Invoke-Compose {
    param([string[]]$Arguments)
    & docker @composeFiles @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ('O Docker retornou erro na etapa: ' + $script:step + '. Confira a mensagem acima.')
    }
}

function Read-Compose {
    param([string[]]$Arguments)
    $output = @(& docker @composeFiles @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw ('O Docker retornou erro na etapa: ' + $script:step + '.')
    }
    return ($output -join "`n")
}

function New-LocalSecret {
    $bytes = New-Object byte[] 64
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Read-LocalEnvironment {
    $values = @{}
    foreach ($line in Get-Content -LiteralPath '.env') {
        if ($line -match '^\s*([A-Z_]+)\s*=(.*)$') {
            $values[$matches[1]] = $matches[2].Trim().Trim('"').Trim("'")
        }
    }
    return $values
}

function Test-LocalPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 8000)
    try {
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        $listener.Stop()
    }
}

try {
    Set-Location -LiteralPath $projectRoot
    Write-Host 'SENTINEL - inicializacao local no Windows' -ForegroundColor Cyan
    Write-Host ('Pasta: ' + $projectRoot)
    if (-not (Test-Path -LiteralPath 'manage.py') -or -not (Test-Path -LiteralPath 'compose.web.local.yaml')) {
        throw 'Extraia o pacote completo. Os arquivos do projeto nao foram encontrados.'
    }
    $step = 'verificar Docker Desktop'
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker nao encontrado. Instale Docker Desktop pelo site https://docs.docker.com/desktop/setup/install/windows-install/ e abra-o. Depois execute ABRIR-SENTINEL.cmd novamente.'
    }
    # O formato selecionado evita imprimir nomes de contas, configuracoes ou segredos.
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $engine = @(& docker info --format '{{.OSType}}' 2>$null)
        $engineExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($engineExit -ne 0) {
        throw 'Docker Desktop nao esta pronto. Abra-o e espere o mecanismo iniciar. Se ele solicitar WSL ou reinicio, conclua a configuracao antes de repetir.'
    }
    if (($engine -join '').Trim() -ne 'linux') {
        throw 'O Docker esta usando containers Windows. Selecione containers Linux no Docker Desktop e tente novamente.'
    }
    & docker compose version
    if ($LASTEXITCODE -ne 0) { throw 'Docker Compose nao foi encontrado. Atualize ou repare a instalacao do Docker Desktop.' }
    Write-Host 'Docker: disponivel, containers Linux.' -ForegroundColor Green

    if ($DiagnosticOnly) {
        Write-Host ('Arquivo .env presente: ' + (Test-Path -LiteralPath '.env'))
        if (Test-Path -LiteralPath '.env') {
            $values = Read-LocalEnvironment
            foreach ($key in @('DJANGO_SECRET_KEY', 'POSTGRES_OWNER_PASSWORD', 'POSTGRES_PASSWORD')) {
                Write-Host ($key + ': ' + $(if ([string]::IsNullOrWhiteSpace($values[$key])) { 'ausente/vazio' } else { 'preenchido (valor oculto)' }))
            }
            if (-not [string]::IsNullOrWhiteSpace($values['DJANGO_SECRET_KEY']) -and
                -not [string]::IsNullOrWhiteSpace($values['POSTGRES_OWNER_PASSWORD']) -and
                -not [string]::IsNullOrWhiteSpace($values['POSTGRES_PASSWORD'])) {
                Invoke-Compose -Arguments @('ps', '-a')
            }
        }
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/health/' -TimeoutSec 5
            Write-Host ('HTTP /health/: ' + $response.StatusCode)
        } catch { Write-Host 'HTTP /health/: indisponivel.' }
        Write-Host 'Diagnostico encerrado. Nenhuma configuracao ou banco foi alterado.'
        exit 0
    }

    $step = 'configurar o ambiente local'
    if (-not (Test-Path -LiteralPath '.env')) {
        $volumes = @(& docker volume ls --format '{{.Name}}')
        if ($LASTEXITCODE -ne 0) { throw 'Nao foi possivel conferir os volumes existentes. Nenhum segredo foi criado.' }
        if ($volumes -contains 'sentinel-web_postgres-data') {
            throw 'Existe um banco SENTINEL, mas falta o arquivo .env. Recupere o .env original. Nao apague o volume: ele pode conter seus dados.'
        }
        @(
            ('DJANGO_SECRET_KEY=' + (New-LocalSecret)),
            ('POSTGRES_OWNER_PASSWORD=' + (New-LocalSecret)),
            ('POSTGRES_PASSWORD=' + (New-LocalSecret)),
            'POSTGRES_DB=sentinel',
            'POSTGRES_USER=sentinel_app',
            'DJANGO_DEBUG=1',
            'SENTINEL_DOMAIN=localhost',
            'DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1',
            'DJANGO_CSRF_TRUSTED_ORIGINS='
        ) | Set-Content -LiteralPath '.env' -Encoding ASCII
        Write-Host 'Configuracao local criada com segredos aleatorios.'
    }
    $values = Read-LocalEnvironment
    foreach ($key in @('DJANGO_SECRET_KEY', 'POSTGRES_OWNER_PASSWORD', 'POSTGRES_PASSWORD')) {
        if ([string]::IsNullOrWhiteSpace($values[$key])) {
            throw ('O campo ' + $key + ' esta vazio no .env existente. Ele foi preservado para nao invalidar um banco anterior. Complete a configuracao antes de iniciar.')
        }
    }
    if ($values['DJANGO_SECRET_KEY'].Length -lt 50) { throw 'DJANGO_SECRET_KEY precisa ter pelo menos 50 caracteres. O .env existente foi preservado.' }
    # Nunca exibir docker compose config sem --quiet: ele pode revelar senhas.
    Invoke-Compose -Arguments @('config', '--quiet')
    if (-not (Test-LocalPort)) {
        $running = Read-Compose -Arguments @('ps', '--status', 'running', '-q', 'app')
        if ([string]::IsNullOrWhiteSpace($running)) {
            throw 'A porta 8000 ja esta ocupada por outro processo. Nenhum processo foi encerrado. Feche a outra aplicacao ou envie o diagnostico para ajustar a porta.'
        }
    }

    $step = 'construir a aplicacao'
    Write-Host 'Preparando a aplicacao. A primeira vez pode demorar alguns minutos.'
    Invoke-Compose -Arguments @('build', 'app', 'migrate')
    $step = 'iniciar PostgreSQL'
    Invoke-Compose -Arguments @('up', '-d', '--wait', '--wait-timeout', '120', 'db')
    # Evita servir a versao anterior enquanto o esquema e atualizado.
    $step = 'preparar migracoes'
    Invoke-Compose -Arguments @('stop', 'app')
    Invoke-Compose -Arguments @('run', '--rm', 'migrate')
    $step = 'configurar grupos'
    Invoke-Compose -Arguments @('run', '--rm', '-T', 'app', 'python', 'manage.py', 'setup_roles')
    $step = 'conferir dados e usuario inicial'
    $statusCode = 'from django.contrib.auth import get_user_model; from inventory.models import Asset; print("SENTINEL_SETUP:%s:%s" % (int(get_user_model().objects.filter(is_superuser=True, is_active=True).exists()), Asset.objects.count()))'
    # stdin evita problemas com aspas em argumentos nativos no Windows PowerShell 5.1.
    $statusOutput = ($statusCode | & docker @composeFiles run --rm -T app python manage.py shell) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao consultar o estado do banco.' }
    $statusMatch = [regex]::Match($statusOutput, 'SENTINEL_SETUP:([01]):(\d+)')
    if (-not $statusMatch.Success) { throw 'Nao foi possivel verificar o estado do banco. A inicializacao foi interrompida.' }
    if ($statusMatch.Groups[1].Value -eq '0') {
        $step = 'criar sua conta'
        Write-Host 'Crie seu usuario administrador. A senha deve ter 12 caracteres ou mais.' -ForegroundColor Cyan
        Write-Host 'Ao digitar a senha, os caracteres nao aparecem. Isso e normal.'
        Invoke-Compose -Arguments @('run', '--rm', 'app', 'python', 'manage.py', 'createsuperuser')
    }
    if ($statusMatch.Groups[2].Value -eq '0') {
        $answer = Read-Host 'Deseja carregar os ativos ficticios da demonstracao? Digite S para sim, ou Enter para iniciar vazio'
        if ($answer -match '^[sS]$') {
            $step = 'importar dados de demonstracao'
            Invoke-Compose -Arguments @('run', '--rm', '-T', 'app', 'python', 'manage.py', 'import_inventory', 'dados_exemplo/inventario_exemplo.json')
        }
    }
    $step = 'iniciar o servidor'
    Invoke-Compose -Arguments @('up', '-d', '--wait', '--wait-timeout', '120', 'app')
    $step = 'verificar a interface'
    foreach ($route in @('/health/', '/entrar/', '/static/inventory/app.css', '/static/inventory/graph.js', '/static/inventory/theme.js')) {
        $response = Invoke-WebRequest -UseBasicParsing -Uri ('http://127.0.0.1:8000' + $route) -TimeoutSec 15
        if ($response.StatusCode -ne 200) { throw ('A verificacao falhou no endereco ' + $route) }
    }
    Write-Host 'SENTINEL iniciado. Use o usuario e a senha que voce criou.' -ForegroundColor Green
    Write-Host 'Endereco: http://127.0.0.1:8000/'
    Write-Host 'Abra esse endereco no Edge ou Chrome DESTE computador Windows.'
    Start-Process 'http://127.0.0.1:8000/'
    exit 0
} catch {
    Write-Host ''
    Write-Host ('Nao foi possivel concluir a etapa: ' + $step) -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host 'Se precisar de ajuda, envie uma captura desta janela. Nao envie o arquivo .env nem suas senhas.'
    exit 1
}
