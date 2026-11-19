# SD-WAN para pfSense CE

Pacote experimental para monitorar links, comparar gateways por SLA e acompanhar as recomendações de caminho na WebGUI do **pfSense CE 2.9.1**. Projeto independente da Netgate.

[Baixar a release mais recente](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest) · [Instalação](#como-instalar-pelo-diagnostics--command-prompt) · [Histórico](CHANGELOG.md) · [Resultados de laboratório](docs/RESULTADOS.pt-BR.md)

[![Testes do pacote](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/allanlopesprado/pfsense-sdwan/actions/workflows/checks.yml)

## O que o pacote faz

- **Dashboard** mostra IP, latência, variação do RTT, perda e estado por gateway.
- **Políticas** classificam os caminhos por latência, perda e custo. **Diagnostics** explica a avaliação de cada candidato.
- **Status → Services** registra o serviço `sdwan` com controles nativos. Seus eventos aparecem em **Status → System Logs**, no log Geral.
- **Updates** consulta o GitHub, verifica o SHA-256 e instala a versão publicada pela WebGUI.

![Widget SD-WAN com métricas e estado de três gateways no tema claro](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-light-554.png)

[Widget no tema escuro](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/widget-dark-554.png) · [Tela Status](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/status-pfSense.png) · [Tela Updates](https://github.com/allanlopesprado/pfsense-sdwan/releases/latest/download/updates-pfSense.png)

| Ambiente | Uso |
| --- | --- |
| **pfSense CE 2.9.1 padrão** | Monitoramento de gateways, avaliação de SLAs e recomendação de caminho. |
| **pfSense CE 2.9.1 com o core de laboratório** | Ensaio de encaminhamento por política com o [adaptador do core](core/README.md) e um grupo nativo dedicado. |

## Como instalar pelo Diagnostics → Command Prompt

1. Em um clone de laboratório, abra **Diagnostics → Command Prompt** com acesso administrativo. Use `cat /etc/version && pkg config ABI` para conferir o **CE 2.9.1** e o ABI **FreeBSD:16:amd64**.
2. Execute a linha abaixo. Ela baixa o pacote de uma revisão fixa em um diretório temporário, valida seu SHA-256 e instala com `pkg`.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.4.14.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/96f78ffe9cffbda10f6273971d648b12b5277351/dist/pfSense-pkg-SDWAN-0.4.14.pkg' && sha256 -c 04c34b1152c813dc55ed2457b67ad196f8fd538ef5434256199963965d4adb15 "$p" && pkg add "$p")
```

3. Abra **Services → SD-WAN**. Confira o serviço em **Status → Services** e a versão instalada em **SD-WAN → Updates**.

Se o registro da WebGUI for adiado durante a instalação, aguarde o PHP-FPM voltar e execute `/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL`. [Instalação e verificação em laboratório](docs/LAB.pt-BR.md#construção-e-instalação)

## Configurar e atualizar

1. Confirme as medições em **Status → Gateways** e adicione os links em **Services → SD-WAN → Members**.
2. Defina os limites de RTT e perda em **Performance SLAs** e associe os links a uma política em **Policies**.
3. Acompanhe o resultado em **Status** e **Diagnostics**. Em **Status → Dashboard**, use **+ → SD-WAN** para exibir o widget.

Para atualizar uma instalação a partir da **0.4.8**, abra **SD-WAN → Updates**, clique em **Check GitHub** e selecione **Upgrade to …** quando houver versão disponível. A ação usa o privilégio nativo de instalação de pacotes.

[Logs e severidade no pfSense](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html) · [Remoção e retorno de versão](docs/LAB.pt-BR.md#remoção-e-retorno-à-versão-anterior)

## Desenvolvimento e validação

- [Versionamento e publicação](docs/VERSIONAMENTO.pt-BR.md)
- [Matriz de cenários e testes](docs/VALIDACAO.pt-BR.md)
- [Resultados e evidências de laboratório](docs/RESULTADOS.pt-BR.md)
- [Integração com IPsec, CARP, NAT e rotas](docs/INTEGRACAO.pt-BR.md)
- [Interoperabilidade com FortiOS](docs/FORTIOS.pt-BR.md)

Execute `sh tests/run.sh` com PHP CLI 8.2+, Python 3 e uma shell POSIX. Após instalar, use [`verify-appliance.sh`](tools/verify-appliance.sh) com a versão esperada para conferir o pacote, os registros da WebGUI, o serviço e a amostra atual.
