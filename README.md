# SD-WAN para pfSense CE

A versão pública **0.4.0** acompanha gateways e recomenda caminhos na WebGUI do pfSense. O pacote está disponível em `main` com maturidade **experimental**. O alvo de homologação é o **pfSense CE 2.9.1**. O projeto é independente do pfSense e da Netgate.

## Como instalar pelo Diagnostics → Command Prompt

Use um clone de laboratório com acesso administrativo. O próprio firewall baixa o pacote por HTTPS. O instalador cuida apenas dos arquivos do pacote. A integração avançada depende do suporte correspondente no core do clone. O binário publicado no GitHub é um pacote local de laboratório sem assinatura de repositório.

1. Abra **Diagnostics → Command Prompt**. No campo **Execute Shell Command**, execute `cat /etc/version && pkg config ABI`. Confira a versão do pfSense e a compatibilidade com o pacote produzido para `FreeBSD:16:*`.
2. Cole a linha abaixo no mesmo campo e clique em **Execute**. Ela baixa o arquivo de uma revisão fixa em uma pasta temporária privada, confere o SHA-256 e instala o pacote se a verificação passar. A pasta é removida ao terminar.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.4.0.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/681cc6bf7e95a62a456b39eae923a430ae251049/dist/pfSense-pkg-SDWAN-0.4.0.pkg' && sha256 -c b9300cb5ac2cf0655865aa46b2e59af2617ccb6838e9dbd5456a9d1ba8a57ce6 "$p" && pkg add "$p")
```

3. No registro da versão 0.4.0, o pacote inicia o serviço ou reinicia a instância que já está rodando. Confira a versão e o estado do serviço com o comando abaixo. O resultado esperado inclui `pfSense-pkg-SDWAN-0.4.0` e a indicação de que o serviço está em execução.

```sh
pkg query '%n-%v' pfSense-pkg-SDWAN && /usr/local/etc/rc.d/sdwand.sh status
```

4. Recarregue a WebGUI e abra **Services → SD-WAN**. Se a saída indicar que o registro foi adiado porque o PHP-FPM estava parado, aguarde a WebGUI voltar e execute `/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-SDWAN POST-INSTALL`. Confira de novo o menu e o serviço.

[Pacote experimental 0.4.0](dist/pfSense-pkg-SDWAN-0.4.0.pkg) · [SHA-256](dist/pfSense-pkg-SDWAN-0.4.0.pkg.sha256) · [Command Prompt na documentação Netgate](https://docs.netgate.com/pfsense/en/latest/diagnostics/command-prompt.html)

## Monitorar gateways e comparar caminhos

1. Em **Status → Gateways**, confirme que o gateway tem monitoramento ativo e métricas recentes. Em **Services → SD-WAN → Members**, cadastre esse gateway e seu custo.
2. Em **Performance SLAs**, defina os limites de tempo de ida e volta (RTT) e perda. Em **Policies**, selecione o SLA e o membro. **Um membro** permite acompanhar o SLA de um único link. Se ele falhar, a política fica sem alternativa.
3. Para comparar caminhos, cadastre **dois ou mais gateways** e inclua-os na mesma política. Use a mesma família IP e destinos de monitoramento que representem o serviço avaliado. Selecione menor custo ou menor RTT. Um empate preserva a ordem dos candidatos.
4. Em **Status**, confira as medições e a recomendação. **Diagnostics** mostra a avaliação de cada candidato. No clone, introduza perda controlada no caminho preferido e acompanhe o resultado após a janela de medição do dpinger.

O serviço lê os sockets do monitor de gateways do pfSense. Uma amostra ausente ou inválida torna o membro inelegível. O editor salva as configurações em uma seção própria de `config.xml`. O último resultado é publicado atomicamente em `/var/run` e expira em 30 segundos.

**A instalação começa em observação.** No firewall padrão, a recomendação indica qual caminho atenderia ao SLA. O encaminhamento experimental requer um clone com a integração correspondente compilada no core. Instalar o arquivo `.pkg` não aplica o patch ao sistema. A configuração de IPsec, a rota padrão, o failover CARP e a sincronização entre nós são administrados pelo pfSense. Em **Services → SD-WAN → Forwarding**, veja a prévia de uma política com um grupo nativo dedicado. O botão **Bind policy to this group** depende do suporte do core, dos privilégios e dos resultados de validação. Para comparar WANs e túneis VTI e testar o retorno de cada fluxo, consulte a matriz de integração. [Encaminhamento, assimetria, HA e IPsec](docs/INTEGRACAO.pt-BR.md)

[Preparar o core de laboratório](core/README.md) · [Interoperabilidade com FortiOS e plano de testes](docs/FORTIOS.pt-BR.md)

## Exibir o widget

Em **Status → Dashboard**, clique em **+** e selecione **SD-WAN**. Para cada política, o widget mostra quantos membros atendem ao SLA, o membro recomendado e a hora da amostra. Quem tem acesso à página **Forwarding** também vê o gateway solicitado para cada grupo vinculado. O título abre a página **Status** do pacote. Para retirar o widget do painel, clique no **×**.

![Prévia do widget SD-WAN no tema claro do pfSense, com a recomendação e os membros elegíveis por política](https://github.com/allanlopesprado/pfsense-sdwan/releases/download/v0.4.0/widget-light-640.png)

[Ver no tema escuro](https://github.com/allanlopesprado/pfsense-sdwan/releases/download/v0.4.0/widget-dark-640.png) · [Ver em tela de 360 px](https://github.com/allanlopesprado/pfsense-sdwan/releases/download/v0.4.0/widget-light-360.png)

## Consultar eventos no log do pfSense

Abra **Status → System Logs → System → General** e filtre o campo **Process** por `sdwan`. Os eventos registram o início e a parada do serviço, alterações na recomendação de caminhos, falhas e recuperação da coleta. O pacote envia eventos com os níveis `notice`, `warning` e `err`. A disponibilidade no painel depende do registro local e da severidade configurados pelo administrador. [Configurações de log do pfSense](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/settings.html)

## Consultar versões

Em **Services → SD-WAN → Updates**, um administrador pode ver a versão instalada no banco local do `pkg`. Clique em **Check GitHub** para consultar a versão publicada em `main`, a maturidade declarada e o SHA-256. A 0.2.0 também consulta `main`. A 0.3.0 continua consultando a branch `dev/native-forwarding`. Para migrar desse canal público de laboratório, use o instalador 0.4.0 acima e confirme a nova versão local. A consulta usa HTTPS e as configurações de proxy do firewall. Se houver uma versão nova, o botão **Installation instructions** abre as instruções para a atualização manual.

**System → Package Manager → Installed Packages** utiliza o catálogo do produto. Um pacote instalado diretamente de um arquivo pode ficar ausente dessa lista. Para distribuição e atualização pelo catálogo oficial, a Netgate precisa avaliar o port para inclusão na árvore de pacotes e na branch da versão desejada. [Gerenciador de pacotes](https://docs.netgate.com/pfsense/en/latest/packages/manager.html) · [Desenvolvimento e publicação de pacotes](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)

## Remover o pacote

Para retirar o pacote do clone, abra **Services → SD-WAN → Forwarding → Configured bindings**, use **Remove binding** em cada grupo vinculado e confira o caminho de uma nova conexão. Em **Diagnostics → Command Prompt**, execute o comando abaixo. Na desinstalação, o pacote solicita a parada do serviço e remove o arquivo de amostras. [Remoção e retorno à versão anterior](docs/LAB.pt-BR.md#remoção-e-retorno-à-versão-anterior)

```sh
pkg delete -y pfSense-pkg-SDWAN
```

Recarregue a WebGUI e confirme que o menu e o widget deixaram de estar disponíveis. No Command Prompt, execute os comandos abaixo. Após a remoção, a consulta do pacote retorna um código diferente de zero, a busca do processo fica vazia e a verificação final imprime a confirmação de remoção dos arquivos.

```sh
pkg info -e pfSense-pkg-SDWAN; echo "pkg info retornou $?"
pgrep -lf '/usr/local/sbin/[s]dwand\.php'
test ! -e /usr/local/www/sdwan/status.php && test ! -e /usr/local/www/widgets/widgets/sdwan.widget.php && test ! -e /var/run/sdwan-observer.json && test ! -e /var/run/sdwan-observer.json.events && echo "Arquivos removidos"
```

## Histórico de publicação

| Versão | Distribuição e recursos |
|---|---|
| 0.4.0 | Publicação experimental em `main`. Revisão da WebGUI e do widget, eventos SD-WAN no log geral do pfSense e consulta de versão com indicação de maturidade. |
| 0.3.0 | Versão de laboratório com prévia na instalação padrão e encaminhamento opcional em imagem com a ABI do core. [Revisão publicada](https://github.com/allanlopesprado/pfsense-sdwan/tree/439f140540b5493408c15f89d90a13f316993ab1) |
| 0.2.0 | Observação da saúde dos gateways, SLAs e recomendação de caminhos. [Revisão publicada](https://github.com/allanlopesprado/pfsense-sdwan/tree/ef7d32da3a09cd5d33867eccae07588276e0cb4b) |

## Evidências de laboratório

Veja os resultados da troca de WAN, do tráfego de retorno com NAT, da transferência do VIP e dos testes de túnel, com links para os jobs e as limitações do ambiente. [Resultados da versão 0.3.0](docs/RESULTADOS.pt-BR.md)

## Verificação de desenvolvimento

Execute a suíte com PHP CLI 8.2 ou superior, Python 3 e uma shell POSIX.

```sh
sh tests/run.sh
```

A suíte verifica o port, a correspondência entre pacote e código, o índice de versão do GitHub, a interface e o motor com dados controlados. O roteiro de homologação detalha o que medir em um clone real, inclusive instalação, atualização, remoção e comportamento durante falhas. [Roteiro de laboratório e construção do port](docs/LAB.pt-BR.md)
