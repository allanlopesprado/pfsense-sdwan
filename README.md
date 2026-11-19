# SD-WAN para pfSense CE

A versão **0.2.0** acompanha a qualidade dos gateways e recomenda um caminho por política na WebGUI. O primeiro alvo de homologação é o **pfSense CE 2.9.1**. O pacote é experimental e independente do projeto pfSense e da Netgate.

## Como instalar pelo Diagnostics → Command Prompt

Use um clone de laboratório com acesso administrativo. O próprio firewall baixa o pacote por HTTPS. O binário publicado no GitHub é um pacote local de laboratório sem assinatura de repositório.

1. Abra **Diagnostics → Command Prompt**. No campo **Execute Shell Command**, execute `cat /etc/version && pkg config ABI`. Confira a versão do pfSense e a compatibilidade com o pacote produzido para `FreeBSD:16:*`.
2. Cole a linha abaixo no mesmo campo e clique em **Execute**. Ela baixa o arquivo de uma revisão fixa em uma pasta temporária privada, confere o SHA-256 e instala o pacote se a verificação passar. A pasta é removida ao terminar.

<!-- install-command -->
```sh
d=$(mktemp -d /tmp/sdwan.XXXXXXXX) && (trap 'rm -rf "$d"' EXIT; p="$d/pfSense-pkg-SDWAN-0.2.0.pkg"; fetch -o "$p" 'https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/d36dddb6de4c63846cee4d2c0aa6448154274f7d/dist/pfSense-pkg-SDWAN-0.2.0.pkg' && sha256 -c c8f75b540e896b555f840bdb8d3e04304a3942a81515295d1f481ce5482a15d5 "$p" && pkg add "$p")
```

3. Ao atualizar uma instalação anterior, execute `/usr/local/etc/rc.d/sdwand.sh restart` para carregar o novo observador. Confira a versão e o estado do serviço com o comando abaixo. O resultado esperado inclui `pfSense-pkg-SDWAN-0.2.0` e a indicação de que o serviço está em execução.

```sh
pkg query '%n-%v' pfSense-pkg-SDWAN && /usr/local/etc/rc.d/sdwand.sh status
```

4. Recarregue a WebGUI e abra **Services → SD-WAN**. Se ocorrer erro, guarde a saída exibida pelo Command Prompt.

[Pacote 0.2.0](dist/pfSense-pkg-SDWAN-0.2.0.pkg) · [SHA-256](dist/pfSense-pkg-SDWAN-0.2.0.pkg.sha256) · [Command Prompt na documentação Netgate](https://docs.netgate.com/pfsense/en/latest/diagnostics/command-prompt.html)

## Monitorar gateways e comparar caminhos

1. Em **Status → Gateways**, confirme que o gateway tem monitoramento ativo e métricas recentes. Em **Services → SD-WAN → Members**, cadastre esse gateway e seu custo.
2. Em **Performance SLAs**, defina os limites de tempo de ida e volta (RTT) e perda. Em **Policies**, selecione o SLA e o membro. **Um membro** permite acompanhar o SLA de um único link. Se ele falhar, a política fica sem alternativa.
3. Para comparar caminhos, cadastre **dois ou mais gateways** e inclua-os na mesma política. Use a mesma família IP e destinos de monitoramento que representem o serviço avaliado. Selecione menor custo ou menor RTT. Um empate preserva a ordem dos candidatos.
4. Em **Status**, confira as medições e a recomendação. **Diagnostics** mostra a avaliação de cada candidato. No clone, introduza perda controlada no caminho preferido e acompanhe o resultado após a janela de medição do dpinger.

O serviço lê os sockets do monitor de gateways do pfSense. Uma amostra ausente ou inválida torna o membro inelegível. O editor salva as configurações em uma seção própria de `config.xml`. O último resultado é publicado atomicamente em `/var/run` e expira em 30 segundos.

**O modo de operação é observação.** O pacote exibe qual caminho atenderia ao SLA. Regras, rotas, NAT e estados do pfSense determinam por onde passa cada sessão. A configuração de IPsec, a rota padrão, o failover CARP e a sincronização entre nós continuam a cargo dos mecanismos nativos. Para comparar WANs e túneis VTI e testar o retorno de cada fluxo, consulte a matriz de integração. [Encaminhamento, assimetria, HA e IPsec](docs/INTEGRACAO.pt-BR.md)

## Exibir o widget

Em **Status → Dashboard**, clique em **+** e selecione **SD-WAN**. O widget mostra o membro recomendado por política e a hora da última amostra válida. O título abre a página **Status** do pacote. O usuário precisa de acesso ao painel e ao status do SD-WAN. Para retirar o widget do seu painel, clique no **×** do próprio widget.

## Consultar versões

Em **Services → SD-WAN → Updates**, um administrador pode ver a versão instalada no banco local do `pkg`. Clique em **Check GitHub** para consultar a versão publicada e seu SHA-256. A consulta usa HTTPS e as configurações de proxy do firewall. Se houver uma versão nova, o botão **Installation instructions** abre as instruções para a atualização manual.

**System → Package Manager → Installed Packages** utiliza o catálogo do produto. Um pacote instalado diretamente de um arquivo pode ficar ausente dessa lista. Para distribuição e atualização pelo catálogo oficial, a Netgate precisa avaliar o port para inclusão na árvore de pacotes e na branch da versão desejada. [Gerenciador de pacotes](https://docs.netgate.com/pfsense/en/latest/packages/manager.html) · [Desenvolvimento e publicação de pacotes](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)

## Remover o pacote

Em **Diagnostics → Command Prompt**, execute o comando abaixo. Na desinstalação, o pacote solicita a parada do observador e remove o arquivo de amostras.

```sh
pkg delete -y pfSense-pkg-SDWAN
```

Recarregue a WebGUI e confirme que o menu e o widget deixaram de estar disponíveis. No Command Prompt, execute os comandos abaixo. Após a remoção, a consulta do pacote retorna um código diferente de zero, a busca do processo fica vazia e a verificação final imprime a confirmação de remoção dos arquivos.

```sh
pkg info -e pfSense-pkg-SDWAN; echo "pkg info retornou $?"
pgrep -lf '/usr/local/sbin/[s]dwand\.php'
test ! -e /usr/local/www/sdwan/status.php && test ! -e /usr/local/www/widgets/widgets/sdwan.widget.php && test ! -e /var/run/sdwan-observer.json && echo "Arquivos removidos"
```

## Verificação de desenvolvimento

Execute a suíte com PHP CLI 8.2 ou superior, Python 3 e uma shell POSIX.

```sh
sh tests/run.sh
```

A suíte verifica o port, a correspondência entre pacote e código, o índice de versão do GitHub, a interface e o motor com dados controlados. O roteiro de homologação detalha o que medir em um clone real, inclusive instalação, atualização, remoção e comportamento durante falhas. [Roteiro de laboratório e construção do port](docs/LAB.pt-BR.md)
