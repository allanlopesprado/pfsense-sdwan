# SD-WAN para pfSense CE

Port experimental para acompanhar a qualidade dos gateways e simular a seleção de caminho dentro da WebGUI do pfSense. O menu **Services → SD-WAN** reúne cinco abas. O primeiro alvo de homologação é o **pfSense CE 2.9.1**.

## O que esta versão faz

- **Members** associa um nome e custo a um gateway já configurado.
- **Performance SLAs** define limites de RTT e perda.
- **Policies** escolhe o caminho de menor custo ou menor RTT entre os membros que atendem ao SLA. Um empate preserva a ordem dos candidatos da política.
- **Status** mostra as medições e a recomendação por política.
- **Diagnostics** apresenta o resultado por candidato e o motivo de cada exclusão.

O serviço local lê os sockets do monitor de gateways do pfSense (dpinger). Uma medição ausente ou inválida torna o membro inelegível. As configurações são persistidas em uma seção própria do config.xml. O último resultado é gravado atomicamente em /var/run e expira em 30 segundos.

**Modo de operação da versão 0.1.0: observação.** A decisão exibida é uma recomendação. O encaminhamento segue as regras, as rotas e os estados já configurados pelo administrador. Esta versão não classifica conexões, troca rotas, altera túneis, muda a rota padrão nem sincroniza políticas entre nós CARP.

## Pacote de laboratório

[Baixar o .pkg 0.1.0](https://raw.githubusercontent.com/allanlopesprado/pfsense-sdwan/main/dist/pfSense-pkg-SDWAN-0.1.0.pkg) · [Checksum SHA-256](dist/pfSense-pkg-SDWAN-0.1.0.pkg.sha256) · [Instruções de instalação](docs/LAB.pt-BR.md)

O instalador experimental foi empacotado com a ferramenta FreeBSD pkg 2.9.3 em um host Linux, com destino `FreeBSD:16:*`. Contém scripts PHP e shell, com os arquivos, permissões, proprietários e rotinas de instalação e remoção conferidos. O arquivo é distribuído sem assinatura de repositório. A instalação e a remoção no pfSense CE 2.9.1 ainda precisam ser validadas em um clone com console disponível.

## Primeiro uso no laboratório

1. No clone do firewall, configure dois gateways com monitoramento ativo. Confirme que ambos têm métricas em **Status → Gateways**.
2. Após instalar o pacote de laboratório, abra **Services → SD-WAN → Members** e cadastre os dois gateways com custos distintos.
3. Em **Performance SLAs**, crie um perfil com RTT máximo de 100 ms e perda máxima de 1%. Em **Policies**, selecione o perfil, os dois membros e a estratégia de menor custo.
4. Compare o resultado de **Status** com os candidatos em **Diagnostics**. Introduza perda controlada no caminho preferido e observe a mudança de recomendação após a janela do dpinger e o ciclo de coleta.

Consulte o [roteiro de construção, instalação, homologação e remoção](docs/LAB.pt-BR.md). A árvore deste repositório representa o port `net/pfSense-pkg-SDWAN` para um builder compatível. O pacote é independente do projeto pfSense e da Netgate.

## Verificação de desenvolvimento

Com PHP CLI 8.2 ou superior, Python 3 e uma shell POSIX:

```sh
sh tests/run.sh
```

A suíte verifica sintaxe PHP, metadados do port e comportamento do motor com amostras controladas. A instalação no appliance, o aspecto visual com o tema do pfSense e o comportamento de dados reais exigem validação no sistema alvo.
