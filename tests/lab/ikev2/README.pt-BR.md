# Negociação e renovação de chaves IKEv2 em Linux

O laboratório executa dois processos strongSwan independentes no Ubuntu 24.04. Cada peer tem seu próprio namespace de rede, configuração, diretório de execução e socket de controle. Um terceiro namespace, com duas bridges Ethernet isoladas, permite observar o que realmente percorre cada enlace. Os endereços externos são documentais. Todos os IPs internos, rotas, capturas e chaves pertencem ao ensaio.

| Caminho | Endereços externos | IPs protegidos | Identificador do CHILD no kernel |
|---|---|---|---|
| A | 192.0.2.1 e 192.0.2.2 | 10.241.1.1 e 10.241.1.2 | 101 |
| B | 198.51.100.1 e 198.51.100.2 | 10.241.2.1 e 10.241.2.2 | 102 |

Cada caminho negocia uma IKE SA e uma CHILD_SA com um par de identidades e uma chave pré-compartilhada aleatória exclusiva da execução. As propostas usam AES-128-GCM com tag de 128 bits e grupo ECP-256, incluindo a renovação da CHILD_SA. O daemon instala as associações e políticas IPsec no kernel Linux. Cada par protegido tem uma rota e uma proteção independente no nftables que exige o identificador IPsec daquele caminho para permitir sua saída.

## O que constitui um resultado aprovado

1. Antes de instalar a proteção, o cliente e o peer trocam pings e a captura de trânsito enxerga as mensagens em claro nas duas redes. Esse controle demonstra que um vazamento durante o teste também seria observável.
2. Os dois pares negociam IKEv2 e ESP. O teste cruza o SPI de saída de cada peer com o SPI de entrada da outra ponta. Exige respostas a sondas iniciadas pelos dois lados, crescimento dos contadores de bytes das associações e pacotes ESP com os SPIs esperados nas duas direções.
3. O iniciador solicita a renovação da CHILD_SA do caminho A. Os SPIs ESP de ida e volta devem mudar. Em seguida, solicita a renovação da IKE SA de A e verifica a mudança dos SPIs IKE. O caminho B conserva suas associações. As sondas e verificações de ESP se repetem após cada mudança.
4. O teste encerra a IKE SA de A e observa a remoção da associação nas duas pontas. As sondas protegidas de A devem falhar, os contadores locais de bloqueio devem aumentar e a captura de ambos os enlaces precisa ficar sem ICMP em claro entre os endereços protegidos. O caminho B deve continuar respondendo por ESP.

O ensaio testa dois peers strongSwan no Linux com conjuntos de endereços protegidos distintos. Ele fornece medições de negociação, renovação e isolamento entre caminhos. A comutação do mesmo fluxo entre túneis pelo pfSense, o failover CARP durante a renegociação e a interoperabilidade com FortiOS exigem testes próprios. A proteção de saída usada aqui é uma regra nftables específica do laboratório.

## Execução

Em uma VM Ubuntu 24.04 de laboratório com privilégios de root, namespaces de rede e montagem, Linux XFRM e suporte a nftables, instale os pacotes da distribuição e execute o teste a partir da raiz do repositório.

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends iproute2 iputils-ping nftables tcpdump strongswan-charon strongswan-swanctl libstrongswan-standard-plugins
sudo python3 -B -u tests/lab/ikev2/run.py
```

A execução dispensa imagens de fornecedores e acesso externo depois da instalação dos pacotes. O script remove os processos e namespaces que criou, as configurações com chaves de laboratório e as capturas temporárias. Para acompanhar o resultado de cada revisão, abra o workflow [IKEv2 tunnel checks](../../../.github/workflows/ikev2.yml).

**Referências.** [strongSwan em namespaces Linux](https://docs.strongswan.org/docs/latest/howtos/nameSpaces.html) · [Configuração das conexões e CHILD_SAs](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html) · [Comando de renovação](https://docs.strongswan.org/docs/latest/swanctl/swanctlRekey.html) · [Campos de status e contadores](https://docs.strongswan.org/docs/latest/swanctl/swanctlListSas.html)
