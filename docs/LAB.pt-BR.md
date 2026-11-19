# Homologação em pfSense CE 2.9.1

Esta versão observa as medições dos gateways e recomenda membros para políticas. O teste deve demonstrar duas coisas distintas: que a recomendação acompanha os dados do gateway e que a instalação, o serviço e a interface preservam o encaminhamento nativo. A alteração real do caminho é um ensaio de uma versão futura.

## Topologia e evidência

Use um clone CE 2.9.1 com console independente. Para testar HA, inclua dois nós pfSense, um peer em outra rede, duas WANs virtuais com degradação independente, uma LAN de clientes e uma rede de sincronização. Use endereços e certificados de laboratório. Registre revisão Git, versão do pacote, arquitetura, versão do peer, nomes reais de interfaces, parâmetros do dpinger e limite de cada SLA. Preserve uma cópia local da configuração e snapshots dos nós antes da instalação.

Configure ao menos dois gateways com monitoramento habilitado, alvos distintos e rotas de retorno conhecidas. Se usar VTI, identifique qual VTI corresponde a cada transporte. Para HA, atribua as interfaces VTI na mesma ordem, separadamente nos dois nós. Vincule a Fase 1 ao VIP da WAN que corresponde ao túnel. Teste uma conexão pelo caminho em uso e anote o resultado antes da instalação.

## Construção e instalação

O diretório [dist](../dist/) contém o .pkg de laboratório e seu checksum. Para usar o artefato já construído, baixe os dois arquivos no mesmo diretório do clone e confira a integridade com o comando abaixo. Compare a saída com o hash publicado antes de usar `pkg add`.

```sh
sha256 -q pfSense-pkg-SDWAN-0.1.0.pkg
cat pfSense-pkg-SDWAN-0.1.0.pkg.sha256
```

Para compilar o port, use um builder FreeBSD/pfSense com a árvore de ports, dependências e ABI compatíveis com o appliance alvo. O diretório que contém o Makefile deste projeto é o port. Disponibilize-o como `net/pfSense-pkg-SDWAN` na árvore de trabalho do builder. Dentro desse diretório, execute:

```sh
make stage
make check-plist
make stage-qa
make package
make -V PKGFILE
```

O último comando informa o caminho do pacote gerado. Registre seu SHA-256 no builder e confira o mesmo valor após copiar o arquivo para o clone. No clone, como root, substitua o caminho abaixo pelo nome exato do arquivo:

```sh
cat /etc/version
uname -m
pkg -vv | grep ABI
pkg add /caminho/para/pacote.pkg
pkg info -l pfSense-pkg-SDWAN
/usr/local/etc/rc.d/sdwand.sh status
```

Confirme a instalação na lista de pacotes instalados e abra **Services → SD-WAN**. Falha no registro, ABI, dependência, checksum ou menu é um resultado de teste a investigar. Registre o erro original. Evite mascará-lo copiando os arquivos diretamente para a WebGUI.

## Estado de referência

Em cada nó, observe estes dados antes da instalação, com o serviço ativo, depois de editar a política e após remover o pacote. Salve as saídas localmente. Contadores, tempo de vida, IDs efêmeros e número de sessões podem mudar normalmente. Compare as regras efetivas, o destino, o próximo salto e o caminho da mesma classe de fluxos.

```sh
pfctl -sr
pfctl -sn
netstat -rn -f inet
netstat -rn -f inet6
ifconfig -a
/usr/local/sbin/swanctl --list-sas
```

Verifique os estados relevantes com **Diagnostics → States**. Faça capturas de uma conexão de teste na LAN e no destino. Com VTI, capture também em cada interface de túnel. Nas WANs físicas confira os endereços externos do peer e o encapsulamento. Leia o primeiro pacote útil e sua resposta no cliente e no destino. Uma SA estabelecida, isoladamente, não comprova que houve entrega.

## Matriz de homologação do observador

| Teste | Ação no laboratório | Evidência esperada |
|---|---|---|
| Instalação sem configuração | Abrir todas as abas com o conjunto inicial vazio. | Navegação funcional e ausência de recomendação para política inexistente. Rota padrão e regras de passagem continuam equivalentes às da referência. |
| Dois caminhos saudáveis | Cadastrar membros associados aos gateways reais, SLA e uma política com ambos. Definir custos distintos e verificar também a estratégia de menor latência. | O candidato selecionado e o motivo batem com os dados de monitoramento e o critério configurado. Os novos fluxos continuam seguindo a política **nativa** já presente. |
| Degradação com túnel ativo | Introduzir perda ou atraso só no transporte A através do emulador da WAN. Aguardar a janela do dpinger e o ciclo do observador. | Confirmar em **Status → Gateways** o efeito no A. Registrar a primeira alteração de recomendação e conferir os dois caminhos com captura. Uma eventual comutação causada por regra nativa deve ser identificada separadamente. |
| Falha do alvo | Tornar indisponível apenas um destino de monitoramento. Remover candidatos elegíveis para uma política em teste. | Resultado reflete a perda de observabilidade desse membro. Uma política sem candidatos elegíveis não recomenda caminho saudável. Serviço real e endereço de teste podem ter condições diferentes. |
| Amostra ausente e reinício | Parar o observador no clone, aguardar até que o registro fique antigo e atualizar a página. Iniciar novamente e aguardar amostra nova. | Estado desatualizado ou indisponível não deve aparecer como decisão atual. A conectividade existente sobrevive à parada do observador. |
| Integridade das configurações | Salvar uma política válida, tentar referências inválidas e abrir a página simultaneamente em duas sessões. Reabrir após reinício. | Configuração válida persiste. Um erro de validação ou conflito de revisão não pode sobrescrever silenciosamente a configuração válida. |
| Controle de acesso | Testar com administrador, usuário sem privilégio de acesso e sessão encerrada; incluir acessos às URLs diretas. | Política de acesso da WebGUI respeitada inclusive nos formulários de gravação. |
| Recarga | No clone e sob tráfego, usar **Status → Filter Reload** para recarregar o filtro. Repetir a observação com o serviço parado. | Rotas, NAT, política existente e alcance da gerência equivalentes à referência. Uma recomendação não cria regra de encaminhamento. |
| HA | Instalar a mesma versão nos dois nós de teste e configurar ambos explicitamente. Desligar o MASTER. Registrar papel CARP, SAs, primeiro tráfego útil e atualização da telemetria do novo MASTER. | Distinguir tempo de takeover de tempo de renegociação IPsec. O observador não deve promover nó nem reiniciar túnel. Verificar a configuração em ambos antes de considerar que existe sincronização. |
| Remoção | Remover o pacote em **System → Package Manager → Installed Packages**. Verificar menu, processo e encaminhamento; depois reinstalar a mesma versão. | Serviço parado, entrada removida e regras/rotas nativas preservadas. Registrar se preferências locais persistiram e se a reinstalação funciona. |

O teste de degradação fica mais fácil de atribuir se a política nativa inicial fixar um caminho para o tráfego de teste. Se houver failover de um grupo de gateways já configurado, repita com o observador parado e compare os eventos. Os mecanismos nativos podem trocar a rota independentemente do pacote.

## Aceite adicional antes de qualquer versão com steering ativo

O snapshot público examinado do gerador PF pode omitir regras de pacote durante um `packagelock` ou se uma regra gerada falhar na validação. Uma futura política obrigatória de VPN precisa continuar efetiva durante recarga, atualização e indisponibilidade do pacote. Comprovar em build CE exato.

1. Degradar A mantendo as duas SAs de pé. A captura deve mostrar **novas** sessões da classe configurada no caminho previsto em ambas as pontas. Medir separadamente os fluxos estabelecidos e a preservação do NAT.
2. Remover as duas VTIs mantendo as WANs físicas ativas. Manter um fluxo marcado e repetitivo para rede privada de teste. Capturar simultaneamente a saída física depois de qualquer NAT e o destino. Confirmar criptografia enquanto houver túnel e zero tráfego privado em claro durante a queda, recarga e reinicialização do módulo. Registrar drops da própria captura.
3. Com `0.0.0.0/0` pela zona, provar que IKE, a gerência e rotas mais específicas permanecem pelo caminho esperado. Repetir com peer idêntico nas duas WANs e rotas dinâmicas, se esses recursos forem declarados.
4. Verificar o mesmo perfil em três cenários: pfSense↔pfSense, pfSense↔FortiGate e FortiGate↔FortiGate como referência. Publicar métricas por versão e pareamento, incluindo perda, duração da interrupção e tempo até o primeiro pacote útil.

## Fontes

- [Desenvolvimento de pacotes pfSense](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)
- [Verificações de um port FreeBSD](https://docs.freebsd.org/en/books/porters-handbook/quick-porting/)
- [VTI no pfSense](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html)
- [IPsec em HA, associação de VTI, DPD e VIP CARP](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)
- [Revisão de referência do gerador de regras PF](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/filter.inc#L6098-L6162)


## Reprodução do artefato experimental

O script `tools/build-lab-pkg.py` lê os arquivos deste port, prepara o manifesto e chama `pkg create`. Ele confere o pacote resultante com `pkg info -F` e verifica a identidade, os hooks, os modos e os bytes de todos os arquivos. A compilação cruzada usada para o arquivo em dist empregou a CLI FreeBSD pkg 2.9.3 em Linux, com metadados de proprietário root:wheel. Para repetir a geração com essa CLI em um ambiente de empacotamento com a propriedade correta, execute `python3 tools/build-lab-pkg.py --pkg /caminho/para/pkg --output /tmp/sdwan-dist`. A validação do artefato não executa os hooks no appliance.
