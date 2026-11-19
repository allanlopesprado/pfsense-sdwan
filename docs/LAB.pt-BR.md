# Homologação em pfSense CE 2.9.1

A versão experimental 0.4.2 inclui o observador e a integração experimental de encaminhamento. Registre a revisão do pacote e a do core separadamente. Em um clone com o core padrão, valide o observador e o encaminhamento nativo. Para testar o efeito da escolha de caminhos use uma imagem de laboratório que incorpore a integração de core. [Integração com IPsec, CARP, NAT, estados e rotas](INTEGRACAO.pt-BR.md)

## Topologia e evidência

Use um clone CE 2.9.1 com console independente. Para testar HA, inclua dois nós pfSense, um peer em outra rede, duas WANs virtuais com degradação independente, uma LAN de clientes e uma rede de sincronização. Use endereços e certificados de laboratório. Registre revisão Git, versão do pacote, arquitetura, versão do peer, nomes reais de interfaces, parâmetros do dpinger e limite de cada SLA. Preserve uma cópia local da configuração e snapshots dos nós antes da instalação.

Para observar um SLA, basta um gateway com monitoramento habilitado. Para comparar alternativas, configure dois ou mais gateways da mesma família IP, com alvos que representem o mesmo serviço e rotas de retorno conhecidas. Se usar VTI, identifique qual VTI corresponde a cada transporte. Para HA, atribua as interfaces VTI na mesma ordem, separadamente nos dois nós. Vincule a Fase 1 ao VIP da WAN que corresponde ao túnel. Teste uma conexão pelo caminho em uso e anote o resultado antes da instalação.

## Dependência do core para o teste de encaminhamento

O pacote instala seus próprios arquivos em `/usr/local` e sua definição de privilégios em `/etc/inc/priv`. O adaptador do gerador de regras faz parte de uma **imagem distinta de laboratório**. A prévia funciona quando a instalação dispõe apenas do pacote. Para testar o vínculo de regras, confira na aba **Forwarding** se a imagem expõe a ABI 1.

O patch tem como referência o commit público `9363ac5b8651a1c7a333180425ce7719070f95f9`. O arquivo `src/etc/version` dessa revisão identifica `2.9.0-DEVELOPMENT`. Antes de preparar a imagem do alvo, compare o gerador de regras e o inventário de gateways com a árvore exata que produzirá o clone. No checkout de **build** da base, valide o patch com `git apply --check /caminho/para/filter-sdwan.patch`; integre o arquivo do adaptador em `src/etc/inc/filter-sdwan.inc` junto da alteração de `filter.inc`. No clone, confira a revisão do core, interfaces e regras compiladas. Um patch que aplica sem conflito ainda requer ensaio de tráfego. [Patch do gerador](../core/filter-sdwan.patch) · [Adaptador da ABI 1](../core/filter-sdwan.inc)

## Construção e instalação

Para baixar e instalar diretamente pela WebGUI, siga [Como instalar pelo Diagnostics → Command Prompt](../README.md#como-instalar-pelo-diagnostics--command-prompt).

O diretório [dist](../dist/) contém o .pkg de laboratório e seu checksum. Para usar o artefato já construído, baixe os dois arquivos no mesmo diretório do clone e confira a integridade com o comando abaixo. Compare a saída com o hash publicado antes de usar `pkg add`.

```sh
sha256 -q pfSense-pkg-SDWAN-0.4.2.pkg
cat pfSense-pkg-SDWAN-0.4.2.pkg.sha256
```

Para compilar o port, use um builder FreeBSD/pfSense com a árvore de ports, dependências e ABI compatíveis com o appliance alvo. O diretório que contém o Makefile deste projeto é o port. Disponibilize-o como `net/pfSense-pkg-SDWAN` na árvore de trabalho do builder. Dentro desse diretório, execute:

```sh
make stage
make check-plist
make stage-qa
make package
make -V PKGFILE
```

### Alternativa de empacotamento para laboratório

O arquivo de pré-lançamento também pode ser reproduzido com Python 3.9+, a ferramenta oficial FreeBSD `pkg` v2 (testada na versão 2.9.3) e um ambiente que represente os arquivos do pacote como UID 0/GID 0. Em Linux, com essas dependências e `fakeroot` instalados:

```sh
fakeroot python3 tools/build-lab-pkg.py --output ./dist
```

Depois de produzir o pacote e seu arquivo `.sha256`, gere o índice consultado pela aba **Updates**. A versão 0.4.2 usa o canal `main` e a maturidade `experimental`. A versão 0.3.0 continua consultando o índice próprio de laboratório. A verificação confere nome e versão do manifesto, arquivo e SHA-256. Publique o índice e o pacote na mesma revisão. No README de distribuição, fixe a URL do pacote nesse commit e atualize seu SHA-256.

```sh
python3 tools/update-release-index.py
python3 tools/update-release-index.py --check
```

O empacotador inclui o conteúdo listado em `pkg-plist`, preenche o manifesto e os hooks e compara os bytes, modos e proprietários do arquivo final com o conteúdo esperado antes de imprimir o SHA-256. O port declara `NO_ARCH`. A ABI no pacote é `FreeBSD:16:*`; confirme a família e o major com `pkg config ABI` no alvo. O ensaio de extração em uma raiz temporária utiliza scripts desativados. A validação dos hooks, WebGUI, serviço e HA exige uma instalação real em clone.

### Instalação no clone

O último comando do build por ports informa o caminho do pacote gerado. Registre seu SHA-256 no builder e confira o mesmo valor após copiar o arquivo para o clone. No clone, como root, substitua o caminho abaixo pelo nome exato do arquivo:

```sh
cat /etc/version
uname -m
pkg -vv | grep ABI
pkg add /caminho/para/pacote.pkg
pkg info -l pfSense-pkg-SDWAN
/usr/local/etc/rc.d/sdwand.sh status
```

Consulte a versão com `pkg query '%n-%v' pfSense-pkg-SDWAN` e abra **Services → SD-WAN**. Na aba **Updates**, confira a versão instalada e clique em **Check GitHub** para comparar com o índice público do projeto. **System → Package Manager** usa o repositório do produto e pode omitir um pacote adicionado diretamente de um arquivo. A inclusão no catálogo passa pela avaliação da Netgate. Registre a saída original de qualquer falha no registro, ABI, dependência, checksum ou menu. [Guia do catálogo](https://docs.netgate.com/pfsense/en/latest/packages/manager.html) · [Processo de inclusão de ports](https://docs.netgate.com/pfsense/en/latest/development/develop-packages.html)

## Remoção e retorno à versão anterior

O laboratório precisa de uma imagem com o core e os arquivos do pacote identificados separadamente. Guarde um snapshot do clone antes da alteração de core, uma cópia da configuração e o pacote anterior com o respectivo SHA-256. A suíte cobre a 0.2.0 do observador e a 0.3.0 do canal de laboratório. Para o teste de ida e volta, acompanhe no cliente uma conexão nova e uma sessão que já estava estabelecida.

1. Em **Services → SD-WAN → Forwarding → Configured bindings**, use **Remove binding** em cada grupo para voltar ao encaminhamento nativo. Aguarde a recarga do filtro. Confira as regras e grupos que o administrador configurou no pfSense, a rota de saída e o retorno de uma nova conexão. Para prefixos protegidos, confirme também a regra nativa de bloqueio quando o túnel está indisponível.
2. Com a WebGUI disponível, execute `pkg delete -y pfSense-pkg-SDWAN` no Command Prompt. Reabra o dashboard e o menu Services. Consulte os arquivos e o processo com os comandos do README. O `pkg` remove os arquivos de sua lista e o mecanismo `rc.packages` atualiza o menu e o registro de serviços. Em uma remoção com vínculo ainda registrado, o pacote apaga a seleção transitória e solicita recarga. No core experimental, o marcador continua permitindo que a regra vinculada bloqueie novos fluxos quando a recarga termina sem provedor. Os estados já abertos seguem sua política nativa. Se o pacote já foi removido com vínculos, reinstale o pacote compatível e use **Remove binding** antes de uma nova remoção. Regras, rotas e grupos criados pelo administrador possuem ciclo próprio.
3. Para testar o retorno do **pacote**, reinstale a versão original após remover a 0.4.2. Use o SHA-256 da revisão anterior, confirme `pkg query '%n-%v' pfSense-pkg-SDWAN` e a integridade com `pkg check -s pfSense-pkg-SDWAN`. Verifique o menu, o serviço e o caminho de uma nova conexão. [Pacotes de versões anteriores](../dist/)
4. Para desfazer a alteração do **core**, restaure o snapshot anterior da imagem de laboratório. Compare a versão da base, a configuração e a primeira transação bem-sucedida com o estado de referência. Em HA, valide o papel de cada nó e a versão em ambos.

No teste automatizado de pacote em FreeBSD, as raízes são isoladas e os hooks de sistema ficam desativados. A suíte separada de ciclo executa os scripts do pacote e o trecho de registro do serviço com adaptadores controlados, inclusive com PHP-FPM indisponível. A verificação do registro real na WebGUI, da continuidade de sessões e do rollback do core precisa do clone.

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
| Um caminho | Criar uma política com um único membro monitorado. Tornar seu alvo indisponível. | O único membro aparece enquanto elegível. Após a perda da medição ou do SLA, o conjunto fica sem alternativa. |
| Atualização para 0.4.2 | Em cada clone, instalar a versão de origem, salvar uma política de um membro e anotar sua configuração. Aplicar o pacote novo com o instalador do README e confirmar o reinício do serviço pelo registro do pacote. | O registro local passa a 0.4.2. A política é lida, o serviço publica uma amostra nova e o membro continua representando um único caminho. |
| Widget do dashboard | Em **Status → Dashboard**, usar **+ → SD-WAN**. Comparar o membro e a hora da amostra com o status. Parar o observador e aguardar a expiração. Retirar pelo **×**. | Exibe o resultado local válido, informa ausência de políticas ou de medição atual, respeita os privilégios do usuário e sai do painel quando solicitado. |
| Consulta de versão | Abrir **Updates**, observar a versão instalada, acionar **Check GitHub** e repetir com a saída HTTPS indisponível. | A consulta externa ocorre ao clicar. A página diferencia uma versão publicada, uma falha de consulta e uma versão local desconhecida. A operação apenas exibe informação. |
| Dois caminhos saudáveis | Cadastrar membros associados aos gateways reais, SLA e uma política com ambos. Definir custos distintos e verificar também a estratégia de menor latência. | O candidato selecionado e o motivo batem com os dados de monitoramento e o critério configurado. Os novos fluxos continuam seguindo a política **nativa** já presente. |
| Degradação com túnel ativo | Introduzir perda ou atraso só no transporte A através do emulador da WAN. Aguardar a janela do dpinger e o ciclo do observador. | Confirmar em **Status → Gateways** o efeito no A. Registrar a primeira alteração de recomendação e conferir os dois caminhos com captura. Uma eventual comutação causada por regra nativa deve ser identificada separadamente. |
| Falha do alvo | Tornar indisponível apenas um destino de monitoramento. Remover candidatos elegíveis para uma política em teste. | Resultado reflete a perda de observabilidade desse membro. Uma política sem candidatos elegíveis não recomenda caminho saudável. Serviço real e endereço de teste podem ter condições diferentes. |
| Amostra ausente e reinício | Parar o observador no clone, aguardar até que o registro fique antigo e atualizar a página. Iniciar novamente e aguardar amostra nova. | Estado desatualizado ou indisponível não deve aparecer como decisão atual. A conectividade existente sobrevive à parada do observador. |
| Integridade das configurações | Salvar uma política válida, tentar referências inválidas e abrir a página simultaneamente em duas sessões. Reabrir após reinício. | Configuração válida persiste. Um erro de validação ou conflito de revisão não pode sobrescrever silenciosamente a configuração válida. |
| Controle de acesso | Testar com administrador, usuário sem privilégio de acesso e sessão encerrada; incluir acessos às URLs diretas. | Política de acesso da WebGUI respeitada inclusive nos formulários de gravação. |
| Recarga | No clone e sob tráfego, usar **Status → Filter Reload** para recarregar o filtro. Repetir a observação com o serviço parado. | Rotas, NAT, política existente e alcance da gerência equivalentes à referência. Uma recomendação não cria regra de encaminhamento. |
| HA | Instalar a mesma versão nos dois nós de teste e configurar ambos explicitamente. Desligar o MASTER. Registrar papel CARP, SAs, primeiro tráfego útil e atualização da telemetria do novo MASTER. | Distinguir tempo de takeover de tempo de renegociação IPsec. O observador não deve promover nó nem reiniciar túnel. Verificar a configuração em ambos antes de considerar que existe sincronização. |
| Remoção | Em **Diagnostics → Command Prompt**, executar `pkg delete -y pfSense-pkg-SDWAN` e as verificações do README. Recarregar a WebGUI e reinstalar o pacote. | O pacote deixa o banco local. O processo, o menu, o arquivo do widget e o arquivo das amostras desaparecem. Registrar o resultado da comparação de regras e rotas, a retenção de preferências e o resultado da reinstalação. |

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
