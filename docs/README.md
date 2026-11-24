# SD-WAN documentation

## Install and configure

| Task | Guide |
| --- | --- |
| Install the published package | [Installation on pfSense CE](../README.md#install-from-diagnostics--command-prompt) |
| Review gateway, monitor, interface, or firewall changes | [Configuration impact](CONFIGURATIONS.md) |
| Assess interactions with IDS, IPS, DNS filtering, or routing packages | [Package compatibility](PACKAGE-COMPATIBILITY.md) |
| Configure lab forwarding or review IPsec, NAT, and HA | [Forwarding and routing integration](INTEGRATION.md) |
| Test a FortiGate peer | [FortiGate interoperability](FORTIOS.md) |
| Test two pfSense nodes, CARP and two IPsec VTIs with a FortiGate | [Two-node HA acceptance](HA-FORTIOS-LAB.md) |

## Validate and troubleshoot

- [Lab setup, installation checks, updates, and rollback](LAB.md)
- [Validation matrix and automated regression tests](VALIDATION.md)
- [Forwarding benchmarks and raw measurements](benchmarks/README.md)
- [Results by test environment](RESULTS.md)
- [Feature comparison with other SD-WAN platforms](FEATURE-COMPARISON.md)

## Develop and publish

- [Core adapter setup](../core/README.md)
- [Versioning and release procedure](VERSIONING.md)
- [Changelog and release notes](../CHANGELOG.md)

## Links em português

Os atalhos históricos levam aos guias atuais em inglês.

- [Impacto das configurações](CONFIGURACOES.pt-BR.md) e [integração com pfSense](INTEGRACAO.pt-BR.md)
- [Laboratório](LAB.pt-BR.md), [validação](VALIDACAO.pt-BR.md) e [resultados](RESULTADOS.pt-BR.md)
- [Interoperabilidade com FortiOS](FORTIOS.pt-BR.md) e [versionamento](VERSIONAMENTO.pt-BR.md)
