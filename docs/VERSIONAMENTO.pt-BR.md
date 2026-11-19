# Versionamento e publicação

O projeto usa números `MAJOR.MINOR.PATCH` e tags `vMAJOR.MINOR.PATCH`. A série `0.x` está em desenvolvimento experimental. Use **patch** para correções e ajustes compatíveis, **minor** para novos recursos que marcam uma etapa do projeto e **major** para uma nova série com mudanças de compatibilidade. Os três componentes são comparados numericamente. [Semantic Versioning](https://semver.org/lang/pt-BR/)

## Identidade de uma versão

| Arquivo ou referência | Informação |
| --- | --- |
| `Makefile` | A versão do port, em `PORTVERSION`. |
| `dist/pfSense-pkg-SDWAN-<versão>.pkg` e `.sha256` | O pacote e seu checksum. |
| `dist/release.json` | Versão, maturidade e SHA-256 consultados pela WebGUI. |
| `docs/releases/v<versão>.md` | As mudanças daquela versão. O workflow usa esse texto para montar a release. |
| Tag no GitHub | A revisão que passou pelos testes e contém o pacote daquela versão. |

O GitHub Releases é o canal de distribuição da versão mais recente. A maturidade **experimental** é registrada no índice e nas notas da release. A aba **Updates** usa uma release publicada e confere se o SHA-256 do asset corresponde ao índice e ao arquivo daquela tag. [GitHub Releases](https://github.com/allanlopesprado/pfsense-sdwan/releases)

## Preparar uma release

1. Atualize `PORTVERSION` no `Makefile`, adicione `docs/releases/v<versão>.md` e registre a mudança no [histórico](../CHANGELOG.md).
2. Envie o código para `build/**` ou execute **Build pfSense package** no GitHub Actions sobre o commit que será empacotado. O workflow constrói duas vezes e compara os bytes antes de publicar o artefato de build.
3. Baixe o artefato `sdwan-package`, confira o checksum e faça um commit com o `.pkg` e o `.sha256` em `dist/`. A partir desse commit, gere o índice e o comando de instalação do README.

```sh
python3 tools/update-release-index.py --artifact-commit "$(git rev-parse HEAD)"
python3 tools/update-release-index.py --check
```

4. Inclua esses arquivos no commit de publicação e use o assunto `Release X.Y.Z` ou `Release X.Y.Z <descrição>`. Envie-o para `main`. O workflow verifica WebGUI, FreeBSD, IPsec e a matriz de homologação, exige uma versão maior que as releases publicadas e cria a tag e a release.
5. Depois da publicação, confira versão, pacote e SHA-256 na release. Em um appliance já atualizado, execute [`verify-appliance.sh`](../tools/verify-appliance.sh) com a versão esperada.

Os arquivos e a tag de uma versão identificam o pacote publicado. Para distribuir uma correção, incremente a versão e repita a publicação. Para ajustar a apresentação ou a documentação, atualize o README ou as notas no GitHub. [Gerenciar releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)

[Construção em FreeBSD e homologação](LAB.pt-BR.md)
