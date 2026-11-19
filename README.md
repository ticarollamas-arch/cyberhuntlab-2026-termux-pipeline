# Cyber Hunt Lab 2026 — Termux Bug Bounty Audit

Scanner Python de **configuração HTTP/TLS não invasivo**, não um pentest completo. Sem chat ou interface web. Exige autorização e host exato. Não faz fuzzing, exploração, crawling, brute force nem autenticação. A inclusão de um domínio em plataforma bug bounty **não garante** que toda técnica esteja permitida; consulte o escopo e as regras atuais do programa.

## Instalação no Termux

```bash
pkg update -y
pkg install -y python
python -m pip install -r requirements.txt
python scanner.py
```

Ou `bash install.sh`. Na primeira execução, informe URL, host exato e digite `AUTORIZADO` somente se tiver permissão. Use Ctrl+C para interromper.

Exemplo para **seu próprio domínio**:

```bash
python scanner.py --url https://seu-dominio.example/ --scope-host seu-dominio.example --yes-authorized
```

## IA opcional

ChatGPT Plus e API OpenAI têm faturamentos separados. Obtenha chave em https://platform.openai.com/api-keys e configure sem inseri-la no código:

```bash
read -rsp 'OpenAI API key: ' OPENAI_API_KEY; echo
export OPENAI_API_KEY
python scanner.py --ai
unset OPENAI_API_KEY
```

O modelo padrão é `gpt-4.1-mini` (pode mudar conforme sua conta). Para selecionar outro, use `--model NOME`. Somente achados sanitizados são enviados à API. Custos podem ser aplicados. Não envie informações privadas de programas de bug bounty a provedores externos sem autorização.

## Arquivos

Relatórios JSON, Markdown e HTML em `reports/`. Estados `OBSERVATION` significam sinais a revisar, **não** vulnerabilidades confirmadas.

## Limites conhecidos

- Máximo 3 requisições GET por execução, sem seguir redirects fora do host autorizado.
- TLS é checado com validação padrão do Python.
- DNS é validado antes da conexão, mas a biblioteca requests resolve o DNS novamente; um host sujeito a DNS rebinding pode contornar essa verificação. Não execute contra hosts não confiáveis ou dinâmicos; para auditorias mais amplas use um worker com firewall/egress proxy que fixe o IP validado.
- O scanner não confirma CVEs/CWEs nem faz testes ativos de vulnerabilidades.
- O processamento de `Set-Cookie` é agregado e não substitui auditoria individual de cookies.
- As respostas HTTP não são lidas integralmente, reduzindo consumo de dados.
