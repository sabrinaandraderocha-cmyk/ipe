# Ipê 🌳 (Versão 2.0)

Plataforma simples para pesquisadores divulgarem suas pesquisas em formato acessível, com:

- Área (macro)
- Nível de evidência (badge)
- Link original/DOI obrigatório
- Imagem opcional por URL
- Código de convite (anti-spam simples)

## Rodar localmente

```bash
pip install -r requirements.txt
python app.py
```

Abra: http://127.0.0.1:5000

### Código de convite (local)
Por padrão: `IPE2026`

Em produção, configure por variável de ambiente:

- `IPE_INVITE_CODE=SEU_CODIGO`
- `SECRET_KEY=UMA_CHAVE_FORTE`

## Observação
Não substitui avaliação por pares nem representa instituições.
