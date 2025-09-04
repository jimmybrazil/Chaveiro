# Chaveiro
Um gerenciador de senhas.

Chaveiro é um gerenciador de senhas, seguro e elegante desenvolvido em Python. Com interface gráfica e criptografia forte, suas senhas ficam protegidas localmente no seu computador.

Funcionalidades

🔒 Criptografia Forte: PBKDF2-HMAC-SHA256 + Fernet (AES-128)
🎨 Interface Moderna: Tema escuro elegante em azul-prussiano
🔑 Senha Mestra: Acesso protegido ao cofre
🔍 Busca Rápida: Encontre suas senhas instantaneamente
📋 Área de Transferência Segura: Copia senhas com limpeza automática após 15s
🎲 Gerador de Senhas: Crie senhas fortes e personalizáveis
💾 Armazenamento Local: Seus dados nunca saem do seu computador
🌓 Temas: Escuro (padrão), Claro ou Sistema

Instalação

Requisitos:
Python 3.9 ou superior
pip (gerenciador de pacotes Python)

Passo a Passo

Linux:

Copie e cole no seu terminal:  git clone https://github.com/jimmybrazil/chaveiro.git && cd chaveiro && pip install -r requirements.txt && python chaveiro.py

Windows:

Copie e cole no Prompt de Comando: pip install pyinstaller
pyinstaller --noconsole --onefile --name "Chaveiro" --icon assets/chaveiro.ico chaveiro.py

MacOS:

Copie e cole no Terminal:  pip install pyinstaller
pyinstaller --windowed --onefile --name "Chaveiro" chaveiro.py

Como Usar

    Primeira Execução:
        Crie uma senha mestra forte (mínimo 8 caracteres)
        Esta senha protegerá todas as outras
        ⚠️ IMPORTANTE: Não há recuperação de senha mestra!

    Adicionar Senha:
        Clique em "+ Nova entrada"
        Preencha: Serviço, Usuário, Senha
        Use o gerador para criar senhas fortes
        Adicione notas se necessário

    Buscar Senhas:
        Use a barra de pesquisa
        Busca por serviço ou usuário

    Copiar Senha:
        Clique em "Copiar"
        A senha é copiada para área de transferência
        Limpa automaticamente após 15 segundos

    Segurança:
        Sempre clique em "Bloquear" ao terminar
        O cofre bloqueia automaticamente ao fechar

Segurança:

Criptografia

    Derivação de Chave: PBKDF2-HMAC-SHA256 (390.000 iterações)
    Criptografia de Dados: Fernet (AES-128 em modo CBC com HMAC)
    Armazenamento: SQLite com WAL mode
    Senha Mestra: Nunca armazenada, apenas seu hash

Boas Práticas

    Use uma senha mestra forte e única
    Faça backup regular do arquivo vault.db
    Não compartilhe o arquivo do cofre sem criptografia adicional
    Mantenha o software atualizado

Este projeto está sob a licença MIT. Copyright (c) 2025 Thiago Freitas

Agradecimentos:

    CustomTkinter - Interface
    Cryptography - Criptografia 
    Pillow - Geração de ícones
    
Desenvolvedor:

Thiago Freitas

    GitHub: @jimmybrazil
    LinkedIn: http://linkedin.com/in/thiago-freitas-9428412bb



    
        



