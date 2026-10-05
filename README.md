# SafeConsole C

Projeto pratico de fundamentos de C aplicado a Seguranca da Informacao.

## Integrantes

- Daniel Ferreira Alves

## Compilacao e execucao

```sh
gcc -std=c11 -Wall -Wextra -Wpedantic main.c -o safe_console
./safe_console
```

## Etapa 1

Leitura com `fgets`, rejeicao e descarte de linhas maiores que o buffer,
mascaramento que preserva os quatro ultimos caracteres e validacao ASCII de
senhas com oito caracteres, maiuscula, minuscula e digito.

## Etapa 2

Menu com Cesar reversivel e deslocamentos inteiros positivos ou negativos.
XOR com chave char, exibicao hexadecimal e descifragem de hexadecimal.

## Etapa 3

Historico em memoria com matriz 2D de 100 registros. Busca com `strstr`,
sensivel a maiusculas, no payload e no nome do algoritmo; termo vazio lista tudo.
Relatorio com ID, tamanho original em bytes (`strlen` para entradas textuais),
tamanho do payload armazenado (`strlen`), algoritmo e resultado protegido.
Para XOR, cada byte e representado por dois caracteres hexadecimais.
Ao atingir 100 registros, novas operacoes continuam, com aviso de que nao
foram registradas. O historico desaparece ao encerrar o programa.
Senhas e chaves nao sao registradas; validacao armazena apenas o resultado.
Descifragem registra a entrada cifrada. Mascaramento registra o resultado mascarado.

## Uso e limites

- Opcoes 1 e 2: mascarar dados e validar senha.
- Opcoes 3 e 4: cifrar e descifrar Cesar usando o mesmo deslocamento.
- Opcoes 5 e 6: cifrar texto XOR e recuperar usando o hexadecimal e a mesma chave.
- Opcoes 7 e 8: relatorio completo e busca. Opcao 0 ou EOF: sair.
- Texto: ate 255 bytes. Linhas maiores sao rejeitadas e descartadas integralmente.
- Chave XOR: um caractere ASCII, inclusive espaco; nao pode ser vazia.
- Hexadecimal: pares de digitos, sem espacos, ate 510 caracteres.
- Mascaramento preserva os quatro ultimos caracteres; entradas com quatro ou
  menos caracteres permanecem visiveis. Para CPF/cartao, prefira somente digitos.
- As regras de senha e Cesar usam ASCII. Tamanhos sao bytes; nao ha tratamento
  de caracteres Unicode no mascaramento. Use entradas ASCII neste exercicio.
- Na descifragem XOR, bytes fora do ASCII imprimivel aparecem como `\xHH`.
- Cesar e XOR com chave de um byte sao algoritmos didaticos, inadequados para
  proteger dados reais. A validacao de senha implementa os criterios da atividade.

## Exemplo

Cesar: `Abc XYZ!` com deslocamento `3` produz `Def ABC!`.
XOR: `ABC` com chave `A` produz `000302`; descifrar recupera `ABC`.
Senha `Abcdefg1` atende aos criterios. `12345678901` vira `*******8901`.

## Entrega

O repositorio local possui um commit para cada etapa. Crie um repositorio vazio
chamado `safe-console-c` na sua conta GitHub e, dentro desta pasta, execute
(substitua `SEU_USUARIO`):

```sh
git remote add origin https://github.com/SEU_USUARIO/safe-console-c.git
git push -u origin main
```

Envie no Google Classroom o link desse repositorio e o arquivo `main.c`.
