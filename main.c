#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define TAM_BUFFER 256
#define MAX_LOGS 100
#define TAM_PAYLOAD (2 * TAM_BUFFER)

/* Somente resultados protegidos: nunca armazenamos senhas ou chaves. */
static char historico[MAX_LOGS][TAM_PAYLOAD];
static char algoritmos[MAX_LOGS][24];
static size_t tamanhos[MAX_LOGS];
static size_t total_logs = 0;

static void registrar_log(const char *algoritmo, const char *payload, size_t tamanho)
{
    if (total_logs == MAX_LOGS) {
        puts("Historico cheio; resultado exibido, mas nao registrado.");
        return;
    }
    snprintf(historico[total_logs], TAM_PAYLOAD, "%s", payload);
    snprintf(algoritmos[total_logs], sizeof algoritmos[0], "%s", algoritmo);
    tamanhos[total_logs] = tamanho;
    ++total_logs;
}

static void exibir_log(size_t i)
{
    printf("%03zu | %5zu | %7zu | %-18s | %s\n", i + 1, tamanhos[i],
           strlen(historico[i]), algoritmos[i], historico[i]);
}

static void relatorio(const char *termo)
{
    size_t encontrados = 0;
    puts("ID  | Bytes | Payload | Algoritmo          | Payload cifrado/resultado");
    puts("----+-------+---------+--------------------+--------------------------");
    for (size_t i = 0; i < total_logs; ++i) {
        if (termo == NULL || strstr(historico[i], termo) != NULL ||
            strstr(algoritmos[i], termo) != NULL) {
            exibir_log(i);
            ++encontrados;
        }
    }
    printf("%zu registro(s).\n", encontrados);
}

/* Retorna 1 para sucesso, 0 para EOF e -1 para entrada rejeitada. */
static int ler_linha(const char *prompt, char *destino, size_t capacidade)
{
    int c;
    char *quebra;
    fputs(prompt, stdout);
    fflush(stdout);
    if (fgets(destino, (int)capacidade, stdin) == NULL) return 0;
    quebra = strchr(destino, '\n');
    if (quebra != NULL) {
        *quebra = '\0';
        return 1;
    }
    c = getchar();
    if (c == '\n' || c == EOF) return 1;
    while ((c = getchar()) != '\n' && c != EOF) { }
    destino[0] = '\0';
    puts("Entrada longa demais; operacao cancelada.");
    return -1;
}

