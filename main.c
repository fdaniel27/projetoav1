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
static int ler_numero(const char *prompt, int *valor)
{
    char buffer[64], *fim;
    long numero;
    int estado = ler_linha(prompt, buffer, sizeof buffer);
    if (estado != 1) return estado;
    errno = 0;
    numero = strtol(buffer, &fim, 10);
    if (buffer == fim || *fim != '\0' || errno == ERANGE ||
        numero < INT_MIN || numero > INT_MAX) {
        puts("Digite um numero inteiro valido.");
        return -1;
    }
    *valor = (int)numero;
    return 1;
}

void mascarar_dados(char *dados)
{
    size_t tamanho = strlen(dados);
    for (size_t i = 0; i + 4 < tamanho; ++i) dados[i] = '*';
}

int validar_senha(const char *senha)
{
    int maiuscula = 0, minuscula = 0, digito = 0;
    for (size_t i = 0; senha[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)senha[i];
        if (c >= 'A' && c <= 'Z') maiuscula = 1;
        if (c >= 'a' && c <= 'z') minuscula = 1;
        if (c >= '0' && c <= '9') digito = 1;
    }
    return strlen(senha) >= 8 && maiuscula && minuscula && digito;
}

/* Apenas letras ASCII sao deslocadas; pontuacao e outros bytes permanecem. */
void cifrar_cesar(char *texto, int deslocamento)
{
    int passo = ((deslocamento % 26) + 26) % 26;
    for (size_t i = 0; texto[i] != '\0'; ++i) {
        int c = (unsigned char)texto[i];
        if (c >= 'A' && c <= 'Z') texto[i] = (char)('A' + (c - 'A' + passo) % 26);
        else if (c >= 'a' && c <= 'z') texto[i] = (char)('a' + (c - 'a' + passo) % 26);
    }
}

void descifrar_cesar(char *texto, int deslocamento)
{
    /* Reduz antes de negar, evitando overflow com INT_MIN. */
    cifrar_cesar(texto, -(deslocamento % 26));
}

void cifrar_xor(unsigned char *dados, size_t tamanho, char chave)
{
    for (size_t i = 0; i < tamanho; ++i) dados[i] ^= (unsigned char)chave;
}

static void para_hex(const unsigned char *dados, size_t tamanho, char *hex)
{
    for (size_t i = 0; i < tamanho; ++i)
        snprintf(hex + 2 * i, 3, "%02X", (unsigned int)dados[i]);
    hex[2 * tamanho] = '\0';
}

static int valor_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int de_hex(const char *hex, unsigned char *dados, size_t *tamanho)
{
    size_t n = strlen(hex);
    if (n % 2 != 0) return 0;
    for (size_t i = 0; i < n; i += 2) {
        int alto = valor_hex(hex[i]), baixo = valor_hex(hex[i + 1]);
        if (alto < 0 || baixo < 0) return 0;
        dados[i / 2] = (unsigned char)(alto * 16 + baixo);
    }
    *tamanho = n / 2;
    return 1;
}
int main(void)
{
    int opcao = -1, estado, deslocamento;
    char texto[TAM_BUFFER], chave[2], hex[2 * TAM_BUFFER];
    unsigned char bytes[TAM_BUFFER];
    size_t tamanho;
    do {
        puts("\nSAFECONSOLE C\n1 - Mascarar dados\n2 - Validar senha"
             "\n3 - Cifrar Cesar\n4 - Descifrar Cesar"
             "\n5 - Cifrar XOR\n6 - Descifrar XOR (hex)\n7 - Relatorio de auditoria\n8 - Buscar logs\n0 - Sair");
        estado = ler_numero("Opcao: ", &opcao);
        if (estado == 0) break;
        if (estado != 1) { opcao = -1; continue; }
        switch (opcao) {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
            estado = ler_linha("Texto: ", texto, sizeof texto);
            if (estado == 0) return 0;
            if (estado != 1) break;
            tamanho = strlen(texto);
            if (opcao == 1) {
                mascarar_dados(texto);
                printf("Dados mascarados: %s\n", texto);
                registrar_log("MASCARAMENTO", texto, tamanho);
            } else if (opcao == 2) {
                const char *resultado = validar_senha(texto) ? "Senha forte." : "Senha fraca.";
                puts(resultado);
                registrar_log("VALIDACAO", resultado, tamanho);
            } else if (opcao == 3 || opcao == 4) {
                estado = ler_numero("Deslocamento: ", &deslocamento);
                if (estado == 0) return 0;
                if (estado != 1) break;
                if (opcao == 3) cifrar_cesar(texto, deslocamento);
                else descifrar_cesar(texto, deslocamento);
                printf("Resultado: %s\n", texto);
                if (opcao == 3) registrar_log("CESAR", texto, tamanho);
                else {
                    /* Guarda a versao cifrada, nao o texto recuperado. */
                    cifrar_cesar(texto, deslocamento);
                    registrar_log("CESAR (decifrar)", texto, tamanho);
                }
            } else {
                estado = ler_linha("Chave (um caractere ASCII): ", chave, sizeof chave);
                if (estado == 0) return 0;
                if (estado != 1) break;
                if (strlen(chave) != 1 || (unsigned char)chave[0] > 127) {
                    puts("Chave invalida."); break;
                }
                memcpy(bytes, texto, tamanho);
                cifrar_xor(bytes, tamanho, chave[0]);
                para_hex(bytes, tamanho, hex);
                printf("XOR hexadecimal: %s\n", hex);
                registrar_log("XOR", hex, tamanho);
            }
             break;
        case 6:
            estado = ler_linha("Payload hexadecimal (sem espacos): ", hex, sizeof hex);
            if (estado == 0) return 0;
            if (estado != 1) break;
            if (!de_hex(hex, bytes, &tamanho)) { puts("Hexadecimal invalido."); break; }
            estado = ler_linha("Chave (um caractere ASCII): ", chave, sizeof chave);
            if (estado == 0) return 0;
            if (estado != 1) break;
            if (strlen(chave) != 1 || (unsigned char)chave[0] > 127) {
                puts("Chave invalida."); break;
            }
            registrar_log("XOR (decifrar)", hex, tamanho);
            cifrar_xor(bytes, tamanho, chave[0]);
            fputs("Texto recuperado: ", stdout);
            /* Escapa bytes de controle, inclusive NUL, para nao controlar o terminal. */
            for (size_t i = 0; i < tamanho; ++i) {
                if (bytes[i] >= 32 && bytes[i] <= 126) putchar(bytes[i]);
                else printf("\\x%02X", (unsigned int)bytes[i]);
            }
            putchar('\n');
            break;
        case 7:
            relatorio(NULL);
            break;
        case 8:
        estado = ler_linha("Termo (payload ou algoritmo): ", texto, sizeof texto);
            if (estado == 0) return 0;
            if (estado == 1) relatorio(texto);
            break;
        case 0: break;
        default: puts("Opcao invalida.");
        }
    } while (opcao != 0);
    return 0;
}