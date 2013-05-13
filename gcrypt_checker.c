/*
 * Name: Emma Mirică
 * Email: emma.mirica@cti.pub.ro
 * Library: libgcrypt
 * Encryption Algorithm: Twofish
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <inttypes.h>
#include <time.h>
/* libgcrypt header */
#include <gcrypt.h>

#define GCRYPT_FILE "tests_results/gcrypt_checker.out"
#define TEST_FILENAME "tests/input_"
#define BUFSIZE  128

#define TWOFISH_KEY_LEN 32
#define TWOFISH_BLOCK_LEN 16

#define ENCRYPT 1
#define DECRYPT 2

static FILE *gcrypt_out;

static char iniVector[TWOFISH_BLOCK_LEN];
static char key[TWOFISH_KEY_LEN];
static gcry_cipher_hd_t hd;
static char* file_sizes[] = { "2.6KB", "1MB", "8MB", "64MB", "512MB", "1GB" };

/* Return in us the current time and also, write
 * the current time in timebuf */
static uint64_t get_str_time(char *timebuf)
{
    struct timeval tv;
    struct timezone tz;
    struct tm *tm;
    uint64_t time;
    gettimeofday(&tv, &tz);
    time = tv.tv_sec * 1000000 + tv.tv_usec;
    tm = localtime(&tv.tv_sec);
    memset(timebuf, 0, BUFSIZE);
    sprintf (timebuf, "%02d:%02d:%02d:%03ld",tm->tm_hour, tm->tm_min, tm->tm_sec, (tv.tv_usec/1000) );
    return time;
}

/* The function does the initialization for twofish algorithm */
static void init_twofish(char * pass)
{
    strncpy(key, pass, TWOFISH_KEY_LEN);
    memset(iniVector, 0, TWOFISH_BLOCK_LEN);
    gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, 0);
    gcry_cipher_setkey(hd, key, TWOFISH_KEY_LEN);
    gcry_cipher_setiv(hd, iniVector, TWOFISH_BLOCK_LEN);
}

/* The function will encrypt/decrypt based on the 'type' parameter.*/
static void do_twofish(int type, char * file_in, char * file_out, int buffer_size)
{
    if (!file_in || !file_out) {
        fprintf(stderr, "ERROR: file in or file out name is NULL\n");
        return;
    }

    FILE * in = fopen(file_in, "r");
    if (!in) {
        fprintf(stderr, "ERROR: couldn't open file %s\n", file_in);
        return;
    }
    FILE * out = fopen(file_out, "w");
    if (!out) {
        fprintf(stderr, "ERROR: couldn't open file %s\n", file_out);
        return;
    }

    int bytes;
    char * encBuffer = malloc(buffer_size);
    if (!encBuffer) {
        fprintf(stderr, "ERROR: malloc failed\n");
        return;
    }

    while(!feof(in))
    {
        memset(encBuffer, 0, buffer_size);
        bytes = fread(encBuffer, 1, buffer_size, in);
        if (bytes < 0) {
            fprintf(stderr, "ERROR: reading from %s\n", file_in);
            return;
        }
        if (!bytes) break;
        if (type == ENCRYPT)
            gcry_cipher_encrypt(hd, encBuffer, bytes, NULL, 0);
        if (type == DECRYPT)
            gcry_cipher_decrypt(hd, encBuffer, buffer_size, NULL, 0);
        bytes = fwrite(encBuffer, 1, buffer_size, out);
        if (bytes < 0) {
            fprintf(stderr, "ERROR: writing in %s\n", file_out);
            return;
        }
    }

    gcry_cipher_close(hd);
    fclose(in);
    fclose(out);
    free(encBuffer);
}

int main(int nargc, char * argv[])
{
    if (nargc != 2) {
        fprintf(stderr, "Usage %s passphrase\n"
                "[Use this passphrase to encrypt]\n", argv[0]);
        return 1;
    }
    char timebuf[BUFSIZE];
    uint64_t diff;
    char input[BUFSIZE], input_enc[BUFSIZE], input_dec[BUFSIZE];

    /* Open file for results */
    gcrypt_out = fopen(GCRYPT_FILE, "a");
    if (!gcrypt_out) {
        fprintf(stderr, "ERROR: couldn't open %s\n", GCRYPT_FILE);
        return 1;
    }

    get_str_time(timebuf);
    fprintf(gcrypt_out, "[%s] === Starting testing "
            "gcrypt Twofish implementation ===\n\n", timebuf);

    int i;
    for (i = 1; i <= 6; i++) {
        memset(input, 0, BUFSIZE);
        snprintf(input, BUFSIZE, "%s%d", TEST_FILENAME, i);
        memset(input_enc, 0, BUFSIZE);
        snprintf(input_enc, BUFSIZE, "%s%d.enc", TEST_FILENAME, i);
        memset(input_dec, 0, BUFSIZE);
        snprintf(input_dec, BUFSIZE, "%s%d.dec", TEST_FILENAME, i);
        uint64_t start = get_str_time(timebuf);
        fprintf(gcrypt_out, "\t[%s] === Start: Speed ", timebuf);
        fprintf(gcrypt_out, "%s - Gcrypt Twofish ===\n", file_sizes[i - 1]);
        init_twofish(argv[1]);
        do_twofish(ENCRYPT, input, input_enc, TWOFISH_BLOCK_LEN);
        uint64_t stop_enc = get_str_time(timebuf);

        // Save encryption duration
        fprintf(gcrypt_out, "\t\t[%s] === Encryption for ", timebuf);
        (stop_enc > start) ? diff = stop_enc - start : 0;
        fprintf(gcrypt_out, "%s lasted %llu [us]\n", file_sizes[i - 1], diff);
        init_twofish(argv[1]);
        do_twofish(DECRYPT, input_enc, input_dec, TWOFISH_BLOCK_LEN);
        uint64_t stop = get_str_time(timebuf);

        // Write useful output
        fprintf(gcrypt_out, "\t\t Correctness test for %s", input);
        char diff_string[BUFSIZE];
        memset(diff_string, 0, BUFSIZE);
        snprintf(diff_string, BUFSIZE, "diff %s %s", input, input_dec);
        int rc = system(diff_string);
        (rc == 0) ? fprintf(gcrypt_out, " passed\n") : fprintf(gcrypt_out, " failed\n");
        diff = (stop > stop_enc) ? (stop - stop_enc) : 0;
        fprintf(gcrypt_out, "\t\t[%s] === Decryption for ", timebuf);
        fprintf(gcrypt_out, "%s lasted %llu [us]\n", file_sizes[i - 1], diff);
        diff = (stop > start) ? (stop - start) : 0;
        fprintf(gcrypt_out, "\t[%s] === Stop: Total time ", timebuf);
        fprintf(gcrypt_out, "%llu[us] Speed %s - gcrypt Twofish ===\n\n", diff, file_sizes[i - 1]);

        printf("[ %llu us] Correctness/Speed Test for file %s ended\n", diff, file_sizes[i - 1]);
    }
    get_str_time(timebuf);
    fprintf(gcrypt_out, "[%s] === Testing gcrypt "
            "Twofish implementation ended ===\n\n", timebuf);
    fclose(gcrypt_out);
    return 0;
}
