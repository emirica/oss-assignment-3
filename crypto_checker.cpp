/*
 * Name: Emma Mirică
 * Library: crypto++
 * Encryption Algorithm: Twofish
 */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <sys/time.h>
#include <inttypes.h>


// Crypto++ headers
#include <crypto++/cryptlib.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/twofish.h>
#include <crypto++/base64.h>
#include <crypto++/sha.h>
#include <crypto++/osrng.h>
#include <crypto++/pwdbased.h>
#include <crypto++/files.h>


#define CRYPTO_FILE     "tests_results/crypto_checker.out"
#define TEST_FILENAME   "tests/input_"
#define BUFSIZE         128
#define ENC_HEADER      "------------- Encrypted File -------------"

using namespace CryptoPP;
using namespace std;

static std::ofstream crypto_out;
static std::ifstream input;
static std::fstream input_enc;
static std::ofstream input_dec;
static std::string algo = "Twofish";
static std::string mode = "CBC_Mode";
static std::string file_sizes[] = { "2.6KB", "1MB", "8MB", "64MB", "512MB", "1GB" };

// Return in us the current time and also, write the current time in timebuf
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

int main(int nargc, char *argv[])
{
    if (nargc != 2) {
        std::cerr << "Usage " << argv[0] << " passphrase\n"
            "[Use this passphrase to encrypt]\n";
        return 1;
    }
    char timebuf[BUFSIZE];
    uint64_t diff;

    CryptoPP::AutoSeededRandomPool rng;

    std::string passphrase;

    // Save passphrase
    passphrase = argv[1];

    // Open file where to write the results
    crypto_out.open(CRYPTO_FILE, ios::app);
    if (!crypto_out) {
        std::cerr << "ERROR: couldn't open " << CRYPTO_FILE << std::endl;
        return 1;
    }
    get_str_time(timebuf);
    crypto_out << "[" << timebuf << "] === Starting testing cryptopp Twofish implementation ===\n\n";

    // First do some standard tests to verify the correctness and speed of the algorithm
    std::string input_name(TEST_FILENAME);

    size_t key_len = Twofish::DEFAULT_KEYLENGTH;

    SecByteBlock salt(Twofish::DEFAULT_KEYLENGTH);
    SecByteBlock iv(Twofish::BLOCKSIZE);
    size_t iterations = 8192;

    for (int i = 1; i <= 6; i++) {
        // Open the input file
        std::stringstream ss;
        ss << i;
        input.open((input_name + ss.str()).c_str());
        if (!input) {
            std::cerr << "ERROR: couldn't open " << TEST_FILENAME << i << std::endl;
            return 1;
        }
        input_enc.open((input_name + ss.str() + ".enc").c_str(), ios::out);
        if (!input_enc) {
            std::cerr << "ERROR: couldn't open " << TEST_FILENAME << i << ".enc" << std::endl;
            return 1;
        }
        input_dec.open((input_name + ss.str() + ".dec").c_str());
        if (!input_dec) {
            std::cerr << "ERROR: couldn't open " << TEST_FILENAME << i << ".dec" << std::endl;
            return 1;
        }
        rng.GenerateBlock(salt, salt.size());
        rng.GenerateBlock(iv, iv.size());

        uint64_t start = get_str_time(timebuf);
        crypto_out << "\t[" << timebuf <<"] === Start: Speed ";
        crypto_out << file_sizes[i - 1] << " - CryptoPP Twofish ===\n";

        SecByteBlock derivedkey(key_len);
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
        pbkdf.DeriveKey(derivedkey, derivedkey.size(),
                        0x00,
                        (byte *)passphrase.data(), passphrase.size(),
                        salt, salt.size(),
                        iterations
                       );

        try {
            CryptoPP::CBC_Mode<CryptoPP::Twofish>::Encryption encryptor(derivedkey, key_len, iv);
            FileSource(input, true, new StreamTransformationFilter(encryptor, new FileSink(input_enc)));
        } catch (Exception& e) {
            std::cerr << "ERROR: When trying to encrypt: " << e.what() << std::endl;
            continue;
        }
        uint64_t stop_enc = get_str_time(timebuf);

        // Save encryption duration
        crypto_out << "\t\t[" << timebuf << "] === Encryption for ";
        (stop_enc > start) ? diff = stop_enc - start : 0;
        crypto_out << file_sizes[i - 1] << " lasted " << diff << " [us]\n";

        input_enc.close();
        input_enc.open((input_name + ss.str() + ".enc").c_str(), ios::in);
        if (!input_enc) {
            std::cerr << "ERROR: couldn't open " << TEST_FILENAME << i << ".enc for read" << std::endl;
            return 1;
        }

        try {
            CBC_Mode<CryptoPP::Twofish>::Decryption decryptor(derivedkey, key_len, iv);
            FileSource(input_enc, true, new StreamTransformationFilter(decryptor, new FileSink(input_dec)));
        } catch (Exception& e) {
            std::cerr << "ERROR: When trying to decrypt: " << e.what() << std::endl;
            continue;
        }
        uint64_t stop = get_str_time(timebuf);

        // Write useful output
        std::string diff_string;
        diff_string = "diff " + input_name + ss.str() + " " + input_name + ss.str() + ".dec";
        int rc = system(diff_string.c_str());
        crypto_out << "\t\t Correctness test for " << input_name << i;
        (rc == 0) ? crypto_out << " passed\n" : crypto_out << " failed\n";
        diff = (stop > stop_enc) ? (stop - stop_enc) : 0;
        crypto_out << "\t\t[" << timebuf << "] === Decryption for ";
        crypto_out << file_sizes[i - 1] << " lasted " <<  diff << " [us]\n";
        diff = (stop > start) ? (stop - start) : 0;
        crypto_out << "\t[" << timebuf <<"] === Stop: Total time ";
        crypto_out << diff << "[us] Speed " << file_sizes[i - 1] << " - CryptoPP Twofish ===\n\n";

        std::cout << "[ " << diff << " us] Correctness/Speed: Test for file " << file_sizes[i - 1] << " ended\n";

        input.close();
        input_enc.close();
        input_dec.close();
    }

    get_str_time(timebuf);
    crypto_out << "[" << timebuf << "] === Testing botan Twofish implementation ended ===\n\n";
    crypto_out.close();

    return 0;
}
