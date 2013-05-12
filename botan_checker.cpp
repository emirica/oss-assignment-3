/*
 * Name: Emma Mirică
 * Email: emma.mirica@cti.pub.ro
 * Library: botan
 * Encryption Algorithm: Twofish
 */

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <sstream>
#include <sys/time.h>
#include <inttypes.h>
// botan headers
#include <botan/botan.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
#include <botan/sha160.h>

#define BOTAN_FILE          "tests_results/botan_checker.out"
#define TEST_FILENAME       "tests/input_"
#define TWOFISH_KEY_SIZE    32
#define TWOFISH_IV_SIZE     16
#define ENC_HEADER          "----------------- Encrypted File -----------------"
#define BUFSIZE             128

using namespace Botan;
using namespace std;

static std::ofstream botan_out;
static std::ifstream input;
static std::fstream input_enc;
static std::ofstream input_dec;
static std::string algo = "Twofish";
static std::string mode = "/CBC";
static std::string file_sizes[] = { "1MB", "8MB", "64MB", "512MB", "1GB" };

static Botan::SecureVector<Botan::byte> b64_decode(const std::string& in)
{
    Pipe pipe(new Base64_Decoder);
    pipe.process_msg(in);
    return pipe.read_all();
}

static std::string b64_encode(const Botan::SecureVector<Botan::byte>& in)
{
    Pipe pipe(new Base64_Encoder);
    pipe.process_msg(in);
    return pipe.read_all_as_string();
}

// Return in ns the current time and also, write the current time in timebuf
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

// The function that encrypts a file using Twofish algoritm
static int do_encrypt(std::string passphrase, Botan::SecureVector<Botan::byte> salt,
                      const u32bit key_len, const u32bit iv_len)
{
    // First, we turn the passphrase into an arbitrary length key to use
    // for the Twofish algorithm.
    try {
        std::auto_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-1)"));
        const u32bit PBKDF2_ITERATIONS = 8192;

        SymmetricKey key = pbkdf->derive_key(key_len, "BLK" + passphrase,
                                             &salt[0], salt.size(),
                                             PBKDF2_ITERATIONS);
        SymmetricKey mac_key = pbkdf->derive_key(16, "MAC" + passphrase,
                                                 &salt[0], salt.size(),
                                                 PBKDF2_ITERATIONS);
        InitializationVector iv = pbkdf->derive_key(iv_len, "IVL" + passphrase,
                                                    &salt[0], salt.size(),
                                                    PBKDF2_ITERATIONS);

        // Required header for the decryption phase
        input_enc << ENC_HEADER << std::endl;
        input_enc << b64_encode(salt) << std::endl;

        Pipe encryptor(new Fork(
                                new Chain(
                                          new MAC_Filter("HMAC(SHA-1)", mac_key),
                                          new Base64_Encoder,
                                          new DataSink_Stream(input_enc)
                                         ),
                                new Chain(
                                          get_cipher(algo + mode, key, iv, ENCRYPTION),
                                          new Base64_Encoder(true)
                                         )
                               )
                      );

        encryptor.start_msg();
        input >> encryptor;
        encryptor.end_msg();

        //input_enc << encryptor.read_all_as_string(0) << std::endl;
        input_enc << std::endl;
        input_enc << encryptor.read_all_as_string(1);

    } catch (std::exception& e) {
        std::cerr << "ERROR: caught exception " << e.what() << " for encrypt\n";
        botan_out.close();
        return 1;
    }

    return 0;
}

static int do_decrypt(std::string passphrase, const u32bit key_len,
                      const u32bit iv_len)
{
    int rc = 0;

    try {
        std::string header, salt_str, mac_str;
        std::getline(input_enc, header);
        std::getline(input_enc, salt_str);
        std::getline(input_enc, mac_str);

        if (header != ENC_HEADER) {
            std::cerr << "ERROR: File to decrypt doesn't contain encryption" <<std::endl;
            return 1;
        }
        std::auto_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-1)"));
        const u32bit PBKDF2_ITERATIONS = 8192;

        Botan::SecureVector<Botan::byte> salt = b64_decode(salt_str);
        SymmetricKey key = pbkdf->derive_key(key_len, "BLK" + passphrase,
                                             &salt[0], salt.size(),
                                             PBKDF2_ITERATIONS);
        SymmetricKey mac_key = pbkdf->derive_key(16, "MAC" + passphrase,
                                                 &salt[0], salt.size(),
                                                 PBKDF2_ITERATIONS);
        InitializationVector iv = pbkdf->derive_key(iv_len, "IVL" + passphrase,
                                                    &salt[0], salt.size(),
                                                    PBKDF2_ITERATIONS);

        Pipe decryptor(new Base64_Decoder,
                       get_cipher(algo + mode, key, iv, DECRYPTION),
                       new Fork(
                                0,
                                new Chain(
                                          new MAC_Filter("HMAC(SHA-1)", mac_key),
                                          new Base64_Encoder
                                         )
                               )
                      );

        decryptor.start_msg();
        input_enc >> decryptor;
        decryptor.end_msg();

        std::string our_mac = decryptor.read_all_as_string(1);

        if (our_mac != mac_str) {
            std::cerr << "WARNING: MAC in message failed to verify\n";
            rc = 1;
        }

        input_dec << decryptor.read_all_as_string(0);

    } catch(std::exception& e) {
        std::cerr << "ERROR: caught exception " << e.what() << " for decrypt\n";
        botan_out.close();
        rc = 1;

    }

    return rc;
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

    Botan::LibraryInitializer init;
    AutoSeeded_RNG rng;

    std::string passphrase;

    // Save passphrase
    passphrase = argv[1];

    // Open file where to write the results
    botan_out.open(BOTAN_FILE, ios::app);
    if (!botan_out) {
        std::cerr << "ERROR: couldn't open " << BOTAN_FILE << std::endl;
        return 1;
    }
    get_str_time(timebuf);
    botan_out << "[" << timebuf << "] === Starting testing botan Twofish implementation ===\n\n";

    // First do a standard test to verify the correctness of the algorithm. The
    // output obtained (encryption) will be checked against the output
    // obtained with the implementation from the other two libraries.
    std::string input_name(TEST_FILENAME);
    input.open((input_name + "1").c_str());
    if (!input) {
        std::cerr << "ERROR: couldn't open " << TEST_FILENAME << "1" << std::endl;
        return 1;
    }
    input_enc.open((input_name + "1.enc").c_str(), ios::out);
    if (!input_enc) {
        std::cerr << "ERROR: couldn't open " << TEST_FILENAME << "1.enc" << std::endl;
        return 1;
    }
    input_dec.open((input_name + "1.dec").c_str());
    if (!input_dec) {
        std::cerr << "ERROR: couldn't open " << TEST_FILENAME << "1.dec" << std::endl;
        return 1;
    }
    get_str_time(timebuf);
    botan_out << "\t[" << timebuf <<"] === Start: Correctness - Botan Twofish ===\n";

    const BlockCipher* cipher_proto = global_state().algorithm_factory().prototype_block_cipher(algo);
    if (!cipher_proto) {
        std::cerr << "ERROR: Block cipher unknown " << algo << std::endl;
        return 1;
    }

    const u32bit key_len = cipher_proto->maximum_keylength();
    const u32bit iv_len = cipher_proto->block_size();

    Botan::SecureVector<Botan::byte> salt(8);
    rng.randomize(&salt[0], salt.size());

    do_encrypt(passphrase, salt, key_len, iv_len);
    input_enc.close();
    input_enc.open((input_name + "1.enc").c_str(), ios::in);
    if (!input_enc) {
        std::cerr << "ERROR: couldn't open " << input_name << "1.enc for read\n";
        return 1;
    }
    int rc = do_decrypt(passphrase, key_len, iv_len);

    botan_out << "\t\t Correctness test ";
    (rc == 0) ? botan_out << "passed\n" : botan_out << "failed\n";

    get_str_time(timebuf);
    botan_out << "\t[" << timebuf << "] === Stop: Correctness - Botan Twofish ===\n\n";
    input.close();
    input_dec.close();
    input_enc.close();


    // Test the speed of this implementation using different file sizes.
    // The output will be appended to the BOTAN_FILE and in the end the
    // three implementations will be checked against each other.
    for (int i = 2; i <= 6; i++) {
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
        uint64_t start = get_str_time(timebuf);
        botan_out << "\t[" << timebuf <<"] === Start: Speed ";
        botan_out << file_sizes[i - 2] << " - Botan Twofish ===\n";

        rng.randomize(&salt[0], salt.size());
        do_encrypt(passphrase, salt, key_len, iv_len);
        uint64_t stop_enc = get_str_time(timebuf);

        // Save encryption duration
        botan_out << "\t\t[" << timebuf << "] === Encryption for ";
        (stop_enc > start) ? diff = stop_enc - start : 0;
        botan_out << file_sizes[i - 2] << " lasted " << diff << " [us]\n";

        input_enc.close();
        input_enc.open((input_name + ss.str() + ".enc").c_str(), ios::in);
        if (!input_enc) {
            std::cerr << "ERROR: couldn't open " << TEST_FILENAME << i << ".enc for read" << std::endl;
            return 1;
        }

        rc = do_decrypt(passphrase, key_len, iv_len);
        uint64_t stop = get_str_time(timebuf);

        // Write useful output
        botan_out << "\t\t Correctness test for " << input_name << i;
        (rc == 0) ? botan_out << " passed\n" : botan_out << " failed\n";
        (stop > stop_enc) ? diff = stop - stop_enc : diff = 0;
        botan_out << "\t\t[" << timebuf << "] === Decryption for ";
        botan_out << file_sizes[i - 2] << " lasted " <<  diff << " [us]\n";
        (stop > start) ? diff = stop - start : diff = 0;
        botan_out << "\t[" << timebuf <<"] === Stop: Total time ";
        botan_out << diff << "[us] Speed " << file_sizes[i - 2] << " - Botan Twofish ===\n\n";

        input.close();
        input_enc.close();
        input_dec.close();
        std::cout << "[ " << diff << " us] Test for file " << file_sizes[i - 2] << " ended\n";
    }

    get_str_time(timebuf);
    botan_out << "[" << timebuf << "] === Testing botan Twofish implementation ended ===\n\n";
    botan_out.close();

    return 0;
}
