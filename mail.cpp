#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/stream_parser.hpp>
#include <boost/json/system_error.hpp>
#include <ctime>
#include <curl/curl.h>
#include <curl/easy.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include <curlpp/cURLpp.hpp>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/base64.h>
#include <boost/json/src.hpp>
#include <fcntl.h>
#include <sys/stat.h>

namespace json = boost::json;

static char* mailTo;
static char* mailFrom;
static char* smtpURL;
static char* payloadText;

std::string encrypt(const std::string&, const std::vector<uint8_t>&, const std::vector<uint8_t>);
std::string decrypt(const std::string&, const std::vector<uint8_t>&, const std::vector<uint8_t>);
json::value fileParsing(const char*);
void writeToFile(const char*, json::value);
void checkFirstLaunch();
const char* getCurrentDate();
static size_t payloadSource(char*, size_t, size_t, void*);

struct uploadStatus {
    size_t bytesRead;
};

//encryption function
std::string encrypt(const std::string& input, const std::vector<uint8_t>& key, const std::vector<uint8_t> iv) {
    std::string cipher;

    auto aes = CryptoPP::AES::Encryption(key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes, iv.data());
    
    CryptoPP::StringSource ss(
        input,
        true,
        new CryptoPP::StreamTransformationFilter(
            aes_cbc,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(cipher)
            )
        )
    );

    return cipher;
}

//decryption function
std::string decrypt(const std::string& cipher, const std::vector<uint8_t>& key, const std::vector<uint8_t> iv) {
    std::string plain_text;

    auto aes = CryptoPP::AES::Decryption(key.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes, iv.data());

    CryptoPP::StringSource ss(
        cipher,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(
                aes_cbc,
                new CryptoPP::StringSink(plain_text)
            )
        )
    );

    return plain_text;
}

//function to parse from json
json::value fileParsing(const char* filename) {
    std::ifstream is(filename, std::ifstream::binary);
    
    is.seekg(0, is.end);
    int length = is.tellg();
    is.seekg(0, is.beg);

    char* buf = new char [length];

    is.read(buf, length);
    
    json::value tmp;
    json::error_code ec;

    tmp = json::parse(buf, ec);
    if (ec) return 0;
    
    delete[] buf;
    return tmp;
}

//function to write to json
void writeToFile(const char* filename, json::value tmp) {
    std::ofstream fs(filename, std::ofstream::out);
    const char* buf;
    std::string buff;

    buff = json::serialize(tmp);
    buf = buff.data();
    
    fs.open(filename);
    fs.clear();
    fs.write(buf, buff.length());
    fs.close();

    delete[] buf;
}

//function to check pass encryptin in json
void checkFirstLaunch() {
    json::value root;
    root = fileParsing("./mail.json");

    //check for first launch, if no, then encrypt pass and write it to file
    if (root.at("encrPass") == 0) {
        //vars for encr/decr
        static constexpr size_t AES_KEY_SIZE = 256 / 8;  
        std::vector<uint8_t> key(AES_KEY_SIZE);
        std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
        std::string decrPass;
        std::string encrPass;

        decrPass = json::serialize(root.at("decrPass"));
        decrPass.pop_back();
        decrPass.erase(0, 1);
        encrPass = encrypt(decrPass, key, iv);
    
        root.at("encrPass") = encrPass;
        root.at("decrPass") = 0;
        writeToFile("./mail.json", root);
    }
}

//function to return current date
const char* getCurrentDate() {
    time_t now = time(0);
    struct tm ts;
    char *buf;
    ts = *localtime(&now);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &ts);
    
    return buf;
}

static size_t payloadSource(char *ptr, size_t size, size_t nmemb, void *userp) {
    struct uploadStatus *uploadCtx = (struct uploadStatus *)userp;
    const char *data;

    size_t room = size * nmemb;
       if ((size == 0) || (nmemb = 0) || (size * nmemb < 1)) 
          return 1;
    data = &payloadText[uploadCtx->bytesRead];

    if (data) {
        size_t len = strlen(data);
        if (room < len)
            len = room;
        memcpy(ptr, data, len);
        uploadCtx->bytesRead += len;

        return len;
    }

    return 0;
}

size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    FILE *readhere = (FILE *)userdata;
    curl_off_t nread;
 
    /* copy as much data as possible into the 'ptr' buffer, but no more than
      'size' * 'nmemb' bytes! */
    size_t retcode = fread(ptr, size, nmemb, readhere);
 
    nread = (curl_off_t)retcode;
 
    fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
            " bytes from file\n", nread);
    return retcode;
}

int curlSend(const char* fileToSend, const char* mailTo) {
    //vars for work with files
    FILE *ftu = fopen(fileToSend, "rb");

    //vars for work with curl
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    struct curl_slist *recipients = NULL;
    struct uploadStatus uploadCtx = { 0 };

    const char *currentDate = getCurrentDate();
    
    //vars for work with json
    json::value root;
    
    //parsing json
    root = fileParsing("./mail.json");
    
    std::string mf = json::serialize(root.at("mailAddress"));
    mf.pop_back();
    mf.erase(0,1);
    mailFrom = (char*)mf.c_str();
    std::string sURL = json::serialize(root.at("smtpAddress"));
    sURL.pop_back();
    sURL.erase(0,1);
    smtpURL = (char*)sURL.c_str();

    sprintf(payloadText, 
        "Date: %s\r\n"
        "To: %s\r\n"
        "From: %s\r\n"
        "Subject: SMTP Request test.\r\n"
        "\r\n"
        "Test mail.\r\n",
        currentDate, mailTo, mailFrom);
    
    if (!ftu)
        return 1;
    if (fstat(fileno(ftu), &file_info) != 0)
        return 1;
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, *smtpURL);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, ftu);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, *mailFrom);
        recipients = curl_slist_append(recipients, mailTo);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
        } else {
            /* now extract transfer info */
            curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD_T, &speed_upload);
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &total_time);
 
            fprintf(stderr, "Speed: %lu bytes/sec during %lu.%06lu seconds\n",
                    (unsigned long)speed_upload,
                    (unsigned long)(total_time / 1000000),
                    (unsigned long)(total_time % 1000000));
        }    
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }

    return (int)res;
}

//main function
int main(int argc, char** argv) {
    if ((argv[1] == (std::string)"--help") || (argv[1] == (std::string)"-h")) {
        printf(
            "Using:\r\n"
            "       mail path\\to\\file mail@example.org\r\n"
            "Help:\r\n"
            "-h       --help                    Show this message, and exit.\r\n");
        return 0;
    } else {
        checkFirstLaunch();
        curlSend(argv[1], argv[2]);
        return 0;
    }
    return 0;
}
