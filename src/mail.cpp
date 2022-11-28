#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/stream_parser.hpp>
#include <boost/json/system_error.hpp>
#include <boost/json/src.hpp>

#include <curl/curl.h>
#include <curl/easy.h>

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string>
#include <iomanip>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctime>
#include <format>

#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/base64.h>

namespace json = boost::json;
using std::vector;
using std::string;

static char* mailTo;
static char* mailFrom;
static char* smtpURL;
static string payloadText;

string encrypt(const string&, const vector<uint8_t>&, const vector<uint8_t>);
string decrypt(const string&, const vector<uint8_t>&, const vector<uint8_t>);
json::value fileParsing(const char*);
void writeToFile(const char*, json::value);
void checkFirstLaunch();
const char* getCurrentDate();
static size_t payloadSource(char*, size_t, size_t, void*);

struct Option {
    string option;
    string alternative;
    string message;
    string value;
};

struct uploadStatus {
    size_t bytesRead;
};

//encryption function
string encrypt(const string& input, const vector<uint8_t>& key, const vector<uint8_t> iv) {
    string cipher;

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
string decrypt(const string& cipher, const vector<uint8_t>& key, const vector<uint8_t> iv) {
    string plain_text;

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
    string buff;

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
        vector<uint8_t> key(AES_KEY_SIZE);
        vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
        string decrPass;
        string encrPass;

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
    std::strftime(buf, sizeof(ts), "%Y-%m-%d.%X", &ts);
    
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

const char* serialize_to_char(json::value tmp) {
    const char* tmp1;
    string tmp2 = json::serialize(tmp);
    tmp2.pop_back();
    tmp2.erase(0, 1);
    tmp1 = tmp2.c_str();
    return tmp1;
}

int curlSend(const char* fileToSend, const char* mailTo, const char* mailFrom, const char* smtpURL) {
    FILE *ftu = fopen(fileToSend, "r");

    CURL *curl;
    CURLcode res = CURLE_OK;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    struct curl_slist *recipients = NULL;
    struct uploadStatus uploadCtx = { 0 };

    const char* currentDate = getCurrentDate();

    payloadText = std::format("Date: {}\r\nTo: {}\r\nFrom: {}\r\nSubject: {}\r\n\r\n{}\r\n", 
        currentDate, mailTo, mailFrom, "test", "test");
    if (!ftu) 
        return 1;
    if (fstat(fileno(ftu), &file_info)) 
        return 1;
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, smtpURL);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, ftu);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mailFrom);
        recipients = curl_slist_append(recipients, mailTo);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
        
        res = curl_easy_perform(curl);
        
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", 
                    curl_easy_strerror(res));
        } else {
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

    delete [] ftu;
    return (int)res;
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
    
    mailTo = (char*)serialize_to_char(root.at("mailAddress"));
    smtpURL = (char*)serialize_to_char(root.at("smtpAddress"));

    payloadText = std::format("Date: {}\r\nTo: {}\r\nFrom: {}\r\nSubject: {}\r\n\r\n{}\r\n", 
        currentDate, mailTo, mailFrom, "test", "test");
    
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
    
    delete [] ftu;
    return (int)res;
}

/**
 * @brief Shows help message
 * 
 * @param options available options
 */
void help_message(const vector<Option> &options) {
    std::cout << "Usage: " << std::endl
        << "\tmail \033[33m-f \033[34mpath/to/file.txt \033[33m-mt \033[34mmail@example.com\033[0m" << std::endl
        << "Options: " << std::endl; 

    for(vector<Option>::const_iterator i = options.begin(); i != options.end(); i++) {
        std::cout << "\t" << "\033[33m" << std::left << std::setw(4) << i->option << "\033[0m";
        if (!i->alternative.empty()) {
            std::cout << "| " << "\033[33m" << std::left << std::setw(12) <<  i->alternative << "\033[0m";
        } else {
      std::cout << std::setw(14) << " ";
    }
        if (!i->value.empty()) {
            std::cout << "\033[34m" << std::left << std::setw(15)  << " <" + i->value + ">" << "\033[0m";
        } else {
      std::cout << std::setw(15) << " ";
    }
        std::cout << "-- " << i->message << std::endl;
    }
}

/**
 * @brief Finds option in the list of options
 * 
 * @param args arguments
 * @param option option
 * @return empty string if not found, "true" or <value> if found
 */
string find_args(const vector<string> &args, Option option) {
    for (vector<string>::const_iterator i = args.begin(); i != args.end(); i++) {
        if ((*i).compare(option.option) == 0 || (*i).compare(option.alternative)) {
            if (!option.value.empty()) {
                if (i + 1 == args.end()) {
                    std::cout << "\033[31m" << "Value for option '" << option.option << "' was not provided!" << std::endl;
                    exit(1);
                } else {
                    return *(i + 1);
                }
            } else {
                return "true";
            }
        }
    }
    return "";
}

int main(int argc, char** argv) {
    vector<Option> options = {
        {"-h",  "--help",       "Get help message",         ""},
        {"-mt", "--mailto",     "Set mail to send to",      "string"},
        {"-f",  "--file",       "Set file name",            "string"},
        {"-mf", "--mailfrom",   "Set mail to send from",    "string"},
        {"-s",  "--smtp",       "Set smtp server url",      "string"}
    };

    vector<string> args(argv, argv + argc);
    // if (args.size() < 2 || !find_args(args, options[0]).empty()) {
    //     help_message(options);
    //     return EXIT_FAILURE;
    // }
    // string result = find_args(args, options[2]);
    // if (!result.empty()) {
    //     std::cout << "\033[31mNOT IMPLEMENTED | Value: " << result << "\033[0m" << std::endl;
    // }
    curlSend("./mail.json", "", "", "");
    return EXIT_SUCCESS;
}