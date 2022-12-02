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

#include <fmt/format.h>

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
static string headers_text[];
static string inline_text[];

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

/**
 * @brief Function to encrypt password
 * 
 * @param input decrypted password
 * @param key key to encrypt
 * @param iv ???
 * @return encrypted password
 */
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

/**
 * @brief Function to decrypt password
 * 
 * @param cipher encrypted password
 * @param key key to decrypt
 * @param iv ???
 * @return decrypted password
 */
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

/**
 * @brief Parse json file
 * 
 * @param filename path to file to parse
 * @return parsed data from json file
 */
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

/**
 * @brief Write changes to json file (for example crypted pass)
 * 
 * @param filename name of file to write
 * @param tmp boost::json::value to write to file
 */
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

/**
 * @brief Check password encryption in json file
 */
void checkFirstLaunch() {
    json::value root;
    root = fileParsing("./mail.json");

    //check for first launch, if no, then encrypt pass and write it to file
    if ((root.at("encrPass") == 0) || (root.at("encrPass") == "")) {
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

/**
 * @brief Get the Current Date object
 * 
 * @return date in char array type
 */
const char* getCurrentDate() {
    time_t now = time(0);
    struct tm ts;
    char *buf = new char;
    ts = *localtime(&now);
    std::strftime(buf, sizeof(ts), "%Y-%m-%d.%X", &ts);
    
    return buf;
}

size_t readCallback(char *ptr, size_t size, size_t nmemb, void *userdata)
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

/**
 * @brief Parse boost::json to char*
 * 
 * @param tmp json value to parse (root.at("..."))
 * @return parsed value
 */
const char* serialize_to_char(json::value tmp) {
    const char* tmp1;
    string tmp2 = json::serialize(tmp);
    tmp2.pop_back();
    tmp2.erase(0, 1);
    tmp1 = tmp2.c_str();
    return tmp1;
}

/**
 * @brief Send mail only with args
 * 
 * @param fileToSend file to send with mail
 * @param mailTo address to mail to
 * @param mailFrom address to mail from
 * @param smtpURL smtp URL address
 * @return CURL answer
 */
int curlSend(const char* file_to_send, const char* mail_to, const char* mail_from, const char* smtp_url, const char* pass) {
    FILE *ftu = fopen(file_to_send, "r");

    CURL *curl;
    CURLcode res = CURLE_OK;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    struct curl_slist *recipients = NULL;

    const char* current_date = getCurrentDate();

    headers_text[0] = fmt::format("Date: {}", current_date);
    headers_text[1] = fmt::format("To: {}", mail_to);
    headers_text[2] = fmt::format("From: ", mail_from);
    headers_text[3] = fmt::format("Subject: {}", "test");
    
    if (!ftu) 
        return 1;
    if (fstat(fileno(ftu), &file_info)) 
        return 1;
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_USERNAME, mail_from);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
        curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=PLAIN");
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mail_from);

        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
        curl_easy_setopt(curl, CURLOPT_READDATA, ftu);
        curl_easy_setopt(curl, CURLOPT_FILE, ftu);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

        recipients = curl_slist_append(recipients, mail_to);
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

/**
 * @brief Send mail with json file
 * 
 * @param fileToSend file to send with mail
 * @param mailTo address to mail to
 * @return CURL answer
 */
int curlSend(const char* fileToSend, const char* tmp) {
    //vars for work with files
    FILE *ftu = fopen(fileToSend, "rb");

    //vars for work with curl
    CURL *curl;
    CURLcode res = CURLE_OK;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    struct curl_slist *recipients = NULL;
    mailTo = (char*)tmp;

    const char *currentDate = getCurrentDate();
    
    //vars for work with json
    json::value root;
    
    //parsing json
    root = fileParsing("./mail.json");
    
    mailFrom = (char*)serialize_to_char(root.at("mailAddress"));
    smtpURL = (char*)serialize_to_char(root.at("smtpAddress"));

    //payloadText = fmt::format("Date: {}\r\nTo: {}\r\nFrom: {}\r\nSubject: {}\r\n\r\n{}\r\n", 
    //    currentDate, mailTo, mailFrom, "test", "test");
    
    if (!ftu)
        return 1;
    if (fstat(fileno(ftu), &file_info) != 0)
        return 1;
    
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, *smtpURL);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCallback);
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
    curlSend("./mail.cpp", "", "", "", "");
    return EXIT_SUCCESS;
}