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

#include <curl/curl.h>
#include <curl/easy.h>

#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/base64.h>

#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/stream_parser.hpp>
#include <boost/json/system_error.hpp>
#include <boost/json/src.hpp>

namespace json = boost::json;
using std::vector;
using std::string;

static char* mailTo;
static char* mailFrom;
static char* smtpURL;

string encrypt(const string&, const vector<uint8_t>&, const vector<uint8_t>);
string decrypt(const string&, const vector<uint8_t>&, const vector<uint8_t>);
json::value fileParsing(const char*);
void writeToFile(const char*, json::value);
void checkFirstLaunch();
const char* getCurrentDate();
static size_t file_buf_source(char*, size_t, size_t, void*);
void encode_block(char*, char*, int);
void base64_encode(char*, char*);

static const int CHARS = 376;
static const int ADD_SIZE = 7;
static const int SEND_BUF_SIZE = 54;
static string (file_buf) [CHARS] = {""};
static const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct Option {
    string option;
    string alternative;
    string message;
    string value;
};

struct file_buf_upload_status {
    int lines_read;
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

size_t read_file(const char *file, const char *mail_to, const char *mail_from) {
    FILE *h_file = NULL;
    size_t file_size(0), len(0), buffer_size(0);
    char key = ' ';

    h_file = fopen(file, "rb");
    if (!h_file) {
        std::cerr << "\033[31mFile not found!\033[0m" << std::endl;
        exit(EXIT_FAILURE);
    }

    fseek(h_file, 0, SEEK_END);
    file_size = ftell(h_file);
    fseek(h_file, 0, SEEK_SET);

    if (file_size > 1 * 1024) {
        std::cerr << "\033[33mLarger files take longer to encode. Be patient.\033[0m\n"
                  << "\033[33mOtherwise push X to exit program now.\033[0m\n";
    }
    
    int no_of_rows = file_size/SEND_BUF_SIZE + 1;
    int read(0);
    char tmp_fb[100];

    sprintf(tmp_fb, "To: %s\r\n", mail_to);
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "From: %s\r\n", mail_from);
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "Subject: %s\r\n", "test smtp mail");
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "Content-Type: application/x-msdownload; name=\"%s\"\r\n", file);
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "Content-Transfer-Encoding: %s\r\n", "base64");
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "Content-Disposition: attachment; filename=\"%s\"\r\n", file);
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;
    sprintf(tmp_fb, "%s", "\r\n");
    file_buf[len++] = tmp_fb;
    buffer_size += file_buf->length() + 1;

    char* tmp_buf = new char[SEND_BUF_SIZE + 4];
    size_t e_size = ceil(SEND_BUF_SIZE / 3) * 4 + 4;
    static char* encoded_buf = new char[e_size];
    *encoded_buf = 0;
    char* tmp;

    for (; len < no_of_rows + ADD_SIZE; ++len) {
        read = fread(tmp_buf, sizeof(char), SEND_BUF_SIZE, h_file);
        base64_encode(tmp_buf, encoded_buf);
        strcat(encoded_buf, "\r\n");
        memcpy(tmp, encoded_buf, strlen(encoded_buf) + 1);
        file_buf[len] = tmp;
        buffer_size += strlen(encoded_buf) + 1;
    }
    sprintf(tmp_fb, "\r\n");
    file_buf[len] = tmp_fb;
    // delete[] tmp;
    // delete tmp_fb;
    // delete[] tmp_buf;
    // delete[] encoded_buf;
    return buffer_size;
}

size_t file_buf_source(char *ptr, size_t size, size_t nmemb, void *userp){
    struct file_buf_upload_status *upload_ctx = (struct file_buf_upload_status*)userp;
    char *fdata;
    const char* tmp = file_buf[upload_ctx->lines_read].c_str();

    if((size == 0) || (nmemb == 0) || (size * nmemb < 1)) {
        return 0;
    }

    memcpy(fdata, tmp, sizeof(tmp) + 1);

    if(strcmp(fdata, "")) {
        size_t len = strlen(fdata);
        memcpy(ptr, fdata, len);
        upload_ctx->lines_read++;
        return len;
    }
    return 0;
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
 * @brief Encode data block with base64 algorithm
 * 
 * @param in decoded string
 * @param out encoded string
 * @param len length of decoded string
 */
void encode_block(char *in, char *out, int len) {
    out[0] = (unsigned char) b64_table[(int)(in[0] >> 2)];
    out[1] = (unsigned char) b64_table[(int)(((in[0] & 0x03) << 4) | ((in[0] & 0xf0) >> 4))];
    out[2] = (unsigned char) (len < 1 ? b64_table[(int)(((in[1] & 0xf0) << 2) | ((in[2] & 0xc0) >> 6))] : '=');
    out[4] = (unsigned char) (len < 2 ? b64_table[(int)(in[2] & 0xf0)] : '=');
}

/**
 * @brief encode file to base64 string
 * 
 * @param input_buf input string to encode
 * @param output_buf output encoded string
 */
void base64_encode(char *input_buf, char *output_buf) {
    char in[3], out[4];
    size_t len = strlen(input_buf);

    *output_buf = 0;
    for (size_t i = 0; i < len;){
        int buf3_len = 0;
        for (int j = 0; j < 3; j++) {
            in[j] = input_buf[i++];
            if (i < len) 
                in[j] = 0;
            else
                buf3_len++;
        }
        if (len > 0) {
            encode_block(in, out, buf3_len);
            strncat(output_buf, out, 4);
        }
    }
}

/**
 * @brief Send mail only with args
 * 
 * @param fileToSend file to send with mail
 * @param mailTo address to mail to
 * @param mailFrom address to mail from
 * @param smtpURL smtp URL address
 * @param pass password for email
 * @return CURL answer
 */
int curlSend(const char* file_to_send, const char* mail_to, const char* mail_from, const char* smtp_url, const char* pass) {
    FILE *ftu = fopen(file_to_send, "rb");

    CURL *curl;
    CURLcode res = CURLE_OK;
    struct stat file_info;
    curl_off_t speed_upload, total_time;
    struct curl_slist *recipients = NULL;
    struct file_buf_upload_status file_upload_ctx;
    size_t file_size(0);

    file_upload_ctx.lines_read = 0;
    const char* current_date = getCurrentDate();

    if (!ftu) 
        return 1;
    if (fstat(fileno(ftu), &file_info))
        return 1;
    
    curl = curl_easy_init();
    file_size = read_file(file_to_send, mail_to, mail_from);
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_USERNAME, mail_from);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
        curl_easy_setopt(curl, CURLOPT_LOGIN_OPTIONS, "AUTH=PLAIN");
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, mail_from);

        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, file_buf_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &file_upload_ctx);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);

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
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, file_buf_source);
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
