#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <filesystem>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <chrono>

using namespace std;
namespace fs = std::filesystem;

std::set<string> setfOfLine;
string invalid_characters = "<>:\"/\\|?*|";

string hash_password(const string& password, string source_file) {
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    unsigned char sha1_hash[SHA_DIGEST_LENGTH];
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

    MD5((unsigned char*)password.c_str(), password.size(), md5_hash);
    SHA1((unsigned char*)password.c_str(), password.size(), sha1_hash);
    SHA256((unsigned char*)password.c_str(), password.size(), sha256_hash);

    std::ostringstream md5_ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        md5_ss << std::hex << std::setw(2) << std::setfill('0') << (int)md5_hash[i];

    std::ostringstream sha1_ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i)
        sha1_ss << std::hex << std::setw(2) << std::setfill('0') << (int)sha1_hash[i];

    std::ostringstream sha256_ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sha256_ss << std::hex << std::setw(2) << std::setfill('0') << (int)sha256_hash[i];

    string line = password + "|" + md5_ss.str() + "|" + sha1_ss.str() + "|" + sha256_ss.str() + "|" + source_file;
    return line;
}

void addToSet() {
    for (const auto& entry : fs::directory_iterator("..\\..\\Unproccessed-Passwords")) {
        ifstream infile(entry.path());
        string file_name = entry.path().filename().string();
        string line;

        while (std::getline(infile, line))
        {
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            string hashed_password = hash_password(line, entry.path().filename().string());
            setfOfLine.insert(hashed_password);
        }
        infile.close();
        fs::path source = "..\\..\\Unproccessed-Passwords\\" + file_name;
        fs::path destination = "..\\..\\Proccessed";

        try {
            fs::copy(source, destination, fs::copy_options::overwrite_existing);
            fs::remove(source);
            std::cout << "Dosya baþarýyla taþýndý." << std::endl;
        }
        catch (fs::filesystem_error& e) {
            std::cerr << "Dosya taþýnamadý: " << e.what() << std::endl;
        }
    }
}

void index_passwords() {
    addToSet();
    int i = 0;
    int j = 0;
    for (auto line : setfOfLine) {
        line.erase(line.find_last_not_of(" \n\r\t") + 1);
        char first_char = line.front();
        string index_folder;
        if (invalid_characters.find(first_char) != std::string::npos || first_char > 127 ) {
            index_folder = "..\\..\\Index\\unknown";
            fs::create_directory(index_folder);
            ofstream index_file(index_folder + "\\unknow_" + to_string(i) + ".txt", std::ios_base::app);
            auto file_size = fs::file_size(index_folder + "\\unknow_" + to_string(i) + ".txt");
            if (file_size > 1843200) { i++; }
            index_file << line << std::endl;
            index_file.close();
            continue;
        }
        else if (first_char > 96 && first_char < 123) {
            index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char)) + "_";
        }
        else {
            index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char));
        }
        if (!fs::exists(index_folder)) {
            try {
                fs::create_directory(index_folder);
            }
            catch (const fs::filesystem_error& e) {
                cout << e.what();
            }
        }

        ofstream index_file(index_folder + "\\" + string(1, std::tolower(first_char)) + "_" + to_string(i) + ".txt", std::ios_base::app);
        auto file_size = fs::file_size(index_folder + "\\" + string(1, std::tolower(first_char)) + "_" + to_string(i) + ".txt");
        if (file_size > 1843200) { i++; }
        index_file << line << std::endl;
        index_file.close();
    }
}

void saveOnly(string password) {
    string line = hash_password(password, "unknown");
    string index_folder;
    char first_char = password[0];
    if (invalid_characters.find(first_char) != std::string::npos || first_char > 127) {
        index_folder = "..\\..\\Index\\unknown";
    }
    else if (first_char > 96 && first_char < 123) {
        index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char)) + "_";
    }
    else {
        index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char));
    }
    if (!fs::exists(index_folder)) {
        try {
            fs::create_directory(index_folder);
        }
        catch (const fs::filesystem_error& e) {
            cout << e.what();
        }
    }

    ofstream index_file(index_folder + "\\" + string(1, std::tolower(first_char)) + "_" + ".txt", std::ios_base::app);
    auto file_size = fs::file_size(index_folder + "\\" + string(1, std::tolower(first_char)) + "_" + ".txt");
    index_file << line << std::endl;
    index_file.close();
    cout << "Password has saved." << endl;
}


std::string getFirstPart(const std::string& str, char delimiter) {
    size_t pos = str.find(delimiter);
    if (pos != std::string::npos) {
        return str.substr(0, pos);
    }
    else {
        return str;
    }
}

void search(string password) {
    password.erase(password.find_last_not_of(" \n\r\t") + 1);
    char first_char = password.front();
    string index_folder;
    set<string> setOfpass;
    if (invalid_characters.find(first_char) != std::string::npos || first_char > 127) {
        index_folder = "..\\..\\Index\\unknown";
    }
    else if (first_char > 96 && first_char < 123){
        index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char)) + "_";
    }
    else {
        index_folder = "C:\\Users\\Caner\\Desktop\\TermProject\\Index\\" + string(1, std::tolower(first_char));
    }
    for (const auto& entry : fs::directory_iterator(index_folder)) {
        ifstream infile(entry.path());
        string file_name = entry.path().filename().string();
        string line;
        while (std::getline(infile, line)) {
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
            line = getFirstPart(line, '|');
            setOfpass.insert(line);
        }
    }
    auto result = setOfpass.find(password);
    if (result != setOfpass.end()) {
        std::cout << "Password found: " << *result << std::endl;
    }
    else {
        std::cout << "Password will add to Index file..." << std::endl;
        saveOnly(password);
    }
}




int main() {

    int selection = 0;
    

    while (selection != 99) {
        cout << "---------------------------------------------------" << endl;
        cout << "-- Press 1 for index the unprocccessed password." << endl;
        cout << "-- Press 2 for search a password." << endl;
        cout << "-- Press 99 to EXIT." << endl;
        cout << "-- SELECTION: ";
        std::cin >> selection;

        if (selection == 1) {
            index_passwords();
            cout << "Indexing completed successfully!" << endl;
        }
        else if (selection == 2) {
            string pass;
            cout << "Enter password: ";
            cin >> pass;
            auto start = std::chrono::high_resolution_clock::now();
            search(pass);
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> duration = end - start;
            cout << "Function execution time: " << duration.count() << " milliseconds" << std::endl;
        }
        else if (selection == 99){
            return 0;
        }
        else {
            cout << "Please enter a valid number." << endl;
        }
    }
    return 0;
}
