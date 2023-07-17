#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

#include <windows.h>
#include <wincrypt.h>

#pragma comment (lib, "advapi32")

#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | 12)
#endif

#ifndef MS_ENH_RSA_AES_PROV
#define MS_ENH_RSA_AES_PROV "Microsoft Enhanced RSA and AES Cryptographic Provider"
#endif

bool encryptData(const std::string& data, const std::string& password, BYTE** encryptedData, DWORD* encryptedDataLen);
bool decryptData(const BYTE* encryptedData, DWORD encryptedDataLen, const std::string& password, std::string& decryptedData);

bool encryptData(const std::string& data, const std::string& password, BYTE** encryptedData, DWORD* encryptedDataLen) {
    // Define the encryption algorithm to use
    ALG_ID algorithm = CALG_AES_256;

    // Create a hash object
    HCRYPTPROV hCryptProv;
    HCRYPTHASH hHash;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
        return false;

    // Hash the password
    if (!CryptHashData(hHash, (BYTE*)password.c_str(), password.size(), 0))
        return false;

    // Create a session key from the hash object
    HCRYPTKEY hKey;
    if (!CryptDeriveKey(hCryptProv, algorithm, hHash, 0, &hKey))
        return false;

    // Destroy the hash object
    CryptDestroyHash(hHash);

    // Encrypt the data
    DWORD dataLen = data.size();
    DWORD bufferLen = dataLen + (algorithm == CALG_RC2 ? 8 : 16);
    *encryptedData = new BYTE[bufferLen];
    memcpy(*encryptedData, data.c_str(), dataLen);
    if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, *encryptedData, &dataLen, bufferLen))
        return false;

    *encryptedDataLen = dataLen;

    // Destroy the session key and release the provider handle
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return true;
}

bool decryptData(const BYTE* encryptedData, DWORD encryptedDataLen, const std::string& password, std::string& decryptedData) {
    // Initialize the CryptoAPI
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error acquiring cryptographic context: " << GetLastError() << std::endl;
        return false;
    }

    // Create a hash object
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        std::cerr << "Error creating hash object: " << GetLastError() << std::endl;
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Hash the password
    if (!CryptHashData(hHash, (BYTE*)password.data(), password.size(), 0)) {
        std::cerr << "Error hashing password: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Create a session key from the hash object
    HCRYPTKEY hKey;
    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "Error deriving key: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        return false;
    }

    // Destroy the hash object
    CryptDestroyHash(hHash);

    // Decrypt the data
    DWORD dataSize = encryptedDataLen;
    BYTE* data = new BYTE[dataSize];
    memcpy(data, encryptedData, dataSize);
    if (!CryptDecrypt(hKey, 0, TRUE, 0, data, &dataSize)) {
        std::cerr << "Error decrypting data: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
        delete[] data;
        return false;
    }

    // Save the decrypted data
    decryptedData.assign((char*)data, dataSize);

    // Clean up
    delete[] data;
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);

    return true;
}

void updateDBFile(const std::string& filename, const std::string& data) {
    std::ofstream outputFile(filename, std::ios::binary | std::ios::app); // Open in append mode
    if (outputFile.is_open()) {
        outputFile << data;
        outputFile.close();
        std::cout << "File updated successfully!" << std::endl;
    } else {
        std::cout << "Unable to open file." << std::endl;
    }
}

int main() {
    std::string password;
    std::cout << "Enter the doctor's password: ";
    std::getline(std::cin, password);

    std::string decryptedData;
    bool isFileEncrypted = false;

    // Decrypt the DB file when the program starts
    std::ifstream inputFile("DB.txt", std::ios::binary);
    if (inputFile.is_open()) {
        std::stringstream ss;
        ss << inputFile.rdbuf();
        std::string encryptedData = ss.str();

        if (!decryptData((BYTE*)encryptedData.data(), encryptedData.size(), password, decryptedData)) {
            std::cout << "Decryption failed." << std::endl;
            inputFile.close();
            return -1;
        }

        std::cout << "Decrypted data:" << std::endl;
        std::cout << decryptedData << std::endl;

        inputFile.close();
    } else {
        std::cout << "Unable to open file." << std::endl;
    }

    int choice = -1;
    while (choice != 0) {
        std::cout << "******************************************" << std::endl;
        std::cout << "* 1 - add a new patient record            *" << std::endl;
        std::cout << "* 2 - view records                        *" << std::endl;
        std::cout << "* 0 - exit                                *" << std::endl;
        std::cout << "******************************************" << std::endl;
        std::cout << "Your choice: ";
        std::cin >> choice;
        std::cin.ignore(); // Ignore the newline character

        switch (choice) {
            case 1: {
                // Input ID, username, and time
                std::string username;
                double ID, time;

                std::cout << "Name of the patient: ";
                std::getline(std::cin, username);

                std::cout << "ID of the patient: ";
                std::cin >> ID;

                std::cout << "Enter patient dosing time: ";
                std::cin >> time;

                // Convert data to string
                std::stringstream ss;
                ss << username << " - " << ID << " - " << time;
                std::string dataStr = ss.str();

                // Add the new record to the decrypted data
                decryptedData += "\n" + dataStr;

                // Store the updated decrypted data in the file
                updateDBFile("DB.txt", decryptedData);

                // Encrypt the DB file after adding the new record
                std::ifstream inputFile("DB.txt", std::ios::binary);
                if (inputFile.is_open()) {
                    std::stringstream ss;
                    ss << inputFile.rdbuf();
                    std::string data = ss.str();
                    inputFile.close();

                    // Encrypt the data
                    BYTE* encryptedData;
                    DWORD encryptedDataLen;
                    if (!encryptData(data, password, &encryptedData, &encryptedDataLen)) {
                        std::cout << "Encryption failed." << std::endl;
                        break;
                    }

                    // Store the encrypted data back in the file
                    std::ofstream outputFile("DB.txt", std::ios::binary);
                    if (outputFile.is_open()) {
                        outputFile.write((char*)encryptedData, encryptedDataLen);
                        outputFile.close();
                        std::cout << "File encrypted successfully!" << std::endl;
                    } else {
                        std::cout << "Unable to open file." << std::endl;
                    }

                    delete[] encryptedData;
                } else {
                    std::cout << "Unable to open file." << std::endl;
                }

                break;
            }

            case 2: {
                std::cout << "Decrypted data:" << std::endl;
                std::cout << decryptedData << std::endl;
                break;
            }

            case 0: {
                // Exit the program
                choice = 0;
                break;
            }

            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                break;
        }
    }

    return 0;
}
