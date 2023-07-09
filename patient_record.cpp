#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
using namespace std;

string encrypt(string data) {
    string encryptedData = "";
    int key = 3; // Encryption key
    for (int i = 0; i < data.length(); i++) {
        char c = data[i];
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = (c - offset + key) % 26 + offset;
        }
        encryptedData += c;
    }
    return encryptedData;
}

int main() {
    string username;
    double weight, age, time;

    // Input weight, username, and age
    cout << "Name of the patient: ";
    getline(cin, username);

    cout << "Weight of the patient: ";
    cin >> weight;

    cout << "Enter patient's age: ";
    cin >> age;

    // Calculate inject time
    time = weight / age;
    cout << "Time duration is " << time << endl;

// Convert time to string
stringstream ss;
ss << time;
string timeStr = ss.str();

// Encrypt data
string data = "Username: " + username + ", Time: " + timeStr;
string encryptedData = encrypt(data);


    // Store the encrypted record in "DB.txt" file
    ofstream outputFile("DB.txt", ios::app);
    if (outputFile.is_open()) {
        outputFile << encryptedData << endl;
        outputFile.close();
        cout << "Record saved successfully!" << endl;
    } else {
        cout << "Unable to open file." << endl;
    }

    return 0;
}


























