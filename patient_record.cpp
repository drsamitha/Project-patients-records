#include <iostream>
#include <fstream>
using namespace std;

int main() {
    string username;
    double weight, age, time;

    // Input weight, username, and age
    cout << "Enter weight: ";
    cin >> weight;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter age: ";
    cin >> age;

    // Calculate inject time
    time = weight / age;

    // Store the record in "DB.txt" file
    ofstream outputFile("DB.txt", ios::app);
    if (outputFile.is_open()) {
        outputFile << "Username: " << username << ", Time: " << time << endl;
        outputFile.close();
        cout << "Record saved successfully!" << endl;
    } else {
        cout << "Unable to open file." << endl;
    }

    return 0;
}
