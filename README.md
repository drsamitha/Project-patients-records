# Project-patients-records

Project-patients-records is a C++ program for keeping records of patients that are having medical drugs. It uses AES encryption to protect the data from unauthorized access.

## Installation

To install this program, you need to have a C++ compiler and the Crypto++ library installed on your system. You can download Crypto++ from [here].

To compile the program, run the following command in the project directory:


    g++ -o patient_record patient_record.cpp -lcryptopp

This will create an executable file named patient_record in the same directory.

## Usage

The program will prompt you to enter a password to access the data.  

The program will then display a menu with the following options:

- Add a new patient record
- View a patient record
- Modify a patient record
- Delete a patient record
- Exit the program

You can choose an option by entering the corresponding number. The program will then ask you to enter the details of the patient or the record ID, depending on the option.

The program will store the patient records in a file named data.txt, which is encrypted using AES. You can view the encrypted data by opening only the program, but you will not be able to read it without the password.

License
This project is licensed under the MIT License
