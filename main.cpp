#include <iostream>
#include <fstream>
#include <string>
#include <cctype>
#include <algorithm>
#include <openssl/md5.h>

bool isValidEmail(const std::string& email) {
  if (email.empty() || email.find('@') == std::string::npos || email.find('.') == std::string::npos) {
    std::cout << "Invalid email format." << std::endl;
    return false;
  }

  std::ifstream usersFile("users.txt");
  std::string line;
  while (std::getline(usersFile, line)) {
    if (line.substr(0, email.length()) == email) {
      std::cout << "User already exists." << std::endl;
      return false;
    }
  }

  return true;
}

bool isValidPassword(const std::string& password) {
  if (password.length() < 8 ||
      std::none_of(password.begin(), password.end(), [](char c) { return std::isupper(c); }) ||
      std::none_of(password.begin(), password.end(), [](char c) { return std::islower(c); }) ||
      std::none_of(password.begin(), password.end(), [](char c) { return std::isdigit(c); }) ||
      std::none_of(password.begin(), password.end(), [](char c) { return std::ispunct(c); })) {
    std::cout << "Invalid password. It must meet the criteria." << std::endl;
    return false;
  }

  return true;
}

std::string hashPassword(const std::string& password) {
  unsigned char digest[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), digest);

  char md5string[2 * MD5_DIGEST_LENGTH + 1];

  for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
    std::sprintf(&md5string[i * 2], "%02x", (unsigned int)digest[i]);
  }

  return md5string;
}

bool testLogin(const std::string& username, const std::string& password) {
  std::ifstream usersFile("users.txt");
  std::string line;
  while (std::getline(usersFile, line)) {
    size_t delimiterPos = line.find(":");
    std::string storedUsername = line.substr(0, delimiterPos);
    std::string storedHashedPassword = line.substr(delimiterPos + 1);

    if (storedUsername == username && storedHashedPassword == hashPassword(password)) {
      return true;
    }
  }

  return false;
}

void createUser() {
  std::string username, password;

  std::cout << "Enter email address (username): ";
  std::cin >> username;

  if (!isValidEmail(username)) {
    return;
  }

  std::cout << "Enter password: ";
  std::cin >> password;

  if (!isValidPassword(password)) {
    return;
  }

  std::string hashedPassword = hashPassword(password);

  std::ofstream usersFile("users.txt", std::ios::app);
  usersFile << username << ":" << hashedPassword << std::endl;

  std::cout << "User created successfully." << std::endl;
}

void menu() {
  int choice;
  do {
    std::cout << "\nMenu:\n";
    std::cout << "1. Create user\n";
    std::cout << "2. Test login\n";
    std::cout << "0. Exit\n";
    std::cout << "Enter your choice: ";
    std::cin >> choice;

    switch (choice) {
      case 1:
        createUser();
        break;
      case 2: {
        std::string username, password;
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        if (testLogin(username, password)) {
          std::cout << "OK, login successful." << std::endl;
        } else {
          std::cout << "Error, incorrect username or password." << std::endl;
        }
        break;
      }
      case 0:
        std::cout << "Exiting program.\n";
        break;
      default:
        std::cout << "Invalid choice. Try again.\n";
    }
  } while (choice != 0);
}

int main() {
  menu();
  return 0;
}
