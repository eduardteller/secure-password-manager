#include <iostream>
#include "ui/cli.hpp"

int main(int argc, char* argv[]) {
    std::cout << "DEBUG: Entering main" << std::endl;
    CLI cli;
    std::cout << "DEBUG: CLI initialized" << std::endl;
    return cli.run(argc, argv);
}


