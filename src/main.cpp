
#include "fts.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "[!] Usage: ./fts <library path>" << std::endl;
        exit(0);
    }
    FuzzTargetSelector fts = FuzzTargetSelector(std::string(argv[1]));

    // fts.showFuncMemRefCount();
    // fts.showOneDepthTree();
    // fts.showTotalMemRefCount();

    fts.showResult();

    // If you get result... (C/C++)
    // std::vector<std::string> result;
    // fts.getResult(result);
    // std::cout << "[+] Result Check" << std::endl;
    // for (auto iter : result) {
    //     std::cout << fts.demangle(iter) << std::endl;
    // }

    return 0;
}