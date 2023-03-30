
#include "fts.h"

int main(int argc, char **argv) {

    FuzzTargetSelector fts = FuzzTargetSelector(std::string(argv[1]));

    // fts.getSymbols();
    // fts.getAsm();
    // fts.showAddrRagne();
    // fts.showOpcode();

    // fts.memRefchk();

    // fts.getPltInfo();

    fts.showFuncMemRefCount();
    fts.showOneDepthTree();
    fts.showTotalMemRefCount();

    fts.showResult();

    std::vector<std::string> result;
    fts.getResult(result);
    std::cout << "[+] Result Check" << std::endl;
    for (auto iter : result) {
        std::cout << iter << std::endl;
    }

    return 0;
}