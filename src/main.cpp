
#include "fts.h"

int main(int argc, char **argv) {

    FuzzTargetSelector fts = FuzzTargetSelector(std::string(argv[1]));

    fts.getSymbols();
    fts.getAsm();
    fts.showAddrRagne();
    fts.showOpcode();

    fts.memRefchk();

    return 0;
}