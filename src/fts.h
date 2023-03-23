#include <string>
#include <map>
#include <vector>
#include <list>

typedef struct AddressRange {
    std::uint64_t start;
    std::uint64_t end;
} AddressRange;

class FuzzTargetSelector {
private:
    std::string target_path;
    // std::vector<std::string> global_func_symbols;
    // std::vector<std::string> local_func_symbols;
    std::map<std::string, std::uint64_t> global_func_symbols;
    std::map<std::string, std::uint64_t> local_func_symbols;
    std::map<std::string, std::string> func_asm_opcode;         // <func_sym>:<opcode_byte>
    std::map<std::string, AddressRange> func_asm_addr_range;    // <func_sym>:[<asm_start>, <asm_end>]
    
    std::string hex2bytes(std::string& hexstring);
    std::string bytes2hex(std::string& bytestring);

public:
    FuzzTargetSelector(std::string path);
    void setTargetPath(std::string path);

    // TODO: private
    void getSymbols();
    void getAsm();

    // 함수별 메모리 접근 횟수 카운트 + 호출 구조 Tree화
    int memRefchk();


    void showAddrRagne();
    void showOpcode();    
};
