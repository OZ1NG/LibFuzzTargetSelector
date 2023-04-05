#include <string>
#include <map>
#include <vector>
#include <list>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cxxabi.h>

// #define DEBUG

#define X64
#ifndef X64
#define X86
#endif

typedef struct AddressRange {
    std::uint64_t start;
    std::uint64_t end;
    bool error_state; // true면 에러 발생한 것 
} AddressRange;

class FuzzTargetSelector {
private:
    std::string target_path;
    std::map<std::string, std::uint64_t> global_func_symbols;       // <func_sym>:<func_addr>
    std::map<std::string, std::uint64_t> local_func_symbols;        // <func_sym>:<func_addr>
    std::map<std::string, std::string> func_asm_opcode;             // <func_sym>:<opcode_byte>
    std::map<std::string, AddressRange> func_asm_addr_range;        // <func_sym>:[<asm_start>, <asm_end>]
    std::map<std::string, std::uint64_t> mem_ref_count;             // <func_sym>:memory reference count
    std::map<std::string, std::vector<std::string>> onedepth_tree;  // <parents_func_sym>:[<child_func_sym>, ...]
    std::map<std::string, std::uint64_t> total_mem_ref_count;       // <func_sym>:total memory reference count
    std::vector<std::string> result_func_sym;                       // mem ref이 내림차순으로 정렬된 global func symbol

    // .plt.got ~ .plt.sec
    AddressRange plt_section;
    
    std::string hex2bytes(std::string& hexstring);
    std::string bytes2hex(std::string& bytestring);
    bool memRefCountChk(const char * mnemonic, const char * op_str);
    bool callTreeChk(const char * mnemonic, const char * op_str, AddressRange func_range);

    AddressRange getReadelfRange(std::vector<std::string> vec);

    // 범위 체크
    bool chkRange(std::uint64_t addr, AddressRange range);
    
    // 범위에 해당하는 함수 심볼
    // symstring에 저장
    bool getRange2Sym(std::uint64_t addr, std::string &symstring);

    // 타겟 라이브러리의 plt 영역 범위 파싱
    bool getPltInfo();

    // 전역 함수, 지역 함수의 심볼 + 시작 주소 파싱
    void getSymbols();
    
    // 각 함수의 opcode 파싱
    void getAsm();

    // 함수별 메모리 접근 횟수 카운트 + 호출 구조 Tree화
    void memRefchk();

    // 함수별 최종 카운트 결정 + 내림차순 정렬
    void getTotalMemRefCount();

    // 재귀로 피호출 함수 포함 mem ref count 계산하는 함수
    std::uint64_t calcTotalMemRefCount(std::string parents_func_sym, std::vector<std::string> callstack);
    
    // TODO: 파싱 데이터 저장
    void saveParseData();

    // 체크 가능한 대상 라이브러리인지 확인하는 함수 (file 명령어 사용)
    bool chkValidLib();
public:
    FuzzTargetSelector(std::string path);
    void setTargetPath(std::string path);

    // show
    void showAddrRagne();
    void showOpcode();   
    void showFuncMemRefCount();
    void showOneDepthTree();
    void showTotalMemRefCount();
    void showResult();

    // C++로 개발된 함수의 경우 mangling된 심볼을 demangling 해주는 함수 (결과 출력 때 사용)
    std::string demangle(std::string mangled_sym);

    bool getResult(std::vector<std::string> &result_vec);
};
