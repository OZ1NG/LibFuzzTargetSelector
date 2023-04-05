#include "fts.h"
#include <regex>
#include <capstone/capstone.h>
#include <stdio.h>
#include <iomanip>

bool exec(std::string cmd, std::vector<std::string> &buf) {
    FILE * fp = popen(cmd.c_str(), "r");

    if (!fp) {
        return 0; // Error!
    }

    char buffer[0x100] = {0, };
    std::string buf_string = "";
    // 결과를 한 줄씩 읽어들이면서 벡터에 저장
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        if (buffer[strlen(buffer)-1] == '\n') {
            buffer[strlen(buffer)-1] = '\0';
            buf_string += std::string(buffer);
            buf.push_back(buf_string);
            buf_string.clear();
        } else {
            buf_string += std::string(buffer);
        }
    }

    pclose(fp);
    
    return 1; // Success!
}

FuzzTargetSelector::FuzzTargetSelector(std::string path) {
    this->target_path = path;
    this->plt_section = {0, 0, 0};

    // Start Parsing
    if (!chkValidLib()) {
        exit(1);
    }

    std::cout << "[+] Get .plt.got, .plt.sec Info..." << std::endl;
    getPltInfo();
    if (plt_section.error_state) {
        std::cout << "[PLT ERROR] Is stripped file?" << std::endl;
        exit(1);
    }
    #ifdef DEBUG 
    std::cout << "[plt] start :" << std::hex << plt_section.start << std::endl;
    std::cout << "[plt] end :" << std::hex << plt_section.end << std::endl;
    std::cout << "[plt] error_state :" << std::hex << plt_section.error_state << std::endl;
    #endif
    
    std::cout << "[+] Get Function Symbols..." << std::endl;
    getSymbols();
    std::cout << "[+] Get Functions opcode..." << std::endl;
    getAsm();
    std::cout << "[+] Check Memory Reference Count and Create Function Call Tree..." << std::endl;
    memRefchk();
    std::cout << "[+] Get Result..." << std::endl;
    getTotalMemRefCount();

    std::cout << "[+] Done!" << std::endl;
}

void FuzzTargetSelector::setTargetPath(std::string path) {
    this->target_path = path;
}

void FuzzTargetSelector::getSymbols() {
    // Read global func symbols info
    std::vector<std::string> tmp_gv; // tmp global func symbols vector
    
    int res = exec("nm --defined-only " + this->target_path + " | grep \" T \"", tmp_gv);
    if (!res) {
        std::cout << "[!] global function symbol parse error!" << std::endl;
        exit(1);
    }

    for (std::vector<std::string>::iterator it = tmp_gv.begin(); it != tmp_gv.end(); ++it) {
        this->global_func_symbols.insert({it->substr(19), stoi(it->substr(0,16), nullptr, 16)});
    }

    // Read local func symbols info
    std::vector<std::string> tmp_lv; // tmp local func symbols vector
    
    res = exec("nm --defined-only " + this->target_path + " | grep \" t \"", tmp_lv);
    if (!res) {
        std::cout << "[!] local function symbol parse error!" << std::endl;
        exit(1);
    }

    std::vector<std::string> filter = {"__do_global_dtors_aux", "_fini", "_init"};
    for (std::vector<std::string>::iterator it = tmp_lv.begin(); it != tmp_lv.end(); ++it) {
        bool flag = true;
        for (int i = 0; i < filter.size(); i ++) {
            if (!it->substr(19).compare(filter[i])) { 
                flag = false;   // 필터에 걸린 것
                break;
            }
        }
        
        if (flag)
            this->local_func_symbols.insert({it->substr(19), stoi(it->substr(0,16), nullptr, 16)});
    }
}

void FuzzTargetSelector::getAsm() {
    std::map<std::string, std::uint64_t> *funcsymbols[2] = {&global_func_symbols, &local_func_symbols};
    
    std::vector<std::string> tmp_v;

    // asm 바이트 코드 추출 정규식
    std::regex opcode_reg("\\s+((?:[0-9a-f]{2}\\s)+)");

    // asm 주소 추출 정규식
    std::regex addr_reg("\\s+[0-9a-f]+:");

    for (int i = 0; i < 2; i ++) {
        for (auto iter : *funcsymbols[i]) {
	    	// std::cout << iter.first << " " << iter.second << std::endl; // test

            int res = exec("objdump -d -M intel " + this->target_path + " | grep -Pzo \"(?s)<" + iter.first + ">:.*?\\n\\n\"", tmp_v);
            if (!res) {
                std::cout << "error!" << std::endl;
                exit(1);
            }

            if (tmp_v.size() < 1) {
                continue;
            }

            std::string opcode;
            std::vector<std::uint64_t> addr;
            for (std::vector<std::string>::iterator it = tmp_v.begin(); it != tmp_v.end(); ++it) {
                // std::cout << *it << std::endl; // TEST

                std::smatch opcode_match;
                if (std::regex_search(*it, opcode_match, opcode_reg)) {
                    opcode += opcode_match.str();
                    // std::cout << "Match found: " << opcode_match.str() << std::endl; // TEST   
                }
                else {
                    // std::cout << "No match found." << std::endl; // TEST
                }

                // 주소 추출
                std::smatch addr_match;
                if (std::regex_search(*it, addr_match, addr_reg)) {
                    addr.push_back(stoi(addr_match.str(), nullptr, 16));
                    // std::cout << "addr: " << addr_match.str() << std::endl; // TEST
                }
            }

            // std::cout << "opcode: " << opcode << std::endl; // test 

            // hex string인 opcode를 byte로 변경
            std::string opcode_byte = hex2bytes(opcode);
            // std::cout << "opcode: " << opcode << std::endl; // test

            bytes2hex(opcode_byte);

            // addr 벡터에서 첫 번째 값과 마지막 값만 남기고 제거
            if (addr.size() > 2) {
                addr.erase(addr.begin() + 1, addr.end() - 1);
            }
            AddressRange addr_range = {addr.at(0), addr.at(1)};

            // func_asm_opcode map에 저장
            this->func_asm_opcode.insert({iter.first, opcode_byte});

            // func_asm_addr_range map에 저장
            this->func_asm_addr_range.insert({iter.first, addr_range});

            // TEST
            // std::cout << "addrs: " << std::endl;
            // for (auto byte : addr) {
            //     std::cout << std::hex << (int)byte << " ";
            // }
            // std::cout << std::endl;

            tmp_v.clear();
        }
    }
    
}

std::string FuzzTargetSelector::hex2bytes(std::string& hexstring)
{
    hexstring.erase(remove(hexstring.begin(), hexstring.end(), ' '), hexstring.end());  // 공백 제거
    hexstring.erase(remove(hexstring.begin(), hexstring.end(), '\t'), hexstring.end()); // 탭 제거

    std::string bytes;
    for (size_t i = 0; i < hexstring.length(); i += 2)
    {
        // std::string을 16진수 숫자로 파싱하여 바이트 타입으로 변환
        unsigned char byte = (unsigned char) strtol(hexstring.substr(i, 2).c_str(), nullptr, 16);
        bytes += byte;
    }
    
    return bytes;
}

std::string FuzzTargetSelector::bytes2hex(std::string& bytestring)
{
    const char hex[] = "0123456789abcdef";
    std::string hexstring;
    for (unsigned char byte : bytestring) {
        hexstring.push_back(hex[byte >> 4]);
        hexstring.push_back(hex[byte & 0x0f]);
        hexstring += " ";
    }
    // std::cout << hexstring << std::endl; // test 
    return hexstring;
}

void FuzzTargetSelector::showAddrRagne() {
    std::cout << "[showAddrRagne]" << std::endl;
    for (auto iter : func_asm_addr_range) {
		std::cout << iter.first << ":" << std::hex << iter.second.start << " " << std::hex << iter.second.end << std::endl;
	}
}

void FuzzTargetSelector::showOpcode() {
    std::cout << "[showOpcode]" << std::endl;
    for (auto iter : func_asm_opcode) {
		std::cout << "<" << iter.first << ">:\n" << iter.second << std::endl;
	}
}

bool FuzzTargetSelector::memRefCountChk(const char * mnemonic, const char * op_str) {
    //std::regex mem_ref_reg(".*\\[.*\\].*"); // legacy
    std::regex mem_ref_reg("\\[.*?\\]");

    std::string opstring(op_str);
    
    // 1. memory ref 카운팅
    // memory ref를 사용하는지 체크
    std::smatch mem_ref_match;
    if (std::regex_search(opstring, mem_ref_match, mem_ref_reg)) { // 접근이 있으면 true 반환
        // std::cout << "[memRefCountChk1] mem_ref_match: " << mnemonic << ":" << mem_ref_match.str() << std::endl; // test
        // nop 명령어가 포함되어있는지 체크
        std::regex nop_reg("nop");
        if (std::regex_match(mnemonic, nop_reg))
            return false; // nop 명령어가 포함되어있으므로 카운팅 X
        // if (strstr(mnemonic, "nop") != 0) 
        //     return false; 

        // rip, rsp, rbp 레지스터 검출 정규식
        std::regex non_user_effect_regi_reg("[r][isb][p]");
        
        #ifdef X64
        std::regex regi_reg("[r][a-z0-9][a-z0-9]"); // only x64
        #elif X86
        std::regex regi_reg("[e][a-z0-9][a-z0-9]"); // only x86
        #endif
        std::smatch regi_matches;
        bool rip_flag = false;
        std::string mem_ref_string = mem_ref_match.str();
        while (std::regex_search(mem_ref_string, regi_matches, regi_reg)) {
            // std::cout << "[memRefCountChk2] regi_matches: " << regi_matches.str() << std::endl; // test
            if (!std::regex_match(regi_matches.str(), non_user_effect_regi_reg)) { 
                rip_flag = true; // rip, rsp, rbp가 아닌 다른 레지스터를 사용하는 것을 발견한 경우
                break;
            }
            mem_ref_string = regi_matches.suffix();
        }
        
        if (!rip_flag) { 
            return false; // 만약 rip만 사용된 경우 카운팅 X;
        }

        // 모두 통과하면 카운팅 O
        return true;
    }
    return false;
}

bool FuzzTargetSelector::callTreeChk(const char * mnemonic, const char * op_str, const AddressRange func_range) {
    // mnemonic이 call 또는 jmp 계열 명령어인지 구분
    std::regex call_reg("call");
    std::regex jmp_reg("^j(mp|a|be|cxz|ecx|rcx|o|no|z|nz|s|ns|pe|po)");
    #ifdef X64
    std::regex regi_reg("[r][a-z0-9][a-z0-9]"); // only x64
    #elif X86
    std::regex regi_reg("[e][a-z0-9][a-z0-9]"); // only x86
    #endif

    // op_str이 레지스터인지 체크
    // std::cout << "[callTreeChk] " << mnemonic << ":" << op_str << std::endl; // test
    if (std::regex_match(op_str, regi_reg)) {
        // 레지스터인 경우에는 값을 알 수 없기 때문에 패스
        return false;
    }

    std::string mnemonic_string(mnemonic);

    // call mnemonic check
    if (std::regex_match(mnemonic_string, call_reg)) {
        // std::cout << "\tfind call!:" << std::string(op_str) << std::endl; // test
        std::uint64_t addr;
        try{
            addr = std::stoull(std::string(op_str), nullptr, 16);
        }
        catch (std::invalid_argument &e) { // regi_reg 정규식 매칭에 알수 없는 이유로 실패한 경우를 대비
            return false;
        }

        // plt 영역의 함수인지 체크
        if (chkRange(addr, plt_section)) {
            // std::cout << "\tin plt!" << std::endl; // test
            return false;
        }

        // 재귀 함수인지 체크
        if (chkRange(addr, func_range)) {
            // std::cout << "\trecursive!" << std::endl; // test
            // std::cout << std::hex << addr << ":" << std::hex << func_range.start << ":" << std::hex << func_range.end << std::endl; // test
            return false;
        }

        // 아니면 return true
        return true;
    }

    // jmp 계열 mnemonic check
    else if (std::regex_match(mnemonic_string, jmp_reg)) {
        // std::cout << "\tfind jxx!" << std::string(op_str) << std::endl; // test
        std::uint64_t addr;
        try{
            addr = std::stoull(std::string(op_str), nullptr, 16);
        }
        catch (std::invalid_argument &e) { // regi_reg 정규식 매칭에 알수 없는 이유로 실패한 경우를 대비
            return false;
        }
        // 함수 외부로 점프 하는지 체크
        if (!chkRange(addr, func_range)) {
            // plt 영역의 함수인지 체크
            if (chkRange(addr, plt_section)) {
                // std::cout << "\tin plt!" << std::endl; // test
                return false;
            }
            
            // 맞으면 return true
            return true;
        }
        // std::cout << "\tjmp to another func!" << std::endl; // test
        // 그 이외엔 전부 return false;
        return false;
    }
    return false;
}

bool FuzzTargetSelector::chkRange(std::uint64_t addr, AddressRange range) {
    if (range.error_state) {
        return false;
    }

    if ((addr >= range.start) && (range.end > addr)) {
        // std::cout << "\t(addr >= range.start) :" << (addr >= range.start) << std::endl; // test
        // std::cout << "\t(range.end > addr) :" << (range.end > addr) << std::endl; // test
        return true;
    }

    return false;
}

bool FuzzTargetSelector::getRange2Sym(std::uint64_t addr, std::string &symstring) {
    for (auto iter : func_asm_addr_range) {
        // std::cout << addr << ":" << iter.second.start << ":" << iter.second.end << std::endl; // test
        if (chkRange(addr, iter.second)) {
            symstring = iter.first;
            return true;
        }
    }
    return false;
}

void FuzzTargetSelector::memRefchk() {
    csh handle;

    #ifdef X64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) { // arch : x86-64, mode : x64 인 환경을 뜻함
    #elif X86
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) { // arch : x86-64, mode : x86 인 환경을 뜻함
    #endif
    	std::cout << "[!] capstone library open error!" << std::endl;
        exit(1);
    }
    
    for (auto iter : func_asm_opcode) {
    	cs_insn *insn;
    	size_t count;

        if (func_asm_addr_range.find(iter.first) == func_asm_addr_range.end())
            continue;

        count = cs_disasm(handle, (const uint8_t *)iter.second.c_str(), iter.second.size(), func_asm_addr_range[iter.first].start, 0, &insn);
    	// std::cout << "<" << iter.first << ">" << std::endl; // test 
        if (count > 0) {
    		size_t j;
            for (j = 0; j < count; j++) {
                // std::cout << std::hex << insn[j].address << ":\t" << insn[j].mnemonic << "\t\t" << insn[j].op_str << std::endl; // test

                // TODO: memory ref 카운팅 및 tree 생성
                // memory reference 카운팅
                if (memRefCountChk(insn[j].mnemonic, insn[j].op_str)) {
                    // std::cout << "[mem_ref_count add!] find!" << std::endl; // test
                    try {
                        mem_ref_count[iter.first] += 1;
                    } catch (const std::out_of_range &e) {
                        mem_ref_count[iter.first] = 1;
                    }
                }

                // tree 생성
                if (callTreeChk(insn[j].mnemonic, insn[j].op_str, func_asm_addr_range[iter.first])) {
                    // std::cout << "[in callTreeChk]" << std::endl; // test
                    // std::cout << ":" << std::string(insn[j].op_str) << std::endl; // test
                    std::string func_sym;
                    if (getRange2Sym(std::stoull(std::string(insn[j].op_str), nullptr, 16), func_sym)) {
                        try {
                            onedepth_tree[iter.first].push_back(func_sym);
                        } catch (const std::out_of_range &e) {
                            onedepth_tree[iter.first] = std::vector<std::string>();
                            onedepth_tree[iter.first].push_back(func_sym);
                        }
                    } else {
                        std::cout << "\t[!memRefchk!] Error: Create Tree" << std::endl;
                    }
                }
            }
            // std::cout << std::endl; // test
    		cs_free(insn, count);
    	} else
    		printf("ERROR: Failed to disassemble given code!\n");
    }
    cs_close(&handle);
}

AddressRange FuzzTargetSelector::getReadelfRange(std::vector<std::string> vec) {
    AddressRange result = {0,0,0};
    
    std::uint64_t address;
    std::uint64_t offset;

    std::regex addr_reg("\\s+PROGBITS\\s+([\\dabcdefABCDEF]{16})\\s");
    std::smatch match;
    if (std::regex_search(vec.at(0), match, addr_reg)) {
        // std::cout << "[getReadelfRange1]:" << std::string(match.str(1)) << std::endl; // test
        address = std::stoull(match.str(1), nullptr, 16);
        #ifdef DEBUG
        std::cout << "[getReadelfRange] Address: " << std::hex << address << std::endl; // test
        #endif
    } else {
        result.error_state = true;
        return result;
    }

    std::regex offset_reg("\\b([\\dabcdefABCDEF]{16})\\b");
    if (std::regex_search(vec.at(1), match, offset_reg)) {
        // std::cout << "[getReadelfRange1]:" << std::string(match.str(1)) << std::endl; // test
        offset = std::stoull(match.str(1), nullptr, 16);
        #ifdef DEBUG
        std::cout << "[getReadelfRange] Offset: " << std::hex << offset << std::endl; // test
        #endif
    } else {
        result.error_state = true;
        return result;
    }

    result.start = address;
    result.end = address + offset;

    return result;
}

bool FuzzTargetSelector::getPltInfo() {    
    AddressRange pltgot_range = {0, 0, 0};
    AddressRange pltsec_range = {0, 0, 0};

    // 아직은 only x64, dynamically linked 만 지원
    // Command Injection 취약!
    #ifdef X64
    std::string pltgot_cmd = "readelf -S " + this->target_path + " | grep ' .plt.got ' -A1";
    std::string pltsec_cmd = "readelf -S " + this->target_path + " | grep ' .plt.sec ' -A1";
    #elif X86
    std::string pltgot_cmd = "readelf -S " + this->target_path + " | grep ' .plt.got '";
    std::string pltsec_cmd = "readelf -S " + this->target_path + " | grep ' .plt.sec '";
    #endif
    
    std::vector<std::string> pltgot_v;
    int res = exec(pltgot_cmd, pltgot_v);
    if (res) {
        pltgot_range = getReadelfRange(pltgot_v);
    }
    
    std::vector<std::string> pltsec_v;
    res = exec(pltsec_cmd, pltsec_v);
    if (res) {
        pltsec_range = getReadelfRange(pltsec_v);
    }
    
    // 에러가 발생한 경우 (== 섹션이 존재하지 않는 경우)
    if (pltgot_range.error_state || pltsec_range.error_state) {
        if (pltgot_range.error_state && pltsec_range.error_state) {
            plt_section.error_state = true;
            return false;
        }
        else if (pltgot_range.error_state) {
            plt_section.start = pltsec_range.start;
            plt_section.end = pltsec_range.end;
        } else {
            plt_section.start = pltgot_range.start;
            plt_section.end = pltgot_range.end;
        }
        return true;
    }

    // start 설정
    if (pltgot_range.start < pltsec_range.start) {
        plt_section.start = pltgot_range.start;
    }
    else {
        plt_section.start = pltsec_range.start;
    }

    // end 설정
    if (pltgot_range.end < pltsec_range.end) {
        plt_section.end = pltsec_range.end;
    }
    else {
        plt_section.end = pltgot_range.end;
    }
    
    return true;
}

std::uint64_t FuzzTargetSelector::calcTotalMemRefCount(std::string parents_func_sym, std::vector<std::string> callstack) {
    // A-B-C-A 와 같은 호출에 의한 무한 루프 방지
    if (std::count(callstack.begin(), callstack.end(), parents_func_sym)) {
        return 0;
    }
    
    // 이미 카운팅이 끝난 함수면 바로 리턴
    if (total_mem_ref_count.count(parents_func_sym)) {
        return total_mem_ref_count[parents_func_sym];
    }

    callstack.push_back(parents_func_sym);
    // 재귀로 tree 탐색
    total_mem_ref_count[parents_func_sym] = mem_ref_count[parents_func_sym]; // std::map 특징상 키값이 없으면 값을 0으로 자동 등록 후 리턴
    for (auto sym : onedepth_tree[parents_func_sym]) {
        total_mem_ref_count[parents_func_sym] += calcTotalMemRefCount(sym, callstack);
    }
    return total_mem_ref_count[parents_func_sym];
}

// 전역 함수를 루트 노드로 사용하여 진행
void FuzzTargetSelector::getTotalMemRefCount() {
    // 총 mem ref count 저장
    std::vector<std::string> callstack;
    for (auto iter : global_func_symbols) {
        calcTotalMemRefCount(iter.first, callstack);
    }

    // 내림차순 정렬
    std::vector<std::pair<std::string, std::uint64_t>> sorted_map(total_mem_ref_count.begin(), total_mem_ref_count.end());
    std::sort(sorted_map.begin(), sorted_map.end(), [](const auto& lhs, const auto& rhs){
        return lhs.second > rhs.second; // second 값을 기준으로 내림차순 정렬
    });

    // 정렬된 결과에서 함수 심볼만 뽑아서 저장
    for(const auto& sym_count : sorted_map) {
        result_func_sym.push_back(sym_count.first);
    }
}

void FuzzTargetSelector::showFuncMemRefCount() {
    std::cout << "[showFuncMemRefCount]" << std::endl;
    for (auto iter : mem_ref_count) {
        std::cout << iter.first << ":" << std::dec << iter.second << std::endl;
    }
    std::cout << std::endl;
}

void FuzzTargetSelector::showOneDepthTree() {
    std::cout << "[showOneDepthTree]" << std::endl;
    for (auto iter : onedepth_tree) {
        std::cout << iter.first << ":" << std::endl;
        for (auto it : iter.second) {
            std::cout << "\t" << it << std::endl;
        }
    }
    std::cout << std::endl;
}

void FuzzTargetSelector::showTotalMemRefCount() {
    std::cout << "[showTotalMemRefCount]" << std::endl;
    for (auto iter : total_mem_ref_count) {
        std::cout << "\t" << iter.first << ":" << std::dec << iter.second << std::endl;
    }
    std::cout << std::endl;
}

void FuzzTargetSelector::showResult() {
    // 가장 긴 이름을 가진 심볼의 길이
    std::uint64_t symbol_size = std::string("[GLOBAL FUNC SYMBOL]").size();
    for (auto iter : result_func_sym) {
        if (symbol_size < demangle(iter).size()) {
            symbol_size = demangle(iter).size();
        }
    }
    symbol_size += 5;

    std::cout << "[showResult]" << std::endl;
    std::cout << "\t" << std::setw(symbol_size) << std::left << "[GLOBAL FUNC SYMBOL]" << std::setw(std::string("[TOTAL MEM REF COUNT]").size()) << std::right << "[TOTAL MEM REF COUNT]" << std::endl;
    for (auto iter : result_func_sym) {
        std::cout << "\t" << std::setw(symbol_size) << std::left << demangle(iter) << std::setw(std::string("[TOTAL MEM REF COUNT]").size()) << std::right << total_mem_ref_count[iter] << std::endl;
    }
    std::cout << std::endl;
}

// 내림차순으로 정렬된 함수 심볼을 받아오는 것
// result_vec을 통해 반환
bool FuzzTargetSelector::getResult(std::vector<std::string> &result_vec) {
    if (total_mem_ref_count.size() <= 0) {
        return false;
    }

    result_vec = result_func_sym;

    return true;
}

std::string FuzzTargetSelector::demangle(std::string mangled_sym) {
    int status;
    std::unique_ptr<char, decltype(std::free)*> result {
        abi::__cxa_demangle(mangled_sym.c_str(), nullptr, nullptr, &status),
        std::free
    };
    return (status == 0) ? result.get() : mangled_sym;
}

bool FuzzTargetSelector::chkValidLib() {
    std::vector<std::string> v;
    int res = exec("file " + target_path, v);
    if (!res) {
        return false;
    }

    if (std::strstr(v.at(0).c_str(), "No such file or directory") != 0) {
        std::cout << "[!] Wrong Path!" << std::endl;
        return false;
    }

    if (std::strstr(v.at(0).c_str(), "not stripped") == 0) {
        std::cout << "[!] Stripped File..." << std::endl;
        return false;
    }

    return true;
}

