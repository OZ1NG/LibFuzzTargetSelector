#include "fts.h"
#include "util.h"
#include <regex>
#include <capstone/capstone.h>
#include <stdio.h>

FuzzTargetSelector::FuzzTargetSelector(std::string path) {
    this->target_path = path;

    // TODO: Start Parsing
    // getSymbols();
    // getAsm();
}

void FuzzTargetSelector::setTargetPath(std::string path) {
    this->target_path = path;
}

void FuzzTargetSelector::getSymbols() {
    // Read global func symbols info
    std::vector<std::string> tmp_gv; // tmp global func symbols vector
    
    int res = exec("nm --defined-only " + this->target_path + " | grep \" T \"", tmp_gv);
    if (!res) {
        std::cout << "error!" << std::endl;
        exit(1);
    }

    for (std::vector<std::string>::iterator it = tmp_gv.begin(); it != tmp_gv.end(); ++it) {
        this->global_func_symbols.insert({it->substr(19), stoi(it->substr(0,16), nullptr, 16)});
    }

    // Read local func symbols info
    std::vector<std::string> tmp_lv; // tmp local func symbols vector
    
    res = exec("nm --defined-only " + this->target_path + " | grep \" t \"", tmp_gv);
    if (!res) {
        std::cout << "error!" << std::endl;
        exit(1);
    }

    std::vector<std::string> filter = {"__do_global_dtors_aux", "_fini", "_init"};
    for (std::vector<std::string>::iterator it = tmp_gv.begin(); it != tmp_gv.end(); ++it) {
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
	    	std::cout << iter.first << " " << iter.second << std::endl;

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
                std::cout << *it << std::endl; // TEST

                std::smatch opcode_match;
                if (std::regex_search(*it, opcode_match, opcode_reg)) {
                    opcode += opcode_match.str();
                    // std::cout << "Match found: " << opcode_match.str() << std::endl; // TEST   
                }
                else {
                    std::cout << "No match found." << std::endl; // TEST
                }

                // 주소 추출
                std::smatch addr_match;
                if (std::regex_search(*it, addr_match, addr_reg)) {
                    addr.push_back(stoi(addr_match.str(), nullptr, 16));
                    // std::cout << "addr: " << addr_match.str() << std::endl; // TEST
                }
            }

            std::cout << "opcode: " << opcode << std::endl;

            // hex string인 opcode를 byte로 변경
            std::string opcode_byte = hex2bytes(opcode);
            std::cout << "opcode: " << opcode << std::endl;

            bytes2hex(opcode_byte); // TEST

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
    std::cout << hexstring << std::endl;
    return hexstring;
}

void FuzzTargetSelector::showAddrRagne() {
    for (auto iter : func_asm_addr_range) {
		std::cout << iter.first << ":" << std::hex << iter.second.start << " " << std::hex << iter.second.end << std::endl;
	}
}

void FuzzTargetSelector::showOpcode() {
    for (auto iter : func_asm_opcode) {
		std::cout << "<" << iter.first << ">:\n" << iter.second << std::endl;
	}
}

int FuzzTargetSelector::memRefchk() {
    csh handle;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) // arch : x86-64, mode : x64 인 환경을 뜻함
    	return 0;

    for (auto iter : func_asm_opcode) {
    	cs_insn *insn;
    	size_t count;

        if (func_asm_addr_range.find(iter.first) == func_asm_addr_range.end())
            continue;

        count = cs_disasm(handle, (const uint8_t *)iter.second.c_str(), iter.second.size(), func_asm_addr_range[iter.first].start, 0, &insn);
    	std::cout << "<" << iter.first << ">" << std::endl;
        if (count > 0) {
    		size_t j;
            for (j = 0; j < count; j++) {
                printf("0x%"PRIx64":\t%s\t\t%s\n", 
                        insn[j].address,
                        insn[j].mnemonic,
    					insn[j].op_str
                );
    		}
            std::cout << std::endl;
    		cs_free(insn, count);
    	} else
    		printf("ERROR: Failed to disassemble given code!\n");
    }
    cs_close(&handle);
        
    return 1;
}