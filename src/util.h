#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <cstring>
#include <vector>

int exec(std::string cmd, std::vector<std::string> &buf) {
    FILE * fp = popen(cmd.c_str(), "r");

    if (!fp) {
        return 0; // Error!
    }

    char buffer[0x100] = {0, };

    // 결과를 한 줄씩 읽어들이면서 벡터에 저장
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        if (buffer[strlen(buffer)-1] == '\n') {
            buffer[strlen(buffer)-1] = '\0';
        }
        buf.push_back(std::string(buffer));
    }

    pclose(fp);
    
    return 1; // Success!
}