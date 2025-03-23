#include "log.hpp"
#include "argument_parser.h"

#include <cstdio>
#include <cstdlib>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <cstring>
#include <capstone/capstone.h>

#define CODE_SIZE 16  // Size of code block to read

void trace_function_calls(const pid_t child_pid)
{
    int status;
    user_regs_struct regs{};

    // Wait for the child to stop
    waitpid(child_pid, &status, 0);

    // Initialize Capstone disassembler
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        debug::log(debug::error_log, "Failed to initialize capstone (errno: ", strerror(errno), ")\n");
        return;
    }

    bool calling = false;
    unsigned long long int calling_path = 0;
    std::string operands;

    while (true)
    {
        // Get the registers from the child
        ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
        const unsigned long rip = regs.rip;

        // last instruction is a calling instruction
        if (calling)
        {
            errno = 0;
            // Read 8 bytes (a 64-bit address) from the child's stack at address regs.rsp.
            const unsigned long ret_addr = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsp, nullptr);
            if (ret_addr == -1UL && errno != 0)
            {
                debug::log(debug::error_log, "ptrace(PTRACE_PEEKDATA) failed: ", strerror(errno), "\n");
            }

            if (ret_addr == 0x1FFFFFFFFFFFFFFF || ret_addr < 0xFF) {
                // debug::log(debug::warning_log, "Not a typical call from `", calling_path, "`, retAddr=", ret_addr, "\n");
                if (calling_path != 0) {
                    printf("Call %llX\n", calling_path);
                } else {
                    debug::log(debug::warning_log, "Cannot obtain `call ", operands, "` by conventional methods (tweaks?).\n");
                }
            } else {
                printf("Call %lX\n", ret_addr);
            }

            calling = false; // clear call indicator
        }

        // Read a block of memory from the child process starting at RIP
        unsigned char code[CODE_SIZE];
        for (int i = 0; i < CODE_SIZE; i += sizeof(long))
        {
            long data = ptrace(PTRACE_PEEKDATA, child_pid, rip + i, nullptr);
            if (data == -1) {
                debug::log(debug::error_log, "ptrace(PTRACE_PEEKDATA) failed: ", strerror(errno), "\n");
                cs_close(&handle);
                return;
            }
            memcpy(code + i, &data, sizeof(long));
        }

        // Disassemble the block of code
        cs_insn *insn;
        if (const size_t count = cs_disasm(handle, code, CODE_SIZE, rip, 0, &insn);
            count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                // Check if the instruction is a call
                if (strcmp(insn[i].mnemonic, "call") == 0) {
                    calling = true;
                    operands = insn[i].op_str;
                    calling_path = std::strtoull(insn[i].op_str, nullptr, 16);
                }
            }
            cs_free(insn, count);
        } else {
            debug::log(debug::error_log, "Error occurred when inspecting instructions.\n");
        }

        // Single step the child process
        ptrace(PTRACE_SINGLESTEP, child_pid, nullptr, nullptr);
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
    }

    cs_close(&handle);
}

int main(int argc, char *argv[])
{
#ifdef __DEBUG__
    debug::log_level = debug::DEBUG;
#endif // __DEBUG__

    const Arguments args(argc, (const char**)argv);
    debug::log(debug::debug_log, "ftrace: ",
        static_cast<Arguments::args_t>(args), " >>> ",
        static_cast<Arguments::sub_process_bundle_t>(args), " \n");

    const pid_t pid = fork();

    if (pid == 0) {
        debug::log(debug::debug_log, "Child process started. PID: ", getpid(), "\n");
        std::vector<char*> new_argvs;
        new_argvs.push_back(const_cast<char*>(static_cast<Arguments::sub_process_bundle_t>(args).first.c_str()));
        for (const auto& arg : static_cast<Arguments::sub_process_bundle_t>(args).second) {
            // const_cast is safe here because execvp doesn't modify the strings.
            new_argvs.push_back(const_cast<char*>(arg.c_str()));
        }
        // The array must be terminated by a nullptr.
        new_argvs.push_back(nullptr);

        execvp(static_cast<Arguments::sub_process_bundle_t>(args).first.c_str(),
            new_argvs.data());
        perror("execvp() failed");
        exit(EXIT_FAILURE);  // If execlp fails
    } else if (pid > 0) {
        debug::log(debug::debug_log, "Parent process. Attaching to child PID: ", pid, "\n");
        ptrace(PTRACE_ATTACH, pid, nullptr, nullptr);
        trace_function_calls(pid);
        ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    } else {
        perror("fork() failed");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
