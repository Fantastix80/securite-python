from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def disass(shellcode: bytes) -> str:
    # Crée un désassembleur pour l'architecture x86 32 bits
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    shellcode_disassembled = ""

    # Affiche les instructions désassemblées
    for instruction in md.disasm(shellcode, 0x1000):
        shellcode_disassembled += (
            f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}\n"
        )

    return shellcode_disassembled
