from pylibemu import Emulator


def interpret_shellcode(shellcode: bytes) -> str:
    emulator = Emulator()
    offset = emulator.shellcode_getpc_test(shellcode)
    emulator.prepare(shellcode, offset)
    emulator.test()

    return emulator.emu_profile_output.decode("utf-8")
