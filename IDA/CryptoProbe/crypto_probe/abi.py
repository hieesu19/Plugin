"""Pure ABI readers. Site arguments are BEFORE CALL; entry arguments include return address."""

from .memory import Unknown


class AbiError(ValueError):
    pass


class ABI:
    def __init__(self, name, register, memory, endian="little"):
        self.name = name
        self.register = register
        self.memory = memory
        self.endian = endian
        self.word = 8 if name in ("win64", "sysv64", "aarch64") else 4
        self.sp = (
            "RSP"
            if self.word == 8 and name in ("win64", "sysv64")
            else "ESP" if name in ("cdecl32", "stdcall32", "fastcall32") else "SP"
        )
        self.registers = {
            "win64": ["RCX", "RDX", "R8", "R9"],
            "sysv64": ["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
            "aarch64": ["X" + str(i) for i in range(8)],
            "arm32": ["R" + str(i) for i in range(4)],
            "cdecl32": [],
            "stdcall32": [],
            "fastcall32": ["ECX", "EDX"],
        }.get(name)
        if self.registers is None:
            raise AbiError("Unsupported ABI " + name)

    def reg(self, name):
        try:
            v = self.register(name)
            return (
                int(v)
                if isinstance(v, int)
                else Unknown("register not integer: " + name)
            )
        except Exception as e:
            return Unknown("register " + name + ": " + str(e))

    def read_int(self, ea, size):
        if not isinstance(ea, int):
            return Unknown("SP unresolved")
        try:
            raw = self.memory(ea, size)
        except Exception:
            raw = None
        return (
            int.from_bytes(raw, self.endian)
            if raw is not None and len(raw) == size
            else Unknown("unreadable stack argument")
        )

    def arguments(self, argc, site="call", sizes=None):
        if site not in ("call", "entry"):
            raise AbiError("site must be call or entry")
        if not 0 <= argc <= 24:
            raise AbiError("argc outside limit")
        sizes = sizes or {}
        sp = self.reg(self.sp)
        offset = 0
        result = []
        reg_index = 0
        if site == "entry" and self.name in (
            "win64",
            "sysv64",
            "cdecl32",
            "stdcall32",
            "fastcall32",
        ):
            offset += self.word
        if self.name == "win64":
            offset += 32  # caller-allocated home area, after return address at entry
        for index in range(argc):
            size = sizes.get(str(index), sizes.get(index, self.word))
            size = (
                4
                if size == "c_long"
                and self.name
                in ("win64", "cdecl32", "stdcall32", "fastcall32", "arm32")
                else self.word if size == "c_long" else int(size)
            )
            if not 1 <= size <= 16:
                raise AbiError("aggregate/vector argument unsupported")
            # AAPCS32 64-bit scalar arguments start at an even register or doubleword stack boundary.
            if self.name == "arm32" and size == 8:
                if reg_index % 2:
                    reg_index += 1
                if reg_index + 1 < len(self.registers):
                    a = self.reg(self.registers[reg_index])
                    b = self.reg(self.registers[reg_index + 1])
                    reg_index += 2
                    result.append(
                        (a | (b << 32) if self.endian == "little" else (a << 32) | b)
                        if isinstance(a, int) and isinstance(b, int)
                        else Unknown("ARM register pair unreadable")
                    )
                    continue
                offset = (offset + 7) & ~7
            use_reg = reg_index < len(self.registers) and not (
                self.name == "fastcall32" and size > 4
            )
            if use_reg:
                value = self.reg(self.registers[reg_index])
                reg_index += 1
                result.append(
                    value & ((1 << (8 * size)) - 1) if isinstance(value, int) else value
                )
            else:
                addr = sp + offset if isinstance(sp, int) else sp
                result.append(self.read_int(addr, size))
                offset += ((size + self.word - 1) // self.word) * self.word
        return result

    def return_value(self):
        return self.reg(
            "RAX"
            if self.name in ("win64", "sysv64")
            else (
                "EAX"
                if self.name.endswith("32") and self.name != "arm32"
                else "X0" if self.name == "aarch64" else "R0"
            )
        )


def success(value, contract):
    if contract == "void":
        return True
    if not isinstance(value, int):
        return False
    if contract == "ntstatus":
        return value & 0xFFFFFFFF == 0
    if contract == "bool":
        return value & 0xFFFFFFFF != 0
    if contract == "openssl":
        return value & 0xFFFFFFFF == 1
    if contract == "mbedtls":
        return value & 0xFFFFFFFF == 0
    if contract == "zero":
        return value & 0xFFFFFFFF == 0
    if contract == "pointer":
        return value != 0
    if contract == "positive":
        return 0 < value < (1 << 63)
    if contract == "positive32":
        return 0 < (value & 0xFFFFFFFF) < (1 << 31)
    return True
