import numba
import datetime

IVT_SIZE = 256 # векторы

class VideoController:
    def __init__(self):
        self.width = 80
        self.height = 25
        self.vram = [0x20] * (self.width * self.height * 2)
        self.cursor_x = 0
        self.cursor_y = 0
        self.attr = 0x07
        self.mode = 0x03
        self.pallete = [(0,0,0)] * 16
        self.init_graphic_mode()

    def clear_screen(self):
        self.vram = [0x20, 0x07] * (self.width * self.height)
        self.cursor_x = 0
        self.cursor_y = 0

    def set_color(self, color):
        self.attr = color

    def init_graphic_mode(self):
        self.modes = {
            0x13: (320, 200, 256)
        }
        self.framebuffer = []

    def new_line(self):
        self.cursor_y += 1
        self.cursor_x = 0

        if self.cursor_y >= self.height:
            self.vram = self.vram[self.width*2:]
            self.vram += [0x20, self.attr] * self.width
            self.cursor_y = self.height - 1

    def put_char(self, char, attr=None):
        if attr is None:
            attr = self.attr
            
        if char == '\n':
            self.new_line()
            return
        elif char == '\r':
            self.cursor_x = 0
            return

        pos = (self.cursor_y * self.width + self.cursor_x) * 2
        self.vram[pos] = ord(char)
        self.vram[pos+1] = attr
        self.cursor_x += 1
        
        if self.cursor_x >= self.width:
            self.new_line()

class PetyshCore16:
    def __init__(self):
        self.video_output = None
        self.vc = VideoController()  # ммм ютубчик
        self.keyboard_buffer = [] # клава
        self.disk_data = {0: b"Boot sector"} # типо диск
        self.timer_ticks = 0
        self.rtc_time = datetime.datetime.now()
        self.interrupt_enabled = True
        self.debug_mode = False
        self.breakpoints = set()
        self.os_loaded = False
        self.programs_dir = "programs/"
        # 16-битные регистры
        self.registers = {
            'AX': 0x0000,
            'BX': 0x0000,
            'CX': 0x0000,
            'DX': 0x0000,
            'IP': 0x0000,
            'SP': 0xFFFF,
            'FLAGS': 0b00000000
        }

        self.registers.update({
            'CS': 0x0000,
            'DS': 0x0000,
            'ES': 0x0000,
            'SS': 0x0000,
            'SI': 0x0000,
            'DI': 0x0000,
            'BP': 0x0000
        })
        self.ports = [0] * 256
        self.rep_prefix = False
        self.direction_flag = False
        self.reg_names = ['AX', 'BX', 'CX', 'DX']

        self.ivt = [0x0000] * IVT_SIZE # каждая запись
        self.memory = [0x00] * 1048575 # 1мб
        self.memory_map = [False] * 65536 # карта занятой памяти
        self.memory_map[0x0000:0x0400] = [True]*0x0400 # ivt
        self.memory_blocks = {} # блоки памяти (выделенной)
        self.current_mcb = 0x0000 # memory control block
        
        self.gdt = [
            {'base': 0, 'limit': 0, 'access': 0x00},  # Нулевой дескриптор
            {'base': 0, 'limit': 0xFFFFF, 'access': 0x9A},  # Код сегмент
            {'base': 0, 'limit': 0xFFFFF, 'access': 0x92}   # Данные сегмент
        ]
        self.ldt = []
        self.gdtr = {'base': 0, 'limit': 0}
        self.ldtr = 0

    def update_arithmetic_flags(self, result):
        self.registers['FLAGS'] = 0b00000000

        value = result & 0xFFFF

        # нулевой
        if value == 0:
            self.registers['FLAGS'] |= 0b00000001

        if value & 0x8000:
            self.registers['FLAGS'] |= 0b00000010

        if result != value:
            self.registers['FLAGS'] |= 0b00000100

        if (result < -32768) or (result > 32767):
            self.registers['FLAGS'] |= 0b00001000

        if (result & 0xFFFF0000) != 0:
            self.registers['FLAGS'] |= 0b00010000

    def set_breakpoint(self, address):
        self.breakpoints.add(address)

    def single_step(self):
        old_ip = self.registers['IP']
        if self.memory[old_ip] == 0xCD:
            self.execute_int()
        else:
            self.execute_instruction()
        return old_ip

    def load_program(self, program):
        for i, byte in enumerate(program):
            self.memory[i] = byte

    def fetch_instruction(self):
        if self.registers['IP'] >= len(self.memory):
            raise IndexError("Instruction pointer out of memory")
        opcode = self.memory[self.registers['IP']]
        self.registers['IP'] += 1
        return opcode

    def update_flags(self):
        self.registers['FLAGS'] = 0b00000000

        if self.registers['AX'] == 0:
            self.registers['FLAGS'] |= 0b00000001 # з флаг

        if self.registers['AX'] & 0x8000:
            self.registers['FLAGS'] |= 0b000000010 # с флаг

    # прерывания
    def handle_disk_interrupt(self):
        sector = self.registers['DX']
        address = (self.registers['ES'] << 4) + self.registers['BX']

        if sector in self.disk_data:
            data = self.disk_data[sector]
            for i, byte in enumerate(data):
                self.memory[address + i] = byte
            self.registers['AX'] = 0x0000 # Норм
        else:
            self.registers['AX'] = 0x0001 # ааааа ашыбка

    def keyboard_interrupt(self):
        if self.keyboard_buffer:
            self.registers['AX'] = ord(self.keyboard_buffer.pop(0))
        else:
            self.registers['AX'] = 0x0000 # двери не открываются без ключа

    def handle_rtc_interrupt(self):
        function = self.registers['AX'] & 0xFF
        if function == 0x00:
            # получение времени
            self.registers['CX'] = self.rtc_time.hour
            self.registers['DX'] = self.rtc_time.minute

    def handle_video_interrupt(self):
        function = self.registers['AX'] & 0xFF00
        if function == 0x0E00:  
            char = chr(self.registers['AX'] & 0x00FF)
            self.vc.put_char(char)
        elif function == 0x0200: 
            self.vc.cursor_x = self.registers['DX'] & 0xFF
            self.vc.cursor_y = (self.registers['DX'] >> 8) & 0xFF
        elif function == 0x0600:  
            self.vc.clear_screen()
        elif function == 0x0900:  
            char = chr(self.registers['AX'] & 0x00FF)
            count = self.registers['CX']
            attr = self.registers['BX'] & 0xFF
            for _ in range(count):
                self.vc.put_char(char, attr)

    def add_key_input(self, text):
        self.keyboard_buffer.extend(list(text))

    # другой стафф
    def push(self, value):
        self.registers['SP'] -= 2
        self.memory[self.registers['SP']] = (value >> 8) & 0xFF
        self.memory[self.registers['SP'] + 1] = value & 0xFF

    def pop(self):
        value = (self.memory[self.registers['SP']] << 8) | self.memory[self.registers['SP'] + 1]
        self.registers['SP'] += 2
        return value

    def handle_interrupt(self, int_num):
        # чета типа обработчика прерываний
        if int_num == 0x10:
            self.handle_video_interrupt()
        elif int_num == 0x13:
            # диски типо ну это для ос для этого проца это уже в будущем
            # продумал круто типо да?
            self.handle_disk_interrupt()
        elif int_num == 0x16:
            self.keyboard_interrupt() # клава типо
        elif int_num == 0x21:
            # дос
            self.handle_dos_interrupt()
        if int_num == 0x21 and (self.registers['AX'] >> 8) == 0x48:
            # DOS ALLOCATE MEMORY
            size = self.registers['BX']
            addr = self.allocate_memory(size)
            self.registers['AX'] = addr
        elif int_num == 0x21 and (self.registers['AX'] >> 8) == 0x49:
            # DOS FREE MEMORY
            ptr = self.registers['ES']
            self.free_memory(ptr)
        elif int_num == 0x1A:
            # RTC
            self.handle_rtc_interrupt()

        # сохранения состояний
        self.push(self.registers['IP'])
        self.push(self.registers['FLAGS'])

        # переход к обработчику
        self.registers['IP'] = self.ivt[int_num]

    def handle_dos_interrupt(self):
        function = self.registers['AX'] >> 8
        if function == 0x4C:
            self.os_loaded = False
        if function == 0x4B:
            filename_addr = (self.registers['DS'] << 4) + self.registers['DX']
            filename = ""
            while self.memory[filename_addr] != 0:
                filename += chr(self.memory[filename_addr])
                filename_addr += 1
            self.load_and_run_program(filename)

    def run_os_command(self, command):
        if command.startswith("run "):
            filename = command[4:].strip('"')
            self.load_and_run_program(filename)

    def load_and_run_program(self, filename):
        try:
            with open(f"{self.programs_dir}{filename}", "rb") as f:
                program = list(f.read())
            self.load_program(program)
            self.os_loaded = True
            self.execute()
        except FileNotFoundError:
            print(f"File {filename} not found!")

    def video_interrupt(self):
        if self.registers['AX'] & 0xFF00 == 0x0E00:
            char = chr(self.registers['AX'] & 0x00FF)
            self.video_output.append(char)
            print(char, end='')

    # кулл стафф
    def disassemble(self, address):
        opcode = self.memory[address]
        if opcode == 0xA4:
            return "MOVSB"
        elif opcode == 0xA6:
            return "CMPSB"
        elif opcode == 0xAE:
            return "SCASB"
        if opcode == 0x01:
            return f"MOV {['AX','BX','CX','DX'][self.memory[address+1]]}, 0x{self.memory[address+2]:02X}{self.memory[address+3]:02X}"
        elif opcode == 0xFF:
            return "HLT"
        return f"DB 0x{opcode:02X}"

    def debug_info(self):
        print(f"AX: {self.registers['AX']:04X}  BX: {self.registers['BX']:04X}")
        print(f"IP: {self.registers['IP']:04X}  FLAGS: {bin(self.registers['FLAGS'])}")

    # крутая подсистема памяти

    def setup_memory_segments(self):
        self.segments = {
            'CODE': {'base': 0x0000, 'limit': 0xFFFF, 'access': 0x9A},
            'DATA': {'base': 0x1000, 'limit': 0xEFFF, 'access': 0x92},
            'STACK': {'base': 0xF000, 'limit': 0xFFFF, 'access': 0x96},
            'VIDEO': {'base': 0xB800, 'limit': 0x7FFF, 'access': 0x92}
        }

    def read_memory(self, segment, offset):
        seg_info = self.segments.get(segment)
        if not seg_info:
            self.handle_memory_fault(0)
            return 0
            
        if offset > seg_info['limit']:
            self.handle_memory_fault(offset)
            return 0
            
        physical_addr = seg_info['base'] + offset
        return self.memory[physical_addr]
        
    def write_memory(self, segment, offset, value):
        seg_info = self.segments.get(segment)
        if not seg_info:
            self.handle_memory_fault(0)
            return
            
        if seg_info['access'] & 0x02 == 0:
            self.handle_memory_fault(offset)
            return 
            
        if offset > seg_info['limit']:
            self.handle_memory_fault(offset)
            return

        physical_addr = seg_info['base'] + offset
        self.memory[physical_addr] = value
        
    def handle_memory_fault(self, address):
        self.push(self.registers['FLAGS'])
        self.push(self.registers['CS'])
        self.push(self.registers['IP'])
        self.registers['IP'] = self.ivt[0x0D]
        
    def allocate_memory(self, size):
        mcb_addr = self.current_mcb
        while mcb_addr < len(self.memory_map):
            if not self.memory_map[mcb_addr]:
                if self.check_free_block(mcb_addr, size):
                    self.set_mcb(mcb_addr, size)
                    return mcb_addr + 16
            mcb_addr += 16 + (self.memory[mcb_addr+1] << 8 | self.memory[mcb_addr])
        return 0xFFFF
        
    def check_free_block(self, addr, size):
        for i in range(addr, addr + size + 16):
            if self.memory_map[i]:
                return False
            return True
            
    def set_mcb(self, addr, size):
        self.memory[addr] = size & 0xFF
        self.memory[addr+1] = (size >> 8) & 0xFF
        self.memory[addr+2] = 0x4D
        for i in range(addr, addr + size + 16):
            self.memory_map[i] = True
            
    def free_memory(self, ptr):
        mcb_addr = ptr - 16
        if self.memory[mcb_addr+2] != 0x4D:
            self.handle_memory_fault(mcb_addr)
            return
            
        size = self.memory[mcb_addr] | (self.memory[mcb_addr+1] << 8)
        for i in range(mcb_addr, mcb_addr + size + 16):
            self.memory_map[i] = False
            
    def load_gdt(self, base, limit):
        self.gdtr['base'] = base
        self.gdtr['limit'] = limit
        for i in range(0, limit+1, 8):
            entry = {
                'base': self.memory[i+2] | (self.memory[i+3] << 8) | (self.memory[i+4] << 16),
                'limit': self.memory[i] | (self.memory[i+1] << 8),
                'access': self.memory[i+5]
            }
            if i//8 >= len(self.gdt):
                self.gdt.append(entry)
            else:
                self.gdt[i//8] = entry

    def step_debug(self):
        self.debug_show_registers()
        self.debug_disassemble_text()
        input("Press enter to continue...")

    def debug_show_registers(self):
        print(f"AX: {self.registers['AX']:04X}  BX: {self.registers['BX']:04X}")
        print(f"CX: {self.registers['CX']:04X}  DX: {self.registers['DX']:04X}")
        print(f"IP: {self.registers['IP']:04X}  SP: {self.registers['SP']:04X}")
        print(f"FLAGS: {bin(self.registers['FLAGS'])[2:].zfill(8)}")

    def debug_disassemble_text(self, num_instructions=5):
        ip = self.registers['IP']
        for i in range(num_instructions):
            addr = ip + i
            if addr >= len(self.memory):
                break
            print(f"{addr:04X}: {self.disassemble(addr)}")

    def debug_show_memory(self, start, length):
        for i in range(start, start+length, 16):
            line = f"{i:04X}"
            line += ' '.join(f"{self.memory[j]:02X}" for j in range(i, min(i + 16, start + length)))
            print(line)

    # оптимайзинг йоу
    def enable_jit(self):
        self.execute = numba.jit(self.execute, nopython=True)

    def cache_decoded_instructions(self):
        self.instruction_cache = {}
        for addr in range(len(self.memory)):
            self.instruction_cache[addr] = self.disassemble(addr)

    ##########

    def handle_mul_instruction(self):
        reg_code = self.fetch_instruction()
        reg = self.reg_names[reg_code]
        result = self.registers['AX'] * self.registers[reg]
        self.registers['DX'] = (result >> 16) & 0xFFFF
        self.registers['AX'] = result & 0xFFFF
        self.update_arithmetic_flags(result)

    def handle_div_instruction(self):
        divisor = self.registers[self.reg_names[self.fetch_instruction()]]
        if divisor == 0:
            self.handle_interrupt(0x00)
            return
        dividend = (self.registers['DX'] << 16) | self.registers['AX']
        self.registers['AX'] = dividend // divisor
        var = self.registers['DX'] - dividend % divisor

    def handle_loop_instruction(self):
        count_reg = self.reg_names[self.fetch_instruction()]
        offset = self.fetch_instruction()
        self.registers[count_reg] -= 1
        if self.registers[count_reg] != 0:
            self.registers['IP'] += offset - 2

    def handle_interrupt_flag_instruction(self):
        flag = self.fetch_instruction()
        self.interrupt_enabled = (flag == 0x01)

    def execute_instruction(self):
        pass

    def execute_int(self):
        int_num = self.fetch_instruction()
        self.handle_interrupt(int_num)

    def dump_memory_page(self, page=0):
        print(f"Memory page {page:02X}:")
        for i in range(0, 256, 16):
            print(f"{i:02X}: {' '.join(f'{self.memory[page*256 + i + j]:02X}' for j in range(16))}")

    def show_video_output(self):
        for y in range(self.vc.height):
            line = ''
            for x in range(self.vc.width):
                pos = (y * self.vc.width + x) * 2
                line += chr(self.vc.vram[pos])
            print(line)

    def update_logic_flags(self):
        self.registers['FLAGS'] = 0b00000000
        value = self.registers['AX']

        if value == 0:
            self.registers['FLAGS'] |= 0b00000001 # нуль
        if value & 0x8000:
            self.registers['FLAGS'] |= 0b00000010 # сигна

    def update_shift_flags(self, count):
        self.registers['FLAGS'] = 0b00000000
        value = self.registers['AX']

        if value == 0:
            self.registers['FLAGS'] |= 0b00000001  # нуль
        if value & 0x8000:
            self.registers['FLAGS'] |= 0b00000010  # сигна

        if count > 0:
            mask = 0x8000 >> (16 - count)
            if (self.registers['AX'] << (count - 1)) & 0x8000:
                self.registers['FLAGS'] |= 0b00000100

    def execute(self):
        while True:
            if self.registers['IP'] in self.breakpoints and self.debug_mode:
                self.step_debug()
            
            opcode = self.fetch_instruction()

            if opcode == 0x01:
                reg_code = self.fetch_instruction()
                value_high = self.fetch_instruction()
                value_low = self.fetch_instruction()
                value = (value_high << 8) | value_low
                reg_name = ['AX', 'BX', 'CX', 'DX'][reg_code]
                self.registers[reg_name] = value
            elif opcode == 0x02:
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = ['AX', 'BX', 'CX', 'DX'][reg1_code]
                reg2 = ['AX', 'BX', 'CX', 'DX'][reg2_code]

                result = self.registers[reg1] + self.registers[reg2]
                self.registers[reg1] = result & 0xFFFF

                # обнова флагов
                self.registers['FLAGS'] = 0b00000000
                if result > 0xFFFF:
                    self.registers['FLAGS'] |= 0b00000010 # флаг переноса
                if self.registers[reg1] == 0:
                    self.registers['FLAGS'] |= 0b00000001 # нулевой результат
            elif opcode == 0x03:
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x04:
                # sub
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                result = self.registers[reg1] - self.registers[reg2]
                self.registers[reg1] = result & 0xFFFF
                self.update_arithmetic_flags(result)
            elif opcode == 0x05:
                # and
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                self.registers[reg1] &= self.registers[reg2]
                self.update_logic_flags()
            elif opcode == 0x06:
                # shl
                reg_code = self.fetch_instruction()
                count = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                self.registers[reg] = (self.registers[reg] << count) & 0xFF
                self.update_shift_flags(count)
            elif opcode == 0x07:
                # OR
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                self.registers[reg1] |= self.registers[reg2]
                self.update_logic_flags()
            elif opcode == 0x08:
                # XOR
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                self.registers[reg1] ^= self.registers[reg2]
                self.update_logic_flags()
            elif opcode == 0x09:
                # NOT
                reg_code = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                self.registers[reg] = ~self.registers[reg] & 0xFFFF
                self.update_logic_flags()
            elif opcode == 0x10:
                # MUL
                self.handle_mul_instruction()
            elif opcode == 0x11:
                # DIV
                self.handle_div_instruction()
            elif opcode == 0x12:
                # LOOP
                self.handle_loop_instruction()
            elif opcode == 0x13:
                # STI/CLI
                self.handle_interrupt_flag_instruction()
            elif opcode == 0x0A:
                # CMP
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                result = self.registers[reg1] - self.registers[reg2]
                self.update_arithmetic_flags(result)
            elif opcode == 0x0B:
                # JE (jump если есть =)
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                if self.registers['FLAGS'] & 0b0000001:
                    self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x0C:
                # CALL
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                self.push(self.registers['IP'])
                self.registers['IP'] = (addr_high >> 8) | addr_low
            elif opcode == 0x0D:
                # RET
                self.registers['IP'] = self.pop()
            elif opcode == 0x0E:
                # INC
                reg_code = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                self.registers[reg] = (self.registers[reg] + 1) & 0xFFFF
                self.update_arithmetic_flags(self.registers[reg])
            elif opcode == 0x0F:
                # DEC
                reg_code = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                self.registers[reg] = (self.registers[reg] - 1) & 0xFFFF
                self.update_arithmetic_flags(self.registers[reg])
            elif opcode == 0x50:  # PUSH AX
                self.push(self.registers['AX'])
            elif opcode == 0x58:  # POP AX
                self.registers['AX'] = self.pop()
            elif opcode == 0xE4:  # IN AL, port
                port = self.fetch_instruction()
                self.registers['AX'] = self.ports[port]
            elif opcode == 0xE6:  # OUT port, AL
                port = self.fetch_instruction()
                self.ports[port] = self.registers['AX'] & 0xFF
            elif opcode == 0xA4:  # MOVSB
                src = (self.registers['DS'] << 4) + self.registers['SI']
                dest = (self.registers['ES'] << 4) + self.registers['DI']
                self.memory[dest] = self.memory[src]
                self.registers['SI'] += -1 if self.direction_flag else 1
                self.registers['DI'] += -1 if self.direction_flag else 1
            elif opcode == 0xFC:  # CLD (Clear Direction Flag)
                self.direction_flag = False
            elif opcode == 0xFD:  # STD (Set Direction Flag)
                self.direction_flag = True
            elif opcode == 0x14:
                # JNE
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                if not (self.registers['FLAGS'] & 0b00000001):
                    self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x15:
                # JG
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                sf = (self.registers['FLAGS'] & 0b00000010) >> 1
                of = (self.registers['FLAGS'] & 0b00001000) >> 3
                zf = self.registers['FLAGS'] & 0b00000001
                if not zf and (zf == of):
                    self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x17:
                # TEST reg1, reg2
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                result = self.registers[reg1] & self.registers[reg2]
                self.update_logic_flags(result)
            elif opcode == 0x9C:
                # PUSHF
                self.push(self.registers['FLAGS'])
            elif opcode == 0x9D:
                # POPF
                self.registers['FLAGS'] = self.pop() & 0xFF
            elif opcode == 0x8D:
                # LEA reg, [offset]
                reg_code = self.fetch_instruction()
                offset_high = self.fetch_instruction()
                offset_low = self.fetch_instruction()
                self.registers[self.reg_names[reg_code]] = (offset_high << 8) | offset_low
            elif opcode in {0x53, 0x51, 0x52}:
                # PUSH BX/CX/DX
                reg_map = {0x53: 'BX', 0x51: 'CX', 0x52: 'DX'}
                self.push(self.registers[reg_map[opcode]])
                
            elif opcode in {0x5B, 0x59, 0x5A}:
                # POP BX/CX/DX
                reg_map = {0x5B: 'BX', 0x59: 'CX', 0x5A: 'DX'}
                self.registers[reg_map[opcode]] = self.pop()
            elif opcode == 0x1B:
                # JMP short
                offset = self.fetch_instruction()
                self.registers['IP'] += offset - 2
            elif opcode == 0x1C:
                # JC (Jump if Carry)                
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                if self.registers['FLAGS'] & 0b00000010:
                    self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x1D:
                # JNC (Jump if Not Carry)
                addr_high = self.fetch_instruction()
                addr_low = self.fetch_instruction()
                if not (self.registers['FLAGS'] & 0b00000010):
                    self.registers['IP'] = (addr_high << 8) | addr_low
            elif opcode == 0x1E:
                # MOV [BX], AX
                address = self.registers['BX']
                self.memory[address] = (self.registers['AX'] >> 8) & 0xFF
                self.memory[address + 1] = self.registers['AX'] & 0xFF
            elif opcode == 0x1F:
                # MOV AX, [BX]
                address = self.registers['BX']
                self.registers['AX'] = (self.memory[address] << 8) | self.memory[address + 1]
            elif opcode == 0x20:
                # ADC (Add with Carry)                
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                carry = (self.registers['FLAGS'] & 0b00000010) >> 1
                result = self.registers[reg1] + self.registers[reg2] + carry
                self.registers[reg1] = result & 0xFFFF
                self.update_arithmetic_flags(result)
            elif opcode == 0x21:
                # SBB (Subtract with Borrow)
                reg1_code = self.fetch_instruction()
                reg2_code = self.fetch_instruction()
                reg1 = self.reg_names[reg1_code]
                reg2 = self.reg_names[reg2_code]
                borrow = (self.registers['FLAGS'] & 0b00000010) >> 1
                result = self.registers[reg1] - self.registers[reg2] - borrow
                self.registers[reg1] = result & 0xFFFF
                self.update_arithmetic_flags(result)
            elif opcode == 0x22:
                # CLC (Clear Carry Flag)
                self.registers['FLAGS'] &= ~0b00000010
            elif opcode == 0x23:
                # STC (Set Carry Flag)
                self.registers['FLAGS'] |= 0b00000010
            elif opcode == 0x24:
                # LODSB (Load String Byte)
                self.registers['AX'] = self.memory[(self.registers['DS'] << 4) + self.registers['SI']]
                self.registers['SI'] += 1 if not self.direction_flag else -1
            elif opcode == 0x25:
                # STOSB (Store String Byte)
                self.memory[(self.registers['ES'] << 4) + self.registers['DI']] = self.registers['AX'] & 0xFF
                self.registers['DI'] += 1 if not self.direction_flag else -1
            elif opcode == 0x26:
                # PUSHA (Push All Registers)
                sp = self.registers['SP']
                self.push(self.registers['AX'])
                self.push(self.registers['CX'])
                self.push(self.registers['DX'])
                self.push(self.registers['BX'])
                self.push(sp)
                self.push(self.registers['BP'])
                self.push(self.registers['SI'])
                self.push(self.registers['DI'])
            elif opcode == 0x27:
                # POPA (Pop All Registers)
                self.registers['DI'] = self.pop()
                self.registers['SI'] = self.pop()
                self.registers['BP'] = self.pop()
                self.pop()  # Skip SP
                self.registers['BX'] = self.pop()
                self.registers['DX'] = self.pop()
                self.registers['CX'] = self.pop()
                self.registers['AX'] = self.pop()
            elif opcode == 0x28:
                # ROL (Rotate Left)
                reg_code = self.fetch_instruction()
                count = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                value = self.registers[reg]
                for _ in range(count):
                    bit = (value >> 15) & 1
                    value = ((value << 1) | bit) & 0xFFFF
                self.registers[reg] = value
                self.update_shift_flags(count)
            elif opcode == 0x29:
                # ROR (Rotate Right)
                reg_code = self.fetch_instruction()
                count = self.fetch_instruction()
                reg = self.reg_names[reg_code]
                value = self.registers[reg]
                for _ in range(count):
                    bit = value & 1
                    value = (value >> 1) | (bit << 15)
                self.registers[reg] = value
                self.update_shift_flags(count)
            # Обработка префиксов
            if opcode == 0xF3:  # REP префикс
                self.rep_prefix = True
                opcode = self.fetch_instruction()
            
            if opcode == 0xA4:  # MOVSB
                count = self.registers['CX'] if self.rep_prefix else 1
                for _ in range(count):
                    src = (self.registers['DS'] << 4) + self.registers['SI']
                    dest = (self.registers['ES'] << 4) + self.registers['DI']
                    self.memory[dest] = self.memory[src]
                    self.registers['SI'] += -1 if self.direction_flag else 1
                    self.registers['DI'] += -1 if self.direction_flag else 1
                    if self.rep_prefix: 
                        self.registers['CX'] -= 1
                        if self.registers['CX'] == 0: break
                self.rep_prefix = False

            elif opcode == 0xA6:  # CMPSB
                count = self.registers['CX'] if self.rep_prefix else 1
                for _ in range(count):
                    src = (self.registers['DS'] << 4) + self.registers['SI']
                    dest = (self.registers['ES'] << 4) + self.registers['DI']
                    res = self.memory[src] - self.memory[dest]
                    self.update_arithmetic_flags(res)
                    self.registers['SI'] += -1 if self.direction_flag else 1
                    self.registers['DI'] += -1 if self.direction_flag else 1
                    if self.rep_prefix: 
                        self.registers['CX'] -= 1
                        if self.registers['CX'] == 0 or res != 0: break
                self.rep_prefix = False

            elif opcode == 0xAE:  # SCASB
                count = self.registers['CX'] if self.rep_prefix else 1
                for _ in range(count):
                    addr = (self.registers['ES'] << 4) + self.registers['DI']
                    res = (self.registers['AX'] & 0xFF) - self.memory[addr]
                    self.update_arithmetic_flags(res)
                    self.registers['DI'] += -1 if self.direction_flag else 1
                    if self.rep_prefix: 
                        self.registers['CX'] -= 1
                        if self.registers['CX'] == 0 or res == 0: break
                self.rep_prefix = False
            elif opcode == 0x54:  # PUSH SP
                self.push(self.registers['SP'])
            elif opcode == 0x55:  # PUSH BP
                self.push(self.registers['BP'])
            elif opcode == 0x56:  # PUSH SI
                self.push(self.registers['SI'])
            elif opcode == 0x57:  # PUSH DI
                self.push(self.registers['DI'])
            elif opcode == 0x06:  # PUSH ES
                self.push(self.registers['ES'])
            elif opcode == 0x0E:  # PUSH CS
                self.push(self.registers['CS'])
            elif opcode == 0x16:  # PUSH SS
                self.push(self.registers['SS'])
            elif opcode == 0x1E:  # PUSH DS
                self.push(self.registers['DS'])
                
            elif opcode == 0x5C:  # POP SP
                self.registers['SP'] = self.pop()
            elif opcode == 0x5D:  # POP BP
                self.registers['BP'] = self.pop()
            elif opcode == 0x5E:  # POP SI
                self.registers['SI'] = self.pop()
            elif opcode == 0x5F:  # POP DI
                self.registers['DI'] = self.pop()
            elif opcode == 0x07:  # POP ES
                self.registers['ES'] = self.pop()
            elif opcode == 0x0F:  # POP CS
                self.registers['CS'] = self.pop()
            elif opcode == 0x17:  # POP SS
                self.registers['SS'] = self.pop()
            elif opcode == 0x1F:  # POP DS
                self.registers['DS'] = self.pop()

            # Special case for flags
            elif opcode == 0x9C:  # PUSHF
                self.push(self.registers['FLAGS'])
            elif opcode == 0x9D:  # POPF
                self.registers['FLAGS'] = self.pop() & 0xFF
            elif opcode == 0xCD:
                # INT (обработчик)
                int_num = self.fetch_instruction()
                self.handle_interrupt(int_num)
            elif opcode == 0xFF:
                break

            self.update_flags()


if __name__ == "__main__":
    cpu = PetyshCore16()
    program = [
        0xB4, 0x0E, 0xB0, 0x48, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x65, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x6C, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x6C, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x6F, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x2C, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x20, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x77, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x6F, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x72, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x6C, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x64, 0xCD, 0x10,
        0xB4, 0x0E, 0xB0, 0x21, 0xCD, 0x10,
        0xB4, 0x4C, 0xCD, 0x21
    ]
    cpu.load_program(program)
    cpu.add_key_input("A")

    try:
        while True:
            cpu.step_debug()
            if cpu.memory[cpu.registers['IP']] == 0xFF:
                cpu.execute()
                break
            cpu.execute()
            cpu.show_video_output()
    except IndexError:
        print("\n[CPU HALTED] Instruction pointer out of bounds")