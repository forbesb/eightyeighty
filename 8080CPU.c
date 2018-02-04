#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct ConditionCodes {
 uint8_t z:1;
 uint8_t s:1;
 uint8_t p:1;
 uint8_t cy:1;
 uint8_t ac:1;
 uint8_t pad:3;
 } ConditionCodes;

typedef struct State8080 {
 uint8_t a;
 uint8_t b;
 uint8_t c;
 uint8_t d;
 uint8_t e;
 uint8_t h;
 uint8_t l;
 uint16_t sp;
 uint16_t pc;
 uint8_t * memory;
 struct ConditionCodes cc;
 uint8_t int_enable;
} State8080;

void UnimplementedInstruction(State8080* state)
{
 printf("Error: Unimplemented Instruction\n");
 exit(1);
}

int Parity(uint16_t n){
 return n % 2 == 0;
}

void LXI(uint8_t* r1, uint8_t* r2, char *opcode, State8080* state){
 *r1 = opcode[2];
 *r2 = opcode[1];
 state->pc += 2;
}

void MOV(uint8_t* r1, uint8_t val, State8080* state){
 *r1 = val;
}

void ADD(uint8_t r, bool carry, State8080 *state){
    uint16_t answer = (uint16_t) state->a + (uint16_t) r + carry ? state->cc.cy : 0;
    state->cc.z = ((answer & 0xff) == 0);
    state->cc.s = ((answer & 0x80) != 0);
    state->cc.cy = (answer > 0xff);
    state->cc.p = Parity(answer & 0xff);
    state->a = answer & 0xff;
}

void SUB(uint8_t r, bool carry, State8080 *state){
    uint16_t answer = (uint16_t) state->a - (uint16_t) r - carry ? state->cc.cy: 0;
    state->cc.z = ((answer & 0xff) == 0);
    state->cc.s = ((answer & 0x80) != 0);
    state->cc.cy = (answer > 0xff);
    state->cc.p = Parity(answer & 0xff);
    state->a = answer & 0xff;
}

void INC(uint8_t* r, State8080 *state){
    uint16_t answer = (uint16_t) *r + 1;
    state->cc.z = ((answer & 0xff) == 0);
    state->cc.s = ((answer & 0x80) != 0);
    state->cc.p = Parity(answer & 0xff);
    *r = answer & 0xff;
}

void DCR(uint8_t* r, State8080 *state){
    uint16_t answer = (uint16_t) *r - 1;
    *r = answer & 0xff;
}

void INX(uint16_t* r, State8080 *state){
    uint32_t answer = (uint32_t) *r + 1;
    *r = answer & 0xffff;
}

void DCX(uint16_t* r, State8080 *state){
    uint32_t answer = (uint32_t) *r - 1;
    *r = answer & 0xffff;
}

void DAD(uint16_t r, State8080 *state){
    uint32_t answer = (state->h << 8 | state->l) + r;
    state->cc.cy = answer > 0xffff;
    state->h = answer >> 8;
    state->l = answer & 0xff;
}

void DAA(State8080 *state){
    //TODO auxiliary Carry
}
int Emulate8080Op(State8080* state) {
 unsigned char *opcode = &state->memory[state->pc];

 switch(*opcode) {
    case 0x00: break; // NOP
    //// Data Transfer
    //LXI rp, data
    case 0x01: LXI(&state->b, &state->c, opcode, state); break;
    case 0x11: LXI(&state->d, &state->e, opcode, state); break;
    case 0x21: LXI(&state->h, &state->l, opcode, state); break;
    case 0x31: LXI((uint8_t *) &state->sp,(uint8_t*)  &state->sp + sizeof(uint8_t), opcode, state); break;
    /*
    // MVI r | Mem, data
    case 0x06: printf("MVI B, #$%02x", code[1]); opbytes=2; break;
    case 0x0E: printf("MVI C, #$%02x", code[1]); opbytes=2; break;
    case 0x16: printf("MVI D, #$%02x", code[1]); opbytes=2; break;
    case 0x1E: printf("MVI E, #$%02x", code[1]); opbytes=2; break;
    case 0x26: printf("MVI H, #$%02x", code[1]); opbytes=2; break;
    case 0x2E: printf("MVI L, #$%02x", code[1]); opbytes=2; break;
    case 0x36: printf("MVI M, #$%02x", code[1]); opbytes=2; break;
    case 0x3E: printf("MVI A, #$%02x", code[1]); opbytes=2; break;
    */
    // MOV (r1, r2) | (r, M) | (M, r)
    case 0x40: break; // B->B
    case 0x41: MOV(&state->b, state->c, state); break;
    case 0x42: MOV(&state->b, state->d, state); break;
    case 0x43: MOV(&state->b, state->e, state); break;
    case 0x44: MOV(&state->b, state->h, state); break;
    case 0x45: MOV(&state->b, state->l, state); break;
    case 0x46: MOV(&state->b, state->memory[state->h<<8 | state->l], state); break;
    case 0x47: MOV(&state->b, state->a, state); break;
    /*
    case 0x48: printf("MOV C, B"); break;
    case 0x49: printf("MOV C, C"); break;
    case 0x4A: printf("MOV C, D"); break;
    case 0x4B: printf("MOV C, E"); break;
    case 0x4C: printf("MOV C, H"); break;
    case 0x4D: printf("MOV C, L"); break;
    case 0x4E: printf("MOV C, M"); break;
    case 0x4F: printf("MOV C, A"); break;
    case 0x50: printf("MOV D, B"); break;
    case 0x51: printf("MOV D, C"); break;
    case 0x52: printf("MOV D, D"); break;
    case 0x53: printf("MOV D, E"); break;
    case 0x54: printf("MOV D, H"); break;
    case 0x55: printf("MOV D, L"); break;
    case 0x56: printf("MOV D, M"); break;
    case 0x57: printf("MOV D, A"); break;
    case 0x58: printf("MOV E, B"); break;
    case 0x59: printf("MOV E, C"); break;
    case 0x5A: printf("MOV E, D"); break;
    case 0x5B: printf("MOV E, E"); break;
    case 0x5C: printf("MOV E, H"); break;
    case 0x5D: printf("MOV E, L"); break;
    case 0x5E: printf("MOV E, M"); break;
    case 0x5F: printf("MOV E, A"); break;
    case 0x60: printf("MOV H, B"); break;
    case 0x61: printf("MOV H, C"); break;
    case 0x62: printf("MOV H, D"); break;
    case 0x63: printf("MOV H, E"); break;
    case 0x64: printf("MOV H, H"); break;
    case 0x65: printf("MOV H, L"); break;
    case 0x66: printf("MOV H, M"); break;
    case 0x67: printf("MOV H, A"); break;
    case 0x68: printf("MOV L, B"); break;
    case 0x69: printf("MOV L, C"); break;
    case 0x6A: printf("MOV L, D"); break;
    case 0x6B: printf("MOV L, E"); break;
    case 0x6C: printf("MOV L, H"); break;
    case 0x6D: printf("MOV L, L"); break;
    case 0x6E: printf("MOV L, M"); break;
    case 0x6F: printf("MOV L, A"); break;
    case 0x70: printf("MOV M, B"); break;
    case 0x71: printf("MOV M, C"); break;
    case 0x72: printf("MOV M, D"); break;
    case 0x73: printf("MOV M, E"); break;
    case 0x74: printf("MOV M, H"); break;
    case 0x75: printf("MOV M, L"); break;
    case 0x77: printf("MOV M, A"); break;
    case 0x78: printf("MOV A, B"); break;
    case 0x79: printf("MOV A, C"); break;
    case 0x7A: printf("MOV A, D"); break;
    case 0x7B: printf("MOV A, E"); break;
    case 0x7C: printf("MOV A, H"); break;
    case 0x7D: printf("MOV A, L"); break;
    case 0x7E: printf("MOV A, M"); break;
    case 0x7F: printf("MOV A, A"); break;
    /*
    // LD/ST A
    case 0x32: printf("STA, $%02x%02x", code[2], code[1]); opbytes=3;break;
    case 0x3a: printf("LDA, $%02x%02x", code[2], code[1]); opbytes=3;break;
    // L/SHLD
    case 0x2A: printf("LHLD $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0x22: printf("SHLD $%02x%02x", code[2], code[1]); opbytes=3; break;
    // LD/STAX
    case 0x02: printf("STAX BC"); break;
    case 0x0A: printf("LDAX BC"); break;
    case 0x12: printf("STAX DE"); break;
    case 0x1A: printf("LDAX DE"); break;
    // XCHG
    case 0xEB: printf("XCHG"); break;
    */
    //// Arithmetic:
    // ADD
    case 0x80: ADD(state->b, false, state); break;
    case 0x81: ADD(state->c, false, state); break;
    case 0x82: ADD(state->d, false, state); break;
    case 0x83: ADD(state->e, false, state); break;
    case 0x84: ADD(state->h, false, state); break;
    case 0x85: ADD(state->l, false, state); break;
    case 0x86: ADD(state->memory[state->h << 8 | state->l], false, state); break;
    case 0x87: ADD(state->a, false, state); break;
    case 0x88: ADD(state->b, true, state); break;
    case 0x89: ADD(state->c, true, state); break;
    case 0x8A: ADD(state->d, true, state); break;
    case 0x8B: ADD(state->e, true, state); break;
    case 0x8C: ADD(state->h, true, state); break;
    case 0x8D: ADD(state->l, true, state); break;
    case 0x8E: ADD(state->memory[state->h << 8 | state->l], true, state); break;
    case 0x8F: ADD(state->a, true, state); break;
    case 0xC6: ADD((uint8_t) opcode[1], false, state); state->pc += 1; break; // ADDI
    case 0xCE: ADD((uint8_t) opcode[1], true, state); state->pc += 1; break; // ADCI
    // SUB
    case 0x90: SUB(state->b, false, state); break; 
    case 0x91: SUB(state->c, false, state); break;
    case 0x92: SUB(state->d, false, state); break;
    case 0x93: SUB(state->e, false, state); break;
    case 0x94: SUB(state->h, false, state); break;
    case 0x95: SUB(state->l, false, state); break;
    case 0x96: SUB(state->memory[state->h << 8 | state->l], false, state); break;
    case 0x97: SUB(state->a, false, state); break;
    case 0x98: SUB(state->b, true, state); break;
    case 0x99: SUB(state->c, true, state); break;
    case 0x9A: SUB(state->d, true, state); break;
    case 0x9B: SUB(state->e, true, state); break;
    case 0x9C: SUB(state->h, true, state); break;
    case 0x9D: SUB(state->l, true, state); break;
    case 0x9E: SUB(state->memory[state->h << 8 | state->l], true, state); break;
    case 0x9F: SUB(state->b, true, state); break;
    case 0xD6: SUB((uint8_t) opcode[1], false, state); state->pc += 1; break; 
    case 0xDE: SUB((uint8_t) opcode[1], true, state); state->pc += 1; break;
    // IN/DC
    case 0x04: INC(&state->b, state);
    case 0x0C: INC(&state->c, state);
    case 0x14: INC(&state->d, state);
    case 0x1C: INC(&state->e, state);
    case 0x24: INC(&state->h, state);
    case 0x2C: INC(&state->l, state);
    case 0x34: INC(&state->memory[state->h << 8 | state->l], state);
    case 0x3C: INC(&state->a, state);
    case 0x05: DCR(&state->b, state);
    case 0x0D: DCR(&state->c, state);
    case 0x15: DCR(&state->d, state);
    case 0x1D: DCR(&state->e, state);
    case 0x25: DCR(&state->h, state);
    case 0x2D: DCR(&state->l, state);
    case 0x35: DCR(&state->memory[state->h << 8 | state->l], state);
    case 0x3D: DCR(&state->a, state);
    case 0x03: INX((uint16_t*) &state->b, state);
    case 0x13: INX((uint16_t*) &state->d, state);
    case 0x23: INX((uint16_t*) &state->h, state);
    case 0x33: INX(&state->sp, state);
    case 0x0B: DCX((uint16_t*) &state->b, state);
    case 0x1B: DCX((uint16_t*) &state->b, state);
    case 0x2B: DCX((uint16_t*) &state->b, state);
    case 0x3B: DCX((uint16_t*) &state->b, state);
    case 0x09: DAD(state->b << 8 | state->c, state);
    case 0x19: DAD(state->d << 8 | state->e, state);
    case 0x29: DAD(state->h << 8 | state->l, state);
    case 0x39: DAD(state->sp, state);
    //case 0x27: printf("DAA"); break;
    //TODO: DAA
    /*

    //// Logical
    // AN
    case 0xA0: printf("ANA B"); break;
    case 0xA1: printf("ANA C"); break;
    case 0xA2: printf("ANA D"); break;
    case 0xA3: printf("ANA E"); break;
    case 0xA4: printf("ANA H"); break;
    case 0xA5: printf("ANA L"); break;
    case 0xA6: printf("ANA M"); break;
    case 0xA7: printf("ANA A"); break;
    case 0xE6: printf("ANI #%02x", code[1]); opbytes=2; break;
    // XR
    case 0xA8: printf("XRA B"); break;
    case 0xA9: printf("XRA C"); break;
    case 0xAA: printf("XRA D"); break;
    case 0xAB: printf("XRA E"); break;
    case 0xAC: printf("XRA H"); break;
    case 0xAD: printf("XRA L"); break;
    case 0xAE: printf("XRA M"); break;
    case 0xAF: printf("XRA A"); break;
    case 0xEE: printf("XRI #%02x", code[1]); opbytes=2; break;
    // OR
    case 0xB0: printf("ORA B"); break;
    case 0xB1: printf("ORA C"); break;
    case 0xB2: printf("ORA D"); break;
    case 0xB3: printf("ORA E"); break;
    case 0xB4: printf("ORA H"); break;
    case 0xB5: printf("ORA L"); break;
    case 0xB6: printf("ORA M"); break;
    case 0xB7: printf("ORA A"); break;
    case 0xF6: printf("ORI #%02x", code[1]); opbytes=2; break;
    //CMP
    case 0xB8: printf("CMP B"); break;
    case 0xB9: printf("CMP C"); break;
    case 0xBA: printf("CMP D"); break;
    case 0xBB: printf("CMP E"); break;
    case 0xBC: printf("CMP H"); break;
    case 0xBD: printf("CMP L"); break;
    case 0xBE: printf("CMP M"); break;
    case 0xBF: printf("CMP A"); break;
    case 0xFE: printf("CPI #$%02x", code[1]); opbytes=2; break;
    // R
    case 0x07: printf("RLC"); break;
    case 0x0F: printf("RRC"); break;
    case 0x17: printf("RAL"); break;
    case 0x1F: printf("RAR"); break;
    // CM
    case 0x2F: printf("CMA"); break;
    case 0x3F: printf("CMC"); break;
    // ST
    case 0x37: printf("STC"); break;
    //// Branch
    // Conditions: NZ 000, Z 001, NC 010, C 011, PO 100, PE 101, P 110, M 111
    // JMP
    case 0xC3: printf("JMP $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xC2: printf("JNZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xCA: printf("JZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xD2: printf("JNC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xDA: printf("JC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xE2: printf("JPO $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xEA: printf("JPE $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xF2: printf("JP $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xFA: printf("JM $%02x%02x", code[2], code[1]); opbytes=3; break;
    // CALL
    case 0xCD: printf("CALL $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xC4: printf("CNZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xCC: printf("CZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xD4: printf("CNC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xDC: printf("CC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xE4: printf("CPO $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xEC: printf("CPE $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xF4: printf("CP $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xFC: printf("CM $%02x%02x", code[2], code[1]); opbytes=3; break;
    // RET
    case 0xC9: printf("RET $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xC0: printf("RNZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xC8: printf("RZ $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xD0: printf("RNC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xD8: printf("RC $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xE0: printf("RPO $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xE8: printf("RPE $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xF0: printf("RP $%02x%02x", code[2], code[1]); opbytes=3; break;
    case 0xF8: printf("RM $%02x%02x", code[2], code[1]); opbytes=3; break;
    // RST
    case 0xC7: printf("RST 0"); break;
    case 0xCF: printf("RST 1"); break;
    case 0xD7: printf("RST 2"); break;
    case 0xDF: printf("RST 3"); break;
    case 0xE7: printf("RST 4"); break;
    case 0xEF: printf("RST 5"); break;
    case 0xF7: printf("RST 6"); break;
    case 0xFF: printf("RST 7"); break;
    // PCHL
    case 0xE9: printf("PCHL"); break;
    //// Stack, IO, Machine Control
    // PUSH/POP
    case 0xC5: printf("PUSH BC"); break;
    case 0xD5: printf("PUSH DE"); break;
    case 0xE5: printf("PUSH HL"); break;
    case 0xF5: printf("PUSH PSW"); break;
    case 0xC1: printf("POP BC"); break;
    case 0xD1: printf("POP DE"); break;
    case 0xE1: printf("POP HL"); break;
    case 0xF1: printf("POP PSW"); break;
    case 0xE3: printf("XTHL"); break;
    case 0xF9: printf("SPHL"); break;
    // IO
    case 0xDB: printf("IN #$%02x", code[1]); opbytes=2; break;
    case 0xD3: printf("OUT #$%02x", code[1]); opbytes=2; break;
    case 0xFB: printf("EI"); break;
    case 0xF3: printf("DI"); break;
    case 0x76: printf("HLT"); break;
    */
    default: UnimplementedInstruction(state);
 }

 state->pc+=1;
}

int main(int argc, char *argv){

 return 0;
}
