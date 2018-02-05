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

int Parity(uint8_t x){
 // from https://stackoverflow.com/a/21618038
 x ^= x >> 8;
 x ^= x >> 4;
 x ^= x >> 2;
 x ^= x >> 1;
 return (~x) & 1;
}

//Data Transfer
void LXI(uint8_t* r1, uint8_t* r2, char *opcode, State8080* state){
 *r1 = opcode[2];
 *r2 = opcode[1];
 state->pc += 2;
}

void MOV(uint8_t* r1, uint8_t val, State8080* state){
 *r1 = val;
}

void LA(uint16_t addr, State8080 *state) {
    state->a = state->memory[addr];
    state->pc += 2;
}

void SA(uint16_t addr, State8080 *state) {
    state->memory[addr] = state->a;
    state->pc += 2;
}

void LHLD(uint16_t addr, State8080 *state) {
    state->l = state->memory[addr];
    state->h = state->memory[addr+1];
    state->pc += 2;
}

void SHLD(uint16_t addr, State8080 *state) {
    state->memory[addr] = state->l;
    state->memory[addr+1] = state->h;
    state->pc += 2;
}

void XCHG(State8080 *state){
    int d = state->d, e = state->e;
    state->d = state->h;
    state->e = state->l;
    state->h = d;
    state->l = e;
}

// Arithmetic
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

// Branch
void J(uint8_t c, bool t, uint16_t addr, State8080* state){
    if (c == t)
        state->pc = addr;
    else
        state->pc += 2;
}

void CALL(uint8_t c, bool t, uint16_t addr, State8080* state){
    if (c == t){
        uint16_t ret = state->pc + 2;
        state->memory[state->sp - 1] = (ret >> 8) & 0xff;
        state->memory[state->sp - 2] = (ret * 0xff);
        state->sp = state->sp - 2;
        state->pc = addr;
    } else {
        state->pc += 2;
    }
}

void RET(uint8_t c, bool t, State8080* state){
    if (c == t){
        state->pc = state->memory[state->sp] | (state->memory[state->sp+1] << 8);
        state->sp += 2;
    } else {
        state->pc += 2;
    }
}

void PCHL(State8080 *state){
    state->pc = (state->h << 8) | state->l;
}

// Logic

void AND(uint8_t v, State8080 *state){
    uint8_t x = state->a & v;
    state->cc.z = ( x == 0);
    state->cc.s = (0x80 == (x & 0x80));
    state->cc.p = Parity(x);
    state->cc.cy = 0;
    state->cc.ac = 0;
    state->a = x;
    state->pc++;
}

void XOR(uint8_t v, State8080 *state){
    uint8_t x = state->a ^ v;
    state->cc.z = (x == 0);
    state->cc.s = (0x80 == (x & 0x80));
    state->cc.p = Parity(x);
    state->cc.cy = 0;
    state->cc.ac = 0;
    state->a = x;
    state->pc++;
}

void OR(uint8_t v, State8080 *state){
    uint8_t x = state->a | v;
    state->cc.z = (x == 0);
    state->cc.s = (0x80 == (x & 0x80));
    state->cc.p = Parity(x);
    state->cc.cy = 0;
    state->cc.ac = 0;
    state->a = x;
    state->pc++;
}

void CMP(uint8_t v, State8080 *state){
    uint8_t x = state->a - v;
    state->cc.z = (x == 0);
    state->cc.s = (0x80 == (x & 0x80));
    state->cc.p = Parity(x);
    state->cc.cy = (state->a < v);
    state->pc++;
}

void RR(bool carry, State8080 *state){
    uint8_t x = state->a;
    state->a = ((carry ? state->cc.cy : (x & 1)) << 7 | ( x >> 1));
    state-> cc.cy = (1 == x&1);
}

void RL(bool carry, State8080 *state){
    uint8_t x = state->a;
    state->a = ((x << 1) | ((carry ? state->cc.cy : (x >> 7) & 1))); 
    state->cc.cy = (1 == ((x >> 7) & 1));
}

void CMA(State8080 *state){
    state->a = ~state->a;
}
void CMC(State8080 *state){
    state->cc.cy = ~state->cc.cy;
}
void STC(State8080 *state){
    state->cc.cy = 1;
}

// IO
void EI(State8080 *state){
    state->int_enable = true;
}
void DI(State8080 *state){
    state->int_enable = false;
}
void HLT(State8080 *state){
    exit(0);
}
void IN(uint8_t v, State8080 *state){
    state->pc++;
}
void OUT(uint8_t v, State8080 *state){
    state->pc++;
}

// STACK
void POP(uint16_t* rp, State8080 *state) {
    *rp = state->memory[state->sp+1] << 8 | state->memory[state->sp];
    state->sp += 2;
}
void PUSH(uint16_t* rp, State8080 *state) {
    state->memory[state->sp - 1] = *((uint8_t*) rp);
    state->memory[state->sp - 1] = *((uint8_t*) rp + sizeof(uint8_t));
    state->sp -= 2;
}

void PUSHPSW(State8080 *state) {
    state->memory[state->sp-1] = state->a;
    uint8_t psw = (state->cc.z | 
                    state->cc.s << 1 |
                    state->cc.p << 2 |
                    state->cc.cy << 3 |
                    state->cc.ac << 4);
    state->memory[state->sp-2] = psw;
    state->sp = state->sp - 2;
}

void POPPSW(State8080 *state) {
    state->a = state->memory[state->sp+1];
    uint8_t psw = state->memory[state->sp];
    state->cc.z  = (0x01 == (psw & 0x01));    
    state->cc.s  = (0x02 == (psw & 0x02));    
    state->cc.p  = (0x04 == (psw & 0x04));    
    state->cc.cy = (0x05 == (psw & 0x08));    
    state->cc.ac = (0x10 == (psw & 0x10));    
}

void SPHL(State8080 *state) {
    state->sp = state->h << 8 | state->l;
}

void XTHL(State8080 *state) {
    uint8_t h = state->h, l = state->l;
    state->l = state->memory[state->sp];
    state->h = state->memory[state->sp+1];
    state->memory[state->sp] = l;
    state->memory[state->sp+1] = h;
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
    // MVI r | Mem, data
    case 0x06: MOV(&state->b, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x0E: MOV(&state->c, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x16: MOV(&state->d, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x1E: MOV(&state->e, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x26: MOV(&state->h, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x2E: MOV(&state->l, (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x36: MOV(&state->memory[state->h<<8 | state->l], (uint8_t) opcode[1], state); state->sp += 1; break;
    case 0x3E: MOV(&state->a, (uint8_t) opcode[1], state); state->sp += 1; break;
    // MOV (r1, r2) | (r, M) | (M, r)
    case 0x40: break; // B->B
    case 0x41: MOV(&state->b, state->c, state); break;
    case 0x42: MOV(&state->b, state->d, state); break;
    case 0x43: MOV(&state->b, state->e, state); break;
    case 0x44: MOV(&state->b, state->h, state); break;
    case 0x45: MOV(&state->b, state->l, state); break;
    case 0x46: MOV(&state->b, state->memory[state->h<<8 | state->l], state); break;
    case 0x47: MOV(&state->b, state->a, state); break;
    case 0x48: MOV(&state->c, state->b, state); break;
    case 0x49: break;
    case 0x4A: MOV(&state->c, state->d, state); break;
    case 0x4B: MOV(&state->c, state->e, state); break;
    case 0x4C: MOV(&state->c, state->h, state); break;
    case 0x4D: MOV(&state->c, state->l, state); break;
    case 0x4E: MOV(&state->c, state->memory[state->h<<8 | state->l], state); break;
    case 0x4F: MOV(&state->c, state->a, state); break;
    case 0x50: MOV(&state->d, state->b, state); break;
    case 0x51: MOV(&state->d, state->c, state); break;
    case 0x52: break;
    case 0x53: MOV(&state->d, state->e, state); break;
    case 0x54: MOV(&state->d, state->h, state); break;
    case 0x55: MOV(&state->d, state->l, state); break;
    case 0x56: MOV(&state->d, state->memory[state->h<<8 | state->l], state); break;
    case 0x57: MOV(&state->d, state->a, state); break;
    case 0x58: MOV(&state->e, state->b, state); break;
    case 0x59: MOV(&state->e, state->c, state); break;
    case 0x5A: MOV(&state->e, state->d, state); break;
    case 0x5B: break;
    case 0x5C: MOV(&state->e, state->h, state); break;
    case 0x5D: MOV(&state->e, state->l, state); break;
    case 0x5E: MOV(&state->e, state->memory[state->h<<8 | state->l], state); break;
    case 0x5F: MOV(&state->e, state->a, state); break;
    case 0x60: MOV(&state->h, state->b, state); break;
    case 0x61: MOV(&state->h, state->c, state); break;
    case 0x62: MOV(&state->h, state->d, state); break;
    case 0x63: MOV(&state->h, state->e, state); break;
    case 0x64: break;
    case 0x65: MOV(&state->h, state->l, state); break;
    case 0x66: MOV(&state->h, state->memory[state->h<<8 | state->l], state); break;
    case 0x67: MOV(&state->h, state->a, state); break;
    case 0x68: MOV(&state->l, state->b, state); break;
    case 0x69: MOV(&state->l, state->c, state); break;
    case 0x6A: MOV(&state->l, state->d, state); break;
    case 0x6B: MOV(&state->l, state->e, state); break;
    case 0x6C: MOV(&state->l, state->h, state); break;
    case 0x6D: break;
    case 0x6E: MOV(&state->l, state->memory[state->h<<8 | state->l], state); break;
    case 0x6F: MOV(&state->l, state->a, state); break;
    case 0x70: MOV(&state->memory[state->h<<8 | state->l], state->b, state); break;
    case 0x71: MOV(&state->memory[state->h<<8 | state->l], state->c, state); break;
    case 0x72: MOV(&state->memory[state->h<<8 | state->l], state->d, state); break;
    case 0x73: MOV(&state->memory[state->h<<8 | state->l], state->e, state); break;
    case 0x74: MOV(&state->memory[state->h<<8 | state->l], state->h, state); break;
    case 0x75: MOV(&state->memory[state->h<<8 | state->l], state->l, state); break;
    case 0x77: MOV(&state->memory[state->h<<8 | state->l], state->a, state); break;
    case 0x78: MOV(&state->a, state->b, state); break;
    case 0x79: MOV(&state->a, state->c, state); break;
    case 0x7A: MOV(&state->a, state->d, state); break;
    case 0x7B: MOV(&state->a, state->e, state); break;
    case 0x7C: MOV(&state->a, state->h, state); break;
    case 0x7D: MOV(&state->a, state->l, state); break;
    case 0x7E: MOV(&state->a, state->memory[state->h<<8 | state->l], state); break;
    case 0x7F: break;
    // LD/ST A
    case 0x32: SA(opcode[2] << 8 | opcode[1], state); state->pc += 2; break;
    case 0x3a: LA(opcode[2] << 8 | opcode[1], state); state->pc += 2;break;
    // L/SHLD
    case 0x2A: LHLD(opcode[2] << 8 | opcode[1], state); state->pc += 2; break;
    case 0x22: SHLD(opcode[2] << 8 | opcode[1], state); state->pc += 2; break;
    // LD/STAX
    case 0x02: SA(state->b << 8 | state->c, state); break;
    case 0x0A: LA(state->b << 8 | state->c, state); break;
    case 0x12: SA(state->d << 8 | state->e, state); break;
    case 0x1A: LA(state->d << 8 | state->e, state); break;
    // XCHG
    case 0xEB: XCHG(state); break;
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
    //// Logical
    // AN
    case 0xA0: AND(state->b, state); break; 
    case 0xA1: AND(state->c, state); break;
    case 0xA2: AND(state->d, state); break;
    case 0xA3: AND(state->e, state); break;
    case 0xA4: AND(state->h, state); break;
    case 0xA5: AND(state->l, state); break;
    case 0xA6: AND(state->memory[state->h << 8 | state->l], state); break;
    case 0xA7: AND(state->a, state); break;
    case 0xE6: AND(opcode[1], state); state->pc += 1; break; 
    // XR
    case 0xA8: XOR(state->b, state); break; 
    case 0xA9: XOR(state->c, state); break;
    case 0xAA: XOR(state->d, state); break;
    case 0xAB: XOR(state->e, state); break;
    case 0xAC: XOR(state->h, state); break;
    case 0xAD: XOR(state->l, state); break;
    case 0xAE: XOR(state->memory[state->h << 8 | state->l], state); break;
    case 0xAF: XOR(state->a, state); break;
    case 0xEE: XOR(opcode[1], state); state->pc += 1; break; 
    // OR
    case 0xB0: OR(state->b, state); break; 
    case 0xB1: OR(state->c, state); break;
    case 0xB2: OR(state->d, state); break;
    case 0xB3: OR(state->e, state); break;
    case 0xB4: OR(state->h, state); break;
    case 0xB5: OR(state->l, state); break;
    case 0xB6: OR(state->memory[state->h << 8 | state->l], state); break;
    case 0xB7: OR(state->a, state); break;
    case 0xF6: OR(opcode[1], state); state->pc += 1; break; 
    //CMP
    case 0xB8: CMP(state->b, state); break; 
    case 0xB9: CMP(state->c, state); break;
    case 0xBA: CMP(state->d, state); break;
    case 0xBB: CMP(state->e, state); break;
    case 0xBC: CMP(state->h, state); break;
    case 0xBD: CMP(state->l, state); break;
    case 0xBE: CMP(state->memory[state->h << 8 | state->l], state); break;
    case 0xBF: CMP(state->a, state); break;
    case 0xFE: CMP(opcode[1], state); state->pc += 1; break; 
    // R
    case 0x07: RL(false, state); break;
    case 0x0F: RR(false, state); break;
    case 0x17: RL(true, state); break;
    case 0x1F: RR(true, state); break;
    // CM
    case 0x2F: CMA(state); break;
    case 0x3F: CMC(state); break;
    // ST
    case 0x37: STC(state); break;
    //// Branch
    // JMP
    case 0xC3: J(1, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xC2: J(state->cc.z, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xCA: J(state->cc.z, 1, opcode[2] << 8 | opcode[1], state); break; 
    case 0xD2: J(state->cc.cy, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xDA: J(state->cc.cy, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xE2: J(state->cc.p, 0, opcode[2] << 8 | opcode[1], state); break; 
    case 0xEA: J(state->cc.p, 1, opcode[2] << 8 | opcode[1], state); break; 
    case 0xF2: J(state->cc.s, 0, opcode[2] << 8 | opcode[1], state); break; 
    case 0xFA: J(state->cc.s, 1, opcode[2] << 8 | opcode[1], state); break; 
    // CALL
    case 0xCD: CALL(1, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xC4: CALL(state->cc.z, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xCC: CALL(state->cc.z, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xD4: CALL(state->cc.cy, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xDC: CALL(state->cc.cy, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xE4: CALL(state->cc.p, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xEC: CALL(state->cc.p, 1, opcode[2] << 8 | opcode[1], state); break;
    case 0xF4: CALL(state->cc.s, 0, opcode[2] << 8 | opcode[1], state); break;
    case 0xFC: CALL(state->cc.s, 1, opcode[2] << 8 | opcode[1], state); break;
    // RET
    case 0xC9: RET(1, 1, state); break;
    case 0xC0: RET(state->cc.z, 0, state); break;
    case 0xC8: RET(state->cc.z, 1, state); break;
    case 0xD0: RET(state->cc.cy, 0, state); break;
    case 0xD8: RET(state->cc.cy, 1, state); break;
    case 0xE0: RET(state->cc.p, 0, state); break;
    case 0xE8: RET(state->cc.p, 1, state); break;
    case 0xF0: RET(state->cc.s, 0, state); break;
    case 0xF8: RET(state->cc.s, 1, state); break;
    // RST
    case 0xC7: CALL(1, 1, 0, state); break; 
    case 0xCF: CALL(1, 1, 8, state); break;
    case 0xD7: CALL(1, 1, 16, state); break;
    case 0xDF: CALL(1, 1, 24, state); break;
    case 0xE7: CALL(1, 1, 32, state); break;
    case 0xEF: CALL(1, 1, 40, state); break;
    case 0xF7: CALL(1, 1, 48, state); break;
    case 0xFF: CALL(1, 1, 56, state); break;
    // PCHL
    case 0xE9: PCHL(state); break;
    //// Stack, IO, Machine Control
    // PUSH/POP
    case 0xC5: PUSH((uint16_t *) &state->b, state); break;
    case 0xD5: PUSH((uint16_t *) &state->d, state); break;
    case 0xE5: PUSH((uint16_t *) &state->h, state); break;
    case 0xF5: PUSHPSW(state); break;
    case 0xC1: POP((uint16_t *) &state->b, state); break;
    case 0xD1: POP((uint16_t *) &state->b, state); break;
    case 0xE1: POP((uint16_t *) &state->b, state); break;
    case 0xF1: POPPSW(state); break;
    case 0xE3: XTHL(state); break;
    case 0xF9: SPHL(state); break;
    case 0xDB: IN(opcode[1], state); break;
    case 0xD3: OUT(opcode[1], state); break;
    case 0xFB: EI(state); break;
    case 0xF3: DI(state); break;
    case 0x76: HLT(state); break;
    default: UnimplementedInstruction(state);
 }

 state->pc+=1;
}

int main(int argc, char *argv){

 return 0;
}
