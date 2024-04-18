#
#   Vanity - stream cipher made for fun lol
#   Python reference implementation - slow as piss
#
#   Copyright 2024 NullException
#   No rights reserved
#
import sys
import secrets

#   I   K   N   K
#   K   I   K   P
#   P   K   I   K
#   K   N   K   I

ROUNDS = 8
read_state = 0
state =  [
    [ 0x437A616A,0x00000000,0x00000000,0x00000000],
    [ 0x00000000,0x6F776E69,0x00000000,0x00000000],
    [ 0x00000000,0x00000000,0x6B20456C,0x00000000],
    [ 0x00000000,0x00000000,0x00000000,0x656B7472]
]


def ror(x,a): 
    return (((x&0xFFFFFFFF)>>a)|((x&0xFFFFFFFF)<<(32-a))&0xFFFFFFFF)
def rol(x,a): 
    return ((((x&0xFFFFFFFF)<<a)|((x&0xFFFFFFFF)>>(32-a)))&0xFFFFFFFF)


def Q(a,b,c,d):
    a += c; a^=d; ror(a,b%21)
    b += d; b^=a; ror(b,c%19)
    c += a; c^=b; ror(c,d%13)
    d += b; d^=c; ror(d,a% 7)

    a^=rol(b,13)
    b^=rol(c,21)
    c^=rol(d,17)
    d^=rol(a,7)

    return [a&0xFFFFFFFF,b&0xFFFFFFFF,c&0xFFFFFFFF,d&0xFFFFFFFF]

def round():
    global state
    op = (state[3][0] | (state[2][3]<<32)) % 6
    
    match op:
        #   1   2   1   2
        #   1   2   1   2
        #   3   4   3   4
        #   3   4   3   4
        case 0:
            nstate = [  
                Q(state[0][0], state[1][0], state[0][2], state[1][2]),
                Q(state[0][1], state[1][1], state[0][3], state[1][3]),
                Q(state[2][0], state[3][0], state[2][2], state[3][2]),
                Q(state[2][1], state[3][1], state[2][3], state[3][3]),
            ]
            state = nstate

        #   1   3   3   4
        #   2   1   2   4
        #   3   2   1   2
        #   3   4   4   1
        case 1:
            nstate = [  
                Q(state[0][0], state[1][1], state[2][2], state[3][3]),
                Q(state[1][0], state[2][1], state[1][2], state[2][3]),
                Q(state[2][0], state[3][0], state[0][1], state[0][1]),
                Q(state[3][1], state[3][2], state[0][3], state[1][3])
            ]
            state = nstate

        #   1   3   2   1
        #   2   4   4   3
        #   4   2   3   4
        #   3   1   1   2
        case 2:
            nstate = [  
                Q(state[0][0], state[1][1], state[2][2], state[3][3]),
                Q(state[1][0], state[2][1], state[1][2], state[2][3]),
                Q(state[2][0], state[3][0], state[0][1], state[0][1]),
                Q(state[3][1], state[3][2], state[0][3], state[1][3])
            ]
            state = nstate

        #   1   2   1   2
        #   3   4   3   4
        #   1   2   1   2
        #   3   4   3   4
        case 3:
            nstate = [  
                Q(state[0][0], state[0][2], state[2][0], state[2][2]),
                Q(state[0][1], state[0][3], state[2][1], state[2][3]),
                Q(state[1][0], state[1][2], state[3][0], state[3][2]),
                Q(state[1][1], state[1][3], state[3][1], state[3][3])
            ]
            state = nstate


        #   1   2   3   4
        #   1   2   3   4
        #   1   2   3   4
        #   1   2   3   4
        case 4:
            nstate = [  
                Q(state[0][0], state[0][1], state[0][2], state[0][3]),
                Q(state[1][0], state[1][1], state[1][2], state[1][3]),
                Q(state[2][0], state[2][1], state[2][2], state[2][3]),
                Q(state[3][0], state[3][1], state[3][2], state[3][3])
            ]
            state = nstate

        #   1   1   1   1
        #   2   2   2   2
        #   3   3   3   3
        #   4   4   4   4
        case 5:
            nstate = [  
                Q(state[0][0], state[1][0], state[2][0], state[3][0]),
                Q(state[0][1], state[1][1], state[2][1], state[3][1]),
                Q(state[0][2], state[1][2], state[2][2], state[3][2]),
                Q(state[0][3], state[1][3], state[2][3], state[3][3])
            ]
            state = nstate

def next():
    global read_state
    if (read_state == 16):
        for i in range(ROUNDS): round()
        read_state = 0
    
    s = state[read_state%4][read_state//4]
    read_state+=1
    return s


def KEY(k,n):
    return (k & (0xFF <<n*32))>>(n*32)

# nce = nonce
def init(key, nce):
    state =  [
        [ 0x437A616A,   KEY(key,1), KEY(nce,0), KEY(key,7)],
        [ KEY(key,5),   0x6F776E69, KEY(key,0), 0x00000000],
        [ 0x00000000,   KEY(key,3), 0x6B20456C, KEY(key,2)],
        [ KEY(key,4),   KEY(nce,1), KEY(key,7), 0x656B7472]
    ]

init(secrets.randbits(256),secrets.randbits(64))


while True:
    sys.stdout.buffer.write(next().to_bytes(4))

