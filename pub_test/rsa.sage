def fermat_attack(N):
   
    a = ceil(sqrt(N))
    
    while not is_square(a ** 2 - N):
        a += 1
        
    b = sqrt(a ** 2 - N)
    p = a - b
    q = a + b

    return p, q

def create_private(p, q):
    pi = (p - 1) * (q - 1)
    return (e.xgcd(pi)[1]) % pi

def sign(private_key, message, n):
    return power_mod(message, private_key, n)

if __name__ == "__main__":
    name = "정금종"
    name_decimal= int.from_bytes(name.encode("utf-8"), "big")

    e = 65537
    n = 179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430652885096550381956977355009744407642308411545070379136134645709973060633048727107215362312651042098054062317216389604359801702614666769905641776363676873830995947
    
    p, q = map(int, fermat_attack(n))

    d = create_private(p, q)
    s = sign(d, name_decimal, n)

    mprime = power_mod(s, e, n)
    result = bytes.fromhex(hex(mprime)[2:]).decode('utf-8')
    if mprime == name_decimal:
        print("s", s)
        print("e", e)
        print("n", n)    
        print("mprime", mprime)
        print("name", result)
    else:
        print("Fail")
