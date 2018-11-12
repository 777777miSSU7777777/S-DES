from SDES import SDES

def main():
    while(True):
        choice = input("Input 1 to encrypt or 2 to decrypt or press 'Enter' to exit: ")
        if choice == "1":
            operation = "encrypt"
        elif choice == "2":
            operation = "decrypt"
        else:
            return 
        symbol = input("Input symbol: ")
        key = int(input("Input key: "))
        res = SDES.crypt(symbol,key,operation)
        print(res)

main()