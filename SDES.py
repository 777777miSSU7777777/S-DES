class SDES:

    __Sl = [['01','00','11','10'],
          ['11','10','01','00'],
          ['00','10','01','11'],
          ['11','01','11','10']]

    __Sr = [['00','01','10','11'],
            ['10','00','01','11'],
            ['11','00','01','00'],
            ['10','01','00','11']]

    @staticmethod
    def crypt(symbol, key, operation="encrypt"):
        bin_key = str(bin(key))[2:]
        if len(bin_key) < 10:
            bin_key = '0' * (10 - len(bin_key)) + bin_key
        elif len(bin_key) > 10:
            bin_key = bin_key[:10]

        bin_symbol = str(bin(ord(symbol)))[2:]
        if len(bin_symbol) < 8:
            bin_symbol = '0' * (8 - len(bin_symbol)) + bin_symbol
        elif len(bin_symbol) > 8:
            bin_symbol = bin_symbol[:8]

        key1 = SDES.__transformP10P8FirstKey(bin_key)
        key2 = SDES.__transformP10P8SecondKey(bin_key)
        text = SDES.__transformIP(bin_symbol)
        firstKey = key2
        secondKey = key1
        if operation == "encrypt":
            firstKey = key1
            secondKey = key2
        elif operation == "decrypt":
            firstKey == key2
            secondKey == key1
        sw1 = SDES.__getRight(text) + SDES.__fK(firstKey, text)
        sw2 = SDES.__fK(secondKey, sw1) + SDES.__getRight(sw1)
        result = SDES.__transformIP_1(sw2)
        return result

    @staticmethod
    def __getRight(key):
        return key[4:]
    
    @staticmethod
    def __getLeft(key):
        return key[:4]

    @staticmethod
    def __index(key):
        if key == "00":
            return 0
        elif key == "01":
            return 1
        elif key == "10":
            return 2
        elif key == "11":
            return 3
        return 0

    @staticmethod
    def __transformP10P8FirstKey(key):
        return key[0] + key[6] + key[8] + key[3] + key[7] + key[2] + key[9] + key[5]

    @staticmethod
    def __transformP10P8SecondKey(key):
        return key[7] + key[2] + key[5] + key[4] + key[9] + key[1] + key[8] + key[0]
    
    @staticmethod
    def __transformIP(text):
        return text[1] + text[5] + text[2] + text[0] + text[3] + text[7] + text[4] + text[6]

    @staticmethod
    def __transformIP_1(text):
        return text[3] + text[0] + text[2] + text[4] + text[6] + text[1] + text[7] + text[5]
    
    @staticmethod
    def __expansion(key):
        return key[3] + key[0] + key[1] + key[2] + key[1] + key[2] + key[3] + key[0]
    
    @staticmethod
    def __xor(key, addKey):
        res = ''
        for i in range(len(key)):
            res += str(1 if key[i] != addKey[i] else 0)
        return res
    
    @staticmethod
    def __findRow(key2byte):
        return key2byte[0] + key2byte[3]
    
    @staticmethod
    def __findCol(key2byte):
        return key2byte[1] + key2byte[2]
    
    @staticmethod
    def __fK(key,text):
        l = SDES.__getLeft(text)
        r = SDES.__expansion(SDES.__getRight(text))
        
        xor_key = SDES.__xor(key,r)

        l = xor_key[:4]
        r = xor_key[4:]
        index1_1 = SDES.__index(SDES.__findRow(l))
        index1_2 = SDES.__index(SDES.__findCol(l))
        index2_1 = SDES.__index(SDES.__findRow(r))
        index2_2 = SDES.__index(SDES.__findCol(r))

        res = SDES.__Sl[index1_1][index1_2] + SDES.__Sr[index2_1][index2_2]
        res = res[1] + res[3] + res[2] + res[0]

        return SDES.__xor(SDES.__getLeft(text),res)
