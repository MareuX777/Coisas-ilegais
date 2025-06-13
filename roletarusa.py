import time
import random
pergunta = input("Você deseja jogar o jogo?(Y/N): ")
if pergunta == ("Y"): #Funciona apenas com Y maiusculo, tentei por o minusculo mas não deu :p
    while True:
        therandom_games = random.randint(1 , 6)
        if therandom_games <= 5:
            print("Carregando...")
            time.sleep(3)
            print("Apontando...")
            time.sleep(2)
            print("Tsc...")
            time.sleep(1)
            print("Tá com sorte hoje.")
            print(f"A bala no tambor era: {therandom_games}")
            print("-----------------------------------------")
        else:      
                print("Carregando...")
                time.sleep(3)
                print("Apontando...")
                time.sleep(2)
                print("Pow!!!")
                time.sleep(1)
                print("Que falta de sorte, não?")
                print(f"A bala no tambor era: {therandom_games}")
                print("-----------------------------------------")
                break   
else:
     print("Que pena...")
     time.sleep(2)
     print("Tiros....")
     time.sleep(2)
     print("Você morreu.")