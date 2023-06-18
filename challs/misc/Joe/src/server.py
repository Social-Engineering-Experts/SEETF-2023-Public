import random

FLAG = "SEE{Joe_was_shy_but_we_are_friends_now!}"

MAX_RADIUS = 2000000000
ATTEMPTS = 670

e = 7
n = 10

if __name__ == '__main__':
    print("Welcome to the game of 'Where are you?'")
    print(f"You have to find the Joe in a {n}D plane.")
    print("Who is Joe? I don't know, but he is somewhere in the multiverse.")
    print("You have to find him in the least amount of attempts possible.")
    print("You can only ask for the distance between your point and Joe's point.")
    print(f"You can give me the coordinates of your point as a list of {n} integers separated by spaces.")
    print("The game will tell you if your point is detected if you find his galaxy.")
    print("The game will tell you if you find him if you get his exact location.")
    print("Joe is very shy, so he will move to some other universe every time you find him.")
    print("The game will end if you reach the maximum number of attempts.")
    print("Joe will give you the flag if you find him and when he is not shy.")
    print("Good luck!")
    howmanytimes = random.randint(20,30)
    for i in range(howmanytimes):
        print(f"Find Joe #{i}:")
        R = random.randint(MAX_RADIUS // 4, MAX_RADIUS // 2)
        COORDS = []
        for j in range(n):
            c = random.randint(-R + MAX_RADIUS//4 , R - MAX_RADIUS//4)
            COORDS.append(c)

        for a in range(ATTEMPTS[n]):
            line = input("> ")
            coords = [int(n) for n in line.split(' ')]
            if len(coords) != n:
                print("You cannot find Joe in a different dimension.")
                exit(1)
            D = 0
            for i in range(n):
                D += (COORDS[i] - coords[i]) ** 2
            D = D ** 0.5
            if D <= e:
                print("\033[94mJoe Point", end="\n\033[0m")
                break
            elif D <= R:
                print("\033[92mInside his Galaxy Point", end="\n\033[0m")
            else:
                print("\033[91mOutside his Galaxy Point", end="\n\033[0m")
        else:
            exit(1337)

    print(f'Wow you found me so many times! Here is your flag: {FLAG}')


