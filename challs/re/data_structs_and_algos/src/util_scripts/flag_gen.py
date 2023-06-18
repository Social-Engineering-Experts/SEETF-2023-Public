from typing import List, Generator, Union
import itertools
import random

FLAG = "SEE{5w1n61n6_7hr0u6h_7h3_7r335_51e72e7f398a4fb0e3b8cd8457147552}"


def factorize(n: int) -> Generator[int, None, None]:
    f: int = 2
    increments = itertools.chain([1,2,2], itertools.cycle([4,2,4,2,4,6,2,6]))
    for incr in increments:
        if f*f > n:
            break
        while n % f == 0:
            yield f
            n //= f
        f += incr
    if n > 1:
        yield n


OPERATOR_PRIORITY = {"+": 1, "-": 1, "*": 2, "/": 2, "^": 3, "**": 3, "(": 4, ")": 4}


def separate_infixes(equation: str) -> List[str]:
    infixes, tmp = [], ""
    for symbol in equation:
        if symbol.isdigit() or symbol.isalpha():
            tmp += symbol
        else:
            infixes, tmp = infixes + ([tmp, symbol] if tmp else [symbol]), ""
    infixes.append(tmp)
    return infixes


def convert_infix_to_postfix(equation: str) -> str:
    answer, stack = [], []
    infixes = separate_infixes(equation)
    for symbol in infixes:
        # print(symbol, infixes)
        if symbol.isdigit() or symbol.isalpha():
            answer.append(symbol)
        elif symbol == "(":
            stack.append(symbol)
        elif symbol == ")":
            while stack != [] and stack[-1] != "(":
                answer.append(stack.pop())
        else:
            while (
                stack != []
                and OPERATOR_PRIORITY[symbol] <= OPERATOR_PRIORITY[stack[-1]]
            ):
                answer.append(stack.pop())
            stack.append(symbol)
    while stack != []:
        answer.append(stack.pop())
    return " ".join(answer).replace("(", "")


def format_for_cpp(postfix: str, vec_prefix: int) -> str:
    temp: List[str] = []
    for char in postfix.split():
        temp.append(f'"{char}"')
    return f"vector<string> vec_{vec_prefix} = \u007b {', '.join(temp)} \u007d ;"


def generate_random_sum(to_sum: int, num_components: int = 10) -> List[int]:
    base: int = to_sum // 10
    
    components: List[int] = []

    for i in range(num_components):
        if i == num_components - 1:
            components.append(to_sum - sum(components))
            break

        rand_num: int = random.randint(0, base // 2)
        flip_base: bool = bool(random.randint(0, 1))
        flip_rand: bool = bool(random.randint(0, 1))

        if flip_rand:
            rand_num = -rand_num

        if flip_base:
            components.append(base + rand_num)
        else:
            components.append(base - rand_num)

    return components


def get_sums_prime_factors(char: str) -> List[List[int]]:
    out_list: List[List[int]] = []
    
    char_code: int = ord(char)
    components: List[int] = generate_random_sum(char_code)
    for component in components:
        out_list.append(list(factorize(component)))

    return out_list


def main():
    # expression = "a+b*c+(d*e+f)*g"
    # print(format_for_cpp(infix_to_postfix(expression)))
    # for char in FLAG:
    #     print(ord(char))

    random.seed(42)
    OUTFILE = "out.txt"
    out_ls: List[str] = []

    for idx, char in enumerate(FLAG):
        # express character as sum of prime factors
        gen_list: List[List[int]] = get_sums_prime_factors(char)
        # print(gen_list)
        temp_ls: List[Union[str, int]] = []

        # remove empty lists
        for sub_idx, sub_ls in enumerate(gen_list):
            if sub_ls == []:
                gen_list.pop(sub_idx)

        # iterate through each prime factorized list
        for inner_ls in gen_list:
            # iterating through 
            inner_ls_joined: str = '*'.join([str(i) for i in inner_ls])
            temp_ls.append(inner_ls_joined)

        # temp_ls: ['2*2*2', '7', '2*2*2', '2*2*2', '7', '2*2*3', '7', '2*2*2', '2*5', '2*2*2']
        temp_ls = '+'.join(temp_ls)
        # temp_ls: 2*2*2+7+2*2*2+2*2*2+7+2*2*3+7+2*2*2+2*5+2*2*2
        # print(temp_ls) 
        out_ls.append(format_for_cpp(convert_infix_to_postfix(temp_ls), idx))

        if idx == 0:
            out_ls.append(f"Leaf* root = insert_into_expression_tree(vec_{idx});")
            out_ls.append(f"int result = et.evaluate(root);")
        else:
            out_ls.append(f"root = insert_into_expression_tree(vec_{idx});")
            out_ls.append(f"result = et.evaluate(root);")

        out_ls.append("accumulated.push_back(result);\n")
        

    with open(OUTFILE, "w") as outf:
        for expr in out_ls:
            outf.write(f"{expr}\n")


if __name__ == '__main__':
    main()