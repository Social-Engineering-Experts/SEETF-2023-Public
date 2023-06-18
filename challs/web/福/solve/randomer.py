import random
import itertools

def secret(value):
	random.seed(value)
	return random.randint(8, 88888)

values_to_find = [41, 1728, 803, 1463, 88888]
found_values = []

for combination in itertools.product('abcdefghijklmnopqrstuvwxyz', repeat=4):
	input_value = ''.join(combination)
	result = secret(input_value)
	if result in values_to_find:
		found_values.append(input_value)
		values_to_find.remove(result)
		print(result)
	if not values_to_find:
		print("Found all four values at index:", found_values)
		break

'''
cdsn:41
aqoi:1728
ewmu:803
aucl:1463
bphi:88888
'''