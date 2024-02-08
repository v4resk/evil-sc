import re
import random
import string

def replace_varX(input_code):
    # Define a regular expression pattern to match varX where X is any number
    pattern = re.compile(r'\bvar(\d+)\b')

    # Find all matches in the input code
    matches = pattern.findall(input_code)

    # Replace each match with a randomly generated variable name
    for match in matches:
        old_var = f'var{match}'
        new_var = generate_random_variable()
        input_code = input_code.replace(old_var, new_var)

    return input_code

def generate_random_variable():
    # Generate a random variable name using letters and digits
    length = random.randint(5, 10)
    variable_name = ''.join(random.choices(string.ascii_letters, k=length))
    return variable_name