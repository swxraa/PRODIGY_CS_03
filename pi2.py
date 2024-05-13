import re

def assess_password_strength(password):

    # Define criteria
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*()\-_=+{};:,<.>/?\[\]\'"\\|`~]', password))

    # Assess password strength
    if length_criteria and uppercase_criteria and lowercase_criteria and digit_criteria and special_char_criteria:
        return "Password is strong."
    else:
        feedback = "Password is weak. Consider improving by:"
        if not length_criteria:
            feedback += "\n- Ensuring the password has at least 8 characters."
        if not uppercase_criteria:
            feedback += "\n- Adding at least one uppercase letter."
        if not lowercase_criteria:
            feedback += "\n- Adding at least one lowercase letter."
        if not digit_criteria:
            feedback += "\n- Adding at least one digit."
        if not special_char_criteria:
            feedback += "\n- Adding at least one special character."
        return feedback

def main():
    password = input("Enter your password: ")
    strength_feedback = assess_password_strength(password)
    print(strength_feedback)

if __name__ == "__main__":
    main()
