# Author: Djena Siabdellah
# Description: provides a custom password validator for CodePulse, enforcing security requirements on user passwords.
# References 
# https://sixfeetup.com/blog/custom-password-validators-in-django


# this imports ValidationError for raising exceptions during validation
from django.core.exceptions import ValidationError
# this import re module for regular expression operations
import re

class CustomPasswordValidator:
    # validate the given password
    def validate(self, password, user=None):
        # checks if the password length is less than 8 characters
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        # checks for the presence of at least one uppercase letter in the password
        if not re.findall('[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        # checks for the presence of at least one special character in the password
        if not re.findall('[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")

    # provide a description of the password requirements
    def get_help_text(self):
        return "Your password must contain at least 8 characters, including an uppercase letter and one special character."


