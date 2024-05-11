# Author: Djena Siabdellah
# Description: Defines forms for user registration, authentication, and other form-based interactions in CodePulse
# References 
# https://github.com/adeyosemanputra/pygoat/blob/master/introduction/forms.py
#https://www.crunchydata.com/blog/building-a-user-registration-form-with-djangos-built-in-authentication

# codepulse/forms.py handeling libraries and user models
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser
from django.contrib.auth import get_user_model

# this sets the User model to the custom or current active user model.
User = get_user_model()

# Define a registration form class that inherits from UserCreationForm
class RegistrationForm(UserCreationForm):
    # this adds an email field that is required for form submission
    email = forms.EmailField(required=True)

    # this meta class to specifies information about this form class
    class Meta:
        # this is to link this form to the active user model
        model = User
        # fields that are to be included in the form
        fields = ("username", "email", "password1", "password2")

    # this defines the save method to save the form data to the database
    def save(self, commit=True):
        # this calls the superclass's save method with commit=False
        user = super(RegistrationForm, self).save(commit=False) 
        # this sets the email of the user model instance
        user.email = self.cleaned_data["email"]  
        if commit:
            # this saves the user instance to the database if commit is True
            user.save()  
        # this returns the user model instance
        return user  

# this defines a login form class that inherits AuthenticationForm
class LoginForm(AuthenticationForm):
    # Meta class to specify information about this form class
    class Meta:
        model = CustomUser  # this links this form to the CustomUser model
        fields = ['username', 'password']  # these fields are included in the form

# this defines a simple form for code input with a textarea widget
class CodeForm(forms.Form):
    # this defines a form field for code input as a large text area
    code_input = forms.CharField(widget=forms.Textarea)  

# Define a form for URL input
class UrlForm(forms.Form):
    # this defines a form field for URL input
    url_input = forms.URLField(label='Enter the URL to scan') 

