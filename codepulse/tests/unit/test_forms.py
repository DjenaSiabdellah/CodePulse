# Author: Djena Siabdellah
# Description: Contains unit tests for forms/models/views in CodePulse, ensuring that they behave as expected under various conditions.
# Reference 
# https://www.javatpoint.com/unit-testing-in-django


from django.test import TestCase
from codepulse.forms import RegistrationForm, UrlForm

# Form tests

# Tests the validation logic of the RegistrationForm.
class RegistrationFormTest(TestCase):
    def test_form_valid(self):
        # provide a set of valid data to the form.
        form_data = {'username': 'newuser', 'email': 'user@example.com', 'password1': 'complexpassword123', 'password2': 'complexpassword123'}
        form = RegistrationForm(data=form_data)
        # This test that the form is valid with correct data.
        self.assertTrue(form.is_valid())
    def test_form_password_mismatch(self):
        # provide mismatching passwords to test form validation.
        form_data = {'username': 'newuser', 'email': 'user@example.com', 'password1': 'complexpassword123', 'password2': 'wrongpassword'}
        form = RegistrationForm(data=form_data)
        # This ensures the form is invalid if passwords do not match.
        self.assertFalse(form.is_valid())

# These are to test the UrlForm specifically its validation on URL inputs.
class UrlFormTest(TestCase):
    def test_url_form_valid(self):
        # this provide a valid URL to the form.
        form_data = {'url_input': 'http://validurl.com'}
        form = UrlForm(data=form_data)
        # test that the form is valid with a correct URL format.
        self.assertTrue(form.is_valid())
    def test_url_form_invalid(self):
        # gives an invalid URL format to test form validation.
        form_data = {'url_input': 'not-a-valid-url'}
        form = UrlForm(data=form_data)
        # makes sure that the form is invalid with incorrect URL format.
        self.assertFalse(form.is_valid())

