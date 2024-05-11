# Author: Djena Siabdellah
# Description: settings configuration for running tests in the CodePulse project. Overrides certain settings from the main settings file for isolated testing environments.
# References
# https://stackoverflow.com/questions/16186866/testing-django-email-backend
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases


from .settings import * # this imports all the default settigns from the main settigns 

# this configures the database with a setup for testing 
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', # used this as the database engine
        'NAME': 'test_db.sqlite3', # this is the name of the database for testing 
    }
}

# email backened being set up to mail backend, doest send real emails(good for testing)
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
