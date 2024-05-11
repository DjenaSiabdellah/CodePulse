# Author: Djena Siabdellah
# Description: Sets up the CodePulse application configuration for Django, including model field defaults.

# imports AppConfig class from Django's applications module
from django.apps import AppConfig

# this define a class CodepulseConfig which inherits from AppConfig
class CodepulseConfig(AppConfig):
    # this specify the default field type for auto-created primary keys
    # BigAutoField is used to create a 64-bit integer field that automatically increments.
    default_auto_field = 'django.db.models.BigAutoField'
    # this defines the name of the application, 'codepulse', which Django uses to recognize the application throughout the project.
    name = 'codepulse'
