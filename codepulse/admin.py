# Author: Djena Siabdellah
# Description: Configures the Django admin interface for managing instances of CustomUser and other models.

# admin module to manage the admin interface
from django.contrib import admin
# CustomUser model from the local models.py file
from .models import CustomUser

# custom admin class to manage CustomUser instances in the Django admin
class CustomUserAdmin(admin.ModelAdmin):
    # specifies fields to be displayed in the admin list view
    list_display = ('username', 'email', 'is_active')  # Fields displayed in the user list
    # fields that can be searched in the admin list view
    search_fields = ('username', 'email')
    # specifies filters to be available in the admin list view
    list_filter = ('is_active', 'is_staff')  # Filters available for quick sorting

# register the CustomUser model with the CustomUserAdmin to enable custom admin features
admin.site.register(CustomUser, CustomUserAdmin)
