from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin # Import Django's default UserAdmin
from .models import CustomUser # Import your CustomUser model

# If you have an existing UserAdmin or CustomUserAdmin, ensure it looks like this
# or is modified to work with CustomUser (which inherits from AbstractUser).
class CustomUserAdmin(BaseUserAdmin):
    # These are common fields for AbstractUser based custom admins.
    # Adjust these fields based on what you want to see/edit in the admin.
    fieldsets = (
        (None, {'fields': ('email', 'password')}), # USERNAME_FIELD and password
        ('Personal info', {'fields': ('first_name', 'last_name', 'national_id', 'phone_number')}), # Your custom fields
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    list_display = ('email', 'national_id', 'first_name', 'last_name', 'is_staff', 'is_active')
    search_fields = ('email', 'national_id', 'first_name', 'last_name')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions',)

# Register your CustomUser model with your CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)

# IMPORTANT: If you also have other models in census/models.py that you want
# to register in the admin, add them here. For example:
# from .models import EnumerationData, PersonalInformation, AddressInformation, \
#                     EducationInformation, EmploymentInformation, OTP, Language, \
#                     SystemSetting, AuditLog
#
# admin.site.register(EnumerationData)
# admin.site.register(PersonalInformation)
# admin.site.register(AddressInformation)
# admin.site.register(EducationInformation)
# admin.site.register(EmploymentInformation)
# admin.site.register(OTP)
# admin.site.register(Language)
# admin.site.register(SystemSetting)
# admin.site.register(AuditLog)
