# E:\django\my_django_projects\myproject\census\forms.py

from django import forms
from django.contrib.auth.forms import UserCreationForm as BaseUserCreationForm
from django.conf import settings # Import settings
from .models import (
    CustomUser, # Changed from User to CustomUser
    EnumerationData, PersonalInformation, AddressInformation,
    EducationInformation, EmploymentInformation, OTP
)


# Custom User Creation Form (for initial signup data collection)
class CustomUserCreationForm(BaseUserCreationForm):
    # These fields are explicitly defined because your custom User model
    # uses national_id as the USERNAME_FIELD and has other custom fields.
    national_id = forms.CharField(max_length=20, help_text='Format: 22U/12345/PS',
                                  widget=forms.TextInput(attrs={'class': 'form-control'}))
    first_name = forms.CharField(max_length=50,
                                  widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(max_length=50,
                                 widget=forms.TextInput(attrs={'class': 'form-control'}))
    phone_number = forms.CharField(max_length=15,
                                   widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=False, # Email is handled by AbstractUser, but explicitly defined here for form
                             widget=forms.EmailInput(attrs={'class': 'form-control'}))

    # BaseUserCreationForm already defines password and password2
    # You might remove these explicit definitions if the BaseUserCreationForm handles them well for your case
    # However, for consistency with earlier discussions about 'password' vs 'password1',
    # if your frontend sends 'password' and 'password2', keep them explicitly defined.
    # If using AbstractUser and BaseUserCreationForm normally, you might not need to define them.
    # For now, keeping them as they match your client's data.
    password = forms.CharField(
        label='Password',
        widget=forms.PasswordInput,
        help_text="Your password must contain at least 8 characters, be strong, and not be a common password."
    )
    password2 = forms.CharField(
        label='Confirm Password',
        widget=forms.PasswordInput,
        help_text="Enter the same password as above, for verification."
    )


    class Meta(BaseUserCreationForm.Meta):
        model = CustomUser # Changed from User to CustomUser
        # BaseUserCreationForm handles password fields automatically if not explicitly defined above.
        # If explicitly defined, make sure they are in 'fields'.
        fields = (
            'national_id',
            'first_name',
            'last_name',
            'email',
            'phone_number',
            'password',
            'password2',
        )

    def clean_national_id(self):
        national_id = self.cleaned_data['national_id']
        # Changed User.objects.filter to CustomUser.objects.filter
        if CustomUser.objects.filter(national_id=national_id).exists():
            raise forms.ValidationError("A user with this National ID already exists.")
        return national_id

    def clean_phone_number(self):
        phone_number = self.cleaned_data['phone_number']
        # Basic validation for phone number format (can be improved with django-phonenumber-field)
        # Ensure it's unique
        # Changed User.objects.filter to CustomUser.objects.filter
        if CustomUser.objects.filter(phone_number=phone_number).exists():
            raise forms.ValidationError("A user with this phone number already exists.")
        return phone_number

    # The save method will be handled in the view after OTP verification.
    # This form will mainly be used for data validation and initial collection.
    # Re-adding save method to ensure password hashing happens during form.save()
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class OTPVerificationForm(forms.Form): # Changed to forms.Form as it's not directly tied to OTP model save in this form
    phone_number = forms.CharField(max_length=15, widget=forms.HiddenInput()) # Hidden, passed from first step
    otp_code = forms.CharField(max_length=settings.OTP_LENGTH, label="OTP Code",
                               widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter OTP'}))

    def clean(self):
        cleaned_data = super().clean()
        phone_number = cleaned_data.get('phone_number')
        otp_code = cleaned_data.get('otp_code')

        if not phone_number or not otp_code:
            raise forms.ValidationError("Phone number and OTP are required.")

        try:
            otp_instance = OTP.objects.get(phone_number=phone_number, code=otp_code, is_verified=False)
            if not otp_instance.is_valid():
                raise forms.ValidationError("OTP is invalid or expired. Please request a new one.")
            # Mark as verified immediately to prevent reuse
            otp_instance.is_verified = True
            otp_instance.save()
            return cleaned_data
        except OTP.DoesNotExist:
            raise forms.ValidationError("Invalid OTP. Please check the code or request a new one.")


# Forms for Enumeration Data and its related models
class EnumerationDataForm(forms.ModelForm): # Renamed to EnumerationDataForm for consistency with views
    class Meta:
        model = EnumerationData
        fields = ['status', 'verification_notes']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'verification_notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }


class PersonalInformationForm(forms.ModelForm):
    class Meta:
        model = PersonalInformation
        fields = [ # Explicitly listing fields instead of exclude
            'first_name',
            'middle_name',
            'last_name',
            'date_of_birth',
            'gender',
            'marital_status',
            'nationality',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'middle_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'date_of_birth': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-select'}),
            'marital_status': forms.Select(attrs={'class': 'form-select'}),
            'nationality': forms.TextInput(attrs={'class': 'form-control'}),
        }


class AddressInformationForm(forms.ModelForm):
    class Meta:
        model = AddressInformation
        fields = [ # Explicitly listing fields instead of exclude
            'region',
            'district',
            'county',
            'sub_county',
            'parish',
            'village',
            'street',
            'house_number',
            'location_description',
            'residence_type',
        ]
        widgets = {
            'region': forms.TextInput(attrs={'class': 'form-control'}),
            'district': forms.TextInput(attrs={'class': 'form-control'}),
            'county': forms.TextInput(attrs={'class': 'form-control'}),
            'sub_county': forms.TextInput(attrs={'class': 'form-control'}),
            'parish': forms.TextInput(attrs={'class': 'form-control'}),
            'village': forms.TextInput(attrs={'class': 'form-control'}),
            'street': forms.TextInput(attrs={'class': 'form-control'}),
            'house_number': forms.TextInput(attrs={'class': 'form-control'}),
            'location_description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'residence_type': forms.Select(attrs={'class': 'form-select'}),
        }


class EducationInformationForm(forms.ModelForm):
    class Meta:
        model = EducationInformation
        fields = [ # Explicitly listing fields instead of exclude
            'highest_education_level',
            'institution_name',
            'completion_year',
            'literacy_status',
        ]
        widgets = {
            'highest_education_level': forms.Select(attrs={'class': 'form-select'}),
            'institution_name': forms.TextInput(attrs={'class': 'form-control'}),
            'completion_year': forms.NumberInput(attrs={'class': 'form-control'}),
            'literacy_status': forms.Select(attrs={'class': 'form-select'}),
        }

class EmploymentInformationForm(forms.ModelForm):
    class Meta:
        model = EmploymentInformation
        fields = [ # Explicitly listing fields instead of exclude
            'employment_status',
            'occupation',
            'industry',
            'employer_name',
            'income_range',
        ]
        widgets = {
            'employment_status': forms.Select(attrs={'class': 'form-select'}),
            'occupation': forms.TextInput(attrs={'class': 'form-control'}),
            'industry': forms.TextInput(attrs={'class': 'form-control'}),
            'employer_name': forms.TextInput(attrs={'class': 'form-control'}),
            'income_range': forms.Select(attrs={'class': 'form-select'}),
        }
