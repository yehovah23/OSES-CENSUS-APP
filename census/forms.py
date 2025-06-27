from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import (
    CustomUser, EnumerationData, PersonalInformation, AddressInformation,
    EducationInformation, EmploymentInformation, # Removed OTP
)
from django.utils import timezone
from django.core.exceptions import ValidationError


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        # Changed User to CustomUser
        model = CustomUser
        fields = (
            'national_id', 'first_name', 'last_name', 'email', 'phone_number'
        )
        # Add labels or help_texts if desired
        labels = {
            'national_id': 'National ID',
            'first_name': 'First Name',
            'last_name': 'Last Name',
            'email': 'Email Address',
            'phone_number': 'Phone Number',
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email and CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with that email already exists.")
        return email

    def clean_national_id(self):
        national_id = self.cleaned_data.get('national_id')
        if national_id and CustomUser.objects.filter(national_id=national_id).exists():
            raise forms.ValidationError("A user with that National ID already exists.")
        return national_id

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        if phone_number and CustomUser.objects.filter(phone_number=phone_number).exists():
            raise forms.ValidationError("A user with that phone number already exists.")
        return phone_number


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        # Changed User to CustomUser
        model = CustomUser
        fields = (
            'national_id', 'first_name', 'last_name', 'email', 'phone_number',
            'is_active', 'is_staff', 'is_superuser',
        )


# REMOVED OTPVerificationForm

class EnumerationDataForm(forms.ModelForm):
    class Meta:
        model = EnumerationData
        fields = ['status', 'verification_notes']
        widgets = {
            'verification_notes': forms.Textarea(attrs={'rows': 4}),
        }

class PersonalInformationForm(forms.ModelForm):
    class Meta:
        model = PersonalInformation
        exclude = ['enumeration'] # Exclude enumeration as it will be set in the view
        widgets = {
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
        }

class AddressInformationForm(forms.ModelForm):
    class Meta:
        model = AddressInformation
        exclude = ['enumeration'] # Exclude enumeration as it will be set in the view

class EducationInformationForm(forms.ModelForm):
    class Meta:
        model = EducationInformation
        exclude = ['enumeration'] # Exclude enumeration as it will be set in the view

class EmploymentInformationForm(forms.ModelForm):
    class Meta:
        model = EmploymentInformation
        exclude = ['enumeration'] # Exclude enumeration as it will be set in the view
