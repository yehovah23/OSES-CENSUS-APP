from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone
from django.conf import settings
import random # Import random for OTP generation

# Define a custom manager for CustomUser
class CustomUserManager(BaseUserManager):
    def create_user(self, email, national_id, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        if not national_id:
            raise ValueError('The National ID must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, national_id=national_id, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, national_id, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True) # Superusers are verified by default

        # Ensure these default values are set for superusers if not provided
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, national_id, password, **extra_fields)


class CustomUser(AbstractUser):
    # AbstractUser already provides 'first_name', 'last_name', 'username' (which we override with email).
    # Explicitly defining email here with unique=True for clarity and to ensure the constraint is picked up.
    email = models.EmailField(unique=True) # <-- Explicitly set unique=True here
    national_id = models.CharField(max_length=20, unique=True)
    phone_number = models.CharField(max_length=15, unique=True)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email' # We use email for login
    # These fields are prompted for when creating a superuser via createsuperuser command
    REQUIRED_FIELDS = ['national_id', 'first_name', 'last_name', 'phone_number']

    objects = CustomUserManager() # <--- ASSIGN CUSTOM MANAGER HERE

    class Meta(AbstractUser.Meta):
        verbose_name = 'Custom User'
        verbose_name_plural = 'Custom Users'
        indexes = [
            models.Index(fields=['national_id']),
            models.Index(fields=['phone_number']),
        ]

    def __str__(self):
        return self.email


# New OTP Model (remains unchanged)
class OTP(models.Model):
    phone_number = models.CharField(max_length=15, db_index=True)
    code = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_verified = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Ensure settings.OTP_EXPIRATION_MINUTES is defined in your settings.py
            self.expires_at = timezone.now() + timezone.timedelta(minutes=settings.OTP_EXPIRATION_MINUTES)
        super().save(*args, **kwargs)

    def is_valid(self):
        return (
            not self.is_verified and
            self.expires_at > timezone.now()
        )

    def __str__(self):
        return f"OTP for {self.phone_number}: {self.code} (Expires: {self.expires_at})"


class EnumerationData(models.Model):
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('submitted', 'Submitted'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='enumerations'
    )
    submission_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='draft'
    )
    # Re-added null=True for TextField as it's typically desired with blank=True for consistency
    verification_notes = models.TextField(blank=True, null=True)
    verified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,  # null=True required for on_delete=models.SET_NULL
        blank=True,
        related_name='verified_enumerations'
    )
    # Re-added null=True for DateTimeField when blank=True is present
    verification_date = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['status']),
        ]
        verbose_name_plural = 'Enumeration Data'

    def __str__(self):
        return f"Enumeration #{self.id} - {self.user.national_id}"


class PersonalInformation(models.Model):
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    ]
    MARITAL_STATUS_CHOICES = [
        ('single', 'Single'),
        ('married', 'Married'),
        ('divorced', 'Divorced'),
        ('widowed', 'Widowed'),
    ]

    enumeration = models.OneToOneField(
        EnumerationData,
        on_delete=models.CASCADE,
        related_name='personal_info'
    )
    first_name = models.CharField(max_length=50)
    # Re-added null=True for CharField when blank=True is present
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    gender = models.CharField(
        max_length=10,
        choices=GENDER_CHOICES
    )
    marital_status = models.CharField(
        max_length=10,
        choices=MARITAL_STATUS_CHOICES
    )
    nationality = models.CharField(max_length=50)

    class Meta:
        verbose_name_plural = 'Personal Information'

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class AddressInformation(models.Model):
    RESIDENCE_TYPE_CHOICES = [
        ('permanent', 'Permanent'),
        ('temporary', 'Temporary'),
    ]

    enumeration = models.OneToOneField(
        EnumerationData,
        on_delete=models.CASCADE,
        related_name='address_info'
    )
    region = models.CharField(max_length=50)
    district = models.CharField(max_length=50)
    county = models.CharField(max_length=50)
    sub_county = models.CharField(max_length=50)
    parish = models.CharField(max_length=50)
    village = models.CharField(max_length=50)
    # Re-added null=True for CharField when blank=True is present
    street = models.CharField(max_length=100, blank=True, null=True)
    # Re-added null=True for CharField when blank=True is present
    house_number = models.CharField(max_length=20, blank=True, null=True)
    location_description = models.TextField(
        blank=True,
        # Re-added null=True for TextField when blank=True is present
        null=True,
        help_text="User's description of their location"
    )
    residence_type = models.CharField(
        max_length=10,
        choices=RESIDENCE_TYPE_CHOICES
    )

    class Meta:
        indexes = [
            models.Index(fields=['district']),
        ]
        verbose_name_plural = 'Address Information'

    def __str__(self):
        return f"{self.district}, {self.sub_county}"


class EducationInformation(models.Model):
    EDUCATION_LEVEL_CHOICES = [
        ('none', 'No Formal Education'),
        ('primary', 'Primary Education'),
        ('secondary', 'Secondary Education'),
        ('certificate', 'Certificate'),
        ('diploma', 'Diploma'),
        ('bachelors', "Bachelor's Degree"),
        ('masters', "Master's Degree"),
        ('phd', 'PhD'),
    ]
    LITERACY_CHOICES = [
        ('literate', 'Literate'),
        ('illiterate', 'Illiterate'),
    ]

    enumeration = models.OneToOneField(
        EnumerationData,
        on_delete=models.CASCADE,
        related_name='education_info'
    )
    highest_education_level = models.CharField(
        max_length=15,
        choices=EDUCATION_LEVEL_CHOICES
    )
    # Re-added null=True for CharField when blank=True is present
    institution_name = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    # Re-added null=True for SmallIntegerField when blank=True is present
    completion_year = models.SmallIntegerField(blank=True, null=True)
    literacy_status = models.CharField(
        max_length=10,
        choices=LITERACY_CHOICES
    )

    class Meta:
        verbose_name_plural = 'Education Information'

    def __str__(self):
        return f"{self.get_highest_education_level_display()}"


class EmploymentInformation(models.Model):
    EMPLOYMENT_STATUS_CHOICES = [
        ('employed', 'Employed'),
        ('self-employed', 'Self-Employed'),
        ('unemployed', 'Unemployed'),
        ('student', 'Student'),
        ('retired', 'Retired'),
    ]
    INCOME_RANGE_CHOICES = [
        ('none', 'No Income'),
        ('low', 'Low Income'),
        ('medium', 'Medium Income'),
        ('high', 'High Income'),
    ]

    enumeration = models.OneToOneField(
        EnumerationData,
        on_delete=models.CASCADE,
        related_name='employment_info'
    )
    employment_status = models.CharField(
        max_length=15,
        choices=EMPLOYMENT_STATUS_CHOICES
    )
    # Re-added null=True for CharField when blank=True is present
    occupation = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    # Re-added null=True for CharField when blank=True is present
    industry = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    # Re-added null=True for CharField when blank=True is present
    employer_name = models.CharField(
        max_length=100,
        blank=True,
        null=True
    )
    income_range = models.CharField(
        max_length=10,
        choices=INCOME_RANGE_CHOICES
    )

    class Meta:
        verbose_name_plural = 'Employment Information'

    def __str__(self):
        return f"{self.get_employment_status_display()}"


class Language(models.Model):
    code = models.CharField(
        max_length=2,
        unique=True,
        help_text='2-letter language code (e.g., en, sw)'
    )
    name = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.name} ({self.code})"


class SystemSetting(models.Model):
    key = models.CharField(
        max_length=50,
        unique=True,
        help_text='Setting key/name'
    )
    value = models.TextField()
    # Re-added null=True for TextField when blank=True is present
    description = models.TextField(blank=True, null=True)
    is_public = models.BooleanField(
        default=False,
        help_text='Whether this setting can be exposed via API'
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,  # null=True required for on_delete=models.SET_NULL
        blank=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['key']),
        ]

    def __str__(self):
        return self.key


class AuditLog(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,  # null=True required for on_delete=models.SET_NULL
        blank=True
    )
    action = models.CharField(max_length=50)
    table_name = models.CharField(max_length=50)
    record_id = models.BigIntegerField()
    # Re-added null=True for JSONField when blank=True is present
    old_values = models.JSONField(blank=True, null=True)
    # Re-added null=True for JSONField when blank=True is present
    new_values = models.JSONField(blank=True, null=True)
    # Re-added null=True as required for GenericIPAddressField when blank=True
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    # Re-added null=True for TextField when blank=True is present
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['action']),
            models.Index(fields=['table_name', 'record_id']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.action} on {self.table_name} #{self.record_id}"
