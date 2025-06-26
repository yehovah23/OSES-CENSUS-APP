# E:\django\my_django_projects\myproject\census\views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.generic import ListView, DetailView, CreateView
from django.views.generic import UpdateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.utils import timezone
from django.contrib.auth import authenticate, login
import base64
from django.core.files.base import ContentFile
from django.db import transaction
from django.contrib import messages
import json

# Django REST Framework imports
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

# Import OTP related utilities and models
from .utils import create_and_send_otp
from .models import (
    EnumerationData, CustomUser, AddressInformation, PersonalInformation, Language,
    SystemSetting, AuditLog, EducationInformation, EmploymentInformation, OTP
)
from .serializers import (
    EnumerationDataSerializer, AuditLogSerializer, UserSerializer, AddressInformationSerializer,
    SystemSettingSerializer, LanguageSerializer, PersonalInformationSerializer,
    UserCreateSerializer,
    EducationInformationSerializer, EmploymentInformationSerializer
)
from .forms import (
    EnumerationDataForm, PersonalInformationForm, AddressInformationForm,
    CustomUserCreationForm, OTPVerificationForm,
    EducationInformationForm, EmploymentInformationForm
)

# --- Constants for duplicated literals ---
ERROR_UNEXPECTED = 'An unexpected error occurred.'
ERROR_INVALID_JSON = 'Invalid JSON.'
ERROR_INVALID_METHOD = 'Invalid request method.'
TEMPLATE_ENUMERATION_FORM = 'census/enumeration_form.html'
# --- End Constants ---


# Template Views
def home(request):
    return render(request, 'census/home.html')

def signup_view(request):
    # This view will handle the final user creation after OTP verification
    # The OTP request and verification will be handled by separate AJAX views
    if request.method == 'POST':
        # Retrieve data from session which was stored after OTP verification
        signup_data = request.session.get('signup_data')
        if not signup_data:
            messages.error(request, "Session expired or no signup data found. Please restart the signup process.")
            return redirect('signup') # Redirect to the start of signup

        # Ensure the phone number from session is marked as verified
        phone_number = signup_data.get('phone_number')
        if not OTP.objects.filter(phone_number=phone_number, is_verified=True, expires_at__gt=timezone.now()).exists():
            messages.error(request, "Phone number not verified. Please complete OTP verification.")
            return redirect('signup')

        # Use CustomUserCreationForm to save the user from session data
        form = CustomUserCreationForm(signup_data)
        if form.is_valid():
            # Create the user here
            user = form.save(commit=False)
            user.set_password(signup_data.get('password')) # Set password as save(commit=False) doesn't hash it
            user.is_verified = True # Mark as verified after successful OTP and creation
            user.save()

            # Clear session data
            del request.session['signup_data']
            messages.success(request, "Account created successfully! You can now log in.")
            return redirect('login') # Redirect to login page

        else:
            # This case should ideally not happen if data from session was already validated
            # But handle it for robustness
            print(f"Error saving user from session data: {form.errors}")
            messages.error(request, "An error occurred during account creation. Please try again.")
            return redirect('signup')
    else:
        # Initial GET request for signup
        form = CustomUserCreationForm()
        # Initial state: only display the main signup form
        return render(request, 'census/signup.html', {'form': form, 'otp_sent': False})


def request_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            phone_number = data.get('phone_number')
            # Add basic validation for phone number format
            if not phone_number:
                return JsonResponse({'success': False, 'message': 'Phone number is required.'}, status=400)

            # Check if user with this phone number already exists and is verified
            if CustomUser.objects.filter(phone_number=phone_number, is_verified=True).exists():
                return JsonResponse({'success': False, 'message': 'This phone number is already registered and verified.'}, status=409)

            # Check if an unverified user exists and use their national_id for form data.
            # This prevents re-registration for an existing but unverified account.
            existing_unverified_user = CustomUser.objects.filter(phone_number=phone_number, is_verified=False).first()
            if existing_unverified_user:
                data['national_id'] = existing_unverified_user.national_id
                data['first_name'] = existing_unverified_user.first_name
                data['last_name'] = existing_unverified_user.last_name
                data['email'] = existing_unverified_user.email
                # We won't pre-fill password for security, user will re-enter or create.

            # Store the preliminary signup data in session
            request.session['signup_data_pre_otp'] = data
            request.session.modified = True

            # Create and send OTP
            otp_instance = create_and_send_otp(phone_number)

            if otp_instance:
                return JsonResponse({'success': True, 'message': 'OTP sent successfully. Please check your phone.'})
            else:
                return JsonResponse({'success': False, 'message': 'Failed to send OTP. Please try again.'}, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': ERROR_INVALID_JSON}, status=400)
        except Exception as e:
            print(f"Error in request_otp: {e}")
            return JsonResponse({'success': False, 'message': ERROR_UNEXPECTED}, status=500)
    return JsonResponse({'success': False, 'message': ERROR_INVALID_METHOD}, status=405)


def verify_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            phone_number = data.get('phone_number')
            otp_code = data.get('otp_code')

            if not phone_number or not otp_code:
                return JsonResponse({'success': False, 'message': 'Phone number and OTP are required.'}, status=400)

            # Verify OTP using the form
            otp_form = OTPVerificationForm({'phone_number': phone_number, 'code': otp_code})
            if otp_form.is_valid():
                # Retrieve the preliminary signup data from session
                signup_data_pre_otp = request.session.get('signup_data_pre_otp')
                if not signup_data_pre_otp or signup_data_pre_otp.get('phone_number') != phone_number:
                    return JsonResponse({'success': False, 'message': 'Session expired or invalid phone number for verification. Please restart signup.'}, status=400)

                # Store all collected signup data including passwords in session for final signup_view
                request.session['signup_data'] = signup_data_pre_otp
                request.session.modified = True

                # Mark OTP as verified (already done in OTPVerificationForm.clean())
                return JsonResponse({'success': True, 'message': 'OTP verified successfully. Redirecting to final registration...'})
            else:
                return JsonResponse({'success': False, 'message': otp_form.errors.as_text()}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': ERROR_INVALID_JSON}, status=400)
        except Exception as e:
            print(f"Error in verify_otp: {e}")
            return JsonResponse({'success': False, 'message': ERROR_UNEXPECTED}, status=500)
    return JsonResponse({'success': False, 'message': ERROR_INVALID_METHOD}, status=405)


def resend_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            phone_number = data.get('phone_number')

            if not phone_number:
                return JsonResponse({'success': False, 'message': 'Phone number is required.'}, status=400)

            # You might want to add rate limiting here to prevent abuse
            # e.g., check last OTP sent time for this phone number

            otp_instance = create_and_send_otp(phone_number)
            if otp_instance:
                return JsonResponse({'success': True, 'message': 'New OTP sent successfully. Check your phone.'})
            else:
                return JsonResponse({'success': False, 'message': 'Failed to resend OTP. Please try again later.'}, status=500)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'message': ERROR_INVALID_JSON}, status=400)
        except Exception as e:
            print(f"Error in resend_otp: {e}")
            return JsonResponse({'success': False, 'message': ERROR_UNEXPECTED}, status=500)
    return JsonResponse({'success': False, 'message': ERROR_INVALID_METHOD}, status=405)


# --- Helper Functions for login_view to reduce complexity ---

def _render_login_error(request, message, form=None):
    """Helper to render the login page with an error message."""
    if form is None:
        form = CustomUserCreationForm() # Provide a default form if none passed
    messages.error(request, message)
    return render(request, 'census/login.html', {'form': form, 'error_message': message})

def _handle_face_authentication(request, user, password, national_id):
    """Handles logic for facial authentication."""
    # Simulate face authentication success for demonstration
    # In reality, you'd perform actual face comparison here.
    if password:
        authenticated_user = authenticate(request, national_id=national_id, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, f"User {national_id} authenticated with password and face data (simulated).")
            return redirect('home')
        else:
            return _render_login_error(request, 'Authentication failed. Invalid password or face mismatch.')
    else:
        # This is a SECURITY RISK if not backed by real face recognition.
        login(request, user)
        messages.success(request, f"User {national_id} authenticated with face data (simulated, no password).")
        return redirect('home')

def _handle_password_authentication(request, national_id, password):
    """Handles logic for password-only authentication."""
    if password:
        authenticated_user = authenticate(request, national_id=national_id, password=password)
        if authenticated_user:
            login(request, authenticated_user)
            messages.success(request, f"User {national_id} authenticated with password only.")
            return redirect('home')
        else:
            return _render_login_error(request, 'Authentication failed. Invalid password.')
    else:
        return _render_login_error(request, 'Please capture your face or enter your password.')

# --- Refactored login_view ---
def login_view(request):
    if request.method == 'GET':
        return render(request, 'census/login.html')

    national_id = request.POST.get('national_id')
    password = request.POST.get('password')
    face_image_data = request.POST.get('face_image_data')

    if not national_id:
        return _render_login_error(request, 'National ID is required.')

    try:
        user = CustomUser.objects.get(national_id=national_id)
    except CustomUser.DoesNotExist:
        return _render_login_error(request, 'National ID not found.')

    # User exists, proceed with authentication methods
    if face_image_data:
        # Delegate to face authentication helper
        return _handle_face_authentication(request, user, password, national_id)
    else:
        # Delegate to password-only authentication helper
        return _handle_password_authentication(request, national_id, password)


def enumeration_create(request):
    personal_form = PersonalInformationForm(prefix='personal_info')
    address_form = AddressInformationForm(prefix='address_info')
    education_form = EducationInformationForm(prefix='education_info')
    employment_form = EmploymentInformationForm(prefix='employment_info')
    enumeration_form = EnumerationDataForm()

    if request.method == 'POST':
        personal_form = PersonalInformationForm(request.POST, prefix='personal_info')
        address_form = AddressInformationForm(request.POST, prefix='address_info')
        education_form = EducationInformationForm(request.POST, prefix='education_info')
        employment_form = EmploymentInformationForm(request.POST, prefix='employment_info')
        enumeration_form = EnumerationDataForm(request.POST)

        if (personal_form.is_valid() and address_form.is_valid() and
            education_form.is_valid() and employment_form.is_valid() and
            enumeration_form.is_valid()):
            try:
                with transaction.atomic():
                    enumeration = enumeration_form.save(commit=False)
                    enumeration.user = request.user
                    enumeration.save()

                    personal_info = personal_form.save(commit=False)
                    personal_info.enumeration = enumeration
                    personal_info.save()

                    address_info = address_form.save(commit=False)
                    address_info.enumeration = enumeration
                    address_info.save()

                    education_info = education_form.save(commit=False)
                    education_info.enumeration = enumeration
                    education_info.save()

                    employment_info = employment_form.save(commit=False)
                    employment_info.enumeration = enumeration
                    employment_info.save()

                    return redirect('enumeration-detail', pk=enumeration.pk)
            except Exception as e:
                print(f"Database save error: {e}")
                return render(request, TEMPLATE_ENUMERATION_FORM, { # Replaced literal
                    'personal_form': personal_form,
                    'address_form': address_form,
                    'education_form': education_form,
                    'employment_form': employment_form,
                    'enumeration_form': enumeration_form,
                    'error_message': 'An error occurred while saving your enumeration. Please try again.'
                })
        else:
            print(f"Personal Form Errors: {personal_form.errors}")
            print(f"Address Form Errors: {address_form.errors}")
            print(f"Education Form Errors: {education_form.errors}")
            print(f"Employment Form Errors: {employment_form.errors}")
            print(f"Enumeration Form Errors: {enumeration_form.errors}")
            return render(request, TEMPLATE_ENUMERATION_FORM, { # Replaced literal
                'personal_form': personal_form,
                'address_form': address_form,
                'education_form': education_form,
                'employment_form': employment_form,
                'enumeration_form': enumeration_form,
            })
    else:
        personal_form = PersonalInformationForm(prefix='personal_info')
        address_form = AddressInformationForm(prefix='address_info')
        education_form = EducationInformationForm(prefix='education_info')
        employment_form = EmploymentInformationForm(prefix='employment_info')
        enumeration_form = EnumerationDataForm()

    return render(request, TEMPLATE_ENUMERATION_FORM, { # Replaced literal
        'personal_form': personal_form,
        'address_form': address_form,
        'education_form': education_form,
        'employment_form': employment_form,
        'enumeration_form': enumeration_form,
    })


class EnumerationListView(LoginRequiredMixin, ListView):
    model = EnumerationData
    template_name = 'census/enumeration_list.html'
    context_object_name = 'enumerations'
    paginate_by = 10

    def get_queryset(self):
        queryset = EnumerationData.objects.filter(user=self.request.user)

        search_query = self.request.GET.get('q')
        if search_query:
            queryset = queryset.filter(
                Q(personal_info__first_name__icontains=search_query) |
                Q(personal_info__last_name__icontains=search_query) |
                Q(address_info__district__icontains=search_query)
            )

        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset.select_related('personal_info', 'address_info')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = EnumerationData.STATUS_CHOICES
        context['q'] = self.request.GET.get('q', '')
        context['status'] = self.request.GET.get('status', '')
        return context

class EnumerationDetailView(LoginRequiredMixin, DetailView):
    model = EnumerationData
    template_name = 'census/enumeration_detail.html'


# API Views
class EnumerationViewSet(viewsets.ModelViewSet):
    queryset = EnumerationData.objects.all()
    serializer_class = EnumerationDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return self.queryset.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
    @action(detail=True, methods=['get'])
    def personal_info(self, request, pk=None):
        enumeration = self.get_object()
        serializer = PersonalInformationSerializer(enumeration.personal_info)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def address_info(self, request, pk=None):
        enumeration = self.get_object()
        serializer = AddressInformationSerializer(enumeration.address_info)
        return Response(serializer.data)

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return UserSerializer

    def get_permissions(self):
        if self.action == 'create':
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

class EnumerationDataViewSet(viewsets.ModelViewSet):
    serializer_class = EnumerationDataSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_staff:
            return EnumerationData.objects.all()
        return EnumerationData.objects.filter(user=user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=['post'])
    def submit(self, request, pk=None):
        enumeration = self.get_object()
        if enumeration.user != request.user and not request.user.is_staff:
            return Response({'error': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        enumeration.status = 'submitted'
        enumeration.save()
        return Response({'status': 'submitted'})

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        if not request.user.is_staff:
            return Response({'error': 'Only staff can verify'}, status=status.HTTP_403_FORBIDDEN)

        enumeration = self.get_object()
        enumeration.status = 'verified'
        enumeration.verified_by = request.user
        enumeration.verification_date = timezone.now()
        enumeration.save()
        return Response({'status': 'verified'})

class EnumerationUpdateView(LoginRequiredMixin, UpdateView):
    model = EnumerationData
    form_class = EnumerationDataForm
    template_name = TEMPLATE_ENUMERATION_FORM # Replaced literal
    success_url = reverse_lazy('enumeration-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.request.POST:
            context['personal_form'] = PersonalInformationForm(
                self.request.POST,
                instance=self.object.personal_info
            )
            context['address_form'] = AddressInformationForm(
                self.request.POST,
                instance=self.object.address_info
            )
            context['education_form'] = EducationInformationForm(
                self.request.POST,
                instance=getattr(self.object, 'education_info', None)
            )
            context['employment_form'] = EmploymentInformationForm(
                self.request.POST,
                instance=getattr(self.object, 'employment_info', None)
            )
        else:
            context['personal_form'] = PersonalInformationForm(
                instance=self.object.personal_info
            )
            context['address_form'] = AddressInformationForm(
                instance=self.object.address_info
            )
            context['education_form'] = EducationInformationForm(
                instance=getattr(self.object, 'education_info', None)
            )
            context['employment_form'] = EmploymentInformationForm(
                instance=getattr(self.object, 'employment_info', None)
            )
        return context

    def form_valid(self, form):
        context = self.get_context_data()
        personal_form = context['personal_form']
        address_form = context['address_form']
        education_form = context['education_form']
        employment_form = context['employment_form']

        if (personal_form.is_valid() and address_form.is_valid() and
            education_form.is_valid() and employment_form.is_valid()):
            with transaction.atomic():
                self.object = form.save()
                personal_form.instance.enumeration = self.object
                personal_form.save()
                address_form.instance.enumeration = self.object
                address_form.save()

                if education_form.instance.pk:
                    education_form.save()
                else:
                    education_info = education_form.save(commit=False)
                    education_info.enumeration = self.object
                    education_info.save()

                if employment_form.instance.pk:
                    employment_form.save()
                else:
                    employment_info = employment_form.save(commit=False)
                    employment_info.enumeration = self.object
                    employment_info.save()

            return super().form_valid(form)
        else:
            return self.render_to_response(
                self.get_context_data(form=form)
            )

class AddressSearchViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AddressInformation.objects.all()
    serializer_class = AddressInformationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()

        district = self.request.query_params.get('district')
        if district:
            queryset = queryset.filter(district__iexact=district)
        return queryset


class LanguageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Language.objects.filter(is_active=True)
    serializer_class = LanguageSerializer
    permission_classes = [permissions.AllowAny]

class SystemSettingViewSet(viewsets.ModelViewSet):
    serializer_class = SystemSettingSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        if self.request.user.is_superuser:
            return SystemSetting.objects.all()
        return SystemSetting.objects.filter(is_public=True)

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all().order_by('-created_at')
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()

        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user__id=user_id)

        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action__iexact=action)

        return queryset
