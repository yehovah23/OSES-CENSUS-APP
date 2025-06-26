from rest_framework import serializers
from .models import (
    CustomUser,
    EnumerationData,
    PersonalInformation,
    AddressInformation,
    EducationInformation,
    EmploymentInformation,
    Language,
    SystemSetting,
    AuditLog
)

class BaseUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['national_id', 'first_name', 'last_name', 'email', 'phone_number']
        read_only_fields = ['national_id']

class UserSerializer(BaseUserSerializer):
    is_active = serializers.BooleanField(read_only=True)

    class Meta(BaseUserSerializer.Meta):
         fields = BaseUserSerializer.Meta.fields + ['is_active']

class UserCreateSerializer(BaseUserSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta(BaseUserSerializer.Meta):
        fields = BaseUserSerializer.Meta.fields + ['password']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user


class PersonalInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = PersonalInformation
        fields = '__all__'

class AddressInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AddressInformation
        fields = '__all__'

class EducationInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationInformation
        fields = '__all__'

class EmploymentInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmploymentInformation
        fields = '__all__'

class EnumerationDataSerializer(serializers.ModelSerializer):
    personal_info = PersonalInformationSerializer()
    address_info = AddressInformationSerializer()
    user = serializers.StringRelatedField()

    class Meta:
        model = EnumerationData
        fields = '__all__'
        read_only_fields = ['user', 'submission_date', 'verified_by', 'verification_date']

    def create(self, validated_data):
        personal_info_data = validated_data.pop('personal_info')
        address_info_data = validated_data.pop('address_info')
        education_info_data = validated_data.pop('education_info', {})  # Make optional
        employment_info_data = validated_data.pop('employment_info', {})  # Make optional
        
        enumeration = EnumerationData.objects.create(**validated_data)
        
        PersonalInformation.objects.create(enumeration=enumeration, **personal_info_data)
        AddressInformation.objects.create(enumeration=enumeration, **address_info_data)
        
        if education_info_data:
            EducationInformation.objects.create(enumeration=enumeration, **education_info_data)
        if employment_info_data:
            EmploymentInformation.objects.create(enumeration=enumeration, **employment_info_data)
        
        return enumeration
    
    def update(self, instance, validated_data):
        personal_info_data = validated_data.pop('personal_info', None)
        address_info_data = validated_data.pop('address_info', None)
        education_info_data = validated_data.pop('education_info', None)
        employment_info_data = validated_data.pop('employment_info', None)
        
        # Update main instance
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update nested instances
        if personal_info_data:
            PersonalInformation.objects.filter(enumeration=instance).update(**personal_info_data)
        if address_info_data:
            AddressInformation.objects.filter(enumeration=instance).update(**address_info_data)
        if education_info_data:
            EducationInformation.objects.filter(enumeration=instance).update(**education_info_data)
        if employment_info_data:
            EmploymentInformation.objects.filter(enumeration=instance).update(**employment_info_data)
        
        return instance

class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Language
        fields = '__all__'

class SystemSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemSetting
        fields = '__all__'
        read_only_fields = ['updated_by', 'updated_at']

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = '__all__'
        read_only_fields = ['created_at']
