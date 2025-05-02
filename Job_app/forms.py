from django import forms
from django.contrib.auth.models import User
from .models import Company, Applicant,Job

class UserRegisterForm(forms.ModelForm):
    ROLE_CHOICES = [
        ('company', 'Company'),
        ('applicant', 'Applicant'),
    ]

    password = forms.CharField(widget=forms.PasswordInput)
    role = forms.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    
    def __init__(self, *args, **kwargs):
        super(UserRegisterForm, self).__init__(*args, **kwargs)
        self.fields['role'].required = True

        
class CompanyForm(forms.ModelForm):
    class Meta:
        model = Company
        fields = ['company_name', 'description']

class ApplicantForm(forms.ModelForm):
    class Meta:
        model = Applicant
        fields = ['resume']

class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={
            'placeholder': 'Username',
            'class': 'form-control'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Password',
            'class': 'form-control'
        })
    )

class JobForm(forms.ModelForm):
    class Meta:
        model = Job
        fields = ['title', 'description', 'location']