from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponseForbidden
from .forms import UserRegisterForm, CompanyForm, ApplicantForm, LoginForm
from .models import UserProfile, Company, Applicant, Job, Application
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError,transaction
from .forms import JobForm


def register(request):
    if request.method == 'POST':
        user_form = UserRegisterForm(request.POST)
        if user_form.is_valid():
            role = user_form.cleaned_data.get('role')
            print("Role from form:", role)

            try:
                with transaction.atomic():
                    user = user_form.save(commit=False)
                    user.set_password(user_form.cleaned_data['password'])
                    user.save()

                    # Check if UserProfile already exists
                    if UserProfile.objects.filter(user__username=user.username).exists():
                        print("UserProfile already exists for this user.")
                        user.delete()  # Clean up and show error
                        return render(request, 'registration/register.html', {
                            'user_form': user_form,
                            'error': 'A profile for this user already exists. Try a new username.'
                        })

                    # Create new profile safely
                    UserProfile.objects.create(user=user, role=role)
                    print("UserProfile created successfully.")

                    if role == 'company':
                        Company.objects.create(
                            user=user,
                            company_name=request.POST.get('company_name', ''),
                            description=request.POST.get('description', '')
                        )
                    elif role == 'applicant':
                        Applicant.objects.create(user=user)

                return redirect('login_view')

            except IntegrityError as e:
                print("Registration IntegrityError:", e)
                user.delete()  # Prevent half-created users
                return render(request, 'registration/register.html', {
                    'user_form': user_form,
                    'error': 'Something went wrong. Please try again with a different username.'
                })

    else:
        user_form = UserRegisterForm()

    return render(request, 'registration/register.html', {'user_form': user_form})


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)

                try:
                    role = user.userprofile.role.lower()
                except UserProfile.DoesNotExist:
                    print("❌ UserProfile not found for:", user.username)
                    messages.error(request, "User profile not found.")
                    return redirect('login_view')

                if role == 'company':
                    return redirect('dashboard_company')
                elif role == 'applicant':
                    return redirect('dashboard_applicant')
                elif role == 'admin':
                    return redirect('dashboard_admin')
                else:
                    messages.error(request, "Unknown user role.")
                    return redirect('login_view')
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()

    return render(request, 'registration/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login_view')


@login_required
def dashboard_company(request):
    company = Company.objects.get(user=request.user)
    jobs = Job.objects.filter(company=company)
    return render(request, 'dashboard/company_dashboard.html', {'jobs': jobs})

@login_required
def dashboard_applicant(request):
    jobs = Job.objects.all()
    return render(request, 'dashboard/applicant_dashboard.html', {'jobs': jobs})

@login_required
def dashboard_admin(request):
    return render(request, 'dashboard/admin_dashboard.html')


@login_required
def dashboard(request):
    try:
        profile = request.user.userprofile
        role=profile.role.lower()
        print(f"Debug Role:{role}")

        if profile.role == 'company':
            return redirect('dashboard_company')
        elif profile.role == 'applicant':
            return redirect('dashboard_applicant')
        else:
            return render(request, 'error.html', {'message': 'Unknown user role.'})
        
    except UserProfile.DoesNotExist:
        return render(request,'error.html', {'message' : 'User profile does not exixt'})
    
@login_required
def post_job(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        location = request.POST.get('location')

        try:
            company = Company.objects.get(user=request.user)
        except Company.DoesNotExist:
            return redirect('dashboard')

        Job.objects.create(
            company=company,
            title=title,
            description=description,
            location=location
        )
        return redirect('dashboard_company')

    return render(request, 'jobs/post_job.html')

# @login_required
# def apply_job(request, job_id):
#     job = get_object_or_404(Job, id=job_id)

#     try:
#         applicant = Applicant.objects.get(user=request.user)
#     except Applicant.DoesNotExist:
#         return redirect('login_view')

 

#     if Application.objects.filter(applicant=applicant, job=job).exists():
#         messages.info(request, "You have already applied to this job.")
#     else:
#         Application.objects.create(applicant=applicant, job=job)

#     return redirect('dashboard_applicant')

from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from .models import Applicant, Application, Job
from django.contrib.auth.decorators import login_required

@login_required
def apply_job(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    try:
        applicant = Applicant.objects.get(user=request.user)
    except Applicant.DoesNotExist:
        return redirect('login_view')

    if request.method == 'POST':
        # Get uploaded resume from form
        resume = request.FILES.get('resume')
        if resume:
            applicant.resume = resume
            applicant.save()

        if Application.objects.filter(applicant=applicant, job=job).exists():
            messages.info(request, "You have already applied to this job.")
        else:
            Application.objects.create(applicant=applicant, job=job)

        return redirect('dashboard_applicant')

    # For GET request, show preview page with upload option
    return render(request, 'jobs/job_preview.html', {'job': job})


@login_required
def edit_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, company__user=request.user)
    if request.method == 'POST':
        form = JobForm(request.POST, instance=job)
        if form.is_valid():
            form.save()
            return redirect('dashboard_company')
    else:
        form = JobForm(instance=job)
    return render(request, 'jobs/edit_job.html', {'form': form, 'job': job})

@login_required
def delete_job(request, job_id):
    job = get_object_or_404(Job, id=job_id, company__user=request.user)
    if request.method == 'POST':
        job.delete()
        return redirect('dashboard_company')
    return render(request, 'jobs/confirm_delete.html', {'job': job})


@login_required
def view_applications(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    try:
        company = Company.objects.get(user=request.user)
    except Company.DoesNotExist:
        return HttpResponseForbidden("You are not authorized to view this page.")

    if job.company != company:
        return HttpResponseForbidden("You can only view applications for your own jobs.")

    applications = Application.objects.filter(job=job).select_related('applicant__user')

    return render(request, 'jobs/view_applications.html', {
        'job': job,
        'applications': applications
    })


def forgot_password_request(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            request.session['reset_user_id'] = user.id  # save in session temporarily
            return redirect('forgot_password_reset')
        except User.DoesNotExist:
            messages.error(request, 'No user with that email exists.')
            return redirect('forgot_password_request')

    return render(request, 'registration/forgot_password_request.html')

def forgot_password_reset(request):
    user_id = request.session.get('reset_user_id')
    if not user_id:
        messages.error(request, 'Session expired. Try again.')
        return redirect('forgot_password_request')

    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            try:
                user = User.objects.get(id=user_id)
                user.password = make_password(password)
                user.save()
                del request.session['reset_user_id']  # clear session
                messages.success(request, 'Password reset successful. You can now log in.')
                return redirect('login_view')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
        else:
            messages.error(request, 'Passwords do not match.')

    return render(request, 'registration/forgot_password_reset.html')


def job_preview(request, job_id):
    job = get_object_or_404(Job, id=job_id)

    if request.method == 'POST':
        if not request.user.is_authenticated:
            return redirect('login_view')

        applicant = get_object_or_404(Applicant, user=request.user)
        resume = request.FILES.get('resume')

        # Save application
        Application.objects.create(
            applicant=applicant,
            job=job,
            resume=resume
        )

        messages.success(request, "You have successfully applied for the job!")
        return redirect('dashboard_applicant')  # Go back to dashboard after applying

    return render(request, 'job_preview.html', {'job': job})