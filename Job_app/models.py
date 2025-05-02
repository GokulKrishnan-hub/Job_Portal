from django.db import models
from django.contrib.auth.models import User

# Extend User model with role
class UserProfile(models.Model):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('company', 'Company'),
        ('applicant', 'Applicant'),
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, null=False, blank=False)

    def __str__(self):
        return f"{self.user.username} - {self.role}"

# Company Profile
class Company(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    company_name = models.CharField(max_length=100)
    description = models.TextField()

    def __str__(self):
        return self.company_name

# Applicant Profile
class Applicant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    resume = models.FileField(upload_to='resumes/', null=True,blank=True)

    def __str__(self):
        return self.user.username

# Job Postings
class Job(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    description = models.TextField()
    location = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    applicants = models.ManyToManyField(Applicant, through='Application', related_name='applied_jobs')

    def __str__(self):
        return self.title

# Job Applications
class Application(models.Model):
    applicant = models.ForeignKey(Applicant, on_delete=models.CASCADE)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    resume = models.FileField(upload_to='resumes/', null=True, blank=True)
    applied_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.applicant.user.username} applied to {self.job.title}"
