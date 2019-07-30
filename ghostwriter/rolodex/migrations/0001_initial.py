# Generated by Django 2.2.3 on 2019-07-26 00:36

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Provide the full name of this client as you would want it to appear in a report', max_length=100, unique=True, verbose_name='Client Name')),
                ('short_name', models.CharField(blank=True, help_text='Provide an abbreviation, or short name, that can be used to refer to this client', max_length=100, null=True, verbose_name='Client Short Name')),
                ('codename', models.CharField(blank=True, help_text='A codename for the client that might be used to discuss the client in public', max_length=100, null=True, verbose_name='Client Codename')),
                ('note', models.TextField(blank=True, help_text='Use this field to describe the client or provide some additional information', max_length=1000, null=True, verbose_name='Client Note')),
            ],
            options={
                'verbose_name': 'Client',
                'verbose_name_plural': 'Clients',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('codename', models.CharField(blank=True, help_text='Create a codename for this project that might be used to refer to it in public', max_length=100, null=True, verbose_name='Project Codename')),
                ('start_date', models.DateField(help_text='Enter the start date of this project', max_length=100, verbose_name='Start Date')),
                ('end_date', models.DateField(help_text='Enter the end date of this project', max_length=100, verbose_name='End Date')),
                ('note', models.TextField(blank=True, help_text='Use this area to provide any additional notes about this project that should be recorded', null=True, verbose_name='Notes')),
                ('slack_channel', models.CharField(blank=True, help_text='Provide an (optional) Slack channel to be used for notifications related to this project', max_length=100, null=True, verbose_name='Project Slack Channel')),
                ('complete', models.BooleanField(default=False, help_text='Mark this project as complete/closed', verbose_name='Completed')),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rolodex.Client')),
                ('operator', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Project',
                'verbose_name_plural': 'Projects',
                'ordering': ['client', 'start_date', 'project_type', 'codename'],
            },
        ),
        migrations.CreateModel(
            name='ProjectRole',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_role', models.CharField(help_text='Enter an operator role', max_length=100, unique=True, verbose_name='Project Role')),
            ],
            options={
                'verbose_name': 'Project role',
                'verbose_name_plural': 'Project roles',
                'ordering': ['project_role'],
            },
        ),
        migrations.CreateModel(
            name='ProjectType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('project_type', models.CharField(help_text='Enter a project type (e.g. red team, penetration test)', max_length=100, unique=True, verbose_name='Project Type')),
            ],
            options={
                'verbose_name': 'Project type',
                'verbose_name_plural': 'Project types',
                'ordering': ['project_type'],
            },
        ),
        migrations.CreateModel(
            name='ProjectNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateField(auto_now_add=True, help_text='Creation timestamp', max_length=100, verbose_name='Timestamp')),
                ('note', models.TextField(blank=True, help_text='Use this area to add a note to this project - it can be anything you want others to see/know about the project', null=True, verbose_name='Notes')),
                ('operator', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rolodex.Project')),
            ],
            options={
                'verbose_name': 'Project note',
                'verbose_name_plural': 'Project notes',
                'ordering': ['project', 'timestamp'],
            },
        ),
        migrations.CreateModel(
            name='ProjectAssignment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_date', models.DateField(help_text='Enter the start date of the project', max_length=100, verbose_name='Start Date')),
                ('end_date', models.DateField(help_text='Enter the end date of the project', max_length=100, verbose_name='End Date')),
                ('note', models.TextField(blank=True, help_text='Use this area to provide any additional notes about this assignment', null=True, verbose_name='Notes')),
                ('operator', models.ForeignKey(help_text='Select a user to assign to this project', null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rolodex.Project')),
                ('role', models.ForeignKey(help_text="Select a role that best describes the selected user's role in this project", null=True, on_delete=django.db.models.deletion.SET_NULL, to='rolodex.ProjectRole')),
            ],
            options={
                'verbose_name': 'Project assignment',
                'verbose_name_plural': 'Project assignments',
                'ordering': ['project', 'start_date', 'operator'],
            },
        ),
        migrations.AddField(
            model_name='project',
            name='project_type',
            field=models.ForeignKey(help_text='Select a category for this project that best describes the work being performed', on_delete=django.db.models.deletion.PROTECT, to='rolodex.ProjectType'),
        ),
        migrations.CreateModel(
            name='ClientNote',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateField(auto_now_add=True, help_text='Creation timestamp', max_length=100, verbose_name='Timestamp')),
                ('note', models.TextField(blank=True, help_text='Use this area to add a note to this client - it can be anything you want others to see/know about the client', null=True, verbose_name='Notes')),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rolodex.Client')),
                ('operator', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Client note',
                'verbose_name_plural': 'Client notes',
                'ordering': ['client', 'timestamp'],
            },
        ),
        migrations.CreateModel(
            name='ClientContact',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text="Enter the contact's full name", max_length=100, null=True, verbose_name='Name')),
                ('job_title', models.CharField(help_text="Enter the contact's job title or role in the project - this will appear in the reports", max_length=100, null=True, verbose_name='Title or Role')),
                ('email', models.CharField(blank=True, help_text='Enter an email address for this contact', max_length=100, null=True, verbose_name='Email')),
                ('phone', models.CharField(blank=True, help_text='Enter a phone number for the contact', max_length=100, null=True, verbose_name='Phone')),
                ('note', models.TextField(blank=True, help_text='Use this field to provide additional information about the contact like availability or more information about their role', max_length=500, null=True, verbose_name='Client Note')),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rolodex.Client')),
            ],
            options={
                'verbose_name': 'Client POC',
                'verbose_name_plural': 'Client POCs',
                'ordering': ['client', 'id'],
            },
        ),
    ]