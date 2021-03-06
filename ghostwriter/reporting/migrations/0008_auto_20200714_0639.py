# Generated by Django 2.2.3 on 2020-07-14 06:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0007_auto_20200110_0505'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='nessusID',
            field=models.IntegerField(default=0, help_text='Set this findings weight to adjust where it appears in the report compared to other findings with the same Severity rating', verbose_name='Report Position'),
        ),
        migrations.AddField(
            model_name='reportfindinglink',
            name='nessusID',
            field=models.IntegerField(default=0, help_text='Set this findings weight to adjust where it appears in the report compared to other findings with the same Severity rating', verbose_name='Report Position'),
        ),
    ]
