# Generated by Django 3.0.2 on 2020-03-23 18:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('okerrui', '0009_auto_20200225_1500'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='bonusactivation',
            name='BonusCode',
        ),
        migrations.AddField(
            model_name='bonusactivation',
            name='name',
            field=models.CharField(default=None, max_length=200, null=True),
        ),
        migrations.DeleteModel(
            name='BonusCode',
        ),
    ]