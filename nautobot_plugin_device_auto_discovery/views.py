"""UI viewsets for the Device Auto-Discovery plugin."""

from django import forms as django_forms
from django.contrib import messages
from django.shortcuts import redirect, reverse
from nautobot.apps.ui import ObjectDetailContent, ObjectFieldsPanel, ObjectsTablePanel, SectionChoices
from nautobot.apps.views import NautobotUIViewSet
from nautobot.dcim.models import Location
from nautobot.extras.models import Job, JobResult, Role
from nautobot.ipam.models import Namespace
from nautobot.tenancy.models import Tenant
from rest_framework.decorators import action
from rest_framework.response import Response

from nautobot_plugin_device_auto_discovery import filtersets, forms, models, tables
from nautobot_plugin_device_auto_discovery.api import serializers


class DiscoveredDeviceOnboardForm(django_forms.Form):
    """Form for the Onboard Selected Devices bulk action."""

    pk_list = django_forms.CharField(widget=django_forms.HiddenInput())
    namespace = django_forms.ModelChoiceField(
        queryset=Namespace.objects.all(),
        required=False,
        help_text="Namespace for the devices' primary IP addresses (defaults to Global).",
    )
    default_location = django_forms.ModelChoiceField(
        queryset=Location.objects.all(),
        required=False,
        help_text="Fallback location when a device has no classification result.",
    )
    default_role = django_forms.ModelChoiceField(
        queryset=Role.objects.all(),
        required=False,
        help_text="Fallback role when a device has no classification result.",
    )
    default_tenant = django_forms.ModelChoiceField(
        queryset=Tenant.objects.all(),
        required=False,
        help_text="Fallback tenant when a device has no classification result.",
    )
    fill_from_classification = django_forms.BooleanField(
        initial=True,
        required=False,
        help_text="Use each device's automated classification results, falling back to the defaults above.",
    )


class DiscoveryProfileUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryProfileBulkEditForm
    filterset_class = filtersets.DiscoveryProfileFilterSet
    filterset_form_class = forms.DiscoveryProfileFilterForm
    form_class = forms.DiscoveryProfileForm
    queryset = models.DiscoveryProfile.objects.all()
    serializer_class = serializers.DiscoveryProfileSerializer
    table_class = tables.DiscoveryProfileTable


class DiscoveryScanUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryScanBulkEditForm
    filterset_class = filtersets.DiscoveryScanFilterSet
    filterset_form_class = forms.DiscoveryScanFilterForm
    form_class = forms.DiscoveryScanForm
    queryset = models.DiscoveryScan.objects.all()
    serializer_class = serializers.DiscoveryScanSerializer
    table_class = tables.DiscoveryScanTable


class DiscoveryResultUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryResultBulkEditForm
    filterset_class = filtersets.DiscoveryResultFilterSet
    filterset_form_class = forms.DiscoveryResultFilterForm
    form_class = forms.DiscoveryResultForm
    queryset = models.DiscoveryResult.objects.all()
    serializer_class = serializers.DiscoveryResultSerializer
    table_class = tables.DiscoveryResultTable


class DiscoveredDeviceUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveredDeviceBulkEditForm
    filterset_class = filtersets.DiscoveredDeviceFilterSet
    filterset_form_class = forms.DiscoveredDeviceFilterForm
    form_class = forms.DiscoveredDeviceForm
    queryset = (
        models.DiscoveredDevice.objects.all()
        .prefetch_related("classifications__matched_rule", "classifications__discovered_device")
    )
    serializer_class = serializers.DiscoveredDeviceSerializer
    table_class = tables.DiscoveredDeviceTable
    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                label="Discovery",
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=(
                    "ip_address",
                    "hostname",
                    "vendor",
                    "model",
                    "serial",
                    "os_version",
                    "status",
                    "device",
                    "last_seen",
                ),
            ),
            ObjectFieldsPanel(
                label="Collection",
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                fields=(
                    "snmp_collection",
                    "snmp_collection_datetime",
                    "snmp_issue",
                    "ssh_collection",
                    "ssh_collection_datetime",
                    "ssh_issue",
                    "ssh_secrets_group",
                    "snmp_secrets_group",
                ),
            ),
            ObjectsTablePanel(
                label="Automated Classification",
                section=SectionChoices.FULL_WIDTH,
                weight=100,
                table_class=tables.DiscoveredDeviceClassificationTable,
                table_attribute="classifications",
                related_field_name="discovered_device",
                table_title="Automated Classification",
                exclude_columns=("discovered_device",),
                include_paginator=False,
            ),
        )
    )

    @action(methods=["get", "post"], detail=False, url_path="onboard", url_name="onboard")
    def onboard(self, request, *args, **kwargs):
        """Bulk-onboard selected Not Imported discovered devices as Nautobot Devices."""
        if request.method == "POST":
            form = DiscoveredDeviceOnboardForm(request.POST)
            if form.is_valid():
                pk_list = form.cleaned_data["pk_list"]
                selected = models.DiscoveredDevice.objects.filter(pk__in=[pk for pk in pk_list.split(",") if pk])
                not_onboardable = selected.exclude(status=models.DiscoveredDevice.CorrelationStatus.NEW).count()
                if not_onboardable:
                    messages.warning(
                        request,
                        f"{not_onboardable} selected device(s) are not in the Not Imported state and will be skipped.",
                    )
                try:
                    job_model = Job.objects.get_for_class_path(
                        "nautobot_plugin_device_auto_discovery.jobs.OnboardDiscoveredDevicesJob"
                    )
                except Job.DoesNotExist:
                    messages.error(
                        request,
                        "The Onboard Discovered Devices job is not registered. "
                        "Run nautobot-server post_upgrade to sync jobs.",
                    )
                    return redirect("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_list")
                job_data = {
                    "pk_list": form.cleaned_data["pk_list"],
                    "namespace": form.cleaned_data["namespace"].pk if form.cleaned_data["namespace"] else None,
                    "default_location": form.cleaned_data["default_location"].pk if form.cleaned_data["default_location"] else None,
                    "default_role": form.cleaned_data["default_role"].pk if form.cleaned_data["default_role"] else None,
                    "default_tenant": form.cleaned_data["default_tenant"].pk if form.cleaned_data["default_tenant"] else None,
                    "fill_from_classification": bool(form.cleaned_data["fill_from_classification"]),
                    "dryrun": False,
                }
                job_result = JobResult.enqueue_job(
                    job_model=job_model,
                    user=request.user,
                    job_kwargs=job_data,
                )
                return redirect("extras:jobresult_detail", pk=job_result.pk)

        pk_list = ",".join(request.GET.getlist("pk")) or request.POST.get("pk_list", "")
        selected = models.DiscoveredDevice.objects.filter(pk__in=[pk for pk in pk_list.split(",") if pk])
        form = DiscoveredDeviceOnboardForm(initial={"pk_list": pk_list})
        return Response(
            {
                "form": form,
                "selected_count": selected.count(),
                "selected": selected,
                "onboard_url": reverse("plugins:nautobot_plugin_device_auto_discovery:discovereddevice_onboard"),
            },
            template_name="nautobot_plugin_device_auto_discovery/discovereddevice_onboard.html",
        )


class DiscoveryProfileSecretsGroupAssignmentUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryProfileSecretsGroupAssignmentBulkEditForm
    filterset_class = filtersets.DiscoveryProfileSecretsGroupAssignmentFilterSet
    filterset_form_class = forms.DiscoveryProfileFilterForm
    form_class = forms.DiscoveryProfileSecretsGroupAssignmentForm
    queryset = models.DiscoveryProfileSecretsGroupAssignment.objects.all()
    serializer_class = serializers.DiscoveryProfileSecretsGroupAssignmentSerializer
    table_class = tables.DiscoveryProfileSecretsGroupAssignmentTable


class DeviceClassificationRuleUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DeviceClassificationRuleBulkEditForm
    filterset_class = filtersets.DeviceClassificationRuleFilterSet
    filterset_form_class = forms.DeviceClassificationRuleFilterForm
    form_class = forms.DeviceClassificationRuleForm
    queryset = models.DeviceClassificationRule.objects.all()
    serializer_class = serializers.DeviceClassificationRuleSerializer
    table_class = tables.DeviceClassificationRuleTable


class DiscoveredDeviceClassificationUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveredDeviceClassificationBulkEditForm
    filterset_class = filtersets.DiscoveredDeviceClassificationFilterSet
    filterset_form_class = forms.DiscoveredDeviceClassificationFilterForm
    form_class = forms.DiscoveredDeviceClassificationForm
    queryset = models.DiscoveredDeviceClassification.objects.all()
    serializer_class = serializers.DiscoveredDeviceClassificationSerializer
    table_class = tables.DiscoveredDeviceClassificationTable
