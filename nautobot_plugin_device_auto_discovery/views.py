"""UI viewsets for the Device Auto-Discovery plugin."""

from django import forms as django_forms
from django.contrib import messages
from django.shortcuts import redirect, reverse
from nautobot.apps.ui import Button, ButtonColorChoices, ObjectDetailContent, ObjectFieldsPanel, ObjectsTablePanel, SectionChoices
from nautobot.apps.views import NautobotUIViewSet
from nautobot.dcim.models import Location
from nautobot.extras.models import Job, JobResult, Role
from nautobot.ipam.models import Namespace
from nautobot.tenancy.models import Tenant
from rest_framework.decorators import action
from rest_framework.response import Response

from nautobot_plugin_device_auto_discovery import filtersets, forms, models, tables
from nautobot_plugin_device_auto_discovery.api import serializers

_NETWORK_DISCOVERY_JOB_CLASS_PATH = "nautobot_plugin_device_auto_discovery.jobs.NetworkDeviceDiscoveryJob"


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


class RunDiscoveryForm(django_forms.Form):
    """Form for the Run Device Discovery action on a Discovery Profile."""

    dryrun = django_forms.BooleanField(
        initial=False,
        required=False,
        help_text="Discover and record results without creating Nautobot objects.",
    )


class DiscoveryProfileUIViewSet(NautobotUIViewSet):
    bulk_update_form_class = forms.DiscoveryProfileBulkEditForm
    filterset_class = filtersets.DiscoveryProfileFilterSet
    filterset_form_class = forms.DiscoveryProfileFilterForm
    form_class = forms.DiscoveryProfileForm
    queryset = models.DiscoveryProfile.objects.all()
    serializer_class = serializers.DiscoveryProfileSerializer
    table_class = tables.DiscoveryProfileTable
    object_detail_content = ObjectDetailContent(
        panels=(
            ObjectFieldsPanel(
                label="Profile",
                section=SectionChoices.LEFT_HALF,
                weight=100,
                fields=(
                    "description",
                    "included_ip_prefixes",
                    "excluded_ip_prefixes",
                    "maximum_ip_addresses",
                    "protocols",
                    "status",
                ),
            ),
            ObjectFieldsPanel(
                label="Scan Settings",
                section=SectionChoices.RIGHT_HALF,
                weight=100,
                fields=(
                    "ssh_port",
                    "snmp_port",
                    "snmp_timeout",
                    "snmp_retries",
                    "snmpv3_auth_protocol",
                    "snmpv3_priv_protocol",
                    "fast_path",
                    "strip_domain_suffixes",
                ),
            ),
        ),
        extra_buttons=(
            Button(
                label="Run Device Discovery",
                color=ButtonColorChoices.GREEN,
                icon="mdi-radar",
                link_name="plugins:nautobot_plugin_device_auto_discovery:discoveryprofile_run-discovery",
                weight=100,
            ),
        ),
    )

    @action(methods=["get", "post"], detail=True, url_path="run-discovery", url_name="run-discovery")
    def run_discovery(self, request, *args, **kwargs):
        """Enqueue the Network Device Discovery job for this profile."""
        profile = self.get_object()
        if request.method == "POST":
            form = RunDiscoveryForm(request.POST)
            if form.is_valid():
                try:
                    job_model = Job.objects.get_for_class_path(_NETWORK_DISCOVERY_JOB_CLASS_PATH)
                except Job.DoesNotExist:
                    messages.error(
                        request,
                        "The Network Device Discovery job is not registered. "
                        "Run nautobot-server post_upgrade to sync jobs.",
                    )
                    return redirect("plugins:nautobot_plugin_device_auto_discovery:discoveryprofile", pk=profile.pk)
                job_data = {
                    "profile": profile.pk,
                    "target_network": str(profile.included_ip_prefixes[0]) if profile.included_ip_prefixes else "0.0.0.0/32",
                    "snmp_version": "2c",
                    "snmp_community": "",
                    "snmpv3_username": "",
                    "snmpv3_auth_key": "",
                    "snmpv3_priv_key": "",
                    "snmpv3_context_name": "",
                    "ssh_username": "",
                    "ssh_password": "",
                    "enable_ping": "ping" in (profile.protocols or []),
                    "enable_snmp": "snmp" in (profile.protocols or []),
                    "enable_ssh": "ssh" in (profile.protocols or []),
                    "dryrun": bool(form.cleaned_data["dryrun"]),
                }
                job_result = JobResult.enqueue_job(
                    job_model=job_model,
                    user=request.user,
                    job_kwargs=job_data,
                )
                return redirect("extras:jobresult_detail", pk=job_result.pk)

        return Response(
            {
                "profile": profile,
                "form": RunDiscoveryForm(),
                "run_url": reverse(
                    "plugins:nautobot_plugin_device_auto_discovery:discoveryprofile_run-discovery",
                    kwargs={"pk": profile.pk},
                ),
            },
            template_name="nautobot_plugin_device_auto_discovery/discoveryprofile_run_discovery.html",
        )


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

    # Status tabs shown above the list (mirrors the Device Discovery app:
    # Imported / New / Conflicts grouping partially_imported + conflict).
    STATUS_TABS = (
        ("imported", "Imported", ("imported",)),
        ("new", "New", ("new",)),
        ("conflicts", "Conflicts", ("partially_imported", "conflict")),
        ("not_reachable", "Not Reachable", ("not_reachable",)),
        ("failed", "Failed", ("failed",)),
        ("all", "All", None),
    )

    def filter_queryset(self, queryset):
        """Apply the status tab (``?tab=<key>``) before standard filtering."""
        tab = self.request.GET.get("tab", "")
        self.active_tab = tab if any(key == tab for key, _label, _statuses in self.STATUS_TABS) else ""
        if self.active_tab and self.active_tab != "all":
            statuses = next(s for key, _l, s in self.STATUS_TABS if key == self.active_tab)
            queryset = queryset.filter(status__in=statuses)
        return super().filter_queryset(queryset)

    @property
    def status_tab_definitions(self):
        """Tab definitions for the list template.

        Each entry carries a pre-built ``querystring`` that preserves the
        current filters while switching to that tab (dropping the previous
        ``tab``/``page`` params).
        """
        params = self.request.GET.copy() if hasattr(self, "request") else {}
        params.pop("tab", None)
        params.pop("page", None)
        base = params.urlencode()
        tabs = []
        for key, label, _statuses in self.STATUS_TABS:
            if key == "all":
                querystring = base
            else:
                querystring = f"{base}&tab={key}" if base else f"tab={key}"
            tabs.append({"key": key, "label": label, "querystring": querystring})
        return tabs

    @property
    def discovered_device_tab_counts(self):
        """Per-tab record counts (unfiltered by the tab itself)."""
        counts = {}
        base = self.queryset
        for key, _label, statuses in self.STATUS_TABS:
            if statuses is None:
                counts[key] = base.count()
            else:
                counts[key] = base.filter(status__in=statuses).count()
        return counts
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
