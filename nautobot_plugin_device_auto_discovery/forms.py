"""UI forms for the Device Auto-Discovery plugin."""

from django import forms
from nautobot.apps.forms import NautobotBulkEditForm, NautobotFilterForm, NautobotModelForm

from nautobot_plugin_device_auto_discovery import models


# ---------------------------------------------------------------------------
# Model forms
# ---------------------------------------------------------------------------


class DiscoveryProfileForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveryProfile
        fields = "__all__"


class DiscoveryScanForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveryScan
        fields = "__all__"


class DiscoveryResultForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveryResult
        fields = "__all__"


class DiscoveredDeviceForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveredDevice
        fields = "__all__"


class DiscoveryProfileSecretsGroupAssignmentForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveryProfileSecretsGroupAssignment
        fields = "__all__"


class DeviceClassificationRuleForm(NautobotModelForm):
    class Meta:
        model = models.DeviceClassificationRule
        fields = "__all__"


class DiscoveredDeviceClassificationForm(NautobotModelForm):
    class Meta:
        model = models.DiscoveredDeviceClassification
        fields = "__all__"


# ---------------------------------------------------------------------------
# Filter forms (sidebar)
# ---------------------------------------------------------------------------


class DiscoveryProfileFilterForm(NautobotFilterForm):
    model = models.DiscoveryProfile
    q = forms.CharField(required=False, label="Search")
    status = forms.ChoiceField(
        choices=[("active", "Active"), ("inactive", "Inactive")],
        required=False,
        label="Status",
    )


class DiscoveryScanFilterForm(NautobotFilterForm):
    model = models.DiscoveryScan
    q = forms.CharField(required=False, label="Search")
    scan_method = forms.ChoiceField(
        choices=[
            ("ping", "Ping"),
            ("snmp", "SNMP"),
            ("ssh", "SSH"),
            ("full", "Full"),
            ("crawl", "Crawl"),
            ("vrf", "VRF"),
        ],
        required=False,
        label="Method",
    )
    status = forms.ChoiceField(
        choices=[("pending", "Pending"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")],
        required=False,
        label="Status",
    )


class DiscoveryResultFilterForm(NautobotFilterForm):
    model = models.DiscoveryResult
    q = forms.CharField(required=False, label="Search")
    result_status = forms.ChoiceField(
        choices=[
            ("imported", "Imported"),
            ("new", "New"),
            ("partially_imported", "Partially Imported"),
            ("conflict", "Conflict"),
            ("not_reachable", "Not Reachable"),
            ("failed", "Failed"),
        ],
        required=False,
        label="Status",
    )
    discovery_method = forms.ChoiceField(
        choices=[("snmp", "SNMP"), ("ssh", "SSH"), ("ping", "Ping")],
        required=False,
        label="Method",
    )


class DiscoveredDeviceFilterForm(NautobotFilterForm):
    model = models.DiscoveredDevice
    q = forms.CharField(required=False, label="Search")
    status = forms.ChoiceField(
        choices=[
            ("imported", "Imported"),
            ("new", "New"),
            ("partially_imported", "Partially Imported"),
            ("conflict", "Conflict"),
            ("not_reachable", "Not Reachable"),
            ("failed", "Failed"),
        ],
        required=False,
        label="Correlation",
    )


class DeviceClassificationRuleFilterForm(NautobotFilterForm):
    model = models.DeviceClassificationRule
    q = forms.CharField(required=False, label="Search")
    classify_as = forms.ChoiceField(
        choices=[
            ("location", "Location"),
            ("role", "Role"),
            ("tenant", "Tenant"),
        ],
        required=False,
        label="Classify As",
    )
    is_active = forms.NullBooleanField(required=False, label="Active")


class DiscoveredDeviceClassificationFilterForm(NautobotFilterForm):
    model = models.DiscoveredDeviceClassification
    q = forms.CharField(required=False, label="Search")
    classify_as = forms.ChoiceField(
        choices=[
            ("location", "Location"),
            ("role", "Role"),
            ("tenant", "Tenant"),
        ],
        required=False,
        label="Classify As",
    )


# ---------------------------------------------------------------------------
# Bulk edit forms
# ---------------------------------------------------------------------------


class DiscoveryProfileBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveryProfile.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveryProfile
        fields = ["status"]


class DiscoveryScanBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveryScan.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveryScan
        fields = ["status"]


class DiscoveryResultBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveryResult.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveryResult
        fields = ["result_status"]


class DiscoveredDeviceBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveredDevice.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveredDevice
        fields = ["status"]


class DiscoveryProfileSecretsGroupAssignmentBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveryProfileSecretsGroupAssignment.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveryProfileSecretsGroupAssignment
        fields = ["weight"]


class DeviceClassificationRuleBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DeviceClassificationRule.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DeviceClassificationRule
        fields = ["weight", "is_active"]


class DiscoveredDeviceClassificationBulkEditForm(NautobotBulkEditForm):
    pk = forms.ModelMultipleChoiceField(
        queryset=models.DiscoveredDeviceClassification.objects.all(),
        widget=forms.MultipleHiddenInput(),
    )

    class Meta:
        model = models.DiscoveredDeviceClassification
        fields = []
