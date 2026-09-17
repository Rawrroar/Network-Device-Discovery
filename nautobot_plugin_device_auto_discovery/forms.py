"""UI forms for the Device Auto-Discovery plugin."""

import json

from django import forms
from nautobot.apps.forms import NautobotBulkEditForm, NautobotFilterForm, NautobotModelForm

from nautobot_plugin_device_auto_discovery import models


class CommaSeparatedListField(forms.CharField):
    """A CharField that accepts comma-separated (or newline-separated) values.

    Backs the JSON-list model fields (prefixes, protocols, domain suffixes,
    IP scopes) so users can type ``192.168.1.0/24, 10.0.0.0/8`` instead of
    strict JSON. Already-JSON input (``["a", "b"]``) is also accepted, as is
    a leading/trailing-bracket shorthand like ``['192.168.1.0/24']``.

    Returns a Python list suitable for direct assignment to the JSONField.
    """

    def to_python(self, value):
        if value in (None, ""):
            return []
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        text = str(value).strip()
        if not text:
            return []
        # Accept strict JSON arrays and the common "['a', 'b']" shorthand.
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, (list, tuple)):
                    return [str(item).strip() for item in parsed if str(item).strip()]
            except json.JSONDecodeError:
                # Fall through to plain comma-splitting.
                pass
        # Not valid JSON: accept a bracket/quote-wrapped shorthand like
        # "['192.168.1.0/24']" before falling back to comma-splitting.
        candidate = text.strip()
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        items = []
        for chunk in candidate.replace("\n", ",").split(","):
            item = chunk.strip().strip("'\"").strip()
            if item:
                items.append(item)
        return items

    def prepare_value(self, value):
        """Render the stored list back as comma-separated text for editing."""
        if value in (None, ""):
            return ""
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value)
        return str(value)


class PrefixListField(CommaSeparatedListField):
    """Comma-separated list validated as CIDR prefixes."""

    def clean(self, value):
        items = super().clean(value)
        import ipaddress

        errors = []
        for item in items:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                errors.append(f"{item!r} is not a valid prefix ({exc})")
        if errors:
            raise forms.ValidationError(errors)
        return items


# ---------------------------------------------------------------------------
# Model forms
# ---------------------------------------------------------------------------


class DiscoveryProfileForm(NautobotModelForm):
    included_ip_prefixes = PrefixListField(
        required=False,
        help_text=(
            "Comma-separated list of CIDR prefixes to scan, e.g. 192.168.1.0/24, 10.0.0.0/8. "
            "Also accepts JSON (e.g. [\"192.168.1.0/24\"])."
        ),
    )
    excluded_ip_prefixes = PrefixListField(
        required=False,
        help_text="Comma-separated list of CIDR prefixes to skip.",
    )
    protocols = CommaSeparatedListField(
        required=False,
        help_text="Comma-separated protocols: ping, snmp, ssh.",
    )
    strip_domain_suffixes = CommaSeparatedListField(
        required=False,
        help_text="Comma-separated domain suffixes stripped from discovered hostnames, e.g. example.com, corp.local.",
    )

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
    ip_scope = PrefixListField(
        required=False,
        help_text="Comma-separated list of CIDR prefixes restricting this rule, e.g. 10.50.0.0/16.",
    )

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
            ("sync", "Sync"),
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
