"""
ResourceClassifier
==================

Maps provider-native resource type strings (``Microsoft.KeyVault/vaults``,
``AWS::S3::Bucket``, ``storage.googleapis.com/Bucket``) onto AuditGraph's
canonical :class:`ResourceType` + :class:`SensitivityLevel` enums.

Why this exists
---------------
The three major clouds each use a different resource-type vocabulary. We do
not want any of that cloud-specific vocabulary leaking into the risk engine,
the attack-path builder, the graph edges, or the PDF exports — they all work
in terms of the AuditGraph canonical enums.

Classification happens exactly once, at scan time, inside the discovery
pipeline. The result is written to the ``resources`` table via the
``type``/``sensitivity`` columns (see
``migrations/create_resources_table.sql``) and every downstream consumer
reads from there.

Design rules
------------
* No hardcoded strings anywhere below the maps — every branch uses the
  enum members directly.
* Lookups are **case-insensitive** because providers are inconsistent
  (``microsoft.keyvault/vaults`` vs ``Microsoft.KeyVault/vaults``).
* Unknown types default to ``(ResourceType.STORAGE, SensitivityLevel.LOW)``
  — low sensitivity so unknown types don't over-flag the audit, storage so
  they still land in a valid bucket.
"""

from __future__ import annotations

import logging
from typing import Mapping

from app.schemas.identity import ResourceType, SensitivityLevel


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Type-token helpers
# ---------------------------------------------------------------------------


def _normalize(token: str) -> str:
    """Return a canonicalized form of a provider type token.

    Normalization is intentionally simple: strip, lower, no fancy regex.
    Providers format these differently and we want matches to be forgiving
    without being wrong — a prefix / suffix match on the raw string is
    always safer than a regex that can misfire on user-supplied names.
    """
    if not isinstance(token, str):
        return ""
    return token.strip().lower()


# ---------------------------------------------------------------------------
# Provider → (canonical type, baseline sensitivity) maps
# ---------------------------------------------------------------------------


#: Azure Resource Manager type strings. Lowercased keys; all matches are
#: case-insensitive. Keep this list sorted by most-sensitive first so code
#: review can spot accidental downgrades.
AZURE_TYPE_MAP: Mapping[str, tuple[ResourceType, SensitivityLevel]] = {
    "microsoft.keyvault/vaults":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "microsoft.keyvault/vaults/secrets":
        (ResourceType.SECRET, SensitivityLevel.CRITICAL),
    "microsoft.keyvault/vaults/certificates":
        (ResourceType.CERTIFICATE_STORE, SensitivityLevel.HIGH),
    "microsoft.keyvault/vaults/keys":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "microsoft.authorization/roleassignments":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "microsoft.authorization/roledefinitions":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "microsoft.managedidentity/userassignedidentities":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "microsoft.storage/storageaccounts":
        (ResourceType.STORAGE, SensitivityLevel.HIGH),
    "microsoft.storage/storageaccounts/blobservices/containers":
        (ResourceType.STORAGE, SensitivityLevel.HIGH),
    "microsoft.dbforpostgresql/servers":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "microsoft.dbforpostgresql/flexibleservers":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "microsoft.dbformysql/servers":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "microsoft.sql/servers/databases":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "microsoft.documentdb/databaseaccounts":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
}

#: AWS type strings. Normalized to lowercase so matching is provider-agnostic.
AWS_TYPE_MAP: Mapping[str, tuple[ResourceType, SensitivityLevel]] = {
    "aws::kms::key":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "aws::kms::alias":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "aws::secretsmanager::secret":
        (ResourceType.SECRET, SensitivityLevel.CRITICAL),
    "aws::ssm::parameter":
        (ResourceType.SECRET, SensitivityLevel.HIGH),
    "aws::acm::certificate":
        (ResourceType.CERTIFICATE_STORE, SensitivityLevel.HIGH),
    "aws::acmpca::certificateauthority":
        (ResourceType.CERTIFICATE_STORE, SensitivityLevel.CRITICAL),
    "aws::iam::role":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "aws::iam::policy":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "aws::iam::user":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "aws::s3::bucket":
        (ResourceType.STORAGE, SensitivityLevel.HIGH),
    "aws::efs::filesystem":
        (ResourceType.STORAGE, SensitivityLevel.HIGH),
    "aws::rds::dbinstance":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "aws::rds::dbcluster":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "aws::dynamodb::table":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "aws::redshift::cluster":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
}

#: GCP type strings. GCP uses ``service.googleapis.com/Kind`` form.
GCP_TYPE_MAP: Mapping[str, tuple[ResourceType, SensitivityLevel]] = {
    "cloudkms.googleapis.com/cryptokey":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "cloudkms.googleapis.com/keyring":
        (ResourceType.KEY_VAULT, SensitivityLevel.CRITICAL),
    "secretmanager.googleapis.com/secret":
        (ResourceType.SECRET, SensitivityLevel.CRITICAL),
    "secretmanager.googleapis.com/secretversion":
        (ResourceType.SECRET, SensitivityLevel.CRITICAL),
    "privateca.googleapis.com/certificate":
        (ResourceType.CERTIFICATE_STORE, SensitivityLevel.HIGH),
    "privateca.googleapis.com/certificateauthority":
        (ResourceType.CERTIFICATE_STORE, SensitivityLevel.CRITICAL),
    "iam.googleapis.com/role":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "iam.googleapis.com/serviceaccount":
        (ResourceType.IAM_SYSTEM, SensitivityLevel.CRITICAL),
    "storage.googleapis.com/bucket":
        (ResourceType.STORAGE, SensitivityLevel.HIGH),
    "sqladmin.googleapis.com/instance":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "bigquery.googleapis.com/dataset":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "bigquery.googleapis.com/table":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "spanner.googleapis.com/instance":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
    "firestore.googleapis.com/database":
        (ResourceType.DATABASE, SensitivityLevel.HIGH),
}


#: Provider key → type map lookup. Declared after the individual maps so the
#: constants above remain the source of truth.
_PROVIDER_MAPS: Mapping[str, Mapping[str, tuple[ResourceType, SensitivityLevel]]] = {
    "azure": AZURE_TYPE_MAP,
    "aws": AWS_TYPE_MAP,
    "gcp": GCP_TYPE_MAP,
}


#: Baseline sensitivity per canonical ResourceType. Used by
#: :meth:`ResourceClassifier.is_sensitive` so callers can ask "is this
#: category intrinsically sensitive?" without knowing the specific row.
_TYPE_BASELINE_SENSITIVITY: Mapping[ResourceType, SensitivityLevel] = {
    ResourceType.KEY_VAULT: SensitivityLevel.CRITICAL,
    ResourceType.SECRET: SensitivityLevel.CRITICAL,
    ResourceType.IAM_SYSTEM: SensitivityLevel.CRITICAL,
    ResourceType.DATABASE: SensitivityLevel.HIGH,
    ResourceType.CERTIFICATE_STORE: SensitivityLevel.HIGH,
    ResourceType.STORAGE: SensitivityLevel.HIGH,
}


#: Safe fallback — low sensitivity so unknown types don't over-flag the
#: audit, storage so they still sit in a valid classification bucket.
DEFAULT_CLASSIFICATION: tuple[ResourceType, SensitivityLevel] = (
    ResourceType.STORAGE,
    SensitivityLevel.LOW,
)


#: Sensitivity levels that count as "sensitive" for blast radius / CISO
#: dashboards. Medium / Low are explicitly excluded.
_SENSITIVE_LEVELS: frozenset[SensitivityLevel] = frozenset(
    {SensitivityLevel.CRITICAL, SensitivityLevel.HIGH}
)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class ResourceClassifier:
    """Classifies cloud resources into typed (ResourceType, SensitivityLevel).

    The classifier is stateless and pure — safe to instantiate once per
    process, per scan, or per call. No I/O, no DB access, no hidden state.
    """

    def classify(
        self,
        cloud_provider: str,
        resource_type_string: str,
    ) -> tuple[ResourceType, SensitivityLevel]:
        """Map a provider-native type string to the canonical classification.

        Parameters
        ----------
        cloud_provider:
            One of ``"azure"``, ``"aws"``, ``"gcp"``. Case-insensitive.
        resource_type_string:
            The provider-native resource type (e.g.
            ``"Microsoft.KeyVault/vaults"``, ``"AWS::S3::Bucket"``,
            ``"storage.googleapis.com/Bucket"``). Case-insensitive.

        Returns
        -------
        tuple[ResourceType, SensitivityLevel]
            The canonical classification, or
            :data:`DEFAULT_CLASSIFICATION` for unknown combinations.

        Notes
        -----
        An unknown ``cloud_provider`` or an empty type string both map to
        the default — we log a DEBUG line so downstream telemetry can
        track how often the classifier sees types it cannot recognize.
        """
        provider_key = _normalize(cloud_provider)
        type_key = _normalize(resource_type_string)

        if not provider_key or not type_key:
            logger.debug(
                "resource_classifier.empty_input provider=%r type=%r",
                cloud_provider,
                resource_type_string,
            )
            return DEFAULT_CLASSIFICATION

        provider_map = _PROVIDER_MAPS.get(provider_key)
        if provider_map is None:
            logger.debug(
                "resource_classifier.unknown_provider provider=%r type=%r",
                cloud_provider,
                resource_type_string,
            )
            return DEFAULT_CLASSIFICATION

        hit = provider_map.get(type_key)
        if hit is not None:
            return hit

        # Prefix fallback — providers often suffix the type with a sub-kind
        # the table doesn't list (e.g. ``microsoft.sql/servers/databases/
        # schemas``). Walk the known keys and return the longest prefix
        # match, which ensures specific mappings still win over generic
        # ones (``keyvault/vaults/secrets`` beats ``keyvault/vaults``).
        longest_prefix_hit: tuple[ResourceType, SensitivityLevel] | None = None
        longest_prefix_len = 0
        for candidate_key, candidate_value in provider_map.items():
            if type_key.startswith(candidate_key) and len(candidate_key) > longest_prefix_len:
                longest_prefix_hit = candidate_value
                longest_prefix_len = len(candidate_key)

        if longest_prefix_hit is not None:
            return longest_prefix_hit

        logger.debug(
            "resource_classifier.unknown_type provider=%s type=%s",
            provider_key,
            type_key,
        )
        return DEFAULT_CLASSIFICATION

    def is_sensitive(self, resource_type: ResourceType) -> bool:
        """True for categories whose baseline sensitivity is Critical or High.

        Parameters
        ----------
        resource_type:
            A canonical :class:`ResourceType`.

        Returns
        -------
        bool
            ``True`` if the category is intrinsically Critical or High
            sensitivity; ``False`` otherwise.

        Raises
        ------
        TypeError
            If ``resource_type`` is not a :class:`ResourceType` instance.
            Callers must pass an enum member — strings are rejected to
            avoid silent typos slipping into dashboards.
        """
        if not isinstance(resource_type, ResourceType):
            raise TypeError(
                f"resource_type must be ResourceType, got {type(resource_type).__name__}"
            )
        baseline = _TYPE_BASELINE_SENSITIVITY.get(resource_type)
        if baseline is None:
            # An enum member we never classified — defensive fallback.
            return False
        return baseline in _SENSITIVE_LEVELS
