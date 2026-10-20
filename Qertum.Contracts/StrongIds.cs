using System.Text.Json;
using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Strongly-typed identifier for a <see cref="CertificateRequest"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(CertificateRequestIdJsonConverter))]
public readonly record struct CertificateRequestId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator CertificateRequestId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(CertificateRequestId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>Strongly-typed identifier for a <see cref="CertificateTemplate"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(CertificateTemplateIdJsonConverter))]
public readonly record struct CertificateTemplateId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator CertificateTemplateId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(CertificateTemplateId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="CertificateRequestId"/> as a plain GUID string.</summary>
public sealed class CertificateRequestIdJsonConverter : JsonConverter<CertificateRequestId>
{
    /// <inheritdoc />
    public override CertificateRequestId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, CertificateRequestId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>JSON converter that serializes <see cref="CertificateTemplateId"/> as a plain GUID string.</summary>
public sealed class CertificateTemplateIdJsonConverter : JsonConverter<CertificateTemplateId>
{
    /// <inheritdoc />
    public override CertificateTemplateId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, CertificateTemplateId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="Webhook"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(WebhookIdJsonConverter))]
public readonly record struct WebhookId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator WebhookId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(WebhookId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="WebhookId"/> as a plain GUID string.</summary>
public sealed class WebhookIdJsonConverter : JsonConverter<WebhookId>
{
    /// <inheritdoc />
    public override WebhookId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, WebhookId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for an <see cref="IssuancePolicy"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(IssuancePolicyIdJsonConverter))]
public readonly record struct IssuancePolicyId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator IssuancePolicyId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(IssuancePolicyId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="IssuancePolicyId"/> as a plain GUID string.</summary>
public sealed class IssuancePolicyIdJsonConverter : JsonConverter<IssuancePolicyId>
{
    /// <inheritdoc />
    public override IssuancePolicyId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, IssuancePolicyId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="BackgroundJob"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(BackgroundJobIdJsonConverter))]
public readonly record struct BackgroundJobId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator BackgroundJobId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(BackgroundJobId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="BackgroundJobId"/> as a plain GUID string.</summary>
public sealed class BackgroundJobIdJsonConverter : JsonConverter<BackgroundJobId>
{
    /// <inheritdoc />
    public override BackgroundJobId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, BackgroundJobId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}
/// <summary>Strongly-typed identifier for an <see cref="Issuer"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(IssuerIdJsonConverter))]
public readonly record struct IssuerId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator IssuerId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(IssuerId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="IssuerId"/> as a plain GUID string.</summary>
public sealed class IssuerIdJsonConverter : JsonConverter<IssuerId>
{
    /// <inheritdoc />
    public override IssuerId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, IssuerId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="PqcException"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(PqcExceptionIdJsonConverter))]
public readonly record struct PqcExceptionId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator PqcExceptionId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(PqcExceptionId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="PqcExceptionId"/> as a plain GUID string.</summary>
public sealed class PqcExceptionIdJsonConverter : JsonConverter<PqcExceptionId>
{
    /// <inheritdoc />
    public override PqcExceptionId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, PqcExceptionId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="BulkOperation"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(BulkOperationIdJsonConverter))]
public readonly record struct BulkOperationId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator BulkOperationId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(BulkOperationId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="BulkOperationId"/> as a plain GUID string.</summary>
public sealed class BulkOperationIdJsonConverter : JsonConverter<BulkOperationId>
{
    /// <inheritdoc />
    public override BulkOperationId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, BulkOperationId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for an <see cref="ApprovalRequest"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(ApprovalRequestIdJsonConverter))]
public readonly record struct ApprovalRequestId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator ApprovalRequestId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(ApprovalRequestId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="ApprovalRequestId"/> as a plain GUID string.</summary>
public sealed class ApprovalRequestIdJsonConverter : JsonConverter<ApprovalRequestId>
{
    /// <inheritdoc />
    public override ApprovalRequestId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, ApprovalRequestId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="Notice"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(NoticeIdJsonConverter))]
public readonly record struct NoticeId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator NoticeId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(NoticeId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="NoticeId"/> as a plain GUID string.</summary>
public sealed class NoticeIdJsonConverter : JsonConverter<NoticeId>
{
    /// <inheritdoc />
    public override NoticeId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, NoticeId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}

/// <summary>Strongly-typed identifier for a <see cref="CertificateNote"/>. Serializes as a plain GUID string.</summary>
[JsonConverter(typeof(NoteIdJsonConverter))]
public readonly record struct NoteId(Guid Value)
{
    /// <summary>Implicit conversion from <see cref="Guid"/>.</summary>
    public static implicit operator NoteId(Guid value) => new(value);

    /// <summary>Implicit conversion to <see cref="Guid"/>.</summary>
    public static implicit operator Guid(NoteId id) => id.Value;

    /// <inheritdoc />
    public override string ToString() => Value.ToString();
}

/// <summary>JSON converter that serializes <see cref="NoteId"/> as a plain GUID string.</summary>
public sealed class NoteIdJsonConverter : JsonConverter<NoteId>
{
    /// <inheritdoc />
    public override NoteId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => new(reader.GetGuid());

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, NoteId value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.Value);
}
