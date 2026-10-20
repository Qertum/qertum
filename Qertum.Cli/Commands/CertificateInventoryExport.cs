using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>Collects the API's live inventory pages for CLI export.</summary>
internal static class CertificateInventoryExport
{
    internal static async Task<IReadOnlyList<CertificateInventoryItem>> CollectAsync(
        CertificateRequestsApiClient client, int pageSize = 500, CancellationToken cancellationToken = default)
    {
        pageSize = Math.Clamp(pageSize, 1, 500);
        var items = new List<CertificateInventoryItem>();
        for (var page = 1; ; page++)
        {
            var result = await client.GetCertificateInventoryAsync(page, pageSize, cancellationToken);
            items.AddRange(result.Items);
            if (result.Items.Count == 0 || page >= result.TotalPages) break;
        }
        return items;
    }
}
