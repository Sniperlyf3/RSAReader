using RSAReader.Research;

namespace RSAReader;

// The report is kept in memory. Import and copy use only the redacted schema.
public sealed class ResearchPage : ContentPage
{
    private readonly Label _summary = new() { LineBreakMode = LineBreakMode.WordWrap };
    private Pkcs15Report? _current;

    public ResearchPage(Pkcs15Report? report)
    {
        Title = "PKCS#15 research";
        _current = report;
        _summary.Text = report?.Summary() ?? "Run a PACE/CAN read first, then return here. You can also open a redacted report from another scan.";

        var copy = new Button { Text = "Copy redacted JSON report" };
        copy.Clicked += async (_, _) =>
        {
            if (_current is null) return;
            await Clipboard.Default.SetTextAsync(_current.ToJson());
            copy.Text = "Copied redacted report";
        };
        var open = new Button { Text = "Open redacted report and compare" };
        open.Clicked += async (_, _) =>
        {
            try
            {
                var file = await FilePicker.Default.PickAsync(new PickOptions { PickerTitle = "Choose a redacted RSAReader JSON report" });
                if (file is null) return;
                await using var stream = await file.OpenReadAsync();
                using var reader = new StreamReader(stream);
                var prior = Pkcs15Report.FromJson(await reader.ReadToEndAsync());
                if (prior.SchemaVersion != 1) throw new FormatException("Unsupported report schema.");
                _summary.Text = (_current?.Summary() ?? prior.Summary()) + "\n\nComparison: " +
                    (_current is null ? "This report is loaded for replay. Scan a card to compare." : _current.Compare(prior));
                if (_current is null) _current = prior;
            }
            catch (Exception ex) { _summary.Text = $"Could not open report: {ex.Message}"; }
        };
        Content = new ScrollView
        {
            Content = new VerticalStackLayout
            {
                Padding = new Thickness(20), Spacing = 12,
                Children =
                {
                    new Label { Text = "Read-only research", FontSize = 24, FontAttributes = FontAttributes.Bold },
                    new Label { Text = "Directory metadata, certificate extensions, and key fingerprints are shown here. Names, ID numbers, certificate serials, CAN, data-object values, and raw APDUs are excluded from copied reports." },
                    copy, open, _summary
                }
            }
        };
    }
}
