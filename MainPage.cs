using System.Text;
#if ANDROID
using Android.Nfc;
#endif

namespace RSAReader;

public sealed class MainPage : ContentPage
{
    private readonly Label _status = new() { Text = "Ready to scan", FontAttributes = FontAttributes.Bold };
    private readonly Label _scan = new() { Text = "Hold your Smart ID against the phone. NFC data will not be saved.", LineBreakMode = LineBreakMode.WordWrap };
    private readonly Entry _idInput = new() { Placeholder = "13-digit ID number", Keyboard = Keyboard.Numeric, MaxLength = 13, IsPassword = true };
    private readonly Label _decoded = new() { Text = "Nothing decoded yet." };
#if ANDROID
    private NfcAdapter? _adapter;
    private readonly NfcAdapter.IReaderCallback _reader;
#endif

    public MainPage()
    {
        Title = "RSAReader";
#if ANDROID
        _reader = new CardReader(this);
#endif
        var decode = new Button { Text = "Decode entered ID number" };
        decode.Clicked += (_, _) => _decoded.Text = IdDecoder.Decode(_idInput.Text ?? "");
        var clear = new Button { Text = "Clear displayed information" };
        clear.Clicked += (_, _) => { _idInput.Text = ""; _decoded.Text = "Nothing decoded yet."; _scan.Text = "Ready to scan."; };

        Content = new ScrollView { Content = new VerticalStackLayout
        {
            Padding = new Thickness(20), Spacing = 14,
            Children = {
                new Label { Text = "NFC scan", FontSize = 24, FontAttributes = FontAttributes.Bold },
                _status, _scan,
                new Label { Text = "Manual fallback: SA ID number", FontSize = 20, FontAttributes = FontAttributes.Bold },
                new Label { Text = "This derives limited information from an ID number. It does not authenticate identity or read protected chip data." },
                _idInput, decode, _decoded, clear
            }
        }};
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
#if ANDROID
        try
        {
            var activity = Platform.CurrentActivity;
            _adapter = NfcAdapter.GetDefaultAdapter(Android.App.Application.Context);
            if (_adapter is null) { _status.Text = "This phone does not support NFC."; return; }
            if (!_adapter.IsEnabled) { _status.Text = "Enable NFC in Android settings."; return; }
            if (activity is null) { _status.Text = "NFC ready. Open this page again to start scanning."; return; }

            _status.Text = "NFC ready. Tap your card.";
            _adapter.EnableReaderMode(activity, _reader,
                NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck, null);
        }
        catch (Exception ex)
        {
            // NFC initialization must never prevent the app itself from opening.
            _status.Text = "NFC initialization failed.";
            _scan.Text = ex.Message;
        }
#endif
    }

    protected override void OnDisappearing()
    {
#if ANDROID
        if (_adapter != null && Platform.CurrentActivity != null)
            _adapter.DisableReaderMode(Platform.CurrentActivity);
#endif
        base.OnDisappearing();
    }

#if ANDROID
    private sealed class CardReader : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        private readonly MainPage _page;
        public CardReader(MainPage page) => _page = page;

        public void OnTagDiscovered(Tag? tag)
        {
            if (tag is null) return;
            var technologies = tag.GetTechList() ?? Array.Empty<string>();
            var isoDep = Android.Nfc.Tech.IsoDep.Get(tag);
            var details = new StringBuilder("Card detected.\nSupported technologies:\n");
            foreach (var technology in technologies) details.AppendLine("• " + technology);
            details.AppendLine(isoDep is null
                ? "ISO-DEP: unavailable. This app cannot exchange ISO-7816 APDUs with this tag."
                : $"ISO-DEP: available. Max transceive length: {isoDep.MaxTransceiveLength} bytes.");

            MainThread.BeginInvokeOnMainThread(() =>
            {
                _page._status.Text = "Card detected";
                _page._scan.Text = details.ToString();
            });
        }
    }
#endif
}