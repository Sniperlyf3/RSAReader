using System.Text;
#if ANDROID
using Android.Nfc;
using Android.Nfc.Tech;
#endif

namespace RSAReader;

public sealed class MainPage : ContentPage
{
    private readonly Label _status = new() { Text = "Ready to scan", FontAttributes = FontAttributes.Bold };
    private readonly Label _scan = new()
    {
        Text = "Hold a Smart ID against the phone. The app does not save card data.",
        LineBreakMode = LineBreakMode.WordWrap
    };
    private readonly Entry _apduInput = new()
    {
        Placeholder = "APDU hex, e.g. 00 A4 00 00 02 3F 00"
    };
    private readonly Label _apduOutput = new()
    {
        Text = "No command sent.",
        LineBreakMode = LineBreakMode.WordWrap
    };
    private readonly Entry _idInput = new()
    {
        Placeholder = "13-digit ID number",
        Keyboard = Keyboard.Numeric,
        MaxLength = 13,
        IsPassword = true
    };
    private readonly Label _decoded = new() { Text = "Nothing decoded yet.", LineBreakMode = LineBreakMode.WordWrap };

#if ANDROID
    private NfcAdapter? _adapter;
    private readonly NfcAdapter.IReaderCallback _reader;
    private IsoDep? _isoDep;
#endif

    public MainPage()
    {
        Title = "RSAReader";
#if ANDROID
        _reader = new CardReader(this);
#endif

        var sendApdu = new Button { Text = "Send allowed APDU" };
        sendApdu.Clicked += async (_, _) => await SendApduAsync(sendApdu);
        var decode = new Button { Text = "Decode entered ID number" };
        decode.Clicked += (_, _) => _decoded.Text = IdDecoder.Decode(_idInput.Text ?? "");
        var clear = new Button { Text = "Clear displayed information" };
        clear.Clicked += (_, _) =>
        {
            _idInput.Text = "";
            _decoded.Text = "Nothing decoded yet.";
            _apduInput.Text = "";
            _apduOutput.Text = "No command sent.";
            _scan.Text = "Hold a Smart ID against the phone. The app does not save card data.";
            _status.Text = "Ready to scan";
#if ANDROID
            _isoDep = null;
#endif
        };

        Content = new ScrollView
        {
            Content = new VerticalStackLayout
            {
                Padding = new Thickness(20),
                Spacing = 14,
                Children =
                {
                    new Label { Text = "NFC scan", FontSize = 24, FontAttributes = FontAttributes.Bold },
                    _status,
                    _scan,
                    new Label { Text = "APDU probe", FontSize = 20, FontAttributes = FontAttributes.Bold },
                    new Label
                    {
                        Text = "Commands are sent only when you tap the button. Only SELECT, READ BINARY, GET DATA, GET CHALLENGE, and GET RESPONSE instruction bytes are allowed. Responses may contain personal data and are shown only on this screen.",
                        LineBreakMode = LineBreakMode.WordWrap
                    },
                    _apduInput,
                    sendApdu,
                    _apduOutput,
                    new Label { Text = "Manual fallback: SA ID number", FontSize = 20, FontAttributes = FontAttributes.Bold },
                    new Label
                    {
                        Text = "This derives limited information from an ID number. It does not authenticate identity or read protected chip data.",
                        LineBreakMode = LineBreakMode.WordWrap
                    },
                    _idInput,
                    decode,
                    _decoded,
                    clear
                }
            }
        };
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
#if ANDROID
        try
        {
            var activity = Platform.CurrentActivity;
            _adapter = NfcAdapter.GetDefaultAdapter(Android.App.Application.Context);
            if (_adapter is null)
            {
                _status.Text = "This phone does not support NFC. The ID-number decoder is still available.";
                return;
            }
            if (!_adapter.IsEnabled)
            {
                _status.Text = "Enable NFC in Android settings.";
                return;
            }
            if (activity is null)
            {
                _status.Text = "NFC is ready. Reopen this page to start scanning.";
                return;
            }

            _status.Text = "NFC ready. Tap your card.";
            _adapter.EnableReaderMode(activity, _reader,
                NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck, null);
        }
        catch (Exception ex)
        {
            // NFC initialization must never prevent the app itself from opening.
            _status.Text = "NFC initialization failed; the decoder remains available.";
            _scan.Text = ex.Message;
        }
#endif
    }

    protected override void OnDisappearing()
    {
#if ANDROID
        if (_adapter is not null && Platform.CurrentActivity is { } activity)
        {
            try { _adapter.DisableReaderMode(activity); }
            catch (Exception) { /* The activity may already be stopping. */ }
        }
        _isoDep = null;
#endif
        base.OnDisappearing();
    }

    private async Task SendApduAsync(Button sendButton)
    {
#if ANDROID
        if (_isoDep is null)
        {
            _apduOutput.Text = "Scan an ISO-DEP card first.";
            return;
        }
        if (!TryParseReadOnlyApdu(_apduInput.Text ?? "", out var command, out var error))
        {
            _apduOutput.Text = error;
            return;
        }

        var card = _isoDep;
        sendButton.IsEnabled = false;
        _apduOutput.Text = "Waiting for card…";
        try
        {
            var response = await Task.Run(() => Transceive(card, command));
            if (response.Length < 2)
            {
                _apduOutput.Text = $"Malformed response ({response.Length} bytes): {Convert.ToHexString(response)}";
                return;
            }

            var data = response.AsSpan(0, response.Length - 2).ToArray();
            var sw1 = response[^2];
            var sw2 = response[^1];
            var text = new StringBuilder();
            text.AppendLine($"TX: {Convert.ToHexString(command)}");
            text.AppendLine($"RX data ({data.Length} bytes): {Convert.ToHexString(data)}");
            text.AppendLine($"Status word: {sw1:X2}{sw2:X2} ({DescribeStatusWord(sw1, sw2)})");
            _apduOutput.Text = text.ToString();
        }
        catch (Exception ex)
        {
            _apduOutput.Text = $"APDU failed: {ex.GetType().Name}: {ex.Message}";
        }
        finally
        {
            sendButton.IsEnabled = true;
        }
#else
        _apduOutput.Text = "NFC/APDU communication is available on Android only.";
#endif
    }

#if ANDROID
    private static byte[] Transceive(IsoDep isoDep, byte[] command)
    {
        isoDep.Timeout = 5000;
        try
        {
            isoDep.Connect();
            if (!isoDep.IsConnected) throw new IOException("Could not connect to the card.");
            if (command.Length > isoDep.MaxTransceiveLength)
                throw new ArgumentException($"Command exceeds the card limit of {isoDep.MaxTransceiveLength} bytes.");
            return isoDep.Transceive(command) ?? throw new IOException("Card returned no response.");
        }
        finally
        {
            if (isoDep.IsConnected) isoDep.Close();
        }
    }

    private static bool TryParseReadOnlyApdu(string input, out byte[] command, out string error)
    {
        command = Array.Empty<byte>();
        error = "Enter a valid short APDU as hexadecimal bytes.";
        var hex = new string(input.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length < 8 || hex.Length % 2 != 0 || input.Any(c => !Uri.IsHexDigit(c) && !char.IsWhiteSpace(c) && c != ':' && c != '-'))
            return false;

        try
        {
            command = Convert.FromHexString(hex);
        }
        catch (System.FormatException)
        {
            return false;
        }

        var instruction = command[1];
        if (instruction is not (0xA4 or 0xB0 or 0xB1 or 0xCA or 0x84 or 0xC0))
        {
            error = $"INS {instruction:X2} is not allowed. Allowed: A4, B0, B1, CA, 84, C0.";
            command = Array.Empty<byte>();
            return false;
        }

        // Accept ISO 7816 short APDU cases 1, 2, 3 and 4. Extended APDUs are not supported.
        if (command.Length == 4 || command.Length == 5) return true;
        var lc = command[4];
        if (lc == 0 || (command.Length != 5 + lc && command.Length != 6 + lc))
        {
            error = "APDU length does not match its short Lc field; extended APDUs are not supported.";
            command = Array.Empty<byte>();
            return false;
        }
        return true;
    }

    private static string DescribeStatusWord(byte sw1, byte sw2) => (sw1, sw2) switch
    {
        (0x90, 0x00) => "success",
        (0x61, _) => $"more response bytes available ({sw2:X2} indicated)",
        (0x6A, 0x82) => "file or application not found",
        (0x69, 0x82) => "security status not satisfied",
        (0x6D, 0x00) => "instruction not supported",
        (0x6E, 0x00) => "class not supported",
        _ => "card-specific or ISO 7816 status"
    };

    private sealed class CardReader : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        private readonly MainPage _page;
        public CardReader(MainPage page) => _page = page;

        public void OnTagDiscovered(Tag? tag)
        {
            if (tag is null) return;
            var technologies = tag.GetTechList() ?? Array.Empty<string>();
            var isoDep = IsoDep.Get(tag);
            var details = new StringBuilder("Card detected.\nSupported technologies:\n");
            foreach (var technology in technologies) details.AppendLine("• " + technology);
            details.AppendLine(isoDep is null
                ? "ISO-DEP: unavailable. This card cannot exchange ISO 7816 APDUs through this app."
                : $"ISO-DEP: available. Max transceive length: {isoDep.MaxTransceiveLength} bytes.");
            if (isoDep is not null)
            {
                var historicalBytes = isoDep.GetHistoricalBytes();
                if (historicalBytes is { Length: > 0 })
                    details.AppendLine($"ISO-DEP historical bytes (NFC-A): {Convert.ToHexString(historicalBytes)}");
                var hiLayerResponse = isoDep.GetHiLayerResponse();
                if (hiLayerResponse is { Length: > 0 })
                    details.AppendLine($"ISO-DEP higher-layer response (NFC-B): {Convert.ToHexString(hiLayerResponse)}");
            }

            MainThread.BeginInvokeOnMainThread(() =>
            {
                _page._isoDep = isoDep;
                _page._status.Text = "Card detected. APDUs are not sent automatically.";
                _page._scan.Text = details.ToString();
            });
        }
    }
#endif
}
