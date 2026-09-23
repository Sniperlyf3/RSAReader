namespace RSAReader;
public static class IdDecoder
{
    public static string Decode(string id)
    {
        if (id.Length != 13 || !id.All(char.IsAsciiDigit)) return "Enter exactly 13 digits.";
        var sum = 0;
        for (var i = 0; i < 13; i++)
        {
            var digit = id[12 - i] - '0';
            if (i % 2 == 1) { digit *= 2; if (digit > 9) digit -= 9; }
            sum += digit;
        }
        if (sum % 10 != 0) return "Invalid checksum. Check the ID number.";
        var year = int.Parse(id[..2]);
        var month = int.Parse(id.Substring(2, 2));
        var day = int.Parse(id.Substring(4, 2));
        var now = DateTime.Today;
        var candidates = new[] { 1900 + year, 2000 + year }
            .Select(y => new { Year = y, Valid = DateTime.TryParseExact($"{y:D4}-{month:D2}-{day:D2}", "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out var date) && date <= now })
            .Where(x => x.Valid).Select(x => x.Year).ToArray();
        if (candidates.Length == 0) return "Invalid date of birth.";
        var genderCode = int.Parse(id.Substring(6, 4));
        var gender = genderCode >= 5000 ? "Male (encoded)" : "Female (encoded)";
        var birth = string.Join(" or ", candidates.Select(y => $"{y:D4}-{month:D2}-{day:D2}"));
        return $"Checksum: valid\nPossible date(s) of birth: {birth}\nGender marker: {gender}\n" +
               "Birth century cannot be established reliably from the number alone. " +
               "A valid checksum does not establish that the ID or its holder is authentic.";
    }
}