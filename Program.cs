// EntraDpapiDecrypt - DPAPI recovery for Entra ID-joined Windows hosts.
// Given a password, unlocks CloudAP CacheData, unwraps matching master keys,
// and decrypts Credential Manager blobs. File-system only, does not touch LSASS.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace EntraDpapiDecrypt;

internal static class Calg
{
    public const uint SHA1   = 0x8004;
    public const uint SHA256 = 0x800c;
    public const uint SHA512 = 0x800e;
    public const uint TDES   = 0x6603;
    public const uint AES128 = 0x660e;
    public const uint AES192 = 0x660f;
    public const uint AES256 = 0x6610;
}

internal static class Program
{
    private static bool _verbose;
    private static bool _fileMode;

    private static int Main(string[] args)
    {
        if (!TryParseArgs(args, out IList<string> passwords, out string passwordFile, out string usernameFilter))
            return 1;

        try
        {
            PrintHeader(passwords, passwordFile, usernameFilter);
            var users          = UserEnumerator.EnumerateUsers();
            var cacheDataFiles = CacheDataLocator.FindAllCacheData();

            if (!string.IsNullOrEmpty(usernameFilter))
            {
                users = users
                    .Where(u => u.Username.Equals(usernameFilter, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                if (users.Count == 0)
                {
                    Console.WriteLine($"[!] FATAL: no profile found for username '{usernameFilter}'");
                    return 1;
                }
            }

            PrintDiscovery(users, cacheDataFiles, usernameFilter);

            var report = new RunReport();
            var passwordKeys = DerivePasswordKeys(passwords);
            foreach (var user in users)
            {
                var cacheForUser = string.IsNullOrEmpty(usernameFilter)
                    ? cacheDataFiles
                    : FilterCacheDataForUser(cacheDataFiles, user);
                ProcessUser(user, passwordKeys, cacheForUser, report);
            }

            Console.WriteLine();
            Console.WriteLine($"[*] Done. Recovered {report.MksUnlocked} master keys, {report.CredsRecovered} credentials.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] FATAL: {ex.GetType().Name}: {ex.Message}");
            if (_verbose) Console.WriteLine(ex.StackTrace);
            return 2;
        }
    }

    private static bool TryParseArgs(string[] args, out IList<string> passwords, out string passwordFile, out string usernameFilter)
    {
        passwords      = null;
        passwordFile   = null;
        usernameFilter = null;
        _verbose       = false;
        _fileMode      = false;

        string singlePassword = null;

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg is "-v" or "--verbose")
            {
                _verbose = true;
                continue;
            }
            if (arg is "-f" or "--password-file")
            {
                if (passwordFile != null)
                {
                    Console.WriteLine("[!] -f may only be specified once.");
                    PrintUsage();
                    return false;
                }
                if (singlePassword != null)
                {
                    Console.WriteLine("[!] -f cannot be combined with a positional password.");
                    PrintUsage();
                    return false;
                }
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("[!] -f requires a file path.");
                    PrintUsage();
                    return false;
                }
                passwordFile = args[++i];
                continue;
            }
            if (arg is "-u" or "--username")
            {
                if (usernameFilter != null)
                {
                    Console.WriteLine("[!] -u may only be specified once.");
                    PrintUsage();
                    return false;
                }
                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("[!] -u requires a profile name.");
                    PrintUsage();
                    return false;
                }
                usernameFilter = args[++i];
                continue;
            }
            if (arg.StartsWith("-"))
            {
                Console.WriteLine($"[!] Unknown flag: {arg}");
                PrintUsage();
                return false;
            }
            if (singlePassword != null || passwordFile != null)
            {
                Console.WriteLine("[!] Unexpected extra argument.");
                PrintUsage();
                return false;
            }
            singlePassword = arg;
        }

        if (passwordFile == null && singlePassword == null)
        {
            PrintUsage();
            return false;
        }

        try
        {
            passwords = passwordFile != null
                ? LoadPasswordsFromFile(passwordFile)
                : new List<string> { singlePassword };
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] FATAL: {ex.GetType().Name}: {ex.Message}");
            return false;
        }

        _fileMode = passwordFile != null;
        return true;
    }

    private static List<string> LoadPasswordsFromFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"password file not found: {path}");

        var passwords = new List<string>();
        foreach (string line in File.ReadAllLines(path))
        {
            string trimmed = line.Trim();
            if (trimmed.Length > 0)
                passwords.Add(trimmed);
        }

        if (passwords.Count == 0)
            throw new InvalidOperationException("password file contains no passwords");

        return passwords;
    }

    private static List<PasswordKey> DerivePasswordKeys(IList<string> passwords)
    {
        var cache = new Dictionary<string, byte[]>();
        var keys  = new List<PasswordKey>(passwords.Count);

        for (int i = 0; i < passwords.Count; i++)
        {
            string password = passwords[i];
            if (!cache.TryGetValue(password, out byte[] k1))
            {
                k1 = Pbkdf2(Encoding.Unicode.GetBytes(password),
                            Array.Empty<byte>(), iters: 10_000, len: 32,
                            HashAlgorithmName.SHA256);
                cache[password] = k1;
            }
            keys.Add(new PasswordKey(i + 1, password, k1));
        }

        return keys;
    }

    // -u: only this profile's CacheData plus the SYSTEM CloudAP store.
    private static List<string> FilterCacheDataForUser(IList<string> cacheDataFiles, UserProfile user)
    {
        var results = new List<string>();
        string userRoot = user.ProfilePath.TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
        foreach (var f in cacheDataFiles)
        {
            if (f.StartsWith(userRoot, StringComparison.OrdinalIgnoreCase))
                results.Add(f);
            else if (f.IndexOf(@"\Windows\System32\config\systemprofile\", StringComparison.OrdinalIgnoreCase) >= 0)
                results.Add(f);
        }
        return results;
    }

    private static void ProcessUser(UserProfile user, IList<PasswordKey> passwordKeys, IList<string> cacheDataFiles, RunReport report)
    {
        Console.WriteLine();
        Console.WriteLine($"### {user.Username}  (SID {user.Sid})");

        var mkFiles   = UserEnumerator.FindMasterKeys(user);
        var credFiles = UserEnumerator.FindCredentialFiles(user);
        Console.WriteLine($"    master-key files : {mkFiles.Count}");
        Console.WriteLine($"    credential files : {credFiles.Count}");

        if (mkFiles.Count == 0)
        {
            Console.WriteLine("    -> no master keys on disk for this user; skipping");
            return;
        }

        for (int pi = 0; pi < passwordKeys.Count; pi++)
        {
            PasswordKey pw = passwordKeys[pi];
            if (_fileMode)
                Console.WriteLine($"    [pw {pw.LineNumber}/{passwordKeys.Count}] trying password: {ByteUtils.Mask(pw.Password)}");

            ProcessUserWithPassword(user, pw.K1, pw.Password, pw.LineNumber, mkFiles, credFiles, cacheDataFiles, report);
        }
    }

    private static void ProcessUserWithPassword(
        UserProfile user, byte[] k1, string password, int passwordLine,
        IList<string> mkFiles, IList<string> credFiles, IList<string> cacheDataFiles, RunReport report)
    {
        byte[] credKey = null;
        string matched = null;
        foreach (var cd in cacheDataFiles)
        {
            var ck = CredKeyExtractor.TryUnlockCacheData(cd, k1, _verbose);
            if (ck == null) continue;
            credKey = ck;
            matched = cd;
            break;
        }
        if (credKey == null)
        {
            Console.WriteLine("    -> no CredKey candidate recovered from available CacheData");
            return;
        }
        if (_fileMode)
            Console.WriteLine($"    -> password candidate: line {passwordLine} ({ByteUtils.Mask(password)})");
        Console.WriteLine($"    -> CacheData yielded CredKey candidate: {matched}");
        Console.WriteLine($"    -> candidate CredKey (64B) : {ByteUtils.Hex(credKey)}");

        byte[] prekey = DpapiCrypto.SidBoundPrekey(credKey, user.Sid);
        Console.WriteLine($"    -> candidate prekey (20B)  : {ByteUtils.Hex(prekey)}");

        bool masterKeyValidated = false;
        foreach (var mkPath in mkFiles)
        {
            byte[] mk;
            try { mk = MasterKeyDecryptor.TryDecryptMasterKeyFile(mkPath, prekey, _verbose); }
            catch (Exception ex)
            {
                if (_verbose) Console.WriteLine($"    MK {Path.GetFileName(mkPath)} - parse error: {ex.Message}");
                continue;
            }
            if (mk == null)
            {
                if (_verbose) Console.WriteLine($"    MK {Path.GetFileName(mkPath)} - HMAC mismatch");
                continue;
            }

            report.MksUnlocked++;
            masterKeyValidated = true;
            Console.WriteLine($"    ** DPAPI master key HMAC validated : {Path.GetFileName(mkPath)}");
            Console.WriteLine("       CredKey and password candidate confirmed for this profile.");
            Console.WriteLine($"       MK plaintext : {ByteUtils.Hex(mk)}");

            string mkGuid = MasterKeyDecryptor.ReadMkGuid(mkPath);
            foreach (var cred in credFiles)
            {
                var text = CredentialFileDecryptor.TryDecrypt(cred, mk, mkGuid, _verbose);
                if (text == null) continue;
                report.CredsRecovered++;
                Console.WriteLine($"       *** {Path.GetFileName(cred)}:");
                Console.WriteLine(ByteUtils.Indent(text, "         "));
            }
        }

        if (!masterKeyValidated)
            Console.WriteLine("    -> no DPAPI master key validated for this profile. CredKey and password candidate remain unconfirmed.");
    }

    private static void PrintHeader(IList<string> passwords, string passwordFile, string usernameFilter)
    {
        Console.WriteLine("[*] EntraDpapiDecrypt");
        Console.WriteLine("[*] Running as : " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
        if (passwordFile != null)
            Console.WriteLine($"[*] Passwords  : {passwords.Count} loaded from {passwordFile}");
        else
            Console.WriteLine("[*] Password   : " + ByteUtils.Mask(passwords[0]));
        if (!string.IsNullOrEmpty(usernameFilter))
            Console.WriteLine("[*] Target user: " + usernameFilter);
    }

    private static void PrintDiscovery(IList<UserProfile> users, IList<string> cacheDataFiles, string usernameFilter)
    {
        Console.WriteLine();
        if (!string.IsNullOrEmpty(usernameFilter))
            Console.WriteLine($"[*] Targeting profile '{usernameFilter}' ({users.Count} match):");
        else
            Console.WriteLine($"[*] Found {users.Count} user profiles:");
        foreach (var u in users)
            Console.WriteLine($"    - {u.Username,-24}  SID={u.Sid}   profile={u.ProfilePath}");
        Console.WriteLine();
        Console.WriteLine($"[*] Found {cacheDataFiles.Count} CacheData files:");
        foreach (var f in cacheDataFiles) Console.WriteLine("    - " + f);
        if (!string.IsNullOrEmpty(usernameFilter))
            Console.WriteLine("    (CacheData scan limited to target profile + SYSTEM CloudAP cache)");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("EntraDpapiDecrypt - Windows DPAPI recovery for Entra-ID joined machines");
        Console.WriteLine();
        Console.WriteLine("Usage:  EntraDpapiDecrypt.exe <cleartext-password> [-v|--verbose] [-u|--username <name>]");
        Console.WriteLine("        EntraDpapiDecrypt.exe -f <passwords.txt> [-v|--verbose] [-u|--username <name>]");
        Console.WriteLine();
        Console.WriteLine("For every provisioned user profile on the machine, walks the CloudAP DPAPI");
        Console.WriteLine("chain (CacheData -> CredKey -> SID prekey -> master key -> credential) using");
        Console.WriteLine("the supplied password(s) and prints any recovered plaintext credentials.");
        Console.WriteLine();
        Console.WriteLine("  -f, --password-file   text file with one password per line; each password");
        Console.WriteLine("                        is tried in order for every user profile.");
        Console.WriteLine("  -u, --username        local profile folder name to target (e.g. kerbme);");
        Console.WriteLine("                        only that user's master keys and credentials are processed.");
        Console.WriteLine();
        Console.WriteLine("Must run as NT AUTHORITY\\SYSTEM (or an admin with SeBackupPrivilege) to");
        Console.WriteLine("read every user's Protect\\ folder and the SYSTEM-profile CloudAPCache.");
        Console.WriteLine();
        Console.WriteLine("The tool does NOT touch lsass memory, impersonate any user, or use a driver.");
    }

    // CloudAP wraps CacheData with PBKDF2-HMAC-SHA256 and an empty salt.
    // Rfc2898DeriveBytes on net48 rejects salt < 8 bytes, so that case is manual.
    internal static byte[] Pbkdf2(byte[] password, byte[] salt, int iters, int len, HashAlgorithmName hash)
    {
        salt = salt ?? Array.Empty<byte>();

        if (salt.Length < 8)
            return Pbkdf2Manual(password, salt, iters, len, hash);

        using var kdf = new Rfc2898DeriveBytes(password, salt, iters, hash);
        return kdf.GetBytes(len);
    }

    private static byte[] Pbkdf2Manual(byte[] password, byte[] salt, int iters, int len, HashAlgorithmName hash)
    {
        int hLen = hash == HashAlgorithmName.SHA512 ? 64 :
                   hash == HashAlgorithmName.SHA256 ? 32 :
                   hash == HashAlgorithmName.SHA1   ? 20 :
                   throw new NotSupportedException(hash.Name);

        var dk = new byte[len];
        int offset = 0;
        for (int block = 1; offset < len; block++)
        {
            byte[] t   = Pbkdf2Block(password, salt, iters, block, hash);
            int copyLen = Math.Min(hLen, len - offset);
            Buffer.BlockCopy(t, 0, dk, offset, copyLen);
            offset += copyLen;
        }
        return dk;
    }

    private static byte[] Pbkdf2Block(byte[] password, byte[] salt, int iters, int blockIndex, HashAlgorithmName hash)
    {
        byte[] saltBlock = new byte[salt.Length + 4];
        Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);
        saltBlock[salt.Length + 0] = (byte)((blockIndex >> 24) & 0xFF);
        saltBlock[salt.Length + 1] = (byte)((blockIndex >> 16) & 0xFF);
        saltBlock[salt.Length + 2] = (byte)((blockIndex >>  8) & 0xFF);
        saltBlock[salt.Length + 3] = (byte)( blockIndex        & 0xFF);

        byte[] u = DpapiCrypto.Hmac(hash, password, saltBlock);
        byte[] t = (byte[])u.Clone();
        for (int i = 1; i < iters; i++)
        {
            u = DpapiCrypto.Hmac(hash, password, u);
            for (int j = 0; j < t.Length; j++)
                t[j] ^= u[j];
        }
        return t;
    }
}

internal sealed class RunReport
{
    public int MksUnlocked;
    public int CredsRecovered;
}

internal sealed class PasswordKey
{
    public PasswordKey(int lineNumber, string password, byte[] k1)
    {
        LineNumber = lineNumber;
        Password   = password;
        K1         = k1;
    }

    public int LineNumber { get; }
    public string Password { get; }
    public byte[] K1 { get; }
}

internal sealed class UserProfile
{
    public UserProfile(string sid, string username, string profilePath)
    {
        Sid         = sid;
        Username    = username;
        ProfilePath = profilePath;
    }

    public string Sid { get; }
    public string Username { get; }
    public string ProfilePath { get; }
}

internal static class UserEnumerator
{
    public static List<UserProfile> EnumerateUsers()
    {
        var users = new List<UserProfile>();
        using var root = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
        if (root == null) return users;

        foreach (string sid in root.GetSubKeyNames())
        {
            using var sk = root.OpenSubKey(sid);
            if (sk?.GetValue("ProfileImagePath") is not string profilePath || profilePath.Length == 0)
                continue;

            string lower = profilePath.ToLowerInvariant();
            if (lower.Contains(@"\systemprofile")   ||
                lower.Contains(@"\localservice")    ||
                lower.Contains(@"\networkservice"))
                continue;

            string username = Path.GetFileName(profilePath.TrimEnd('\\', '/'));
            users.Add(new UserProfile(sid, username, profilePath));
        }
        return users;
    }

    public static List<string> FindMasterKeys(UserProfile user)
    {
        var results = new List<string>();
        var candidates = new[]
        {
            Path.Combine(user.ProfilePath, @"AppData\Roaming\Microsoft\Protect", user.Sid),
            Path.Combine(user.ProfilePath, @"AppData\Local\Microsoft\Protect",   user.Sid),
        };
        foreach (var root in candidates)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var f in EnumerateFilesSafe(root, "*"))
            {
                string name = Path.GetFileName(f);
                if (name.Equals("Preferred",    StringComparison.OrdinalIgnoreCase)) continue;
                if (name.Equals("CREDHIST",     StringComparison.OrdinalIgnoreCase)) continue;
                if (name.Equals("BK-" + user.Sid, StringComparison.OrdinalIgnoreCase)) continue;
                if (!Guid.TryParse(name, out _)) continue;
                results.Add(f);
            }
        }
        return results;
    }

    public static List<string> FindCredentialFiles(UserProfile user)
    {
        var results = new List<string>();
        var candidates = new[]
        {
            Path.Combine(user.ProfilePath, @"AppData\Local\Microsoft\Credentials"),
            Path.Combine(user.ProfilePath, @"AppData\Roaming\Microsoft\Credentials"),
        };
        foreach (var root in candidates)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var f in EnumerateFilesSafe(root, "*"))
                results.Add(f);
        }
        return results;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, string pattern)
    {
        IEnumerable<string> results;
        try   { results = Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories); }
        catch { yield break; }
        foreach (var r in results) yield return r;
    }
}

internal static class CacheDataLocator
{
    public static List<string> FindAllCacheData()
    {
        var results = new List<string>();

        string sysRoot = @"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\AzureAD";
        AppendCacheDataUnder(sysRoot, results);

        if (Directory.Exists(@"C:\Users"))
        {
            foreach (var dir in EnumerateSubDirsSafe(@"C:\Users"))
            {
                string userAad = Path.Combine(dir, @"AppData\Local\Microsoft\Windows\CloudAPCache\AzureAD");
                AppendCacheDataUnder(userAad, results);
            }
        }

        return results;
    }

    private static void AppendCacheDataUnder(string root, List<string> dst)
    {
        if (!Directory.Exists(root)) return;
        IEnumerable<string> found;
        try   { found = Directory.EnumerateFiles(root, "CacheData", SearchOption.AllDirectories); }
        catch { return; }
        foreach (var f in found) dst.Add(f);
    }

    private static IEnumerable<string> EnumerateSubDirsSafe(string root)
    {
        IEnumerable<string> subs;
        try   { subs = Directory.EnumerateDirectories(root); }
        catch { yield break; }
        foreach (var s in subs) yield return s;
    }
}

// CacheData layout is undocumented and has drifted between Windows builds, so
// unlock is a brute-force AES sweep over aligned offsets rather than a parser.
internal static class CredKeyExtractor
{
    private static readonly int[] TryLengths = BuildTryLengths();

    private static int[] BuildTryLengths()
    {
        var list = new List<int>();
        for (int L = 640; L >= 32; L -= 16) list.Add(L);
        return list.ToArray();
    }

    public static byte[] TryUnlockCacheData(string cachePath, byte[] k1, bool verbose)
    {
        byte[] bytes = File.ReadAllBytes(cachePath);
        if (verbose) Console.WriteLine($"    [scan] {cachePath} ({bytes.Length} B)");

        byte[] expectedGuid = LookupExpectedCredKeyGuid(cachePath);
        if (verbose && expectedGuid != null)
            Console.WriteLine($"      Keys\\<guid> = {ByteUtils.Hex(expectedGuid)}");

        byte[] zeroIv = new byte[16];

        for (int offset = 0; offset + 32 <= bytes.Length; offset += 4)
        {
            foreach (int ctLen in TryLengths)
            {
                if (offset + 16 + ctLen <= bytes.Length)
                {
                    byte[] iv  = ByteUtils.Slice(bytes, offset, 16);
                    byte[] ct  = ByteUtils.Slice(bytes, offset + 16, ctLen);
                    byte[] pt  = TryAesCbc(ct, k1, iv);
                    if (pt != null)
                    {
                        var found = ExtractCredKey(pt, expectedGuid);
                        if (found.CredKey != null)
                        {
                            if (verbose) Console.WriteLine($"      hit (IV-embed) off=0x{offset:x} ctLen={ctLen} strategy={found.Strategy}");
                            return found.CredKey;
                        }
                    }
                }
                if (offset + ctLen <= bytes.Length)
                {
                    byte[] ct = ByteUtils.Slice(bytes, offset, ctLen);
                    byte[] pt = TryAesCbc(ct, k1, zeroIv);
                    if (pt != null)
                    {
                        var found = ExtractCredKey(pt, expectedGuid);
                        if (found.CredKey != null)
                        {
                            if (verbose) Console.WriteLine($"      hit (zero-IV) off=0x{offset:x} ctLen={ctLen} strategy={found.Strategy}");
                            return found.CredKey;
                        }
                    }
                }
            }
        }
        return null;
    }

    // Win11 26100+: Keys\<guid>. Older builds: Keys\CredKeyInfo (Version + GUID).
    private static byte[] LookupExpectedCredKeyGuid(string cachePath)
    {
        try
        {
            string cacheDir = Path.GetDirectoryName(cachePath);
            string profDir  = Path.GetDirectoryName(cacheDir);
            string keysDir  = Path.Combine(profDir!, "Keys");
            if (!Directory.Exists(keysDir)) return null;

            foreach (var f in Directory.EnumerateFiles(keysDir))
            {
                string name = Path.GetFileName(f);
                if (Guid.TryParse(name, out var g)) return g.ToByteArray();
            }
            string ckiPath = Path.Combine(keysDir, "CredKeyInfo");
            if (File.Exists(ckiPath))
            {
                byte[] cki = File.ReadAllBytes(ckiPath);
                if (cki.Length >= 4 + 16) return ByteUtils.Slice(cki, 4, 16);
            }
        }
        catch { }
        return null;
    }

    private static (byte[] CredKey, string Strategy) ExtractCredKey(byte[] pt, byte[] expectedGuid)
    {
        if (pt == null) return (null, null);

        if (expectedGuid is { Length: 16 })
        {
            for (int i = 0; i + 16 + 64 <= pt.Length; i++)
            {
                if (!ByteUtils.MemEqual(pt, i, expectedGuid, 0, 16)) continue;
                byte[] c = ByteUtils.Slice(pt, i + 16, 64);
                if (ByteUtils.LooksLikeKeyMaterial(c)) return (c, $"guid@0x{i:x}");
            }
        }

        if (pt.Length >= 4 + 16 + 64)
        {
            for (int i = 0; i + 4 + 16 + 64 <= pt.Length; i += 4)
            {
                if (BitConverter.ToUInt32(pt, i) != 0x40) continue;
                byte[] c = ByteUtils.Slice(pt, i + 4 + 16, 64);
                if (ByteUtils.LooksLikeKeyMaterial(c)) return (c, $"0x40+guid@0x{i:x}");
            }
        }

        if (pt.Length >= 4 + 64)
        {
            for (int i = 0; i + 4 + 64 <= pt.Length; i += 4)
            {
                if (BitConverter.ToUInt32(pt, i) != 0x40) continue;

                if (expectedGuid != null && i + 4 + 16 + 64 <= pt.Length &&
                    ByteUtils.MemEqual(pt, i + 4, expectedGuid, 0, 16))
                {
                    byte[] c = ByteUtils.Slice(pt, i + 4 + 16, 64);
                    if (ByteUtils.LooksLikeKeyMaterial(c)) return (c, $"0x40+guid-skip@0x{i:x}");
                }
                byte[] legacy = ByteUtils.Slice(pt, i + 4, 64);
                if (ByteUtils.LooksLikeKeyMaterial(legacy)) return (legacy, $"legacy-0x40@0x{i:x}");
            }
        }
        return (null, null);
    }

    private static byte[] TryAesCbc(byte[] ct, byte[] key, byte[] iv)
    {
        if (ct.Length == 0 || (ct.Length % 16) != 0) return null;
        try
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode    = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key     = key;
            aes.IV      = iv;
            using var xf = aes.CreateDecryptor();
            byte[] pt = xf.TransformFinalBlock(ct, 0, ct.Length);
            return ByteUtils.TryStripPkcs7(pt);
        }
        catch { return null; }
    }
}

internal static class MasterKeyDecryptor
{
    public static string ReadMkGuid(string mkPath)
    {
        byte[] hdr = new byte[128];
        using var fs = File.OpenRead(mkPath);
        int read = fs.Read(hdr, 0, hdr.Length);
        if (read < 84) return string.Empty;
        return Encoding.Unicode.GetString(hdr, 12, 72).TrimEnd('\0');
    }

    public static byte[] TryDecryptMasterKeyFile(string mkPath, byte[] prekey, bool verbose)
    {
        byte[] file = File.ReadAllBytes(mkPath);
        if (file.Length < 128) return null;

        uint version = BitConverter.ToUInt32(file, 0);
        if (version != 2) throw new NotSupportedException($"MK file version {version} not supported (only v2)");

        // Win11 26100+ inserts 4 extra header bytes, so MasterKeyLen moves 92 -> 96
        // and the blob starts at 128 instead of 124. Probe QWORD@92: a plausible
        // length (32..0x10000) means the classic layout.
        long mkLen, bkLen, chLen, dkLen;
        int  blobStart;
        long probe = BitConverter.ToInt64(file, 92);
        if (probe > 32 && probe < 0x10000)
        {
            mkLen     = probe;
            bkLen     = BitConverter.ToInt64(file, 100);
            chLen     = BitConverter.ToInt64(file, 108);
            dkLen     = BitConverter.ToInt64(file, 116);
            blobStart = 124;
        }
        else
        {
            mkLen     = BitConverter.ToInt64(file, 96);
            bkLen     = BitConverter.ToInt64(file, 104);
            chLen     = BitConverter.ToInt64(file, 112);
            dkLen     = BitConverter.ToInt64(file, 120);
            blobStart = 128;
        }
        if (verbose) Console.WriteLine(
            $"        [mk] {Path.GetFileName(mkPath)}  layout=" +
            (blobStart == 128 ? "modern" : "classic") +
            $"  mkLen={mkLen} bkLen={bkLen} chLen={chLen} dkLen={dkLen}");

        if (mkLen <= 32) return null;
        if (blobStart + mkLen > file.Length) return null;

        byte[] mkBlob = ByteUtils.Slice(file, blobStart, (int)mkLen);
        byte[] salt   = ByteUtils.Slice(mkBlob, 4, 16);
        uint rounds   = BitConverter.ToUInt32(mkBlob, 20);
        uint hashAlg  = BitConverter.ToUInt32(mkBlob, 24);
        uint cryptAlg = BitConverter.ToUInt32(mkBlob, 28);
        byte[] ct     = ByteUtils.Slice(mkBlob, 32, mkBlob.Length - 32);

        var (hName, hLen)         = MapHashAlg(hashAlg);
        var (keyLen, blockLen)    = MapCryptAlg(cryptAlg);

        byte[] dk     = DpapiCrypto.DeriveDpapiKdf(prekey, salt, keyLen + blockLen, (int)rounds, hName);
        byte[] aesKey = ByteUtils.Slice(dk, 0, keyLen);
        byte[] iv     = ByteUtils.Slice(dk, keyLen, blockLen);

        byte[] pt;
        try   { pt = AesCbcNoPad(ct, aesKey, iv); }
        catch { return null; }

        if (pt.Length < 16 + hLen + 64) return null;

        // hmacSalt(16) | hmacStored(hLen) | mkMsg... | mk(64)
        byte[] hmacSalt   = ByteUtils.Slice(pt, 0, 16);
        byte[] hmacStored = ByteUtils.Slice(pt, 16, hLen);
        byte[] mkMsg      = ByteUtils.Slice(pt, 16 + hLen, pt.Length - 16 - hLen);
        byte[] mk         = ByteUtils.Slice(pt, pt.Length - 64, 64);

        byte[] outer    = DpapiCrypto.Hmac(hName, prekey, hmacSalt);
        byte[] expected = DpapiCrypto.Hmac(hName, outer,  mkMsg);
        return ByteUtils.ConstEq(expected, hmacStored) ? mk : null;
    }

    private static (HashAlgorithmName Name, int DigestLen) MapHashAlg(uint calg) => calg switch
    {
        Calg.SHA1   => (HashAlgorithmName.SHA1,   20),
        Calg.SHA256 => (HashAlgorithmName.SHA256, 32),
        Calg.SHA512 => (HashAlgorithmName.SHA512, 64),
        _ => throw new NotSupportedException($"unsupported CALG hash 0x{calg:x}")
    };

    private static (int KeyLen, int BlockLen) MapCryptAlg(uint calg) => calg switch
    {
        Calg.AES128 => (16, 16),
        Calg.AES192 => (24, 16),
        Calg.AES256 => (32, 16),
        Calg.TDES   => (24, 8),
        _ => throw new NotSupportedException($"unsupported CALG crypt 0x{calg:x}")
    };

    internal static byte[] AesCbcNoPad(byte[] ct, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = key.Length * 8;
        aes.Mode    = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key     = key;
        aes.IV      = iv;
        using var xf = aes.CreateDecryptor();
        return xf.TransformFinalBlock(ct, 0, ct.Length);
    }
}

internal static class CredentialFileDecryptor
{
    public static string TryDecrypt(string credPath, byte[] mk, string mkGuidExpected, bool verbose)
    {
        byte[] raw;
        try   { raw = File.ReadAllBytes(credPath); }
        catch { return null; }
        if (raw.Length < 20) return null;

        uint credSize = BitConverter.ToUInt32(raw, 4);
        if (12 + credSize > raw.Length) return null;

        byte[] blob = ByteUtils.Slice(raw, 12, (int)credSize);
        if (blob.Length < 0x28 + 16) return null;

        int p = 0;
        _ = ByteUtils.ReadU32(blob, ref p);                                 // Version
        _ = ByteUtils.ReadBytes(blob, ref p, 16);                           // GuidCredential
        _ = ByteUtils.ReadU32(blob, ref p);                                 // MasterKeyVersion
        byte[] guidMk = ByteUtils.ReadBytes(blob, ref p, 16);               // GuidMasterKey
        string mkGuid = new Guid(guidMk).ToString();
        if (verbose) Console.WriteLine($"        [cred] {Path.GetFileName(credPath)} mkGuid={mkGuid}");
        if (!mkGuidExpected.Equals(mkGuid, StringComparison.OrdinalIgnoreCase))
            return null;

        _              = ByteUtils.ReadU32(blob, ref p);                    // Flags
        uint descLen   = ByteUtils.ReadU32(blob, ref p);
        string desc    = Encoding.Unicode.GetString(ByteUtils.ReadBytes(blob, ref p, (int)descLen)).TrimEnd('\0');
        uint cryptAlg  = ByteUtils.ReadU32(blob, ref p);
        _              = ByteUtils.ReadU32(blob, ref p);                    // CryptAlgoLen
        uint saltLen   = ByteUtils.ReadU32(blob, ref p);
        byte[] salt    = ByteUtils.ReadBytes(blob, ref p, (int)saltLen);
        uint hmacKeyLn = ByteUtils.ReadU32(blob, ref p);
        _              = ByteUtils.ReadBytes(blob, ref p, (int)hmacKeyLn);  // HMacKey (unused)
        uint hashAlg   = ByteUtils.ReadU32(blob, ref p);
        _              = ByteUtils.ReadU32(blob, ref p);                    // HashAlgoLen
        uint hmacLen   = ByteUtils.ReadU32(blob, ref p);
        _              = ByteUtils.ReadBytes(blob, ref p, (int)hmacLen);    // HMac (unused)
        uint dataLen   = ByteUtils.ReadU32(blob, ref p);
        byte[] data    = ByteUtils.ReadBytes(blob, ref p, (int)dataLen);

        var (hName, _)       = (hashAlg switch
        {
            Calg.SHA1   => (HashAlgorithmName.SHA1,   20),
            Calg.SHA256 => (HashAlgorithmName.SHA256, 32),
            Calg.SHA512 => (HashAlgorithmName.SHA512, 64),
            _ => throw new NotSupportedException($"unsupported CALG hash 0x{hashAlg:x}")
        });
        var (cKeyLen, cBlockLen) = cryptAlg switch
        {
            Calg.AES128 => (16, 16),
            Calg.AES192 => (24, 16),
            Calg.AES256 => (32, 16),
            Calg.TDES   => (24, 8),
            _ => throw new NotSupportedException($"unsupported CALG crypt 0x{cryptAlg:x}")
        };

        byte[] keyHash    = Sha1(mk);
        byte[] sessionKey = DpapiCrypto.Hmac(hName, keyHash, salt);
        byte[] derivedKey = DpapiCrypto.DeriveDpapiBlobKey(sessionKey, hName, cKeyLen);
        byte[] aesKey     = ByteUtils.Slice(derivedKey, 0, cKeyLen);
        byte[] iv         = new byte[cBlockLen];

        byte[] plain;
        try   { plain = MasterKeyDecryptor.AesCbcNoPad(data, aesKey, iv); }
        catch { return null; }
        plain = ByteUtils.TryStripPkcs7(plain);
        if (plain.Length < 8) return null;

        return FormatCredentialBlob(plain, desc);
    }

    private static string FormatCredentialBlob(byte[] pt, string description)
    {
        var sb = new StringBuilder();
        try
        {
            int p = 0;
            _                 = ByteUtils.ReadU32(pt, ref p);       // Flags
            _                 = ByteUtils.ReadU32(pt, ref p);       // Size
            _                 = ByteUtils.ReadU32(pt, ref p);       // Unknown1
            uint typeVal      = ByteUtils.ReadU32(pt, ref p);
            _                 = ByteUtils.ReadU32(pt, ref p);       // Unknown2
            long lastWritten  = BitConverter.ToInt64(pt, p); p += 8;
            _                 = ByteUtils.ReadU32(pt, ref p);       // Unknown3
            uint persist      = ByteUtils.ReadU32(pt, ref p);
            uint attrCount    = ByteUtils.ReadU32(pt, ref p);
            _                 = ByteUtils.ReadU32(pt, ref p);       // Unknown5
            _                 = ByteUtils.ReadU32(pt, ref p);       // Unknown6
            string target     = ReadPascalUtf16Nul(pt, ref p);
            string aliasStr   = ReadPascalUtf16Nul(pt, ref p);
            string comment    = ReadPascalUtf16Nul(pt, ref p);
            _                 = ReadPascalUtf16Nul(pt, ref p);      // Unknown4 (wide string)
            string username   = ReadPascalUtf16Nul(pt, ref p);
            uint pwdLen       = ByteUtils.ReadU32(pt, ref p);
            byte[] pwdRaw     = ByteUtils.ReadBytes(pt, ref p, (int)pwdLen);
            string pwdString  = Encoding.Unicode.GetString(pwdRaw).TrimEnd('\0');

            DateTime lastWrittenUtc = DateTime.MinValue;
            try { lastWrittenUtc = DateTime.FromFileTimeUtc(lastWritten); } catch { }

            sb.AppendLine($"description : {description}");
            sb.AppendLine($"lastWritten : {(lastWrittenUtc == DateTime.MinValue ? "n/a" : lastWrittenUtc.ToString("o"))}");
            sb.AppendLine($"type        : 0x{typeVal:x8}  ({CredTypeName(typeVal)})");
            sb.AppendLine($"persist     : 0x{persist:x8}");
            sb.AppendLine($"target      : {target}");
            if (!string.IsNullOrEmpty(aliasStr)) sb.AppendLine($"targetAlias : {aliasStr}");
            if (!string.IsNullOrEmpty(comment))  sb.AppendLine($"comment     : {comment}");
            sb.AppendLine($"username    : {username}");
            sb.AppendLine($"password    : {(ByteUtils.LooksPrintableUtf16(pwdString) ? pwdString : "0x" + ByteUtils.Hex(pwdRaw))}");
            sb.Append(    $"attrCount   : {attrCount}");
        }
        catch (Exception ex)
        {
            sb.AppendLine("parse-error : " + ex.Message);
            sb.Append("plaintext(hex) : " + ByteUtils.Hex(pt.Take(64).ToArray()) + (pt.Length > 64 ? "..." : ""));
        }
        return sb.ToString();
    }

    private static string ReadPascalUtf16Nul(byte[] pt, ref int p)
    {
        uint len = ByteUtils.ReadU32(pt, ref p);
        return Encoding.Unicode.GetString(ByteUtils.ReadBytes(pt, ref p, (int)len)).TrimEnd('\0');
    }

    private static string CredTypeName(uint t) => t switch
    {
        1 => "CRED_TYPE_GENERIC",
        2 => "CRED_TYPE_DOMAIN_PASSWORD",
        3 => "CRED_TYPE_DOMAIN_CERTIFICATE",
        4 => "CRED_TYPE_DOMAIN_VISIBLE_PASSWORD",
        5 => "CRED_TYPE_GENERIC_CERTIFICATE",
        6 => "CRED_TYPE_DOMAIN_EXTENDED",
        _ => "CRED_TYPE_UNKNOWN"
    };

    private static byte[] Sha1(byte[] input)
    {
        using var sha = SHA1.Create();
        return sha.ComputeHash(input);
    }
}

// DPAPI master-key unwrap uses a proprietary XOR-chained KDF, not PBKDF2.
internal static class DpapiCrypto
{
    public static byte[] SidBoundPrekey(byte[] rawCredKey, string sid)
    {
        byte[] shaCk;
        using (var sha = SHA1.Create()) shaCk = sha.ComputeHash(rawCredKey);
        byte[] sidUtf16 = Encoding.Unicode.GetBytes(sid + "\0");
        using var hmac  = new HMACSHA1(shaCk);
        return hmac.ComputeHash(sidUtf16);
    }

    // Matches impacket dpapi.MasterKey.deriveKey (XOR-chained HMAC, not PBKDF2).
    public static byte[] DeriveDpapiKdf(byte[] passphrase, byte[] salt, int keyLen, int count, HashAlgorithmName hName)
    {
        var result = new List<byte>(keyLen + 64);
        int blockIndex = 1;
        while (result.Count < keyLen)
        {
            byte[] u = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, u, 0, salt.Length);
            u[salt.Length + 0] = (byte)((blockIndex >> 24) & 0xFF);
            u[salt.Length + 1] = (byte)((blockIndex >> 16) & 0xFF);
            u[salt.Length + 2] = (byte)((blockIndex >>  8) & 0xFF);
            u[salt.Length + 3] = (byte)( blockIndex        & 0xFF);
            blockIndex++;

            byte[] derived = Hmac(hName, passphrase, u);
            for (int r = 0; r < count - 1; r++)
            {
                byte[] actual = Hmac(hName, passphrase, derived);
                for (int j = 0; j < derived.Length; j++)
                    derived[j] = (byte)(derived[j] ^ actual[j]);
            }
            result.AddRange(derived);
        }
        return result.GetRange(0, keyLen).ToArray();
    }

    // Matches impacket dpapi.DPAPI_BLOB.deriveKey (ipad/opad expand if too short).
    public static byte[] DeriveDpapiBlobKey(byte[] sessionKey, HashAlgorithmName hName, int cryptKeyLen)
    {
        int hBlockSize = hName == HashAlgorithmName.SHA512 ? 128 : 64;

        byte[] derived = sessionKey.Length > hBlockSize
            ? Hmac(hName, sessionKey, Array.Empty<byte>())
            : sessionKey;

        if (derived.Length >= cryptKeyLen) return derived;

        byte[] padded = new byte[hBlockSize];
        Buffer.BlockCopy(derived, 0, padded, 0, derived.Length);
        byte[] ipad = new byte[hBlockSize];
        byte[] opad = new byte[hBlockSize];
        for (int i = 0; i < hBlockSize; i++)
        {
            ipad[i] = (byte)(padded[i] ^ 0x36);
            opad[i] = (byte)(padded[i] ^ 0x5c);
        }
        byte[] ipadHash, opadHash;
        using (var h = HashFor(hName)) ipadHash = h.ComputeHash(ipad);
        using (var h = HashFor(hName)) opadHash = h.ComputeHash(opad);

        byte[] combined = new byte[ipadHash.Length + opadHash.Length];
        Buffer.BlockCopy(ipadHash, 0, combined, 0,                combined.Length / 2);
        Buffer.BlockCopy(opadHash, 0, combined, ipadHash.Length,  opadHash.Length);
        return combined;
    }

    public static byte[] Hmac(HashAlgorithmName hName, byte[] key, byte[] msg)
    {
        HMAC hmac = hName == HashAlgorithmName.SHA1   ? new HMACSHA1(key)   :
                    hName == HashAlgorithmName.SHA256 ? new HMACSHA256(key) :
                    hName == HashAlgorithmName.SHA512 ? new HMACSHA512(key) :
                    throw new NotSupportedException(hName.Name);
        using (hmac) return hmac.ComputeHash(msg);
    }

    private static HashAlgorithm HashFor(HashAlgorithmName hName) =>
        hName == HashAlgorithmName.SHA1   ? SHA1.Create()   :
        hName == HashAlgorithmName.SHA256 ? SHA256.Create() :
        hName == HashAlgorithmName.SHA512 ? SHA512.Create() :
        throw new NotSupportedException(hName.Name);
}

internal static class ByteUtils
{
    public static byte[] Slice(byte[] src, int off, int len)
    {
        var d = new byte[len];
        Buffer.BlockCopy(src, off, d, 0, len);
        return d;
    }

    public static bool ConstEq(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public static bool MemEqual(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        if (aOff + len > a.Length || bOff + len > b.Length) return false;
        for (int i = 0; i < len; i++)
            if (a[aOff + i] != b[bOff + i]) return false;
        return true;
    }

    public static uint ReadU32(byte[] b, ref int p)
    {
        uint v = BitConverter.ToUInt32(b, p);
        p += 4;
        return v;
    }

    public static byte[] ReadBytes(byte[] b, ref int p, int n)
    {
        var r = Slice(b, p, n);
        p += n;
        return r;
    }

    public static string Hex(byte[] b) => BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();

    public static string Mask(string s) =>
        s.Length <= 2 ? new string('*', s.Length) : s[0] + new string('*', s.Length - 2) + s[s.Length - 1];

    public static string Indent(string s, string prefix)
    {
        var sb = new StringBuilder();
        foreach (var line in s.Split('\n')) sb.AppendLine(prefix + line.TrimEnd('\r'));
        return sb.ToString().TrimEnd();
    }

    public static bool LooksLikeKeyMaterial(byte[] b)
    {
        if (b == null || b.Length == 0) return false;
        int zeros = 0, printable = 0;
        var distinct = new HashSet<byte>();
        foreach (var x in b)
        {
            if (x == 0) zeros++;
            if (x >= 0x20 && x <= 0x7e) printable++;
            distinct.Add(x);
        }
        if (zeros > b.Length / 2)             return false;
        if (printable > b.Length * 3 / 4)     return false;
        if (distinct.Count <= b.Length / 4)   return false;
        return true;
    }

    public static bool LooksPrintableUtf16(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        foreach (var c in s)
            if (c < 0x20 || c > 0x7e) return false;
        return true;
    }

    public static byte[] TryStripPkcs7(byte[] buf)
    {
        if (buf.Length == 0) return buf;
        int pad = buf[buf.Length - 1];
        if (pad < 1 || pad > 16 || pad > buf.Length) return buf;
        for (int i = buf.Length - pad; i < buf.Length; i++)
            if (buf[i] != pad) return buf;
        return Slice(buf, 0, buf.Length - pad);
    }
}
