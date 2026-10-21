using System.Security.Cryptography;

namespace WinClient.Core.Update;

public static class UpdateVerifier
{
    public static UpdateManifest VerifyManifest(byte[] manifest, byte[] signature, ECDsa publicKey)
    {
        try
        {
            if (manifest.Length > 65536 || signature.Length is 0 or > 4096 || publicKey.KeySize != 256 ||
                !publicKey.VerifyData(manifest, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                throw new InvalidDataException("更新签名校验失败，未安装。");
        }
        catch (CryptographicException) { throw new InvalidDataException("更新签名校验失败，未安装。"); }
        return UpdateManifest.Parse(manifest);
    }
    public static void VerifyPayload(Stream exe, UpdateManifest manifest)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[65536]; long size = 0;
        int read;
        while ((read = exe.Read(buffer)) != 0)
        {
            size += read;
            if (size > manifest.Size || size > UpdateManifest.MaxPayloadBytes) throw new InvalidDataException("更新文件大小不符，未安装。");
            hash.AppendData(buffer, 0, read);
        }
        if (size != manifest.Size || !Convert.ToHexString(hash.GetHashAndReset()).Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("更新文件校验失败，未安装。");
    }
}
