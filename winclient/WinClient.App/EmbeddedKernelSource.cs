using System.IO;
using WinClient.Core.Kernel;

namespace WinClient.App;

internal sealed class EmbeddedKernelSource : IKernelSource
{
    public string ManifestJson
    {
        get
        {
            using var stream = Open("YuanC.Kernel.manifest.json");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }
    }

    public Stream Open(string logicalName) => typeof(EmbeddedKernelSource).Assembly.GetManifestResourceStream(logicalName)
        ?? throw new InvalidOperationException(KernelInstaller.VerificationFailureMessage);
}
