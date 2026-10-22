using System.Text.Json;
using System.Text.Json.Nodes;
using WinClient.Core.Auth;
using WinClient.Core.Client;
using WinClient.Core.Pairing;
using Xunit;

namespace WinClient.Tests;

public sealed class PairingCertificateTests
{
    [Theory]
    [InlineData("hy2_server_name")]
    [InlineData("hy2_certificate")]
    public void V2RequiresEachNewKey(string key)
    {
        var document = PairingTests.ValidDocument();
        document["node"]!.AsObject().Remove(key);
        var error = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Matches("[\u4e00-\u9fff]", error.Message);
    }

    [Theory]
    [InlineData("hy2_server_name", "null")]
    [InlineData("hy2_server_name", "123")]
    [InlineData("hy2_server_name", "\"\"")]
    [InlineData("hy2_server_name", "\"bad name\"")]
    [InlineData("hy2_server_name", "\"bad_name\"")]
    [InlineData("hy2_server_name", "\"-bad.test\"")]
    [InlineData("hy2_server_name", "\"bad-.test\"")]
    [InlineData("hy2_server_name", "\"bad..test\"")]
    [InlineData("hy2_server_name", "\"*.test\"")]
    [InlineData("hy2_certificate", "null")]
    [InlineData("hy2_certificate", "\"not-an-array\"")]
    [InlineData("hy2_certificate", "[]")]
    [InlineData("hy2_certificate", "[123]")]
    [InlineData("hy2_certificate", "[\"-----BEGIN CERTIFICATE-----\",null,\"-----END CERTIFICATE-----\"]")]
    [InlineData("hy2_certificate", "[\"-----BEGIN CERTIFICATE-----\",\"\",\"-----END CERTIFICATE-----\"]")]
    [InlineData("hy2_certificate", "[\"-----BEGIN CERTIFICATE-----\",\"   \",\"-----END CERTIFICATE-----\"]")]
    [InlineData("hy2_certificate", "[\"wrong header\",\"TEST\",\"-----END CERTIFICATE-----\"]")]
    [InlineData("hy2_certificate", "[\"-----BEGIN CERTIFICATE-----\",\"TEST\",\"wrong footer\"]")]
    [InlineData("hy2_certificate", "[\"-----BEGIN CERTIFICATE-----\",\"TEST\\nLINE\",\"-----END CERTIFICATE-----\"]")]
    public void V2RejectsInvalidBackupFields(string key, string value)
    {
        var document = PairingTests.ValidDocument();
        document["node"]![key] = JsonNode.Parse(value);
        var error = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Matches("[\u4e00-\u9fff]", error.Message);
        Assert.DoesNotContain(PairingTests.ValidPairing().Node.Hy2Password, error.Message);
    }

    [Fact]
    public void V2RejectsOverlongHostnameLabelsAndNames()
    {
        foreach (var name in new[] { new string('a', 64), string.Join('.', Enumerable.Repeat(new string('a', 63), 4)) })
        {
            var document = PairingTests.ValidDocument();
            document["node"]!["hy2_server_name"] = name;
            Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        }
    }

    [Theory]
    [InlineData("exitnode")]
    [InlineData("backup.example.test")]
    [InlineData("backup-1.example.test")]
    public void V2UsesBackupNameIndependentlyOfRealityName(string name)
    {
        var document = PairingTests.ValidDocument();
        document["node"]!["hy2_server_name"] = name;
        var pair = PairingFile.Parse(document.ToJsonString());
        Assert.Null(pair.Warning);
        var outbounds = LocalConfigRenderer.Render(pair.Node).GetProperty("outbounds");
        Assert.Equal(pair.Node.Sni, outbounds[0].GetProperty("tls").GetProperty("server_name").GetString());
        Assert.Equal(name, outbounds[1].GetProperty("tls").GetProperty("server_name").GetString());
        Assert.Equal(pair.Node.Hy2Certificate,
            outbounds[1].GetProperty("tls").GetProperty("certificate").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public void RenderedUrltestHasThreeHundredMillisecondTolerance()
    {
        var pair = PairingFile.Parse(PairingTests.ValidDocument().ToJsonString());
        var outbounds = LocalConfigRenderer.Render(pair.Node).GetProperty("outbounds");
        var urltest = outbounds.EnumerateArray().Single(o => o.GetProperty("type").GetString() == "urltest");
        Assert.Equal(300, urltest.GetProperty("tolerance").GetInt32());
        Assert.Equal(new[] { "type", "tag", "outbounds", "url", "interval", "tolerance" },
            urltest.EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public void V1WithoutNewKeysKeepsOriginalConfigurationAndShowsWarning()
    {
        var document = PairingTests.ValidDocument();
        document["format"] = "ycpair/1";
        document["node"]!.AsObject().Remove("hy2_server_name");
        document["node"]!.AsObject().Remove("hy2_certificate");
        var pair = PairingFile.Parse(document.ToJsonString());
        Assert.Equal("配对文件是旧版,备用线路可能不可用,建议在小主机上重新导出", pair.Warning);
        if (OperatingSystem.IsWindows())
            Assert.Contains(pair.Warning!, ClientRuntime.PairingImportMessage(pair));
        var actual = JsonNode.Parse(LocalConfigRenderer.Render(pair.Node).GetRawText())!;
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(PairingTests.GoldenDirectory, "client-windows.json")))!;
        expected.AsObject().Remove("_comment");
        expected["outbounds"]![1]!["tls"]!.AsObject().Remove("certificate");
        Assert.True(JsonNode.DeepEquals(expected, actual));
        Assert.Equal("exitnode", actual["outbounds"]![1]!["tls"]!["server_name"]!.GetValue<string>());
        Assert.False(actual["outbounds"]![1]!["tls"]!.AsObject().ContainsKey("certificate"));
    }

    [Fact]
    public void V3RequiresObfsPassword()
    {
        var document = PairingTests.ValidDocument();
        document["node"]!.AsObject().Remove("hy2_obfs_password");
        var error = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Matches("[一-鿿]", error.Message);
        Assert.Contains("混淆", error.Message);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("123")]
    [InlineData("\"\"")]
    [InlineData("\"abcdefghijklmno\"")]
    [InlineData("\"contains space 0123456789\"")]
    [InlineData("\"with=equals-0123456789\"")]
    public void V3RejectsInvalidObfs(string value)
    {
        var document = PairingTests.ValidDocument();
        document["node"]!["hy2_obfs_password"] = JsonNode.Parse(value);
        var error = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Equal("备用线路混淆密码格式不正确，请重新导出。", error.Message);
        Assert.DoesNotContain(PairingTests.ValidPairing().Node.Hy2Password, error.Message);
    }

    [Theory]
    [InlineData("ycpair/1")]
    [InlineData("ycpair/2")]
    public void OlderFormatsValidateObfsKeyWhenPresent(string format)
    {
        var document = PairingTests.ValidDocument();
        document["format"] = format;
        document["node"]!["hy2_obfs_password"] = "bad obfs value";
        var error = Assert.Throws<InvalidDataException>(() => PairingFile.Parse(document.ToJsonString()));
        Assert.Contains("混淆", error.Message);
    }

    [Fact]
    public void V3RendersObfsLikeNodeAndHasNoWarning()
    {
        var pair = PairingTests.ValidPairing();
        Assert.Null(pair.Warning);
        var backup = JsonNode.Parse(LocalConfigRenderer.Render(pair.Node).GetRawText())!["outbounds"]![1]!.AsObject();
        Assert.Equal(new[] { "type", "tag", "server", "server_port", "password", "obfs", "tls" },
            backup.Select(property => property.Key));
        Assert.Equal("salamander", backup["obfs"]!["type"]!.GetValue<string>());
        Assert.Equal(pair.Node.Hy2ObfsPassword, backup["obfs"]!["password"]!.GetValue<string>());
    }

    [Fact]
    public void V2WithoutObfsParsesWithWarning()
    {
        var document = PairingTests.ValidDocument();
        document["format"] = "ycpair/2";
        document["node"]!.AsObject().Remove("hy2_obfs_password");
        var pair = PairingFile.Parse(document.ToJsonString());
        Assert.Equal("配对文件是旧版,没有备用线路混淆参数;节点已启用混淆时备用线路不可用,建议在小主机上重新导出", pair.Warning);
        Assert.Contains("混淆", pair.Warning);
        Assert.Equal("", pair.Node.Hy2ObfsPassword);
        if (OperatingSystem.IsWindows())
            Assert.Contains(pair.Warning!, ClientRuntime.PairingImportMessage(pair));
        var actual = JsonNode.Parse(LocalConfigRenderer.Render(pair.Node).GetRawText())!;
        Assert.False(actual["outbounds"]![1]!.AsObject().ContainsKey("obfs"));
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(PairingTests.GoldenDirectory, "client-windows.json")))!;
        expected.AsObject().Remove("_comment");
        expected["outbounds"]![1]!.AsObject().Remove("obfs");
        Assert.True(JsonNode.DeepEquals(expected, actual));
    }

    [Fact]
    public void AuthNodeDeserializationUsesSameBackupTlsAsPairing()
    {
        var document = PairingTests.ValidDocument();
        var node = document["node"]!.Deserialize<NodeInfo>(new JsonSerializerOptions
        { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })!;
        var fromAuth = LocalConfigRenderer.Render(node);
        var fromPair = LocalConfigRenderer.Render(PairingTests.ValidPairing().Node);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(fromAuth.GetRawText()), JsonNode.Parse(fromPair.GetRawText())));
    }
}
