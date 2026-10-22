namespace WinClient.App.Presentation;

public sealed record SelfCheckItemView(int Index, string Name, string Result, string Detail)
{
    public TileSpec Tile => Result switch
    {
        "通过" => new(Tone.Ok, Glyph.Check, Flow.None),
        "未通过" => new(Tone.Bad, Glyph.X, Flow.None),
        "跳过" => new(Tone.N, Glyph.Ring, Flow.None, Dim: true),
        _ => new(Tone.Warn, Glyph.Ask, Flow.None)
    };
}
