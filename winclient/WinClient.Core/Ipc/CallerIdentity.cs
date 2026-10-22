namespace WinClient.Core.Ipc;

/// <summary>
/// 管道调用者身份的纯判定（不含系统调用，便于单测）：
/// 只有程序完整路径规范化后严格位于 appRoot（本产品安装目录）之下的进程，才可执行会改变连接状态的指令。
/// 路径规则与 ServerIdentity 的路径部分一致；不看会话号——界面在用户会话、卸载与更新助手在管理员会话，都允许。
/// 安装目录只有管理员能写，普通用户进程无法把自己放进去。
/// </summary>
public static class CallerIdentity
{
    /// <param name="imagePath">调用者进程的程序完整路径；取不到时为 null，按不可信处理。</param>
    /// <param name="appRoot">本产品安装根目录（%ProgramFiles%\YuanC\app）。</param>
    public static bool IsTrusted(string? imagePath, string appRoot) => ServerIdentity.IsImageUnderRoot(imagePath, appRoot);
}
